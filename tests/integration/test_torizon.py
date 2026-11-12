# SPDX-License-Identifier: Apache-2.0
"""firmline-agent run on Torizon: the update of a `docker-compose` component. The agent, a
service of the composition `torizon`, downloads and checks the package, then starts
`firmline-agent apply` in a container of its own (firmline-apply: same image, --volumes-from the
agent's container), follows its outcome in apply.json every second and sends it as the release's
one result. A restart of the agent (an update of the agent itself, a power loss) never loses the
result and never sends two; an apply that ended without an outcome is failed install_failed, and
the composition of compose_file is brought up again.

The device is a TorizonDevice in the test daemon (docker_host.py), with the fake platform and
broker of harness.py; the packages are made with `pack`."""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from docker_host import TorizonDevice, docker_host
from harness import (
    AGENT_BINARY,
    SANITIZER_MARKERS,
    IntegrationTest,
    assert_no_secrets,
    wait_until,
)
from test_ota import OtaBase

AGENT_1 = "firmline-test/agent:1"
AGENT_2 = "firmline-test/agent:2"
OLD = {"app": "example/old:1"}
RESULT_TIMEOUT = 240


class TorizonTest(IntegrationTest):
    @classmethod
    def setUpClass(cls):
        cls.docker = docker_host()

    def setUp(self):
        super().setUp()
        self.addCleanup(self.docker.reset)
        self.broker = self.make_broker()
        self.mqtt = self.platform.connect(self.broker)
        self.addCleanup(self.mqtt.close)
        self.old = self.docker.app_image("example/old:1", "stay")
        self.agent_1 = self.docker.agent_image(AGENT_1)
        self.device = TorizonDevice(
            self.docker, self.tmp / "device", self.platform.url, self.broker.port,
            self.pki.root_path, self.pki.update_key_path,
        )
        self.addCleanup(self.check_sanitizers)
        self.addCleanup(self.device.close)
        self.token = None
        self.offers = []

    # The device.

    def start_device(self, services=None) -> str:
        """The composition of the agent and `services` (default the old application), the
        agent registered and subscribed: its device ID."""
        self.device.start(services or OLD, AGENT_1)
        self.token = self.platform.new_token()
        device_id = self.device.register(self.token)
        self.device.wait_for_log("subscribed to", timeout=60)
        return device_id

    def pack(self, version: str, composition: str, name: str = "") -> Path:
        """`pack` of a composition (its images must exist in the daemon)."""
        folder = self.tmp / "packages"
        folder.mkdir(exist_ok=True)
        compose = folder / f"{name or version}.yml"
        compose.write_text(composition)
        output = folder / f"{name or version}.tar"
        result = subprocess.run(
            [AGENT_BINARY, "pack", "--compose", str(compose), "--version", version,
             "--output", str(output)],
            env=self.docker.env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=600,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        return output

    def offer(self, device_id: str, version: str, package: Path):
        offer = self.platform.offer(device_id, "app", version, package.read_bytes())
        self.offers.append(offer)
        return offer

    def results(self, device_id: str, count: int = 1) -> list:
        return self.platform.wait_results(device_id, count, timeout=RESULT_TIMEOUT)

    def assert_one_result(self, device_id: str, expected: dict, settle: float = 5) -> None:
        """Exactly one result, `expected`, also some seconds after it came."""
        self.assertEqual([expected], self.results(device_id))
        time.sleep(settle)
        self.assertEqual([expected], self.platform.results(device_id))

    def status_after(self, device_id: str, moment: float, component: str, version: str) -> None:
        topic = self.platform.topic_root(device_id) + "/status"
        wait_until(
            lambda: any(m.json().get("components", {}).get(component) == version
                        and m.time > moment
                        for m in self.mqtt.received(topic)),
            30, f"a status with {component} {version}",
        )

    def result_time(self, device_id: str) -> float:
        topic = self.platform.topic_root(device_id) + "/ota/result"
        return self.mqtt.received(topic)[-1].time

    def running(self) -> dict:
        """{service: image ID} of the project's containers, each of which must be running."""
        containers = self.device.containers()
        for service, (_, state, _) in containers.items():
            self.assertEqual("running", state, service)
        return {service: image for service, (_, _, image) in containers.items()}

    def wait_running(self, expected: dict, what: str) -> None:
        wait_until(
            lambda: {s: (st, i) for s, (_, st, i) in self.device.containers().items()}
            == {s: ("running", i) for s, i in expected.items()},
            60, what,
        )

    def check_sanitizers(self) -> None:
        """The agent stops with exit 0 on SIGTERM (LeakSanitizer reports at the exit), and no
        agent or apply container has a sanitizer report in its log."""
        agent = self.device.containers().get(TorizonDevice.AGENT_SERVICE)
        if agent is not None and agent[1] == "running":
            self.docker.run("stop", "-t", "30", agent[0], timeout=60)
            code = self.docker.run("inspect", "--format", "{{.State.ExitCode}}", agent[0])
            self.assertEqual("0", code.stdout.strip(), self.device.logs(agent[0]))
        for kind, logs in (("agent", self.device.agent_logs()), ("apply", self.device.apply_logs())):
            for container, log in logs:
                for marker in SANITIZER_MARKERS:
                    self.assertNotIn(marker, log, f"{kind} container {container[:12]}:\n{log}")

    def cut_apply(self, release: str, files: dict, unchecked: dict,
                  work_folder: bool = False) -> None:
        """Plays an apply cut short (a power loss, a crash of its container): the composition
        `unchecked` (services {name: image}, with the agent's service as it is) runs in place of
        the application, the agent is stopped, the data folder gets install.json for `release`
        in the state "apply" and `files` ({name: text}) (and with work_folder apply.tmp with a
        file in it), then the agent starts again. No firmline-apply container exists."""
        other = self.tmp / "unchecked.yml"
        other.write_text(self.device.composition(unchecked, AGENT_1))
        self.device.compose("up", "--detach", "--remove-orphans", file=other)
        agent = self.device.agent()
        self.docker.run("stop", agent, timeout=60)
        install = {"release": release, "component": "app", "version": "2.0.0", "state": "apply"}
        self.device.write_data("install.json", json.dumps(install))
        for name, text in files.items():
            self.device.write_data(name, text)
        if work_folder:
            with tempfile.TemporaryDirectory() as folder:
                work = Path(folder) / "apply.tmp"
                work.mkdir()
                (work / "images.tar.gz").write_bytes(b"extracted before the cut")
                self.docker.run("cp", str(work), f"{agent}:{TorizonDevice.DATA}/apply.tmp")
        self.docker.run("start", agent)

    def cut_without_its_outcome(self, files) -> None:
        """RF 1 when apply.json says nothing of the release: files(release) are the files of the
        data folder. failed install_failed, and the composition of compose_file runs again."""
        self.docker.app_image("example/web:2", "stay")
        device_id = self.start_device()
        release = str(uuid.uuid4())

        self.cut_apply(release, files(release), {"web": "example/web:2"})

        self.assert_one_result(device_id, {
            "release": release, "result": "failed", "fw": "1.0.0", "detail": "install_failed"})
        self.wait_running({"firmline-agent": self.agent_1, "app": self.old},
                          "the composition of compose_file running again")
        self.assertNotIn("install.json", self.device.data_files())

    @staticmethod
    def apply_state(release: str, state: str, detail=None, version=None) -> str:
        return json.dumps({"release": release, "state": state, "detail": detail,
                           "version": version})

    # The tests.

    def test_a_package_from_pack_is_installed(self):
        web = self.docker.app_image("example/web:2", "stay")
        package = self.pack("2.0.0", self.device.composition({"web": "example/web:2"}))
        self.docker.run("rmi", "-f", web)  # the device has only what the package brings
        device_id = self.start_device()

        offer = self.offer(device_id, "2.0.0", package)
        self.assert_one_result(
            device_id, {"release": offer.release, "result": "installed", "fw": "2.0.0"})

        self.status_after(device_id, self.result_time(device_id), "app", "2.0.0")
        self.assertEqual({"firmline-agent": self.agent_1, "web": web}, self.running())
        services = json.loads(self.device.compose("config", "--format", "json").stdout)["services"]
        self.assertEqual("firmline.local/web:2.0.0", services["web"]["image"])
        self.assertEqual("2.0.0", json.loads(self.device.read_data("package.json"))["version"])
        left = [n for n in self.device.data_files()
                if n.startswith(("install", "download-", "offer-", "compose-previous", "apply.tmp"))]
        self.assertEqual([], left)
        self.assertEqual(["docker-compose.yml"], sorted(p.name for p in self.device.compose_dir.iterdir()))

    def test_a_container_that_dies_gives_failed_and_the_previous_composition(self):
        web = self.docker.app_image("example/web:dies", "die:5")
        package = self.pack("2.0.0", self.device.composition({"web": "example/web:dies"}))
        self.docker.run("rmi", "-f", web)
        device_id = self.start_device()
        before = self.device.compose_file.read_text()
        agent = self.device.agent()

        offer = self.offer(device_id, "2.0.0", package)
        self.assert_one_result(device_id, {
            "release": offer.release, "result": "failed", "fw": "1.0.0",
            "detail": "health_check_failed"})

        self.assertEqual({"firmline-agent": self.agent_1, "app": self.old}, self.running())
        self.assertEqual(agent, self.device.agent())
        self.assertEqual(before, self.device.compose_file.read_text())
        self.assertIsNone(self.device.read_data("package.json"))

    def test_a_package_that_updates_the_agent_reaches_a_result(self):
        agent_2 = self.docker.agent_image(AGENT_2)
        web = self.docker.app_image("example/web:2", "stay")
        package = self.pack("2.0.0", self.device.composition({"web": "example/web:2"}, AGENT_2))
        device_id = self.start_device()
        old_agent = self.device.agent()

        offer = self.offer(device_id, "2.0.0", package)
        expected = {"release": offer.release, "result": "installed", "fw": "2.0.0"}
        self.assert_one_result(device_id, expected, settle=8)

        new_agent = self.device.agent()
        self.assertNotEqual(old_agent, new_agent)
        self.assertEqual({"firmline-agent": agent_2, "web": web}, self.running())
        logs = dict(self.device.agent_logs())
        self.assertEqual({old_agent, new_agent}, set(logs))
        sent = f"release {offer.release}: result installed"
        self.assertNotIn(sent, logs[old_agent])
        self.assertIn(sent, logs[new_agent])
        self.assertIn(f"release {offer.release}: result delivered", logs[new_agent])

    def test_a_package_without_the_agent_keeps_it(self):
        web = self.docker.app_image("example/web:2", "stay")
        package = self.pack("2.0.0", self.device.composition({"web": "example/web:2"}))
        device_id = self.start_device()
        agent = self.device.agent()
        started = self.docker.run("inspect", "--format", "{{.State.StartedAt}}", agent).stdout

        offer = self.offer(device_id, "2.0.0", package)
        self.assert_one_result(
            device_id, {"release": offer.release, "result": "installed", "fw": "2.0.0"})

        self.assertEqual(agent, self.device.agent())
        self.assertEqual(
            started, self.docker.run("inspect", "--format", "{{.State.StartedAt}}", agent).stdout)
        self.assertEqual({"firmline-agent": self.agent_1, "web": web}, self.running())
        services = json.loads(self.device.compose("config", "--format", "json").stdout)["services"]
        self.assertEqual(AGENT_1, services["firmline-agent"]["image"])

    def test_an_apply_cut_by_a_restart_ends_with_failed(self):
        """RF 1: apply.json was left `running` and no firmline-apply container is there (a power
        loss during the health check, say): failed install_failed at the restart, never a wait,
        and compose_file (the previous composition) runs again in place of the unchecked one."""
        self.docker.app_image("example/web:2", "stay")
        device_id = self.start_device()
        agent = self.device.agent()
        release = str(uuid.uuid4())

        self.cut_apply(release, {"apply.json": self.apply_state(release, "running", None, "1.0.0")},
                       {"web": "example/web:2"}, work_folder=True)

        self.assert_one_result(device_id, {
            "release": release, "result": "failed", "fw": "1.0.0", "detail": "install_failed"})
        self.wait_running({"firmline-agent": self.agent_1, "app": self.old},
                          "the composition of compose_file running again")
        self.assertEqual(agent, self.device.agent())
        log = self.device.logs()
        self.assertIn(f"release {release}: the apply container ended without an outcome", log)
        self.assertIn("bringing the composition", log)
        left = self.device.data_files()
        self.assertNotIn("install.json", left)
        # apply.tmp (as large as the package) would fail the free-space check of the next
        # download, which comes before the next apply.
        self.assertNotIn("apply.tmp", left)
        self.assertEqual("running", json.loads(self.device.read_data("apply.json"))["state"])

    def test_an_apply_cut_without_apply_json_ends_with_failed(self):
        self.cut_without_its_outcome(lambda release: {})

    def test_an_apply_cut_with_the_outcome_of_another_release_ends_with_failed(self):
        """apply.json is an `installed` of another release: not this release's outcome."""
        self.cut_without_its_outcome(lambda release: {
            "apply.json": self.apply_state(str(uuid.uuid4()), "installed", None, "2.0.0")})

    def test_an_apply_that_cannot_start_ends_with_failed(self):
        """`docker run` of apply fails (here the agent takes the application's container for its
        own, and the application's image has no `apply`): failed install_failed, one result, and
        nothing on the device changes."""
        self.docker.app_image("example/web:2", "stay")
        package = self.pack("2.0.0", self.device.composition({"web": "example/web:2"}))
        self.device.agent_environment = {"FIRMLINE_MOUNTINFO_FILE": "/etc/firmline/mountinfo"}
        device_id = self.start_device()
        app = self.device.containers()["app"][0]
        (self.device.etc / "mountinfo").write_text(
            f"4 1 8:1 /var/lib/docker/containers/{app}/hostname /etc/hostname rw - ext4 /dev/a rw\n")

        offer = self.offer(device_id, "2.0.0", package)
        self.assert_one_result(device_id, {
            "release": offer.release, "result": "failed", "fw": "1.0.0",
            "detail": "install_failed"})

        log = self.device.logs()
        self.assertIn(f"release {offer.release}: the firmline-apply container cannot be started", log)
        self.assertIn(f"release {offer.release}: the apply container ended without an outcome", log)
        self.assertEqual({"firmline-agent": self.agent_1, "app": self.old}, self.running())
        self.assertNotIn("install.json", self.device.data_files())

    def test_an_apply_cut_after_the_composition_was_replaced_puts_the_previous_back(self):
        """compose_file was already the new composition (apply's step 6), package.json not yet:
        compose-previous.yml is written back and started."""
        self.docker.app_image("example/web:2", "stay")
        device_id = self.start_device()
        previous = self.device.compose_file.read_text()
        release = str(uuid.uuid4())
        self.device.compose_file.write_text(
            self.device.composition({"web": "example/web:2"}, AGENT_1))

        self.cut_apply(release, {
            "apply.json": self.apply_state(release, "running", None, "1.0.0"),
            "compose-previous.yml": previous,
        }, {"web": "example/web:2"})

        self.assert_one_result(device_id, {
            "release": release, "result": "failed", "fw": "1.0.0", "detail": "install_failed"})
        self.wait_running({"firmline-agent": self.agent_1, "app": self.old},
                          "the previous composition running again")
        self.assertEqual(previous, self.device.compose_file.read_text())
        self.assertNotIn("compose-previous.yml", self.device.data_files())

    def test_an_apply_cut_after_the_version_was_in_place_ends_installed(self):
        """package.json is already the release's (apply's step 6 ended, apply.json not yet
        written): the new composition passed its health check and stays; installed."""
        web = self.docker.app_image("example/web:2", "stay")
        device_id = self.start_device()
        previous = self.device.compose_file.read_text()
        release = str(uuid.uuid4())
        new = self.device.composition({"web": "example/web:2"}, AGENT_1)
        self.device.compose_file.write_text(new)
        architecture = self.docker.run("version", "--format", "{{.Server.Arch}}").stdout.strip()
        description = {"format": 1, "architecture": architecture, "version": "2.0.0", "images": [
            {"service": "web", "image": "firmline.local/web:2.0.0", "id": web}]}

        self.cut_apply(release, {
            "apply.json": self.apply_state(release, "running", None, "1.0.0"),
            "compose-previous.yml": previous,
            "package.json": json.dumps(description),
        }, {"web": "example/web:2"})

        self.assert_one_result(
            device_id, {"release": release, "result": "installed", "fw": "2.0.0"})
        self.wait_running({"firmline-agent": self.agent_1, "web": web}, "the new composition")
        self.assertEqual(new, self.device.compose_file.read_text())
        self.assertNotIn("compose-previous.yml", self.device.data_files())

    def test_an_earlier_apply_container_that_never_ends_fails_the_release(self):
        """A firmline-apply container that never ends (paused, restarted, someone else's): the
        wait before apply starts is bounded (FIRMLINE_APPLY_WAIT_S plays its 30 minutes), then
        the release is failed install_failed with nothing touched, the container stays, and the
        queue goes on with the release of another component."""
        self.docker.app_image("example/web:2", "stay")
        package = self.pack("2.0.0", self.device.composition({"web": "example/web:2"}))
        busybox = shutil.which("busybox")
        self.device.agent_volumes = [f"{busybox}:/usr/local/bin/busybox:ro"]
        self.device.agent_environment = {"FIRMLINE_APPLY_WAIT_S": "15"}
        self.device.extra_config = (
            "\n[component tool]\nmain = false\nversion = fixed:1.0.0\n"
            "install = script:/etc/firmline/install-tool.sh\n")
        busy = self.docker.run("run", "-d", "--name", "firmline-apply", self.old).stdout.strip()
        device_id = self.start_device()
        script = self.device.etc / "install-tool.sh"
        script.write_text("#!/usr/local/bin/busybox sh\nexit 0\n")
        os.chmod(script, 0o755)

        app = self.offer(device_id, "2.0.0", package)
        self.device.wait_for_log(f"release {app.release}: an earlier firmline-apply container "
                                 "still runs: waiting for it")
        tool = self.platform.offer(device_id, "tool", "1.1.0", b"tool 1.1.0")

        self.assertEqual([
            {"release": app.release, "result": "failed", "fw": "1.0.0",
             "detail": "install_failed"},
            {"release": tool.release, "result": "installed", "fw": "1.1.0"},
        ], self.results(device_id, 2))
        time.sleep(5)
        self.assertEqual(2, len(self.platform.results(device_id)))
        self.assertIn(f"release {app.release}: an earlier firmline-apply container still runs "
                      "after 15 s", self.device.logs())
        self.assertEqual(
            "running", self.docker.run("inspect", "--format", "{{.State.Status}}", busy).stdout.strip())
        self.assertEqual([], [n for n in self.device.data_files()
                              if n.startswith(("install", "download-", "offer-"))])
        self.assertEqual({"firmline-agent": self.agent_1, "app": self.old}, self.running())
        self.assertEqual([], self.device.apply_logs()[1:])  # no apply of the release ran

    def test_an_earlier_apply_container_is_waited_for_then_removed(self):
        """A firmline-apply container that still runs (an apply pruning images after its
        outcome) is never removed: the agent waits for it, then removes it once stopped."""
        web = self.docker.app_image("example/web:2", "stay")
        self.docker.app_image("example/busy:1", "die:8")
        package = self.pack("2.0.0", self.device.composition({"web": "example/web:2"}))
        device_id = self.start_device()
        self.docker.run("run", "-d", "--name", "firmline-apply", "example/busy:1")

        offer = self.offer(device_id, "2.0.0", package)
        self.assert_one_result(
            device_id, {"release": offer.release, "result": "installed", "fw": "2.0.0"})

        self.assertIn("an earlier firmline-apply container still runs", self.device.logs())
        self.assertEqual({"firmline-agent": self.agent_1, "web": web}, self.running())
        applies = self.device.apply_logs()
        self.assertEqual(2, len(applies))  # the busy one and the one of the release
        self.assertIn("apply: version 2.0.0 installed", applies[1][1])

    def test_logs_have_no_secrets(self):
        self.docker.app_image("example/web:2", "stay")
        package = self.pack("2.0.0", self.device.composition({"web": "example/web:2"}))
        device_id = self.start_device()

        offer = self.offer(device_id, "2.0.0", package)
        self.assert_one_result(
            device_id, {"release": offer.release, "result": "installed", "fw": "2.0.0"})

        secrets = [self.token, self.device.read_data("device.key"), offer.url,
                   offer.url.rsplit("/", 1)[1], self.pki.update_key_path.read_text()]
        agent_logs = self.device.agent_logs()
        self.assertTrue(agent_logs)
        for _, log in agent_logs:
            assert_no_secrets(log, secrets)
        assert_no_secrets(self.device.exec_log, secrets)
        apply_logs = self.device.apply_logs()
        self.assertEqual(1, len(apply_logs))
        self.assertIn("apply:", apply_logs[0][1])
        assert_no_secrets(apply_logs[0][1], secrets)


class ApplyStateOfAScriptComponentTest(OtaBase):
    """install.json in the state "apply" names a component that is no longer install =
    docker-compose (its configuration changed while apply ran): there is no apply to follow, so
    the release ends failed install_failed at the next start, in the same boot too, with no
    reboot; apply's files in the data folder go, and the queue goes on."""

    def test_it_fails_install_failed_without_a_reboot(self):
        app, folder = self.component("app")
        boot = self.tmp / "boot_id"  # the same boot before and after the restart
        boot.write_text("boot-a\n")
        agent, device = self.start_agent(
            {"app": app}, env={"FIRMLINE_BOOT_ID_FILE": str(boot)},
            reboot_command=f"{folder / 'reboot.sh'} now")
        self.assertEqual(0, agent.stop())
        release = str(uuid.uuid4())
        agent.path("install.json").write_text(json.dumps(
            {"release": release, "component": "app", "version": "2.0.0", "state": "apply",
             "bootId": "boot-a"}))
        agent.path("apply.json").write_text(TorizonTest.apply_state(release, "running"))
        agent.path("compose-previous.yml").write_text("services: {}\n")
        agent.path("apply.tmp").mkdir()
        (agent.path("apply.tmp") / "images.tar.gz").write_bytes(b"left by a cut")

        self.run_agent(agent)
        self.assertEqual(
            [{"release": release, "result": "failed", "fw": "1.0.0", "detail": "install_failed"}],
            self.platform.wait_results(device, timeout=20))
        offer = self.offer(device, "app", "1.1.0", b"version 1.1.0")
        self.assertEqual(
            {"release": offer.release, "result": "installed", "fw": "1.1.0"},
            self.platform.wait_results(device, count=2)[1])

        self.assertFalse((folder / "rebooted").exists(), "no reboot_command")
        self.assertEqual(2, len(self.platform.results(device)))
        self.assertEqual(1, len((folder / "runs").read_text().splitlines()))
        left = agent.data_files()
        for name in ("install.json", "compose-previous.yml", "apply.tmp"):
            self.assertNotIn(name, left)
        self.finish(agent)


class OutsideAContainerTest(IntegrationTest):
    """The agent outside a container (installed with systemd, say) cannot run apply."""

    def test_a_docker_compose_offer_fails_at_once(self):
        broker = self.make_broker()
        mqtt = self.platform.connect(broker)
        self.addCleanup(mqtt.close)
        mountinfo = self.tmp / "mountinfo"
        mountinfo.write_text(
            "22 1 0:21 / / rw,relatime - overlay overlay rw\n"
            "23 22 8:1 /etc/hostname /etc/hostname rw,relatime - ext4 /dev/sda1 rw\n")
        components = {"app": {"main": "true", "version": "package:1.0.0",
                              "install": "docker-compose",
                              "compose_file": str(self.tmp / "compose" / "docker-compose.yml")}}
        agent = self.make_agent(broker=broker, components=components,
                                env={"FIRMLINE_MOUNTINFO_FILE": str(mountinfo)})
        self.assertEqual(0, agent.run("register", "--token", self.platform.new_token(),
                                      "--serial", "SN-OUTSIDE").code)
        device_id = agent.read_json("device.json")["deviceId"]
        agent.start("run")
        agent.wait_for_log("subscribed to")

        offer = self.platform.offer(device_id, "app", "2.0.0", b"not downloaded")
        result = self.platform.wait_results(device_id)[0]

        self.assertEqual({"release": offer.release, "result": "failed", "fw": "1.0.0",
                          "detail": "install_failed"}, result)
        self.assertEqual([], self.platform.download_requests(offer.url))
        self.assertIn("not in a container", agent.running_log)
        self.assertEqual(0, agent.stop())


if __name__ == "__main__":
    unittest.main()
