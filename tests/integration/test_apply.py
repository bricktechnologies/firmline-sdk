# SPDX-License-Identifier: Apache-2.0
"""firmline-agent apply --release <id> [--config <path>]: installs the package of a Docker Compose
application that the agent has downloaded and verified (<data_dir>/download-<release>.bin, with
install.json in the state "apply"). It checks the package, loads its images (never pulled), starts
the new composition as Torizon does (-p <project>, up --detach --remove-orphans), keeps it only if
every container stays running (and healthy, with a healthcheck) for health_timeout seconds, and
otherwise starts the previous composition again. The outcome is apply.json in the data folder:
{release, state: running|installed|failed, detail, version}.

The tests run apply as a binary against the test daemon, with no agent: they write install.json
and the .bin themselves, as the agent does, and make the packages with `pack`."""

import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

from docker_host import docker_host
from harness import AGENT_BINARY, SANITIZER_MARKERS, wait_until

PROJECT = "torizon"
RELEASE = "0b6f1c2e-3d4a-4b5c-8d9e-0f1a2b3c4d5e"
RELEASE_2 = "7c1d9e3a-5b2f-4a6e-9c8d-1e2f3a4b5c6d"
INITIAL_VERSION = "0.9.0"
MEMBERS = ["firmline-package.json", "docker-compose.yml", "images.tar.gz"]
OLD = "services:\n  app:\n    image: example/old:1\n"


class ApplyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docker = docker_host()

    def setUp(self):
        self.addCleanup(self.docker.reset)
        self.folder = Path(tempfile.mkdtemp(prefix="firmline-apply-test-"))
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.data = self.folder / "data"
        self.data.mkdir()
        self.compose_dir = self.folder / "compose"
        self.compose_dir.mkdir()
        self.compose_file = self.compose_dir / "docker-compose.yml"
        self.packages = self.folder / "packages"
        self.packages.mkdir()
        self.config_path = self.folder / "agent.conf"
        self.health_timeout = 10

    # The device.

    def write_config(self) -> Path:
        self.config_path.write_text(
            "[platform]\n"
            "url = https://localhost:9\n"
            "broker = localhost\n"
            "update_key = /nonexistent/update.pem\n"
            f"data_dir = {self.data}\n"
            "\n"
            "[component app]\n"
            "main = true\n"
            f"version = package:{INITIAL_VERSION}\n"
            "install = docker-compose\n"
            f"compose_file = {self.compose_file}\n"
            f"health_timeout = {self.health_timeout}\n"
        )
        return self.config_path

    def start_current(self, text: str) -> dict:
        """The composition the device runs before apply, started as Torizon starts it."""
        self.compose_file.write_text(text)
        self.docker.run("compose", "-p", PROJECT, "-f", str(self.compose_file), "up", "--detach",
                        timeout=120)
        return self.containers()

    def containers(self) -> dict:
        """{service: (container ID, state, image ID)} of the project's containers."""
        listing = self.docker.run(
            "ps", "-a", "--no-trunc", "--filter", f"label=com.docker.compose.project={PROJECT}",
            "--format", '{{.Label "com.docker.compose.service"}} {{.ID}}',
        ).stdout.split()
        found = {}
        for service, container in zip(listing[::2], listing[1::2]):
            state, image = self.docker.run(
                "inspect", "--format", "{{.State.Status}} {{.Image}}", container
            ).stdout.split()
            found[service] = (container, state, image)
        return found

    def composition(self) -> dict:
        """The composition in compose_file as Compose reads it."""
        return json.loads(self.docker.run(
            "compose", "-p", PROJECT, "-f", str(self.compose_file), "config", "--format", "json",
        ).stdout)

    def exists(self, reference: str) -> bool:
        return self.docker.run("image", "inspect", reference, check=False).returncode == 0

    def image_id(self, reference: str) -> str:
        return self.docker.run("image", "inspect", "--format", "{{.Id}}", reference).stdout.strip()

    # The packages.

    def package(self, version: str, services: dict, name: str = "") -> Path:
        """`pack` of a composition of services {name: image}; the images must exist."""
        compose = self.packages / f"{name or version}.yml"
        compose.write_text(
            "services:\n" + "".join(f"  {s}:\n    image: {i}\n" for s, i in services.items()))
        output = self.packages / f"{name or version}.tar"
        result = subprocess.run(
            [AGENT_BINARY, "pack", "--compose", str(compose), "--version", version,
             "--output", str(output)],
            env=self.docker.env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=300,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        return output

    def forget(self, *image_ids: str) -> None:
        """Removes images from the daemon, all their names included: the device has only what
        apply loads from the package."""
        self.docker.run("rmi", "-f", *image_ids)

    @staticmethod
    def members(package: Path) -> dict:
        with tarfile.open(package) as tar:
            return {m.name: tar.extractfile(m).read() for m in tar.getmembers()}

    def rebuild(self, package: Path, name: str, replaced: dict) -> Path:
        """A copy of the package with some members replaced ({name: bytes})."""
        members = {**self.members(package), **replaced}
        output = self.packages / name
        with tarfile.open(output, "w") as tar:
            for member in MEMBERS:
                info = tarfile.TarInfo(member)
                info.size = len(members[member])
                info.mode = 0o644
                tar.addfile(info, io.BytesIO(members[member]))
        return output

    # apply.

    def install(self, package: Path, version: str, release: str = RELEASE) -> None:
        """What the agent leaves before it starts apply."""
        shutil.copyfile(package, self.data / f"download-{release}.bin")
        (self.data / "install.json").write_text(json.dumps(
            {"release": release, "component": "app", "version": version, "state": "apply"}))

    def apply(self, release: str = RELEASE, timeout: float = 300,
              env=None) -> subprocess.CompletedProcess:
        self.write_config()
        result = subprocess.run(
            [AGENT_BINARY, "apply", "--release", release, "--config", str(self.config_path)],
            env=env or self.docker.env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=timeout,
        )
        for marker in SANITIZER_MARKERS:
            self.assertNotIn(marker, result.stderr)
        return result

    def outcome(self) -> dict:
        return json.loads((self.data / "apply.json").read_text())

    def assert_outcome(self, result, state, detail, version, release=RELEASE):
        self.assertEqual(0 if state == "installed" else 1, result.returncode, result.stderr)
        self.assertEqual(
            {"release": release, "state": state, "detail": detail, "version": version},
            self.outcome(), result.stderr)

    def assert_nothing_left(self):
        """Only the agent's files in the data folder (apply's own are gone), nothing next to the
        composition."""
        left = sorted(os.listdir(self.data))
        self.assertNotIn("compose-previous.yml", left)
        self.assertNotIn("apply.tmp", left)
        self.assertEqual(["docker-compose.yml"], sorted(os.listdir(self.compose_dir)))

    def assert_untouched(self, before: dict, text: str):
        self.assertEqual(before, self.containers())
        self.assertTrue(all(state == "running" for _, state, _ in before.values()))
        self.assertEqual(text, self.compose_file.read_text())

    # The tests.

    def test_a_package_installs_and_replaces_the_composition(self):
        old = self.docker.app_image("example/old:1", "stay")
        web = self.docker.app_image("example/web:2", "stay")
        package = self.package("2.0.0", {"web": "example/web:2"})
        self.forget(web)
        self.start_current(OLD)
        self.install(package, "2.0.0")

        result = self.apply()
        self.assert_outcome(result, "installed", None, "2.0.0")

        services = self.composition()["services"]
        self.assertEqual({"web"}, set(services))
        self.assertEqual("firmline.local/web:2.0.0", services["web"]["image"])
        running = self.containers()
        self.assertEqual({"web"}, set(running))
        self.assertEqual(("running", web), running["web"][1:])
        self.assertEqual(web, self.image_id("firmline.local/web:2.0.0"))
        description = json.loads(self.members(package)["firmline-package.json"])
        self.assertEqual(description, json.loads((self.data / "package.json").read_text()))
        self.assertTrue(self.exists(old))  # not an image of a package: never removed
        self.assert_nothing_left()

    def test_a_container_that_dies_brings_back_the_previous_composition(self):
        self.health_timeout = 20
        old = self.docker.app_image("example/old:1", "stay")
        web = self.docker.app_image("example/web:dies", "die:5")
        package = self.package("2.0.0", {"web": "example/web:dies"})
        self.forget(web)
        self.start_current(OLD)
        self.install(package, "2.0.0")

        result = self.apply()
        self.assert_outcome(result, "failed", "health_check_failed", INITIAL_VERSION)
        running = self.containers()
        self.assertEqual({"app"}, set(running))
        self.assertEqual(("running", old), running["app"][1:])
        self.assertEqual(OLD, self.compose_file.read_text())
        self.assertFalse((self.data / "package.json").exists())
        self.assert_nothing_left()

    def test_an_unhealthy_container_fails(self):
        self.health_timeout = 60
        self.docker.app_image("example/old:1", "stay")
        web = self.docker.app_image("example/web:unhealthy", "unhealthy")
        package = self.package("2.0.0", {"web": "example/web:unhealthy"})
        self.forget(web)
        self.start_current(OLD)
        self.install(package, "2.0.0")

        started = time.monotonic()
        result = self.apply()
        self.assertLess(time.monotonic() - started, 45)  # at once, not at the end of the time
        self.assert_outcome(result, "failed", "health_check_failed", INITIAL_VERSION)
        self.assertEqual({"app"}, set(self.containers()))
        self.assertEqual(OLD, self.compose_file.read_text())

    def test_a_healthy_container_passes(self):
        self.docker.app_image("example/old:1", "stay")
        web = self.docker.app_image("example/web:healthy", "healthy")
        package = self.package("2.0.0", {"web": "example/web:healthy"})
        self.forget(web)
        self.start_current(OLD)
        self.install(package, "2.0.0")

        result = self.apply()
        self.assert_outcome(result, "installed", None, "2.0.0")
        container = self.containers()["web"][0]
        health = self.docker.run("inspect", "--format", "{{.State.Health.Status}}", container)
        self.assertEqual("healthy", health.stdout.strip())

    def test_another_architecture_is_refused_without_touching_the_application(self):
        self.docker.app_image("example/old:1", "stay")
        self.docker.app_image("example/web:2", "stay")
        package = self.package("2.0.0", {"web": "example/web:2"})
        description = json.loads(self.members(package)["firmline-package.json"])
        description["architecture"] = "arm64" if description["architecture"] != "arm64" else "amd64"
        other = self.rebuild(package, "other.tar",
                             {"firmline-package.json": json.dumps(description).encode()})
        before = self.start_current(OLD)
        self.install(other, "2.0.0")

        result = self.apply()
        self.assert_outcome(result, "failed", "install_failed", INITIAL_VERSION)
        self.assertIn("architecture", result.stderr)
        self.assert_untouched(before, OLD)
        self.assert_nothing_left()

    def test_a_missing_image_is_refused_without_touching_the_application(self):
        """The description and the composition name web and db; images.tar.gz has only web. It
        is refused before docker load: no image is loaded, and a name the package uses keeps
        the image it names."""
        old = self.docker.app_image("example/old:1", "stay")
        web = self.docker.app_image("example/web:2", "stay")
        db = self.docker.app_image("example/db:2", "stay")
        two = self.package("2.0.0", {"web": "example/web:2", "db": "example/db:2"}, "two")
        one = self.package("2.0.0", {"web": "example/web:2"}, "one")
        missing = self.rebuild(two, "missing.tar",
                               {"images.tar.gz": self.members(one)["images.tar.gz"]})
        self.forget(web, db)
        self.docker.run("tag", old, "firmline.local/web:2.0.0")
        before = self.start_current(OLD)
        self.install(missing, "2.0.0")

        result = self.apply()
        self.assert_outcome(result, "failed", "install_failed", INITIAL_VERSION)
        self.assertIn("firmline.local/db:2.0.0", result.stderr)
        self.assert_untouched(before, OLD)
        self.assert_nothing_left()
        self.assertFalse(self.exists(web))  # not loaded
        self.assertEqual(old, self.image_id("firmline.local/web:2.0.0"))  # not moved

    def test_no_image_is_pulled(self):
        self.docker.app_image("example/old:1", "stay")
        web = self.docker.app_image("example/web:2", "stay")
        db = self.docker.app_image("example/db:2", "healthy")
        package = self.package("2.0.0", {"web": "example/web:2", "db": "example/db:2"})
        self.forget(web, db)
        self.start_current(OLD)
        self.install(package, "2.0.0")
        log_before = len(self.docker.log())

        result = self.apply()
        self.assert_outcome(result, "installed", None, "2.0.0")
        self.assertNotIn("images/create", self.docker.log()[log_before:])
        for container, _, _ in self.containers().values():
            image = self.docker.run("inspect", "--format", "{{.Config.Image}}", container)
            self.assertTrue(image.stdout.startswith("firmline.local/"), image.stdout)

    def test_the_agent_service_is_copied_when_the_package_has_none(self):
        """RF 2: the agent's service, with its named volume and the socket, stays in the new
        composition, and its container is not recreated."""
        self.docker.app_image("example/old:1", "stay")
        self.docker.app_image("example/agent:1", "stay")  # stands in for the agent
        web = self.docker.app_image("example/web:2", "stay")
        package = self.package("2.0.0", {"web": "example/web:2"})
        self.forget(web)
        current = (
            "services:\n"
            "  firmline-agent:\n"
            "    image: example/agent:1\n"
            "    volumes:\n"
            "      - firmline-data:/var/lib/firmline\n"
            f"      - {self.docker.socket}:/var/run/docker.sock\n"
            "  app:\n"
            "    image: example/old:1\n"
            "volumes:\n"
            "  firmline-data: {}\n"
        )
        before = self.start_current(current)
        self.install(package, "2.0.0")

        result = self.apply()
        self.assert_outcome(result, "installed", None, "2.0.0")
        running = self.containers()
        self.assertEqual({"firmline-agent", "web"}, set(running))
        self.assertEqual(before["firmline-agent"], running["firmline-agent"])  # not recreated
        composition = self.composition()
        agent = composition["services"]["firmline-agent"]
        self.assertEqual("example/agent:1", agent["image"])
        self.assertEqual(
            {("volume", "firmline-data", "/var/lib/firmline"),
             ("bind", str(self.docker.socket), "/var/run/docker.sock")},
            {(v["type"], v["source"], v["target"]) for v in agent["volumes"]})
        self.assertIn("firmline-data", composition["volumes"])
        self.assertEqual(f"{PROJECT}_firmline-data", composition["volumes"]["firmline-data"]["name"])
        self.assert_nothing_left()

    def test_a_kept_container_that_restarted_before_apply_passes(self):
        """The agent's container is kept as it is, with its restart count: only a restart during
        the check fails it. This one restarted once (its restart policy) before apply."""
        self.docker.app_image("example/old:1", "stay")
        self.docker.app_image("example/agent:1", "stay")
        web = self.docker.app_image("example/web:2", "stay")
        package = self.package("2.0.0", {"web": "example/web:2"})
        self.forget(web)
        current = (
            "services:\n"
            "  firmline-agent:\n"
            "    image: example/agent:1\n"
            "    restart: on-failure\n"
            "    command: [\"sh\", \"-c\", \"[ -f /var/lib/firmline/once ] && exec sleep 3600;"
            " touch /var/lib/firmline/once; exit 1\"]\n"
            "    volumes:\n"
            "      - firmline-data:/var/lib/firmline\n"
            "  app:\n"
            "    image: example/old:1\n"
            "volumes:\n"
            "  firmline-data: {}\n"
        )
        agent = self.start_current(current)["firmline-agent"][0]
        wait_until(
            lambda: self.docker.run(
                "inspect", "--format", "{{.RestartCount}} {{.State.Status}}", agent
            ).stdout.split() == ["1", "running"],
            timeout=30, what="the agent stand-in restarting once")
        before = self.containers()
        self.install(package, "2.0.0")

        result = self.apply()
        self.assert_outcome(result, "installed", None, "2.0.0")
        self.assertEqual(before["firmline-agent"], self.containers()["firmline-agent"])

    def test_a_failure_after_the_new_composition_is_in_place_puts_the_previous_back(self):
        """package.json cannot be written (a folder is in its place) after the new composition
        has replaced compose_file: compose_file is the previous composition again, and runs."""
        old = self.docker.app_image("example/old:1", "stay")
        web = self.docker.app_image("example/web:2", "stay")
        package = self.package("2.0.0", {"web": "example/web:2"})
        self.forget(web)
        self.start_current(OLD)
        (self.data / "package.json").mkdir()
        self.install(package, "2.0.0")

        result = self.apply()
        self.assert_outcome(result, "failed", "install_failed", INITIAL_VERSION)
        self.assertEqual(OLD, self.compose_file.read_text())
        running = self.containers()
        self.assertEqual({"app"}, set(running))
        self.assertEqual(("running", old), running["app"][1:])
        self.assert_nothing_left()

    def test_only_the_images_of_the_previous_package_are_removed(self):
        """RF 3: after 1.0.0 (web 1, db) comes 2.0.0 (web 2, the same db): web 1 goes, db and
        web 2 stay, and so do the images that were never in a package."""
        old = self.docker.app_image("example/old:1", "stay")
        unrelated = self.docker.app_image("example/unrelated:1", "stay")
        web1 = self.docker.app_image("example/web:1", "stay")
        web2 = self.docker.app_image("example/web:2", "stay")
        db = self.docker.app_image("example/db:1", "stay")
        first = self.package("1.0.0", {"web": "example/web:1", "db": "example/db:1"})
        second = self.package("2.0.0", {"web": "example/web:2", "db": "example/db:1"})
        self.forget(web1, web2, db)
        self.start_current(OLD)
        self.install(first, "1.0.0")
        self.assert_outcome(self.apply(), "installed", None, "1.0.0")
        self.assertTrue(self.exists(old))  # the composition before any package: not pruned
        self.install(second, "2.0.0", release=RELEASE_2)
        # A docker in front of the real one notes apply.json at each image removal: the outcome
        # is written before the removals, so a power loss during them loses no result.
        wrapper = self.folder / "bin"
        wrapper.mkdir()
        noted = self.folder / "apply-at-removal"
        (wrapper / "docker").write_text(
            "#!/bin/sh\n"
            f'if [ "$1" = image ] && [ "$2" = rm ]; then cat "{self.data}/apply.json" >> "{noted}";'
            f' echo >> "{noted}"; fi\n'
            f'exec {shutil.which("docker")} "$@"\n'
        )
        (wrapper / "docker").chmod(0o755)
        env = dict(self.docker.env, PATH=f"{wrapper}:{os.environ['PATH']}")

        result = self.apply(release=RELEASE_2, env=env)
        self.assert_outcome(result, "installed", None, "2.0.0", release=RELEASE_2)
        states = [json.loads(line)["state"] for line in noted.read_text().splitlines() if line]
        self.assertTrue(states)
        self.assertEqual({"installed"}, set(states))
        self.assertFalse(self.exists(web1), result.stderr)
        self.assertFalse(self.exists("firmline.local/web:1.0.0"))
        self.assertEqual(db, self.image_id("firmline.local/db:2.0.0"))
        self.assertEqual(web2, self.image_id("firmline.local/web:2.0.0"))
        self.assertEqual(unrelated, self.image_id("example/unrelated:1"))
        self.assertTrue(self.exists(old))
        self.assertEqual({"web": web2, "db": db},
                         {s: image for s, (_, _, image) in self.containers().items()})

    def test_a_failure_gives_back_a_name_the_package_took(self):
        """1.0+a and 1.0_a have the same tag: when 1.0_a fails, firmline.local/web:1.0_a names
        the image of 1.0+a again, and that is the image that runs."""
        self.docker.app_image("example/old:1", "stay")
        first_image = self.docker.app_image("example/web:first", "stay")
        second_image = self.docker.app_image("example/web:second", "die:1")
        first = self.package("1.0+a", {"web": "example/web:first"}, "first")
        second = self.package("1.0_a", {"web": "example/web:second"}, "second")
        self.forget(first_image, second_image)
        self.start_current(OLD)
        self.install(first, "1.0+a")
        self.assert_outcome(self.apply(), "installed", None, "1.0+a")
        self.install(second, "1.0_a", release=RELEASE_2)

        result = self.apply(release=RELEASE_2)
        self.assert_outcome(result, "failed", "health_check_failed", "1.0+a", release=RELEASE_2)
        self.assertEqual(first_image, self.image_id("firmline.local/web:1.0_a"))
        self.assertEqual(("running", first_image), self.containers()["web"][1:])

    def test_a_load_failure_leaves_the_application_running(self):
        """RF 4: an images.tar.gz cut in half (a disk that filled up while it was written, say)."""
        self.docker.app_image("example/old:1", "stay")
        web = self.docker.app_image("example/web:2", "stay")
        package = self.package("2.0.0", {"web": "example/web:2"})
        images = self.members(package)["images.tar.gz"]
        cut = self.rebuild(package, "cut.tar", {"images.tar.gz": images[: len(images) // 2]})
        self.forget(web)
        before = self.start_current(OLD)
        self.install(cut, "2.0.0")

        result = self.apply()
        self.assert_outcome(result, "failed", "install_failed", INITIAL_VERSION)
        self.assert_untouched(before, OLD)
        self.assert_nothing_left()

    def test_an_install_state_of_another_release_fails(self):
        """install.json names another release: nothing is installed."""
        self.docker.app_image("example/old:1", "stay")
        self.docker.app_image("example/web:2", "stay")
        package = self.package("2.0.0", {"web": "example/web:2"})
        before = self.start_current(OLD)
        self.install(package, "2.0.0", release=RELEASE_2)
        shutil.copyfile(package, self.data / f"download-{RELEASE}.bin")

        result = self.apply()
        self.assert_outcome(result, "failed", "install_failed", INITIAL_VERSION)
        self.assert_untouched(before, OLD)

    def test_an_agent_service_that_depends_on_another_is_refused(self):
        """Compose renders the services the agent depends on with it: copied, they would replace
        the package's own."""
        self.docker.app_image("example/old:1", "stay")
        self.docker.app_image("example/agent:1", "stay")
        self.docker.app_image("example/web:2", "stay")
        package = self.package("2.0.0", {"web": "example/web:2"})
        current = (
            "services:\n"
            "  firmline-agent:\n"
            "    image: example/agent:1\n"
            "    depends_on: [app]\n"
            "  app:\n"
            "    image: example/old:1\n"
        )
        before = self.start_current(current)
        self.install(package, "2.0.0")

        result = self.apply()
        self.assert_outcome(result, "failed", "install_failed", INITIAL_VERSION)
        self.assertIn("depends on other services", result.stderr)
        self.assert_untouched(before, current)
        self.assert_nothing_left()

    def test_a_package_of_another_version_is_refused(self):
        """The package must be the version of the release: the result reports that version."""
        self.docker.app_image("example/old:1", "stay")
        self.docker.app_image("example/web:2", "stay")
        package = self.package("2.0.1", {"web": "example/web:2"})
        before = self.start_current(OLD)
        self.install(package, "2.0.0")

        result = self.apply()
        self.assert_outcome(result, "failed", "install_failed", INITIAL_VERSION)
        self.assertIn("2.0.1", result.stderr)
        self.assert_untouched(before, OLD)
        self.assert_nothing_left()

    def test_usage_errors_exit_1_without_an_outcome(self):
        self.write_config()
        for arguments in ([], ["--release"], ["--release", "not-a-release"],
                          ["--release", RELEASE, "--release", RELEASE], ["--release", RELEASE, "-x"]):
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    [AGENT_BINARY, "apply", *arguments, "--config", str(self.config_path)],
                    env=self.docker.env, stdin=subprocess.DEVNULL, capture_output=True,
                    text=True, timeout=60,
                )
                self.assertEqual(1, result.returncode, result.stderr)
                self.assertTrue(result.stderr.strip())
                self.assertFalse((self.data / "apply.json").exists())


if __name__ == "__main__":
    unittest.main()
