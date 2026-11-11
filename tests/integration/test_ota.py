# SPDX-License-Identifier: Apache-2.0
"""firmline-agent run, updates: offers checked against the update key, queued, downloaded with
resume (Range) and checked, installed with the component's script, and one result per release
on {topicRoot}/ota/result, stored before it is sent."""

import datetime
import os
import shutil
import signal
import time
import unittest
import uuid
from pathlib import Path

from harness import (
    STATUS_429,
    IntegrationTest,
    assert_no_secrets,
    build_clock_shim,
    clock_env,
    cut_after,
    utc_now,
    wait_until,
)

SCRIPTS = Path(__file__).resolve().parent / "scripts"
SMALL_DISK = Path("/tmp/firmline-small")  # a 1 MiB tmpfs, mounted by scripts/check.sh


def payload(size: int, seed: int = 0) -> bytes:
    return bytes((i * 7 + seed) % 251 for i in range(size))


def process_gone(pid: int) -> bool:
    """True when the process no longer runs (gone, or a zombie nobody reaped)."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] == "Z"
    except FileNotFoundError:
        return True


class OtaBase(IntegrationTest):
    """A broker, the platform connected to it, and the helpers of the OTA tests."""

    def setUp(self):
        super().setUp()
        self.broker = self.make_broker()
        self.mqtt = self.platform.connect(self.broker)
        self.addCleanup(self.mqtt.close)
        self.offers = []

    # -- helpers

    def component(self, code, script="install-ok.sh", version="1.0.0", main=True, timeout=None):
        """A copy of the test script in a folder of its own (its marks go there) with the
        component's version file; returns the [component] keys and the folder."""
        folder = self.tmp / "components" / code
        folder.mkdir(parents=True)
        for name in (script, "reboot.sh"):
            shutil.copy(SCRIPTS / name, folder / name)
            os.chmod(folder / name, 0o755)
        (folder / "version").write_text(version + "\n")
        keys = {
            "main": "true" if main else "false",
            "version": f"file:{folder / 'version'}",
            "install": f"script:{folder / script}",
            "timeout": str(timeout) if timeout else None,
        }
        return keys, folder

    def start_agent(self, components=None, data_dir=None, run_env=None, **settings):
        """A registered agent running `run`, subscribed to its offers; its device id. `run_env`
        is added to the environment of `run` only (after the registration)."""
        agent = self.make_agent(broker=self.broker, components=components, **settings)
        if data_dir is not None:
            agent.settings["data_dir"] = str(data_dir)
            agent.data_dir = Path(data_dir)
        token = self.platform.new_token()
        result = agent.run("register", "--token", token, "--serial", f"SN-{uuid.uuid4().hex[:8]}")
        self.assertEqual(0, result.code, result.stderr)
        device_id = agent.read_json("device.json")["deviceId"]
        agent.env.update(run_env or {})
        self.run_agent(agent)
        return agent, device_id

    def run_agent(self, agent):
        agent.start("run")  # a log file per run: "subscribed to" is this run's
        agent.wait_for_log("subscribed to")

    def offer(self, *args, **kwargs):
        offer = self.platform.offer(*args, **kwargs)
        self.offers.append(offer)
        return offer

    def repeat(self, offer, **kwargs):
        again = self.platform.repeat(offer, **kwargs)
        self.offers.append(again)
        return again

    def result_messages(self, device_id):
        return self.mqtt.received(self.platform.topic_root(device_id) + "/ota/result")

    def ranges(self, offer):
        return [r.headers.get("range") for r in self.platform.download_requests(offer.url)]

    def finish(self, agent):
        """Stops the agent (exit 0) and checks its log for secrets: the download links and their
        tokens, the device key."""
        self.assertEqual(0, agent.stop())
        secrets = [agent.read_text("device.key"), self.pki.update_key_path.read_text()]
        for offer in self.offers:
            secrets += [offer.url, offer.url.rsplit("/", 1)[1]]
        assert_no_secrets(agent.log, secrets)

    def assert_clean(self, agent):
        """No offer, download or installation state is left in the data folder."""
        leftovers = [
            name
            for name in agent.data_files()
            if name.startswith(("offer-", "download-", "install"))
        ]
        self.assertEqual([], leftovers)


class OtaTest(OtaBase):
    def test_installs_with_script_and_sends_installed(self):
        app, folder = self.component("app")
        agent, device = self.start_agent({"app": app})
        status_topic = self.platform.topic_root(device) + "/status"
        data = payload(5000)

        offer = self.offer(device, "app", "1.1.0", data)
        result = self.platform.wait_results(device)[0]

        self.assertEqual({"release": offer.release, "result": "installed", "fw": "1.1.0"}, result)
        message = self.result_messages(device)[0]
        self.assertEqual((1, False), (message.qos, message.retain))
        file, version, release, cwd = (folder / "runs").read_text().split()
        self.assertEqual(("1.1.0", offer.release, "/"), (version, release, cwd))
        self.assertTrue(file.startswith(str(agent.data_dir) + "/"), file)
        self.assertFalse(Path(file).exists(), "the downloaded file is deleted after the result")
        self.assertEqual(data, (folder / "installed.bin").read_bytes())
        self.assertEqual([None], self.ranges(offer))
        self.assertIn("script: installing version 1.1.0", agent.running_log)
        stored = f"result-{offer.release}.json"
        self.assertIn(stored, agent.data_files())
        self.assert_clean(agent)
        wait_until(
            lambda: any(
                m.json().get("fw") == "1.1.0" and m.time > message.time
                for m in self.mqtt.received(status_topic)
            ),
            10,
            "a status with the new version",
        )
        self.finish(agent)

    def test_script_inherits_only_stdin_stdout_stderr(self):
        app, folder = self.component("app")
        agent, device = self.start_agent({"app": app})

        self.offer(device, "app", "1.1.0", payload(1000))
        self.assertEqual("installed", self.platform.wait_results(device)[0]["result"])

        fds = {}  # "info script: lr-x------ 1 root root 64 <date> 0 -> /dev/null" (ls -l /proc/$$/fd)
        for line in agent.running_log.splitlines():
            if line.startswith("info script: ") and " -> " in line:
                left, target = line.split(" -> ", 1)
                fds[int(left.split()[-1])] = target
        self.assertEqual("/dev/null", fds[0])
        self.assertTrue(fds[1].startswith("pipe:") and fds[1] == fds[2], fds)
        script = str(folder / "install-ok.sh")
        others = {n: t for n, t in fds.items() if n > 2 and t != script}
        self.assertEqual({}, others, "nothing of the agent (sockets, files) reaches the script")
        self.finish(agent)

    def test_download_resumes_after_interruptions_and_429(self):
        app, folder = self.component("app")
        agent, device = self.start_agent({"app": app})
        data = payload(1000)

        offer = self.offer(
            device, "app", "1.1.0", data, faults=(cut_after(300), STATUS_429, cut_after(700))
        )
        result = self.platform.wait_results(device, timeout=150)[0]

        self.assertEqual({"release": offer.release, "result": "installed", "fw": "1.1.0"}, result)
        self.assertEqual([None, "bytes=300-", "bytes=300-", "bytes=700-"], self.ranges(offer))
        requests = self.platform.download_requests(offer.url)
        self.assertGreaterEqual(requests[2].time - requests[1].time, 59, "60 s after a 429")
        self.assertEqual(data, (folder / "installed.bin").read_bytes())
        self.assertEqual(1, len(self.result_messages(device)))
        self.assert_clean(agent)
        self.finish(agent)

    def test_script_exit_10_installed_after_restart(self):
        app, folder = self.component("app", script="install-later.sh")
        agent, device = self.start_agent(
            {"app": app}, reboot_command=f"{folder / 'reboot.sh'} now please"
        )

        offer = self.offer(device, "app", "1.1.0", payload(2000))
        wait_until(lambda: (folder / "rebooted").exists(), 30, "the reboot command")

        self.assertEqual("now please\n", (folder / "rebooted").read_text())
        state = agent.read_json("install.json")
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.assertEqual(
            {
                "release": offer.release,
                "component": "app",
                "version": "1.1.0",
                "state": "reboot",
                "bootId": boot_id,
            },
            state,
        )
        time.sleep(2)
        self.assertEqual([], self.platform.results(device), "no result before the next start")
        self.assertEqual(0, agent.stop())

        self.run_agent(agent)
        result = self.platform.wait_results(device)[0]
        self.assertEqual({"release": offer.release, "result": "installed", "fw": "1.1.0"}, result)
        wait_until(lambda: not agent.path("install.json").exists(), 10, "install.json removed")
        self.assertEqual(1, len((folder / "runs").read_text().splitlines()))
        self.assertEqual(1, len(self.platform.download_requests(offer.url)))
        self.assert_clean(agent)
        self.finish(agent)

    def test_script_exit_10_without_new_version_is_boot_failed(self):
        app, folder = self.component("app", script="install-later-broken.sh")
        boot = self.tmp / "boot_id"  # played reboots: FIRMLINE_BOOT_ID_FILE (tests only)
        boot.write_text("boot-a\n")
        rebooted = folder / "rebooted"
        agent, device = self.start_agent(
            {"app": app},
            env={"FIRMLINE_BOOT_ID_FILE": str(boot)},
            reboot_command=f"{folder / 'reboot.sh'} first",
        )

        offer = self.offer(device, "app", "1.1.0", payload(2000))
        wait_until(lambda: rebooted.exists(), 30, "the reboot command")
        self.assertEqual("reboot", agent.read_json("install.json")["state"])
        self.assertEqual(0, agent.stop())
        self.assertEqual([], self.platform.results(device))

        # Only the agent restarted, in the same boot (the reboot did not happen): it keeps
        # waiting, and runs reboot_command once more, else nothing would ever reboot the device.
        rebooted.unlink()
        agent.settings["reboot_command"] = f"{folder / 'reboot.sh'} again"
        self.run_agent(agent)
        agent.wait_for_log(f"release {offer.release}: installed at the next start")
        wait_until(lambda: rebooted.exists(), 10, "reboot_command run again")
        self.assertEqual("again\n", rebooted.read_text())
        time.sleep(2)
        self.assertEqual([], self.platform.results(device), "no result before the reboot")
        self.assertTrue(agent.path("install.json").exists())
        self.assertEqual(1, len((folder / "runs").read_text().splitlines()), "no script again")
        self.assertEqual(0, agent.stop())

        boot.write_text("boot-b\n")  # the device rebooted, the old version came back
        self.run_agent(agent)
        result = self.platform.wait_results(device)[0]
        self.assertEqual(
            {"release": offer.release, "result": "failed", "fw": "1.0.0", "detail": "boot_failed"},
            result,
        )
        self.assertEqual(1, len((folder / "runs").read_text().splitlines()))
        self.assertEqual(1, len(self.platform.download_requests(offer.url)))
        self.assert_clean(agent)
        self.finish(agent)

    def stop_during_script(self, exit_code, sleep, expected, detail=None, fw=None):
        """Stops the agent (SIGTERM) while the script sleeps; after the restart exactly one
        result follows, and the script never runs again."""
        app, folder = self.component("app", script="install-sleep.sh")
        (folder / "exit").write_text(f"{exit_code}\n")
        (folder / "sleep").write_text(f"{sleep}\n")
        agent, device = self.start_agent({"app": app})

        offer = self.offer(device, "app", "1.1.0", payload(2000))
        agent.wait_for_log("script: sleeping before the installation")
        self.assertEqual(0, agent.stop())

        self.run_agent(agent)
        self.platform.wait_results(device)
        time.sleep(2)
        expected_result = {"release": offer.release, "result": expected}
        if fw is not None:
            expected_result["fw"] = fw
        if detail is not None:
            expected_result["detail"] = detail
        self.assertEqual([expected_result], self.platform.results(device))
        self.assertEqual(1, len((folder / "runs").read_text().splitlines()), "never run again")
        self.assertEqual(1, len(self.platform.download_requests(offer.url)))
        self.assert_clean(agent)
        self.finish(agent)

    def test_stop_while_script_runs_keeps_its_exit_0(self):
        self.stop_during_script(0, 2, "installed", fw="1.1.0")

    def test_stop_while_script_runs_keeps_its_exit_10(self):
        self.stop_during_script(10, 2, "installed", fw="1.1.0")

    def test_stop_killing_a_long_script_sends_install_failed(self):
        self.stop_during_script(0, 60, "failed", detail="install_failed", fw="1.0.0")

    def stop_with_the_script(self, early, expected, detail, fw):
        """A systemd stop with KillMode=control-group: SIGTERM to the agent and to the script at
        the same moment. The script's death by that signal is no outcome of its own: the next
        start decides from the version (exactly one result, the script never run again)."""
        app, folder = self.component("app", script="install-sleep.sh")
        (folder / "exit").write_text("0\n")
        (folder / "sleep").write_text("60\n")
        if early:
            (folder / "early").write_text("")
        agent, device = self.start_agent({"app": app})

        offer = self.offer(device, "app", "1.1.0", payload(2000))
        agent.wait_for_log("script: sleeping before the installation")
        script = int((folder / "pid").read_text())
        agent._process.send_signal(signal.SIGTERM)
        os.killpg(script, signal.SIGTERM)
        self.assertEqual(0, agent.stop())
        self.assertEqual("running", agent.read_json("install.json")["state"])

        self.run_agent(agent)
        self.platform.wait_results(device)
        time.sleep(2)
        expected_result = {"release": offer.release, "result": expected, "fw": fw}
        if detail is not None:
            expected_result["detail"] = detail
        self.assertEqual([expected_result], self.platform.results(device))
        self.assertEqual(1, len((folder / "runs").read_text().splitlines()), "never run again")
        self.assertEqual(1, len(self.platform.download_requests(offer.url)))
        self.assert_clean(agent)
        self.finish(agent)

    def test_stop_signalling_script_with_version_in_place_sends_installed(self):
        self.stop_with_the_script(True, "installed", None, "1.1.0")

    def test_stop_signalling_script_without_version_sends_install_failed(self):
        self.stop_with_the_script(False, "failed", "install_failed", "1.0.0")

    def test_waiting_older_release_is_refused_after_a_newer_install(self):
        app, folder = self.component("app")
        agent, device = self.start_agent({"app": app})

        older = self.offer(
            device,
            "app",
            "1.1.0",
            payload(1000),
            not_before=utc_now() + datetime.timedelta(seconds=8),
        )
        agent.wait_for_log(f"release {older.release}: offer queued")
        newer = self.offer(device, "app", "1.2.0", payload(1000, seed=2))
        results = self.platform.wait_results(device, count=2, timeout=60)

        self.assertEqual(
            [
                {"release": newer.release, "result": "installed", "fw": "1.2.0"},
                {"release": older.release, "result": "failed", "detail": "older_version"},
            ],
            results,
        )
        self.assertEqual([], self.ranges(older), "the older release is not downloaded")
        self.assertEqual(1, len((folder / "runs").read_text().splitlines()), "one install")
        self.assertEqual("1.2.0\n", (folder / "version").read_text())
        self.assert_clean(agent)
        self.finish(agent)

    def test_queued_older_release_is_refused_after_a_newer_install(self):
        app, folder = self.component("app")
        agent, device = self.start_agent({"app": app})

        newer = self.offer(device, "app", "1.2.0", payload(3000), slow=1500)
        agent.wait_for_log(f"release {newer.release}: downloading")
        older = self.offer(device, "app", "1.1.0", payload(1000, seed=2))
        agent.wait_for_log(f"release {older.release}: offer queued")
        results = self.platform.wait_results(device, count=2, timeout=60)

        self.assertEqual(
            [
                {"release": newer.release, "result": "installed", "fw": "1.2.0"},
                {"release": older.release, "result": "failed", "detail": "older_version"},
            ],
            results,
        )
        self.assertEqual([], self.ranges(older), "the older release is not downloaded")
        self.assertEqual(1, len((folder / "runs").read_text().splitlines()), "one install")
        self.assertEqual("1.2.0\n", (folder / "version").read_text())
        self.assert_clean(agent)
        self.finish(agent)

    def test_script_error_sends_install_failed(self):
        app, folder = self.component("app", script="install-error.sh")
        agent, device = self.start_agent({"app": app})

        offer = self.offer(device, "app", "1.1.0", payload(2000))
        result = self.platform.wait_results(device)[0]

        self.assertEqual(
            {
                "release": offer.release,
                "result": "failed",
                "fw": "1.0.0",
                "detail": "install_failed",
            },
            result,
        )
        self.assertIn("script: cannot write the flash", agent.running_log)
        file = (folder / "runs").read_text().split()[0]
        self.assertFalse(Path(file).exists())
        self.assert_clean(agent)
        self.finish(agent)

    def test_script_timeout_sends_install_failed(self):
        app, folder = self.component("app", script="install-slow.sh", timeout=2)
        agent, device = self.start_agent({"app": app})

        offer = self.offer(device, "app", "1.1.0", payload(2000))
        wait_until(lambda: (folder / "sleep.pid").exists(), 30, "the script")
        started = time.monotonic()
        result = self.platform.wait_results(device)[0]

        self.assertEqual(
            {
                "release": offer.release,
                "result": "failed",
                "fw": "1.0.0",
                "detail": "install_failed",
            },
            result,
        )
        self.assertLess(time.monotonic() - started, 15)
        sleeper = int((folder / "sleep.pid").read_text())
        wait_until(lambda: process_gone(sleeper), 5, "the script's process group killed")
        self.assertIn("script: installing slowly", agent.running_log)
        self.assert_clean(agent)
        self.finish(agent)

    def test_offer_for_none_component_sends_component_mismatch(self):
        agent, device = self.start_agent()  # app: install = none

        offer = self.offer(device, "app", "1.1.0", payload(100))
        result = self.platform.wait_results(device)[0]

        self.assertEqual(
            {"release": offer.release, "result": "failed", "detail": "component_mismatch"}, result
        )
        self.assertEqual([], self.ranges(offer))
        self.finish(agent)

    def test_tampered_manifest_sends_rejected_signature(self):
        app, folder = self.component("app")
        agent, device = self.start_agent({"app": app})

        offer = self.offer(
            device,
            "app",
            "1.1.0",
            payload(100),
            tamper=lambda manifest: manifest.replace(b'"1.1.0"', b'"1.1.1"'),
        )
        result = self.platform.wait_results(device)[0]

        self.assertEqual(
            {
                "release": offer.release,
                "result": "rejected_signature",
                "detail": "signature_invalid",
            },
            result,
        )
        self.assertEqual([], self.ranges(offer))
        self.assertFalse((folder / "runs").exists())
        self.finish(agent)

    def test_wrong_file_sends_hash_mismatch(self):
        app, folder = self.component("app")
        agent, device = self.start_agent({"app": app})

        offer = self.offer(device, "app", "1.1.0", payload(3000), served=payload(3000, seed=1))
        result = self.platform.wait_results(device)[0]

        self.assertEqual(
            {"release": offer.release, "result": "rejected_signature", "detail": "hash_mismatch"},
            result,
        )
        self.assertEqual([None], self.ranges(offer))
        self.assertFalse((folder / "runs").exists(), "nothing unverified is installed")
        self.assert_clean(agent)
        self.finish(agent)

    def test_two_releases_one_at_a_time_each_with_its_result(self):
        app, app_folder = self.component("app")
        extra, extra_folder = self.component("extra", version="2.0.0", main=False)
        agent, device = self.start_agent({"app": app, "extra": extra})

        first = self.offer(device, "app", "1.1.0", payload(6000), slow=2000)
        agent.wait_for_log(f"release {first.release}: downloading")
        second = self.offer(device, "extra", "2.1.0", payload(3000, seed=3))
        results = self.platform.wait_results(device, count=2)

        self.assertEqual(
            [
                {"release": first.release, "result": "installed", "fw": "1.1.0"},
                {"release": second.release, "result": "installed", "fw": "2.1.0"},
            ],
            results,
        )
        log = agent.running_log
        queued = log.index(f"release {second.release}: offer queued")
        first_done = log.index(f"release {first.release}: result installed")
        second_starts = log.index(f"release {second.release}: downloading")
        self.assertLess(queued, first_done, "the second offer arrived during the first download")
        self.assertLess(first_done, second_starts, "one release at a time")
        first_last = self.platform.download_requests(first.url)[-1].time
        self.assertGreater(self.platform.download_requests(second.url)[0].time, first_last)
        self.assertEqual("2.1.0\n", (extra_folder / "version").read_text())
        self.assertEqual("1.1.0\n", (app_folder / "version").read_text())
        self.assert_clean(agent)
        self.finish(agent)

    def test_expired_link_sends_no_result_and_next_offer_installs(self):
        app, folder = self.component("app")
        agent, device = self.start_agent({"app": app})

        offer = self.offer(
            device,
            "app",
            "1.1.0",
            payload(2000),
            url_expires=utc_now() - datetime.timedelta(minutes=1),
        )
        # Whether the link is still valid is the server's answer (404), not the device clock's.
        agent.wait_for_log(f"release {offer.release}: download refused (HTTP 404)")
        time.sleep(1)
        self.assertIn("the device clock may be wrong", agent.running_log)
        self.assertEqual([None], self.ranges(offer), "asked once: a 404 is not retried")
        self.assertEqual([], self.platform.results(device), "an expired link is not a result")

        again = self.repeat(offer)
        result = self.platform.wait_results(device)[0]
        self.assertEqual({"release": offer.release, "result": "installed", "fw": "1.1.0"}, result)
        self.assertEqual([None], self.ranges(again))
        self.assertEqual(1, len(self.result_messages(device)))
        self.finish(agent)

    def test_device_clock_two_hours_ahead_still_downloads_and_installs(self):
        # An RTC in local time read as UTC (+2 h) and no NTP: by the device clock every link
        # (valid for an hour by the platform's) has already expired. The server decides.
        app, folder = self.component("app")
        shim = build_clock_shim(self.tmp)
        agent, device = self.start_agent(
            {"app": app}, run_env=clock_env(shim, datetime.timedelta(hours=2))
        )
        data = payload(2000)

        offer = self.offer(device, "app", "1.1.0", data, faults=(cut_after(700),))
        result = self.platform.wait_results(device)[0]

        self.assertEqual({"release": offer.release, "result": "installed", "fw": "1.1.0"}, result)
        self.assertEqual([None, "bytes=700-"], self.ranges(offer), "retried after the cut")
        self.assertIn("the device clock may be wrong", agent.running_log)
        self.assertEqual(data, (folder / "installed.bin").read_bytes())
        self.assert_clean(agent)
        self.finish(agent)

    def test_repeated_offer_after_result_resends_result(self):
        app, folder = self.component("app")
        agent, device = self.start_agent({"app": app})
        offer = self.offer(device, "app", "1.1.0", payload(2000))
        first = self.platform.wait_results(device)[0]

        again = self.repeat(offer)
        self.platform.wait_results(device, count=2)

        messages = self.result_messages(device)
        self.assertEqual(messages[0].payload, messages[1].payload, "the stored result again")
        self.assertEqual("installed", first["result"])
        self.assertEqual([], self.ranges(again), "no second download")
        self.assertEqual(1, len((folder / "runs").read_text().splitlines()), "no second install")
        self.finish(agent)

    def test_restart_mid_download_resumes(self):
        app, folder = self.component("app")
        agent, device = self.start_agent({"app": app})
        data = payload(30000)

        offer = self.offer(device, "app", "1.1.0", data, slow=3000)
        part = agent.path(f"download-{offer.release}.part")
        wait_until(lambda: part.exists() and part.stat().st_size >= 6000, 30, "half a download")
        agent.kill()  # as a power loss: nothing is cleaned up
        resumed_at = part.stat().st_size
        self.assertLess(resumed_at, len(data))

        self.run_agent(agent)
        result = self.platform.wait_results(device, timeout=60)[0]

        self.assertEqual({"release": offer.release, "result": "installed", "fw": "1.1.0"}, result)
        self.assertEqual([None, f"bytes={resumed_at}-"], self.ranges(offer))
        self.assertEqual(data, (folder / "installed.bin").read_bytes())
        self.assertIn(f"resuming the download at byte {resumed_at}", agent.running_log)
        time.sleep(1)
        self.assertEqual(1, len(self.result_messages(device)), "one result")
        self.assert_clean(agent)
        self.finish(agent)

    def test_not_enough_space_sends_no_space(self):
        try:
            disk = os.statvfs(SMALL_DISK)
        except FileNotFoundError:
            # Review Focus 5 must not vanish from CI: a skip only when asked for explicitly.
            if os.environ.get("FIRMLINE_NO_SMALL_DISK") == "1":
                self.skipTest(f"{SMALL_DISK} is missing and FIRMLINE_NO_SMALL_DISK=1")
            self.fail(f"{SMALL_DISK} is missing: scripts/check.sh mounts it (1 MiB tmpfs); set "
                      "FIRMLINE_NO_SMALL_DISK=1 to skip this test outside check.sh")
        self.assertLessEqual(disk.f_blocks * disk.f_frsize, 2 * 1024 * 1024, "a small disk")
        data_dir = SMALL_DISK / uuid.uuid4().hex
        self.addCleanup(shutil.rmtree, data_dir, ignore_errors=True)
        app, folder = self.component("app")
        agent, device = self.start_agent({"app": app}, data_dir=data_dir)

        offer = self.offer(device, "app", "1.1.0", payload(4 * 1024 * 1024))
        result = self.platform.wait_results(device)[0]

        self.assertEqual(
            {"release": offer.release, "result": "failed", "detail": "no_space"}, result
        )
        self.assertEqual([], self.ranges(offer), "nothing downloaded")
        self.assert_clean(agent)
        self.finish(agent)


class FamilyBeforeT178Test(OtaBase):
    """Devices registered before T178: the platform sent no familyId."""

    send_family_id = False

    def test_family_unknown_sends_failed(self):
        app, folder = self.component("app")
        agent, device = self.start_agent({"app": app})

        offer = self.offer(device, "app", "1.1.0", payload(100))
        result = self.platform.wait_results(device)[0]

        self.assertEqual(
            {"release": offer.release, "result": "failed", "detail": "family_unknown"}, result
        )
        self.assertEqual([], self.ranges(offer))
        self.finish(agent)

    def test_family_from_config_until_renewal(self):
        app, folder = self.component("app")
        agent, device = self.start_agent({"app": app}, family=self.platform.family_id)

        offer = self.offer(device, "app", "1.1.0", payload(100))
        result = self.platform.wait_results(device)[0]

        self.assertEqual({"release": offer.release, "result": "installed", "fw": "1.1.0"}, result)
        self.finish(agent)


if __name__ == "__main__":
    unittest.main()
