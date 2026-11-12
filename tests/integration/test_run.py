# SPDX-License-Identifier: Apache-2.0
"""firmline-agent run: one connection to the broker, the offer topic subscribed before the first
status, the status again at every interval, reconnection with a wait that grows, a clean stop."""

import datetime
import re
import time
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from harness import (
    IntegrationTest,
    assert_no_secrets,
    cert_pem,
    count_connections,
    utc_now,
    wait_until,
)

UTC_TIME = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")


def parse_utc(text: str) -> datetime.datetime:
    return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc
    )


class RunTest(IntegrationTest):
    def setUp(self):
        super().setUp()
        self.broker = self.make_broker()

    def registered_agent(self, name: str = "agent", **kwargs):
        """A registered agent of the test broker, and its device.json."""
        agent = self.make_agent(name, broker=self.broker, **kwargs)
        token = self.platform.new_token()
        result = agent.run("register", "--token", token, "--serial", f"SN-{name}")
        self.assertEqual(0, result.code, result.stderr)
        return agent, agent.read_json("device.json")

    SDK_RULE = re.compile(r"^[A-Za-z0-9._-]{1,32}/\S(.*\S)?$")

    def sdk_name_version(self, agent) -> str:
        """firmline-agent/<version>, the version being what --version prints (0.0.0-dev in the
        default build), checked against the platform rule for the sdk field."""
        result = agent.run("--version")
        self.assertEqual(0, result.code, result.stderr)
        match = re.fullmatch(r"firmline-agent (\S+)\n", result.stdout)
        self.assertIsNotNone(match, result.stdout)
        value = "firmline-agent/" + match.group(1)
        self.assertRegex(value, self.SDK_RULE)
        self.assertLessEqual(len(value), 64)
        return value

    def secrets_of(self, agent):
        return [agent.read_text("device.key"), agent.read_text("device.pem")]

    def platform_client(self):
        client = self.broker.client()
        self.addCleanup(client.close)
        client.subscribe("t/#")
        return client

    @staticmethod
    def received(kind: str, client_id: str) -> str:
        """The broker log line of a packet received from the client."""
        return f"Received {kind} from {client_id}"

    def test_subscribes_before_first_status_and_sends_fw_and_components(self):
        os_release = self.tmp / "os-release"
        os_release.write_text('NAME="Torizon OS"\nVERSION_ID="7.2.0-build.13"\n')
        components = {
            "app": {"main": "true", "version": "fixed:2.4.1", "install": "none"},
            "torizon": {"main": "false", "version": "os-release:VERSION_ID", "install": "none"},
        }
        agent, identity = self.registered_agent(components=components, os_release=os_release)
        client_id, status_topic = identity["clientId"], identity["topicRoot"] + "/status"
        platform = self.platform_client()
        started = utc_now()

        agent.start("run")
        message = platform.wait_for(status_topic)[0]

        status = message.json()
        self.assertEqual({"fw", "components", "sdk", "ts", "uptime"}, set(status))
        self.assertEqual(self.sdk_name_version(agent), status["sdk"])
        self.assertEqual("2.4.1", status["fw"])
        self.assertEqual({"torizon": "7.2.0-build.13"}, status["components"])
        self.assertRegex(status["ts"], UTC_TIME)
        self.assertLess(abs(parse_utc(status["ts"]) - started), datetime.timedelta(minutes=1))
        self.assertIsInstance(status["uptime"], int)
        self.assertGreaterEqual(status["uptime"], 0)
        self.assertEqual((1, False), (message.qos, message.retain))

        log = self.broker.log
        self.assertIn(f"as {client_id} (p5, c1, k60, u'{client_id}')", log)  # MQTT 5, clean
        subscribe = log.index(self.received("SUBSCRIBE", client_id))
        publish = log.index(self.received("PUBLISH", client_id))
        self.assertLess(subscribe, publish, "the offer topic is subscribed before the status")
        self.assertIn(f"{identity['otaOfferTopic']} (QoS 1)", log[subscribe:publish])
        self.assertIn("(d0, q1, r0, m", log[publish:].splitlines()[0])
        self.assertIn(f"'{status_topic}'", log[publish:].splitlines()[0])

        last = parse_utc(agent.read_json("connection.json")["lastConnection"])
        self.assertLess(abs(last - started), datetime.timedelta(minutes=1))
        self.assertEqual(
            agent.read_text("device.pem") + cert_pem(self.pki.intermediate),
            agent.read_text("device-chain.pem"),
        )

        self.assertEqual(0, agent.stop())
        wait_until(lambda: f"Client {client_id} disconnected." in self.broker.log, 10, "DISCONNECT")
        assert_no_secrets(agent.log, self.secrets_of(agent))

    def test_every_https_request_carries_the_versioned_user_agent(self):
        agent, _ = self.registered_agent()
        expected = self.sdk_name_version(agent)
        requests = list(self.platform.requests)
        self.assertTrue(requests, "the registration reached the fake platform")
        for request in requests:
            self.assertEqual(expected, request.headers.get("user-agent"), request.path)

    def test_status_again_after_interval(self):
        agent, identity = self.registered_agent(status_interval=2)
        client_id, status_topic = identity["clientId"], identity["topicRoot"] + "/status"
        stale = agent.path(".device.json.4194304.0.tmp")  # left by a write cut by a power loss
        stale.write_text("{")
        platform = self.platform_client()

        agent.start("run")
        messages = platform.wait_for(status_topic, count=3, timeout=30)

        for before, after in zip(messages, messages[1:3]):
            self.assertGreater(after.time - before.time, 1.5)
            self.assertLess(after.time - before.time, 3.5)
        self.assertEqual(1, self.broker.log.count(f"as {client_id} ("), "one connection")
        self.assertFalse(stale.exists(), "temporary files of an interrupted write are removed")
        self.assertEqual(0, agent.stop())
        assert_no_secrets(agent.log, self.secrets_of(agent))

    def test_reconnects_after_broker_restart_without_flooding(self):
        agent, identity = self.registered_agent()
        client_id = identity["clientId"]
        agent.start("run")
        agent.wait_for_log("status sent")

        self.broker.stop()
        attempts = count_connections(self.broker.port, 10)
        self.assertGreaterEqual(len(attempts), 1, "the agent tries again")
        self.assertLessEqual(len(attempts), 3, "at most 3 connection attempts in 10 s")
        mark = len(self.broker.log)
        self.broker.start()

        after = wait_until(
            lambda: (lambda log: log if self.received("PUBLISH", client_id) in log else None)(
                self.broker.log[mark:]
            ),
            40,
            "a status after the broker is back",
        )
        self.assertLess(
            after.index(self.received("SUBSCRIBE", client_id)),
            after.index(self.received("PUBLISH", client_id)),
        )
        self.assertEqual(0, agent.stop())
        assert_no_secrets(agent.log, self.secrets_of(agent))

    def test_unregistered_run_exits_1(self):
        agent = self.make_agent(broker=self.broker)
        result = agent.run("run", timeout=30)
        self.assertEqual(1, result.code)
        self.assertIn("not registered", result.stderr)
        self.assertNotIn("New client connected", self.broker.log)
        assert_no_secrets(agent.log, [])

    def test_run_waits_for_the_registration_when_asked(self):
        agent = self.make_agent(broker=self.broker)
        platform = self.platform_client()
        process = agent.start("run", "--wait-registration")
        agent.wait_for_log("waiting for the registration", 15)
        time.sleep(25)  # the check is every 10 s: the message is logged once, not at every check
        self.assertIsNone(process.poll(), "the agent must keep running")
        self.assertEqual(1, agent.running_log.count("waiting for the registration"))
        self.assertEqual(1, self.broker.log.count("New client connected"), "only the platform")

        token = self.platform.new_token()
        result = agent.run("register", "--token", token, "--serial", "SN-wait")
        self.assertEqual(0, result.code, result.stderr)
        identity = agent.read_json("device.json")
        message = platform.wait_for(identity["topicRoot"] + "/status", timeout=15)[0]
        self.assertEqual("firmline-agent/", message.json()["sdk"][:15])
        self.assertEqual(0, agent.stop())
        assert_no_secrets(agent.log, self.secrets_of(agent))

    def test_run_stops_at_once_on_sigterm_while_waiting_for_the_registration(self):
        agent = self.make_agent(broker=self.broker)
        agent.start("run", "--wait-registration")
        agent.wait_for_log("waiting for the registration", 15)
        started = time.monotonic()
        self.assertEqual(0, agent.stop(timeout=5))
        self.assertLess(time.monotonic() - started, 3)

    def test_run_with_wait_registration_and_a_registered_device_runs_as_usual(self):
        agent, identity = self.registered_agent()
        platform = self.platform_client()
        agent.start("run", "--wait-registration")
        platform.wait_for(identity["topicRoot"] + "/status")
        self.assertNotIn("waiting for the registration", agent.running_log)
        self.assertEqual(0, agent.stop())

    def test_run_with_wrong_update_key_exits_1(self):
        agent, _ = self.registered_agent()
        p384 = ec.generate_private_key(ec.SECP384R1()).public_key()
        wrong_curve = self.tmp / "p384.pem"
        wrong_curve.write_bytes(
            p384.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        for path in [wrong_curve, self.pki.root_path, self.tmp / "missing.pem"]:
            with self.subTest(update_key=path.name):
                agent.settings["update_key"] = str(path)
                result = agent.run("run", timeout=30)
                self.assertEqual(1, result.code)
                self.assertIn("update_key", result.stderr)
        self.assertNotIn("New client connected", self.broker.log)
        assert_no_secrets(agent.log, self.secrets_of(agent))

    def test_device_chain_that_cannot_be_written_is_not_a_reason_to_register_again(self):
        # device-chain.pem is rewritten from device.pem whenever it differs (after a renewal). A
        # full or read-only data partition must not send the operator to "Registering again",
        # which would throw a valid identity away. The tests run as root, so a folder in the
        # place of the file stands for the write that fails (the rename onto it is refused).
        agent, _ = self.registered_agent()
        secrets = self.secrets_of(agent)
        blocker = agent.path("device-chain.pem")
        blocker.unlink(missing_ok=True)
        blocker.mkdir()
        (blocker / "keep").write_text("x\n")

        result = agent.run("run", timeout=30)
        self.assertEqual(1, result.code)
        self.assertIn(f"cannot write device-chain.pem in {agent.data_dir}", result.stderr)
        self.assertIn("free space or fix permissions, then restart", result.stderr)
        self.assertNotIn("Registering again", result.stderr)
        self.assertNotIn("register the device again", result.stderr)
        self.assertNotIn("incomplete", result.stderr)

        # A missing identity file is still a case for registering again.
        (blocker / "keep").unlink()
        blocker.rmdir()
        agent.path("device.pem").unlink()
        result = agent.run("run", timeout=30)
        self.assertEqual(1, result.code)
        self.assertIn("is incomplete", result.stderr)
        self.assertIn('(see "Registering again" in the integration guide)', result.stderr)
        self.assertNotIn("New client connected", self.broker.log)
        assert_no_secrets(agent.log, secrets)

    def test_no_status_while_no_version_is_readable(self):
        version_file = self.tmp / "app-version"
        components = {"app": {"main": "true", "version": f"file:{version_file}"}}
        agent, identity = self.registered_agent(components=components, status_interval=1)
        client_id, status_topic = identity["clientId"], identity["topicRoot"] + "/status"
        platform = self.platform_client()

        agent.start("run")
        wait_until(
            lambda: f"Sending SUBACK to {client_id}" in self.broker.log,
            30,
            "the subscription",
        )
        time.sleep(3.5)
        self.assertEqual([], platform.received(status_topic), "nothing to report: no status")

        version_file.write_text("3.0.1\n")
        message = platform.wait_for(status_topic, timeout=10)[0]
        self.assertEqual("3.0.1", message.json()["fw"])
        self.assertEqual(0, agent.stop())
        self.assertEqual(1, agent.log.count("no component version can be read"))
        assert_no_secrets(agent.log, self.secrets_of(agent))


if __name__ == "__main__":
    unittest.main()
