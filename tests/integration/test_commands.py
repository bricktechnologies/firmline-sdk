# SPDX-License-Identifier: Apache-2.0
"""firmline-agent status (one JSON object from the files of the data folder, no network) and
firmline-agent endpoint (--relay <host> [--https-port <p>] [--broker-port <p>], --direct): the
relay's addresses saved in endpoint.json, used by the renewal, the downloads and the broker
connection, verified with the root received at registration."""

import datetime
import json
import socket
import ssl
import unittest
import uuid

from cryptography import x509

from harness import (
    FakePlatform,
    Pki,
    assert_no_secrets,
    trust_system_wide,
    utc_now,
    wait_until,
)
from test_ota import OtaBase, payload

DAY = datetime.timedelta(days=1)
STATUS_KEYS = {
    "registered",
    "deviceId",
    "familyId",
    "certificateNotAfter",
    "endpoint",
    "lastConnection",
    "queue",
    "pendingInstall",
}


class CommandsBase(OtaBase):
    def register(self, agent):
        token = self.platform.new_token()
        result = agent.run("register", "--token", token, "--serial", f"SN-{uuid.uuid4().hex[:8]}")
        self.assertEqual(0, result.code, result.stderr)
        return agent.read_json("device.json")

    def status(self, agent):
        """The output of `status`, which must be exactly one JSON object on one line."""
        result = agent.run("status")
        self.assertEqual(0, result.code, result.stderr)
        self.assertEqual(1, len(result.stdout.splitlines()), result.stdout)
        value = json.loads(result.stdout)
        self.assertEqual(STATUS_KEYS, set(value))
        return value


class StatusTest(CommandsBase):
    def test_status_prints_registration_and_queue(self):
        app, folder = self.component("app")
        agent = self.make_agent(broker=self.broker, components={"app": app})

        unregistered = self.status(agent)
        self.assertEqual(dict.fromkeys(STATUS_KEYS), dict(unregistered, registered=None))
        self.assertIs(False, unregistered["registered"])

        identity = self.register(agent)
        status = self.status(agent)
        cert = x509.load_pem_x509_certificate(agent.path("device.pem").read_bytes())
        self.assertEqual(
            {
                "registered": True,
                "deviceId": identity["deviceId"],
                "familyId": self.platform.family_id,
                "certificateNotAfter": FakePlatform.iso(cert.not_valid_after_utc),
                "endpoint": "direct",
                "lastConnection": None,
                "queue": [],
                "pendingInstall": None,
            },
            status,
        )

        # A release waiting for its notBefore stays queued after the agent stops.
        self.run_agent(agent)
        offer = self.offer(
            identity["deviceId"], "app", "1.2.0", payload(100), not_before=utc_now() + DAY
        )
        agent.wait_for_log(f"release {offer.release}: offer queued")
        self.assertEqual(0, agent.stop())
        installing = str(uuid.uuid4())
        agent.path("install.json").write_text(
            json.dumps(
                {
                    "release": installing,
                    "component": "app",
                    "version": "1.1.0",
                    "state": "reboot",
                    "bootId": "x",
                }
            )
        )
        requests = len(self.platform.requests)

        status = self.status(agent)

        last = agent.read_json("connection.json")["lastConnection"]
        self.assertEqual(last, status["lastConnection"])
        self.assertEqual(
            [{"release": offer.release, "component": "app", "version": "1.2.0"}], status["queue"]
        )
        pending = {"release": installing, "component": "app", "version": "1.1.0"}
        self.assertEqual(pending, status["pendingInstall"])
        self.assertEqual(requests, len(self.platform.requests), "status does not use the network")
        assert_no_secrets(agent.log, [agent.read_text("device.key"), offer.url])


class StatusBeforeT178Test(CommandsBase):
    send_family_id = False

    def test_status_family_is_null_before_T178(self):
        agent = self.make_agent(broker=self.broker)
        self.register(agent)
        self.assertIsNone(self.status(agent)["familyId"])


class EndpointTest(CommandsBase):
    def test_endpoint_relay_switches_addresses_and_direct_goes_back(self):
        relay, relay_broker = self.make_relay()
        relay_mqtt = relay.connect(relay_broker)
        self.addCleanup(relay_mqtt.close)
        app, folder = self.component("app")
        agent = self.make_agent(broker=self.broker, components={"app": app})
        self.platform.certificates(datetime.timedelta(days=59))  # renewed at the next start
        identity = self.register(agent)
        self.platform.default_certificates()
        device, status_topic = identity["deviceId"], identity["topicRoot"] + "/status"

        result = agent.run(
            "endpoint",
            "--relay",
            "localhost",
            "--https-port",
            relay.port,
            "--broker-port",
            relay_broker.port,
        )
        self.assertEqual(0, result.code, result.stderr)
        self.assertEqual(
            {
                "https": f"https://localhost:{relay.port}",
                "broker": "localhost",
                "brokerPort": relay_broker.port,
            },
            agent.read_json("endpoint.json"),
        )
        self.assertEqual("relay", self.status(agent)["endpoint"])

        # Only the root of the registration can verify the relay: not the configuration's CA.
        other = Pki(self.tmp / "other-pki")
        agent.settings["ca_file"] = str(other.root_path)
        agent.start("run")
        agent.wait_for_log("device certificate renewed")
        relay_mqtt.wait_for(status_topic)
        self.assertEqual(1, len(relay.requests_to(FakePlatform.RENEWAL)))
        self.assertEqual([], self.platform.requests_to(FakePlatform.RENEWAL))

        # Subscribed again after the renewal (the earlier connection is closed), on the relay.
        mark = "device certificate renewed"
        wait_until(
            lambda: "subscribed to" in agent.running_log.partition(mark)[2], 30, "a subscription"
        )
        offer = relay.offer(device, "app", "1.1.0", payload(300))
        result = relay.wait_results(device)[0]
        self.assertEqual({"release": offer.release, "result": "installed", "fw": "1.1.0"}, result)
        self.assertEqual(1, len(relay.download_requests(offer.url)))
        self.assertEqual([], self.mqtt.received(status_topic), "nothing through the platform")
        self.assertEqual(0, agent.stop())

        result = agent.run("endpoint", "--direct")
        self.assertEqual(0, result.code, result.stderr)
        self.assertFalse(agent.path("endpoint.json").exists())
        self.assertEqual("direct", self.status(agent)["endpoint"])
        agent.settings["ca_file"] = str(self.pki.root_path)
        statuses = len(relay_mqtt.received(status_topic))
        agent.start("run")
        self.mqtt.wait_for(status_topic)
        self.assertEqual(statuses, len(relay_mqtt.received(status_topic)))
        self.assertEqual(0, agent.stop())
        secrets = [agent.read_text("device.key"), offer.url, offer.url.rsplit("/", 1)[1]]
        assert_no_secrets(agent.log, secrets)

    def test_endpoint_defaults_and_bad_arguments(self):
        agent = self.make_agent(broker=self.broker)
        self.register(agent)

        result = agent.run("endpoint", "--relay", "relay.local")
        self.assertEqual(0, result.code, result.stderr)
        self.assertEqual(
            {"https": "https://relay.local:443", "broker": "relay.local", "brokerPort": 8883},
            agent.read_json("endpoint.json"),
        )
        agent.path("endpoint.json").unlink()

        for args in [
            [],
            ["--relay"],
            ["--relay", "bad host"],
            ["--relay", "relay/x"],
            ["--relay", "h", "--https-port", "0"],
            ["--relay", "h", "--broker-port", "65536"],
            ["--relay", "h", "--https-port", "8x"],
            ["--direct", "--relay", "h"],
            ["--https-port", "443"],
            ["--relay", "h", "--relay", "g"],
        ]:
            with self.subTest(args=args):
                result = agent.run("endpoint", *args)
                self.assertEqual(1, result.code, result.stdout)
                self.assertFalse(agent.path("endpoint.json").exists())

        result = agent.run("endpoint", "--direct")  # nothing to remove: fine
        self.assertEqual(0, result.code, result.stderr)


class SystemTrustTest(CommandsBase):
    """A CA file in use (root.pem through a relay, ca_file directly) is the only trust: an HTTPS
    certificate of an authority the system trusts (a public CA) is refused."""

    def public_certificate(self):
        """A certificate for localhost from a CA put into the system's CA directory; checked to
        be trusted by the system's default verification, so that a refusal means something."""
        public = Pki(self.tmp / "public-ca", name="Public Test")  # a subject of its own
        trust_system_wide(self, public.root_path)
        return public.server_certificate("public-https")

    def assert_system_trusts(self, port):
        context = ssl.create_default_context()  # the system's authorities only
        with socket.create_connection(("localhost", port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname="localhost"):
                pass

    def test_relay_with_certificate_of_a_system_authority_is_refused(self):
        relay = self.platform.relay(self.public_certificate()).start()
        self.addCleanup(relay.stop)
        self.assert_system_trusts(relay.port)
        agent = self.make_agent(broker=self.broker)
        self.platform.certificates(datetime.timedelta(days=59))
        self.register(agent)
        self.platform.default_certificates()
        args = ["--relay", "localhost", "--https-port", relay.port]
        self.assertEqual(0, agent.run("endpoint", *args, "--broker-port", self.broker.port).code)

        agent.start("run")
        agent.wait_for_log("certificate renewal: no answer")

        self.assertEqual([], relay.requests_to(FakePlatform.RENEWAL), "no request reached it")
        self.assertTrue(agent.path("renewal-request.json").exists(), "kept for a later check")
        self.assertNotIn("device certificate renewed", agent.running_log)
        self.assertEqual(0, agent.stop())
        assert_no_secrets(agent.log, [agent.read_text("device.key")])

    def test_ca_file_excludes_the_system_authorities(self):
        platform = FakePlatform(self.pki, server_cert=self.public_certificate()).start()
        self.addCleanup(platform.stop)
        self.assert_system_trusts(platform.port)
        agent = self.make_agent(platform=platform)  # ca_file = the test root

        token = platform.new_token()
        result = agent.run("register", "--token", token, "--serial", "SN-public")

        self.assertEqual((3, "network_error"), (result.code, result.stdout.strip()))
        self.assertEqual([], platform.requests_to(FakePlatform.PROVISIONING))
        assert_no_secrets(agent.log, [token])


if __name__ == "__main__":
    unittest.main()
