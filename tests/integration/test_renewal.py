# SPDX-License-Identifier: Apache-2.0
"""firmline-agent run, certificate renewal: from 60 days before the expiry, at most once a day;
the new key and the exact request saved before it is sent, and the same request sent again when
the answer is lost; key, certificate, chain, root and device.json replaced so that a crash at any
step leaves a device that connects; then the broker connection again, with the new certificate."""

import datetime
import json
import os
import stat
import unittest
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from harness import (
    FakePlatform,
    Pki,
    assert_no_secrets,
    build_clock_shim,
    cert_pem,
    clock_env,
    key_pem,
    utc_now,
    wait_until,
    write_private,
)
from test_ota import OtaBase, payload

DAY = datetime.timedelta(days=1)
RENEWAL_FILES = (
    "renewal-new.key",
    "renewal-request.json",
    "renewal-device.pem",
    "renewal-chain.pem",
    "renewal-root.pem",
    "renewal-device.json",
    "renewal-commit",
)


def not_after(pem: str) -> datetime.datetime:
    return x509.load_pem_x509_certificate(pem.encode()).not_valid_after_utc


def parse_utc(text: str) -> datetime.datetime:
    return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc
    )


class RenewalBase(OtaBase):
    """A broker, the platform connected to it (OtaBase), and registered agents whose certificate
    has the validity a test chooses."""

    def registered(self, name="agent", days_left=59, age=2 * DAY, **kwargs):
        """A registered agent (not running) whose certificate expires in `days_left` days and was
        issued `age` ago; the platform issues normal certificates again afterwards."""
        self.platform.certificates(datetime.timedelta(days=days_left), age)
        agent = self.make_agent(name, broker=self.broker, **kwargs)
        token = self.platform.new_token()
        result = agent.run("register", "--token", token, "--serial", f"SN-{uuid.uuid4().hex[:8]}")
        self.assertEqual(0, result.code, result.stderr)
        self.platform.default_certificates()
        return agent, agent.read_json("device.json")

    def renewal_requests(self, certificate=None):
        """The renewal requests that reached the platform (of one certificate, when given)."""
        requests = self.platform.requests_to(FakePlatform.RENEWAL)
        if certificate is not None:
            requests = [r for r in requests if r.json()["certificate"] == certificate]
        return requests

    def statuses(self, identity, mqtt=None):
        return (mqtt or self.mqtt).received(identity["topicRoot"] + "/status")

    @staticmethod
    def wait_connected_after_renewal(agent, timeout=30):
        """Waits until the agent has subscribed again after "device certificate renewed" (the
        connection that was up, or still being made, when the answer came is closed)."""
        mark = "device certificate renewed"
        return wait_until(
            lambda: "subscribed to" in agent.running_log.partition(mark)[2],
            timeout,
            "a subscription after the renewal",
        )

    @staticmethod
    def identity_files(agent):
        return agent.read_text("device.pem"), agent.read_text("device.key")

    def assert_no_pending(self, agent):
        self.assertEqual([], [n for n in agent.data_files() if n in RENEWAL_FILES])

    def assert_key_matches_certificate(self, agent):
        key = serialization.load_pem_private_key(agent.path("device.key").read_bytes(), None)
        cert = x509.load_pem_x509_certificate(agent.path("device.pem").read_bytes())
        public = serialization.PublicFormat.SubjectPublicKeyInfo
        self.assertEqual(
            key.public_key().public_bytes(serialization.Encoding.DER, public),
            cert.public_key().public_bytes(serialization.Encoding.DER, public),
        )
        self.assertEqual(0o600, stat.S_IMODE(os.stat(agent.path("device.key")).st_mode))

    def last_attempt(self, agent) -> datetime.datetime:
        return parse_utc(agent.read_json("renewal.json")["lastAttempt"])

    def stop_and_check(self, agent, *secrets):
        """Stops the agent (exit 0) and checks its log: no key, certificate or request."""
        self.assertEqual(0, agent.stop())
        values = [agent.read_text("device.key"), agent.read_text("device.pem"), *secrets]
        for request in self.renewal_requests():
            values += [request.json()["proof"], request.json()["csr"]]
        assert_no_secrets(agent.log, values)


class RenewalTest(RenewalBase):
    def test_renews_within_60_days_and_reconnects(self):
        agent, identity = self.registered(status_interval=2)
        old_cert, old_key = agent.read_text("device.pem"), agent.read_text("device.key")
        old_root = agent.path("root.pem").read_bytes()
        device = self.platform.devices[identity["deviceId"]]

        agent.start("run")
        agent.wait_for_log("device certificate renewed")
        started = utc_now()
        self.assertEqual(old_root, agent.path("root.pem").read_bytes(), "the root never changes")

        requests = self.renewal_requests()
        self.assertEqual(1, len(requests))
        body = requests[0].json()
        self.assertEqual({"certificate", "csr", "proof"}, set(body))
        self.assertEqual(old_cert, body["certificate"])
        new_cert = agent.read_text("device.pem")
        self.assertEqual(device.certificates[-1], new_cert)
        self.assertNotEqual(old_cert, new_cert)
        self.assertNotEqual(old_key, agent.read_text("device.key"))
        self.assert_key_matches_certificate(agent)
        self.assertLess(
            abs(not_after(new_cert) - (started + 730 * DAY)), datetime.timedelta(minutes=10)
        )
        self.assertEqual(self.pki.chain_pem, agent.read_text("chain.pem"))
        self.assertEqual(cert_pem(self.pki.root), agent.read_text("root.pem"))
        expected = {k: device.response[k] for k in identity}
        self.assertEqual(expected, agent.read_json("device.json"))
        self.assertEqual(self.platform.family_id, agent.read_json("device.json")["familyId"])
        self.assertLess(abs(self.last_attempt(agent) - started), datetime.timedelta(minutes=1))
        self.assert_no_pending(agent)

        # Connected again, presenting the new certificate (rebuilt before the connection).
        self.wait_connected_after_renewal(agent)
        self.assertTrue(agent.read_text("device-chain.pem").startswith(new_cert))

        # The proof: with the old certificate revoked, the device still connects and publishes.
        self.broker.revoke(old_cert)
        self.broker.restart()
        self.mqtt.close()  # a new platform client: its subscription ended with the broker
        self.mqtt = self.platform.connect(self.broker)
        self.addCleanup(self.mqtt.close)
        self.mqtt.wait_for(identity["topicRoot"] + "/status", timeout=45)
        self.assertEqual(1, len(self.renewal_requests()), "renewed once")
        self.stop_and_check(agent, old_key, old_cert, new_cert)

    def test_lost_renewal_response_sends_same_request_again(self):
        agent, identity = self.registered(status_interval=2)
        self.platform.drop_next_renewal_response()

        agent.start("run")
        agent.wait_for_log("device certificate renewed", timeout=60)

        first, second = self.renewal_requests()
        self.assertEqual(first.body, second.body, "byte for byte the same request")
        device = self.platform.devices[identity["deviceId"]]
        self.assertEqual(2, len(device.certificates), "one certificate issued by the renewal")
        self.assertEqual(device.certificates[-1], agent.read_text("device.pem"))
        self.assert_key_matches_certificate(agent)
        self.assertIn("the same request goes again", agent.running_log)
        self.assert_no_pending(agent)
        self.stop_and_check(agent)

    def test_restart_with_pending_request_sends_it_again(self):
        agent, identity = self.registered()
        # 503 until the restart: the first run may send the saved request again after its first
        # status, and must get 503 again.
        back_up = self.platform.renewals_unavailable()

        agent.start("run")
        agent.wait_for_log("HTTP 503")
        self.assertEqual(0, agent.stop())
        self.assertEqual(0o600, stat.S_IMODE(os.stat(agent.path("renewal-new.key")).st_mode))
        saved = agent.path("renewal-request.json").read_bytes()
        self.assertEqual(self.renewal_requests()[0].body, saved)
        old_key = agent.read_text("device.key")
        before = len(self.renewal_requests())

        back_up()
        agent.start("run")
        agent.wait_for_log("device certificate renewed")

        requests = self.renewal_requests()
        self.assertGreater(len(requests), before, "sent again after the restart")
        self.assertEqual({saved}, {r.body for r in requests}, "always the same bytes")
        self.assertNotEqual(old_key, agent.read_text("device.key"))
        self.assert_key_matches_certificate(agent)
        self.assert_no_pending(agent)
        self.stop_and_check(agent, old_key)

    def test_renewal_refused_keeps_current_certificate(self):
        cases = [
            ("certificate_renewal_refused", 400, 2 * DAY),
            ("csr_invalid", 400, 2 * DAY),
            ("certificate_renewed_recently", 409, datetime.timedelta(minutes=5)),  # the fake's own
        ]
        for code, status, age in cases:
            with self.subTest(code=code):
                agent, identity = self.registered(code, age=age, status_interval=1)
                cert, key = agent.read_text("device.pem"), agent.read_text("device.key")
                if age > DAY:
                    self.platform.refuse(FakePlatform.RENEWAL, status, code)

                agent.start("run")
                agent.wait_for_log(f"certificate renewal refused: {code} (HTTP {status})")
                started = utc_now()
                before = len(self.statuses(identity))
                wait_until(lambda: len(self.statuses(identity)) >= before + 3, 30, "3 statuses")

                self.assertEqual(1, len(self.renewal_requests(cert)), "next try in a day")
                self.assertEqual((cert, key), self.identity_files(agent))
                self.assert_no_pending(agent)
                late = abs(self.last_attempt(agent) - started)
                self.assertLess(late, datetime.timedelta(minutes=1))
                self.stop_and_check(agent)

    def test_expired_certificate_is_not_renewed(self):
        agent, identity = self.registered(days_left=-1, age=3 * DAY)

        agent.start("run")
        agent.wait_for_log("register the device again with a new token")
        failed = "cannot connect to the broker"
        wait_until(lambda: agent.running_log.count(failed) >= 2, 30, "two connection attempts")

        self.assertEqual(1, agent.running_log.count("register the device again with a new token"))
        self.assertEqual([], self.renewal_requests())
        self.assert_no_pending(agent)
        self.stop_and_check(agent)


class PendingRequestTest(RenewalBase):
    """Once a request may have been answered, its key and bytes are the only way to the
    certificate the platform issued: they are dropped only on a final refusal or after the swap."""

    def assert_renewed_with_first_answer(self, agent, identity, saved=None):
        device = self.platform.devices[identity["deviceId"]]
        requests = self.renewal_requests()
        self.assertEqual({saved or requests[0].body}, {r.body for r in requests})
        self.assertEqual(2, len(device.certificates), "only the first request issued one")
        self.assertEqual(device.certificates[1], agent.read_text("device.pem"))
        self.assert_key_matches_certificate(agent)
        self.assert_no_pending(agent)

    def test_lost_answer_then_404_then_answer_installs_first_certificate(self):
        agent, identity = self.registered(status_interval=1)
        self.platform.drop_next_renewal_response()
        self.platform.refuse(FakePlatform.RENEWAL, 404, "not_found")  # a relay or a proxy

        agent.start("run")
        agent.wait_for_log("device certificate renewed", timeout=60)

        self.assertIn("HTTP 404", agent.running_log)
        self.assertGreaterEqual(len(self.renewal_requests()), 3)
        self.assert_renewed_with_first_answer(agent, identity)
        self.stop_and_check(agent)

    def test_pending_request_survives_clock_past_expiry_and_back(self):
        agent, identity = self.registered(status_interval=2)
        self.platform.drop_next_renewal_response()  # issued, the answer lost
        back_up = self.platform.renewals_unavailable()
        agent.start("run")
        agent.wait_for_log("the same request goes again")
        self.assertEqual(0, agent.stop())
        saved = agent.path("renewal-request.json").read_bytes()
        sent = len(self.renewal_requests())

        # The clock jumps past notAfter (59 days left): nothing is sent, nothing is lost.
        shim = build_clock_shim(self.tmp)
        agent.env.update(clock_env(shim, 60 * DAY))
        agent.start("run")
        agent.wait_for_log("expired on")
        agent.wait_for_log("status sent", count=2)  # checked again after each (the broker's
        self.assertEqual(0, agent.stop())  # clock is right: it still accepts the certificate)
        self.assertEqual(1, agent.log.count("expired on"), "said once")
        self.assertEqual(sent, len(self.renewal_requests()), "nothing sent while expired")
        self.assertEqual(saved, agent.path("renewal-request.json").read_bytes())
        self.assertTrue(agent.path("renewal-new.key").exists())

        # The clock is right again: the same request, the certificate issued the first time.
        for name in clock_env(shim, DAY):
            agent.env.pop(name, None)
        back_up()
        agent.start("run")
        agent.wait_for_log("device certificate renewed")
        self.assert_renewed_with_first_answer(agent, identity, saved)
        self.stop_and_check(agent)


class AnswerTrustTest(RenewalBase):
    """The platform root and the company intermediate never change: an answer that does not
    chain to the root in use is not installed (and the request is kept)."""

    def assert_answers_refused(self, name, go_wrong):
        """A registered agent whose renewal answers go wrong once go_wrong() was called (after the
        registration; it returns the function that puts the platform right): each answer is
        refused at each check, the request is kept, nothing of the identity changes (root.pem
        byte for byte) and the device stays connected with its old pair."""
        agent, identity = self.registered(name, status_interval=1)
        old = self.identity_files(agent)
        old_root, old_chain = agent.path("root.pem").read_bytes(), agent.read_text("chain.pem")
        put_right = go_wrong()
        try:
            agent.start("run")
            mark = "does not chain to the platform root"
            wait_until(lambda: agent.running_log.count(mark) >= 2, 30, "two answers refused")
            before = len(self.statuses(identity))
            wait_until(lambda: len(self.statuses(identity)) > before, 30, "still connected")
        finally:
            put_right()

        self.assertEqual(old, self.identity_files(agent))
        self.assertEqual(old_root, agent.path("root.pem").read_bytes(), "the root never changes")
        self.assertEqual(old_chain, agent.read_text("chain.pem"))
        self.assertTrue(agent.path("renewal-new.key").exists(), "request kept")
        self.assertTrue(agent.path("renewal-request.json").exists())
        self.assertNotIn("device certificate renewed", agent.running_log)
        self.stop_and_check(agent)

    def test_answer_not_chaining_to_current_root_is_not_installed(self):
        other = Pki(self.tmp / "other-pki", tenant_id=self.pki.tenant_id)
        cases = {
            "another root": (other, None),
            "our chain, another issuer": (other, self.pki.chain_pem),
        }
        platform = self.platform

        def wrong(issuer, chain):
            platform.issuer, platform.chain_override = issuer, chain

            def put_right():
                platform.issuer, platform.chain_override = None, None

            return put_right

        for case, (issuer, chain) in cases.items():
            with self.subTest(case=case):
                self.assert_answers_refused(case.replace(" ", "-"), lambda: wrong(issuer, chain))

    def test_chain_with_anything_but_certificate_blocks_is_not_installed(self):
        evil = cert_pem(Pki(self.tmp / "evil-pki").root)
        cases = {
            # OpenSSL's PEM reader skips a BEGIN line that does not start a line: a text search
            # for the last BEGIN would find this root.
            "a root hidden mid-line": lambda chain: chain + "x" + evil,
            "a last block that is not base64": lambda chain: (
                chain + "-----BEGIN CERTIFICATE-----\n!!!!not base64!!!!\n"
                "-----END CERTIFICATE-----\n"
            ),
        }
        for case, change in cases.items():
            with self.subTest(case=case):
                self.assert_answers_refused(
                    case.replace(" ", "-"),
                    lambda: self.platform.tamper_renewals(
                        lambda answer: answer.update(chain=change(answer["chain"]))
                    ),
                )


class RenewalCrashTest(RenewalBase):
    """A crash (power loss) during the swap: the state found at the next start."""

    SWAP = [
        ("renewal-device.pem", "device.pem"),
        ("renewal-chain.pem", "chain.pem"),
        ("renewal-new.key", "device.key"),
        ("renewal-device.json", "device.json"),
    ]

    def pending_identity(self, agent, identity):
        """The files of a renewal answered and written under their pending names, as the agent
        writes them before the commit marker: a new key and its certificate."""
        key = ec.generate_private_key(ec.SECP256R1())
        now = utc_now()
        cert = cert_pem(
            self.pki.issue_device(
                key.public_key(),
                identity["deviceId"],
                now - datetime.timedelta(minutes=5),
                now + 730 * DAY,
            )
        )
        write_private(agent.path("renewal-new.key"), key_pem(key))
        agent.path("renewal-request.json").write_text('{"certificate":"x","csr":"y","proof":"z"}')
        agent.path("renewal-device.pem").write_text(cert)
        agent.path("renewal-chain.pem").write_text(self.pki.chain_pem)
        agent.path("renewal-device.json").write_text(json.dumps(identity))
        return cert, key_pem(key)

    def test_crash_during_swap_is_finished_at_start(self):
        for done in [0, 1, 2, 3, 4]:  # renames done before the crash, the marker written
            with self.subTest(done=done):
                agent, identity = self.registered(f"agent-{done}", days_left=700)
                cert, key = self.pending_identity(agent, identity)
                agent.path("renewal-commit").write_text("")
                for pending, live in self.SWAP[:done]:
                    os.replace(agent.path(pending), agent.path(live))

                agent.start("run")
                agent.wait_for_log("subscribed to")

                self.assertIn("finished the certificate renewal", agent.running_log)
                self.assertEqual((cert, key), self.identity_files(agent))
                self.assert_key_matches_certificate(agent)
                self.assertTrue(agent.read_text("device-chain.pem").startswith(cert))
                self.assert_no_pending(agent)
                self.assertEqual([], self.renewal_requests())
                self.stop_and_check(agent, key, cert)

    def test_crash_before_commit_keeps_current_identity(self):
        agent, identity = self.registered(days_left=700)
        old = agent.read_text("device.pem"), agent.read_text("device.key")
        cert, key = self.pending_identity(agent, identity)
        agent.path("renewal-request.json").unlink()  # the key written, the request not yet

        agent.start("run")
        agent.wait_for_log("subscribed to")

        self.assertEqual(old, (agent.read_text("device.pem"), agent.read_text("device.key")))
        self.assert_no_pending(agent)
        self.assertEqual([], self.renewal_requests())
        self.stop_and_check(agent, key, cert)

    def test_key_not_matching_certificate_refuses_to_start(self):
        agent, identity = self.registered(days_left=700)
        other = ec.generate_private_key(ec.SECP256R1())
        write_private(agent.path("device.key"), key_pem(other))

        result = agent.run("run", timeout=30)

        self.assertEqual(1, result.code)
        self.assertIn("device.key does not match device.pem", result.stderr)
        self.assertNotIn("connecting to the broker", result.stderr)
        assert_no_secrets(agent.log, [key_pem(other), agent.read_text("device.pem")])


class RenewalFamilyTest(RenewalBase):
    def test_renewal_gives_family_to_device_registered_before_T178(self):
        app, folder = self.component("app")
        self.platform.send_family_id = False  # the platform before T178
        agent, identity = self.registered(components={"app": app})
        self.assertEqual("", identity["familyId"])
        self.platform.send_family_id = True  # the platform updated since

        agent.start("run")
        agent.wait_for_log("device certificate renewed")
        self.wait_connected_after_renewal(agent)

        self.assertEqual(self.platform.family_id, agent.read_json("device.json")["familyId"])
        offer = self.offer(identity["deviceId"], "app", "1.1.0", payload(100))
        result = self.platform.wait_results(identity["deviceId"])[0]
        self.assertEqual({"release": offer.release, "result": "installed", "fw": "1.1.0"}, result)
        self.stop_and_check(agent, offer.url, offer.url.rsplit("/", 1)[1])


if __name__ == "__main__":
    unittest.main()
