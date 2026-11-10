# SPDX-License-Identifier: Apache-2.0
"""firmline-agent register: the identity saved after a 200, the platform's code on a refusal,
network errors, the serial number sources and the token file."""

import stat
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from harness import FakePlatform, IntegrationTest, Pki, Reply, assert_no_secrets, public_key_der

IDENTITY_FILES = ["chain.pem", "device.json", "device.key", "device.pem", "root.pem"]


class RegisterTest(IntegrationTest):
    def write_token_file(self, token: str):
        path = self.tmp / "token"
        path.write_text(token + "\n")
        return path

    def secrets_of(self, agent, token):
        return [token, agent.read_text("device.key"), agent.read_text("device.pem")]

    def assert_not_registered(self, agent):
        self.assertEqual([], agent.data_files(), "no key, certificate or temp file is left")

    def test_register_saves_identity_and_deletes_token_file(self):
        agent = self.make_agent()
        token = self.platform.new_token()
        token_file = self.write_token_file(token)

        result = agent.run("register", "--token-file", token_file, "--serial", "SN-0001")

        self.assertEqual(0, result.code)
        (device,) = self.platform.devices.values()
        self.assertEqual(device.device_id + "\n", result.stdout)
        self.assertFalse(token_file.exists(), "the token file is deleted after a 200")
        self.assertEqual(IDENTITY_FILES, agent.data_files())

        key_path = agent.path("device.key")
        self.assertEqual(0o600, stat.S_IMODE(key_path.stat().st_mode))
        key = serialization.load_pem_private_key(key_path.read_bytes(), None)
        self.assertIn("BEGIN PRIVATE KEY", key_path.read_text())  # PKCS#8, not encrypted
        self.assertEqual(device.certificates[-1], agent.read_text("device.pem"))
        self.assertEqual(self.pki.chain_pem, agent.read_text("chain.pem"))
        self.assertEqual(self.pki.root_path.read_text(), agent.read_text("root.pem"))
        tenant = self.pki.tenant_id
        self.assertEqual(
            {
                "deviceId": device.device_id,
                "familyId": self.platform.family_id,
                "clientId": f"{tenant}.{device.device_id}",
                "topicRoot": f"t/{tenant}/d/{device.device_id}",
                "otaOfferTopic": f"t/{tenant}/d/{device.device_id}/ota/offer",
            },
            agent.read_json("device.json"),
        )

        (request,) = self.platform.requests_to(FakePlatform.PROVISIONING)
        self.assertEqual("POST", request.method)
        self.assertTrue(request.headers["content-type"].startswith("application/json"))
        body = request.json()
        self.assertEqual({"token", "serialNumber", "csr"}, set(body))
        self.assertEqual(token, body["token"])
        self.assertEqual("SN-0001", body["serialNumber"])
        csr = x509.load_pem_x509_csr(body["csr"].encode())
        self.assertTrue(csr.is_signature_valid)
        self.assertEqual("device", csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
        self.assertEqual(public_key_der(key.public_key()), public_key_der(csr.public_key()))
        cert = x509.load_pem_x509_certificate(agent.path("device.pem").read_bytes())
        self.assertEqual(public_key_der(key.public_key()), public_key_der(cert.public_key()))

        assert_no_secrets(agent.log, self.secrets_of(agent, token) + [body["csr"]])

    def test_register_reports_platform_code(self):
        agent = self.make_agent()
        token = self.platform.new_token()
        token_file = self.write_token_file(token)
        self.platform.refuse(FakePlatform.PROVISIONING, 409, "serial_number_taken")

        result = agent.run("register", "--token-file", token_file, "--serial", "SN-0001")

        self.assertEqual(2, result.code)
        self.assertEqual("serial_number_taken\n", result.stdout)
        self.assertFalse(token_file.exists(), "the token file is deleted after a refusal")
        self.assert_not_registered(agent)
        assert_no_secrets(agent.log, self.secrets_of(agent, token))

    def test_register_reports_each_platform_code(self):
        for status, code in [
            (400, "provisioning_token_invalid"),
            (400, "serial_number_invalid"),
            (400, "csr_invalid"),
            (409, "plan_limit_devices"),
        ]:
            with self.subTest(code=code):
                agent = self.make_agent(f"agent-{code}")
                token = self.platform.new_token()
                self.platform.refuse(FakePlatform.PROVISIONING, status, code)
                result = agent.run("register", "--token", token, "--serial", "SN-0001")
                self.assertEqual((2, code + "\n"), (result.code, result.stdout))
                self.assert_not_registered(agent)
                assert_no_secrets(agent.log, self.secrets_of(agent, token))

    def test_register_real_refusals_of_the_fake(self):
        # Not scripted: the fake's own checks (unknown token, serial number already taken).
        agent = self.make_agent("first")
        token = self.platform.new_token()
        self.assertEqual(0, agent.run("register", "--token", token, "--serial", "SN-1").code)
        again = self.make_agent("again")
        result = again.run("register", "--token", token, "--serial", "SN-2")
        self.assertEqual((2, "provisioning_token_invalid\n"), (result.code, result.stdout))
        taken = self.make_agent("taken")
        token2 = self.platform.new_token()
        result = taken.run("register", "--token", token2, "--serial", "SN-1")
        self.assertEqual((2, "serial_number_taken\n"), (result.code, result.stdout))
        self.assert_not_registered(taken)
        for a in (agent, again, taken):
            assert_no_secrets(a.log, self.secrets_of(a, token) + [token2])

    def test_register_error_without_code_reports_http_status(self):
        agent = self.make_agent()
        token = self.platform.new_token()
        html = Reply(400, b"<html>Bad Request</html>", {"Content-Type": "text/html"})
        self.platform.script(FakePlatform.PROVISIONING, html)
        result = agent.run("register", "--token", token, "--serial", "SN-0001")
        self.assertEqual((2, "http_400\n"), (result.code, result.stdout))
        self.assert_not_registered(agent)
        assert_no_secrets(agent.log, self.secrets_of(agent, token))

    def test_register_does_not_follow_redirects(self):
        agent = self.make_agent()
        token = self.platform.new_token()
        self.platform.script(
            FakePlatform.PROVISIONING,
            Reply(307, b"", {"Location": self.platform.url + "/elsewhere"}),
        )
        result = agent.run("register", "--token", token, "--serial", "SN-0001")
        self.assertEqual((2, "http_307\n"), (result.code, result.stdout))
        self.assertEqual(1, len(self.platform.requests), "the token is sent once, to the platform")
        self.assert_not_registered(agent)
        assert_no_secrets(agent.log, self.secrets_of(agent, token))

    def test_register_network_error_keeps_token_file(self):
        agent = self.make_agent()
        token = self.platform.new_token()
        token_file = self.write_token_file(token)
        self.platform.stop()

        result = agent.run("register", "--token-file", token_file, "--serial", "SN-0001")

        self.assertEqual((3, "network_error\n"), (result.code, result.stdout))
        self.assertTrue(token_file.exists(), "kept, so the station can try again")
        self.assertEqual(token + "\n", token_file.read_text())
        self.assert_not_registered(agent)
        assert_no_secrets(agent.log, self.secrets_of(agent, token))

    def test_register_untrusted_platform_certificate_is_network_error(self):
        other = Pki(self.tmp / "other-pki")
        agent = self.make_agent(ca_file=str(other.root_path))
        token = self.platform.new_token()
        token_file = self.write_token_file(token)

        result = agent.run("register", "--token-file", token_file, "--serial", "SN-0001")

        self.assertEqual((3, "network_error\n"), (result.code, result.stdout))
        self.assertEqual([], self.platform.requests, "the token never leaves on a TLS failure")
        self.assertTrue(token_file.exists())
        self.assert_not_registered(agent)
        assert_no_secrets(agent.log, self.secrets_of(agent, token))

    def test_register_temporary_failures_keep_token_file(self):
        # 429 and 5xx do not use up the token: the station tries again later with the same file.
        cases = [
            (FakePlatform.PROVISIONING, 429, "too_many_requests", 2, "too_many_requests\n"),
            (FakePlatform.PROVISIONING, 503, "unavailable", 3, "network_error\n"),
        ]
        for route, status, code, exit_code, stdout in cases:
            with self.subTest(status=status):
                agent = self.make_agent(f"agent-{status}")
                token = self.platform.new_token()
                token_file = self.write_token_file(token)
                self.platform.refuse(route, status, code)
                result = agent.run("register", "--token-file", token_file, "--serial", "SN-0001")
                self.assertEqual((exit_code, stdout), (result.code, result.stdout))
                self.assertTrue(token_file.exists())
                self.assert_not_registered(agent)
                assert_no_secrets(agent.log, self.secrets_of(agent, token))

    def test_register_unreadable_answer_is_network_error(self):
        json_type = {"Content-Type": "application/json"}
        for name, reply in [
            ("garbage", Reply(200, b"{not json", json_type)),
            ("missing-fields", Reply(200, b'{"deviceId":"x"}', json_type)),
            ("too-big", Reply(200, b"x" * (70 * 1024), json_type)),
        ]:
            with self.subTest(name=name):
                agent = self.make_agent(f"agent-{name}")
                token = self.platform.new_token()
                self.platform.script(FakePlatform.PROVISIONING, reply)
                result = agent.run("register", "--token", token, "--serial", "SN-0001")
                self.assertEqual((3, "network_error\n"), (result.code, result.stdout))
                self.assert_not_registered(agent)
                assert_no_secrets(agent.log, self.secrets_of(agent, token))

    def test_register_without_family_id_in_response(self):
        self.platform.send_family_id = False  # the platform before T178
        agent = self.make_agent()
        token = self.platform.new_token()

        result = agent.run("register", "--token", token, "--serial", "SN-0001")

        self.assertEqual(0, result.code)
        (device,) = self.platform.devices.values()
        self.assertNotIn("familyId", device.response)
        self.assertEqual(device.device_id + "\n", result.stdout)
        identity = agent.read_json("device.json")
        self.assertEqual("", identity["familyId"])
        self.assertEqual(device.device_id, identity["deviceId"])
        assert_no_secrets(agent.log, self.secrets_of(agent, token))

    def test_register_serial_from_devicetree_file(self):
        # /proc/device-tree/serial-number on Toradex: the value and a trailing NUL.
        serial_file = self.tmp / "serial-number"
        serial_file.write_bytes(b"06849412\x00")
        agent = self.make_agent(serial=f"file:{serial_file}")
        token = self.platform.new_token()

        result = agent.run("register", "--token", token)

        self.assertEqual(0, result.code)
        (request,) = self.platform.requests_to(FakePlatform.PROVISIONING)
        self.assertEqual("06849412", request.json()["serialNumber"])
        assert_no_secrets(agent.log, self.secrets_of(agent, token))

    def test_register_serial_from_command(self):
        script = self.tmp / "serial.sh"
        script.write_text("#!/bin/sh\necho '  SN-CMD-7  '\n")
        script.chmod(0o755)
        agent = self.make_agent(serial=f"command:{script}")
        token = self.platform.new_token()

        result = agent.run("register", "--token", token)

        self.assertEqual(0, result.code)
        (request,) = self.platform.requests_to(FakePlatform.PROVISIONING)
        self.assertEqual("SN-CMD-7", request.json()["serialNumber"])
        assert_no_secrets(agent.log, self.secrets_of(agent, token))

    def test_register_refuses_when_already_registered(self):
        agent = self.make_agent()
        token = self.platform.new_token()
        self.assertEqual(0, agent.run("register", "--token", token, "--serial", "SN-0001").code)
        identity = agent.read_text("device.json")
        token2 = self.platform.new_token()
        token_file = self.write_token_file(token2)

        result = agent.run("register", "--token-file", token_file, "--serial", "SN-0002")

        self.assertEqual((1, "already_registered\n"), (result.code, result.stdout))
        self.assertEqual(1, len(self.platform.requests))
        self.assertEqual(identity, agent.read_text("device.json"))
        self.assertTrue(token_file.exists())
        assert_no_secrets(agent.log, self.secrets_of(agent, token) + [token2])

    def test_register_usage_and_configuration_errors(self):
        serial_file = self.tmp / "serial-number"
        serial_file.write_text("SN-FILE\n")
        token = self.platform.new_token()
        from_file = {"serial": f"file:{serial_file}"}
        http_url = {"url": "http://localhost:1"}
        cases = [
            ("no token", {}, ["--serial", "SN-1"]),
            ("token twice", {}, ["--token", token, "--token-file", "/none", "--serial", "S"]),
            ("no serial", {}, ["--token", token]),
            ("serial twice", from_file, ["--token", token, "--serial", "S"]),
            ("unknown option", {}, ["--token", token, "--serial", "S", "--force"]),
            ("missing value", {}, ["--serial", "S", "--token"]),
            ("missing token file", {}, ["--token-file", str(self.tmp / "none"), "--serial", "S"]),
            ("missing serial file", {"serial": f"file:{self.tmp / 'none'}"}, ["--token", token]),
            ("bad configuration", http_url, ["--token", token, "--serial", "S"]),
        ]
        for name, settings, args in cases:
            with self.subTest(name=name):
                agent = self.make_agent("agent-" + name.replace(" ", "-"), **settings)
                result = agent.run("register", *args)
                self.assertEqual(1, result.code)
                self.assertEqual("", result.stdout)
                self.assert_not_registered(agent)
                assert_no_secrets(agent.log, [token])
        self.assertEqual([], self.platform.requests)


if __name__ == "__main__":
    unittest.main()
