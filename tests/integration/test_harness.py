# SPDX-License-Identifier: Apache-2.0
"""The harness itself, where the agent does not use it yet: downloads with Range, renewal and the
broker. Later tasks build on these behaving as the platform does."""

import base64
import datetime
import json
import ssl
import time
import unittest
import urllib.error
import urllib.request

import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from harness import FakePlatform, IntegrationTest, cert_pem, key_pem, subject_value, write_private


def make_csr(key) -> str:
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device")]))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )


class HarnessTest(IntegrationTest):
    def call(self, method, path, body=None, headers=None):
        context = ssl.create_default_context(cafile=str(self.pki.root_path))
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            self.platform.url + path, data=data, method=method, headers=headers or {}
        )
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, context=context, timeout=10) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def register(self, key, serial="SN-1"):
        status, _, body = self.call(
            "POST",
            FakePlatform.PROVISIONING,
            {"token": self.platform.new_token(), "serialNumber": serial, "csr": make_csr(key)},
        )
        self.assertEqual(200, status)
        return json.loads(body)

    def test_download_serves_ranges(self):
        url = self.platform.add_download(b"0123456789")
        path = url[len(self.platform.url) :]
        self.assertEqual(200, self.call("GET", path)[0])
        status, headers, body = self.call("GET", path, headers={"Range": "bytes=4-"})
        self.assertEqual((206, b"456789", "bytes 4-9/10"), (status, body, headers["Content-Range"]))
        self.assertEqual(416, self.call("GET", path, headers={"Range": "bytes=10-"})[0])
        status, _, body = self.call("GET", FakePlatform.DOWNLOADS + "unknown")
        self.assertEqual((404, "ota_download_not_found"), (status, json.loads(body)["code"]))
        self.assertEqual("bytes=4-", self.platform.requests_to(path)[1].headers["range"])

    def test_provisioning_issues_certificate_for_csr_key(self):
        key = ec.generate_private_key(ec.SECP256R1())
        answer = self.register(key)
        cert = x509.load_pem_x509_certificate(answer["certificate"].encode())
        tenant, device = self.pki.tenant_id, answer["deviceId"]
        self.assertEqual(f"{tenant}.{device}", answer["clientId"])
        self.assertEqual(f"{tenant}.{device}", subject_value(cert, NameOID.COMMON_NAME))
        self.assertEqual(tenant, subject_value(cert, NameOID.ORGANIZATIONAL_UNIT_NAME))
        self.assertEqual(self.pki.intermediate.subject, cert.issuer)
        cert.verify_directly_issued_by(self.pki.intermediate)
        self.assertEqual(self.platform.family_id, answer["familyId"])
        validity = cert.not_valid_after_utc - cert.not_valid_before_utc
        self.assertEqual(datetime.timedelta(days=730), validity)

    def test_renewal_issues_new_certificate_and_repeats_lost_answer(self):
        self.platform.certificate_backdate = datetime.timedelta(days=2)
        old_key = ec.generate_private_key(ec.SECP256R1())
        first = self.register(old_key)
        new_key = ec.generate_private_key(ec.SECP256R1())
        csr = make_csr(new_key)
        r, s = decode_dss_signature(old_key.sign(csr.encode(), ec.ECDSA(hashes.SHA256())))
        proof = base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()
        body = {"certificate": first["certificate"], "csr": csr, "proof": proof}

        status, _, renewed = self.call("POST", FakePlatform.RENEWAL, body)
        self.assertEqual(200, status)
        renewed = json.loads(renewed)
        self.assertNotEqual(first["certificate"], renewed["certificate"])
        self.assertEqual(first["deviceId"], renewed["deviceId"])

        status, _, again = self.call("POST", FakePlatform.RENEWAL, body)  # the answer was lost
        self.assertEqual((200, renewed["certificate"]), (status, json.loads(again)["certificate"]))

        bad = dict(body, proof=base64.b64encode(bytes(64)).decode())
        status, _, refused = self.call("POST", FakePlatform.RENEWAL, bad)
        refused = json.loads(refused)["code"]
        self.assertEqual((400, "certificate_renewal_refused"), (status, refused))

    def test_renewal_of_a_new_certificate_is_too_early(self):
        old_key = ec.generate_private_key(ec.SECP256R1())
        first = self.register(old_key)
        csr = make_csr(ec.generate_private_key(ec.SECP256R1()))
        proof = base64.b64encode(old_key.sign(csr.encode(), ec.ECDSA(hashes.SHA256()))).decode()
        body = {"certificate": first["certificate"], "csr": csr, "proof": proof}
        status, _, body = self.call("POST", FakePlatform.RENEWAL, body)
        self.assertEqual((409, "certificate_renewed_recently"), (status, json.loads(body)["code"]))

    def test_sanitizer_report_in_agent_stderr_fails(self):
        agent = self.make_agent()
        for report in [
            "==7==ERROR: AddressSanitizer: heap-use-after-free on address 0x6020",
            "==7==ERROR: LeakSanitizer: detected memory leaks",
            "cmd_register.c:10:5: runtime error: signed integer overflow",
        ]:
            with self.subTest(report=report), self.assertRaises(AssertionError):
                agent._take_log("info starting\n" + report + "\n")
        agent._take_log("info nothing wrong\n")  # no report: no failure

    def test_broker_accepts_device_chain_and_refuses_no_certificate(self):
        broker = self.make_broker()
        key = ec.generate_private_key(ec.SECP256R1())
        answer = self.register(key)
        key_path = write_private(self.tmp / "device.key", key_pem(key))
        chain_path = self.tmp / "device-chain.pem"
        chain_path.write_text(answer["certificate"] + cert_pem(self.pki.intermediate))

        def connect(certfile, keyfile):
            result = []
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=answer["clientId"])
            client.tls_set(ca_certs=str(self.pki.root_path), certfile=certfile, keyfile=keyfile)
            client.on_connect = lambda c, u, f, reason, p: result.append(reason.value)
            try:
                client.connect("localhost", broker.port)
            except (ssl.SSLError, OSError):
                return None
            client.loop_start()
            deadline = time.monotonic() + 5
            while not result and time.monotonic() < deadline:
                time.sleep(0.05)
            client.disconnect()
            client.loop_stop()
            return result[0] if result else None

        self.assertEqual(0, connect(str(chain_path), str(key_path)))
        self.assertIsNone(connect(None, None))
        self.assertIn(f"u'{answer['clientId']}'", broker.log)

    def test_broker_acl_limits_device_to_its_topics(self):
        broker = self.make_broker()  # before the registration: the ACL is reloaded by it
        key = ec.generate_private_key(ec.SECP256R1())
        answer = self.register(key)
        other = self.register(ec.generate_private_key(ec.SECP256R1()), serial="SN-2")
        key_path = write_private(self.tmp / "device.key", key_pem(key))
        chain_path = self.tmp / "device-chain.pem"
        chain_path.write_text(answer["certificate"] + cert_pem(self.pki.intermediate))
        device = broker.client(
            name="device", common_name=answer["clientId"], certfile=chain_path, keyfile=key_path
        )
        self.addCleanup(device.close)
        root, not_authorized = answer["topicRoot"], 0x87

        # mosquitto 2.0 grants every SUBSCRIBE and applies the ACL to what it delivers (the
        # platform refuses the subscription itself): only its own offers reach the device.
        offer_of_other = other["topicRoot"] + "/ota/offer"
        for topic in [root + "/ota/offer", root + "/status", offer_of_other]:
            self.assertEqual(1, device.subscribe(topic)[0].value)
        platform = broker.client()
        self.addCleanup(platform.close)
        self.assertEqual(1, platform.subscribe("t/#")[0].value)

        self.assertEqual(0, device.publish(root + "/status", b"{}").value)
        self.assertEqual(0, device.publish(root + "/ota/result", b"{}").value)
        for topic in [root + "/ota/offer", root + "/other", other["topicRoot"] + "/status"]:
            with self.subTest(topic=topic):
                self.assertEqual(not_authorized, device.publish(topic, b"{}").value)
        platform.wait_for(root + "/ota/result")
        self.assertEqual(
            [root + "/status", root + "/ota/result"], [m.topic for m in platform.received()]
        )

        for topic in [offer_of_other, root + "/status", root + "/ota/offer"]:
            self.assertEqual(0, platform.publish(topic, topic.encode()).value)
        device.wait_for(root + "/ota/offer")
        time.sleep(0.5)  # anything else would have arrived by now
        self.assertEqual([root + "/ota/offer"], [m.topic for m in device.received()])


if __name__ == "__main__":
    unittest.main()
