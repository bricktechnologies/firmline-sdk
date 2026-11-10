# SPDX-License-Identifier: Apache-2.0
"""Harness of the integration tests: a fake Firmline platform, a test broker and the agent.

Everything secret (keys, certificates, tokens) is generated when the tests run, in a temporary
folder per test; nothing is committed.

- Pki: root CA, company intermediate (path length 0), server certificates for `localhost`, client
  certificates, device certificates issued for a CSR's key, and the update verification key.
- FakePlatform: HTTPS server on a free port with the device endpoints of the real platform
  (POST /api/v1/provisioning, POST /api/v1/provisioning/renewal, GET /api/v1/ota/downloads/<token>
  with Range). Every request is recorded; faults are scripted per route with `script`/`refuse`.
- Broker: mosquitto with client certificates required, the certificate CN as the user name.
- Agent: writes the configuration, runs `firmline-agent`, keeps its stderr as `log`; a sanitizer
  report in that stderr fails the test.
- assert_no_secrets(log, secrets): none of the secrets, and no PEM block at all, is in the log.
- IntegrationTest: unittest base class with a temporary folder, a Pki and a started FakePlatform.
"""

import base64
import collections
import dataclasses
import datetime
import hashlib
import http.server
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import traceback
import unittest
import uuid
import warnings
from pathlib import Path
from typing import Callable, Optional, Union

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REPO = Path(__file__).resolve().parents[2]

# The agent under test: the sanitizer build of scripts/check.sh, unless FIRMLINE_AGENT names one.
AGENT_BINARY = os.environ.get("FIRMLINE_AGENT", str(REPO / "build" / "linux" / "firmline-agent"))

# Lines that AddressSanitizer, LeakSanitizer and UndefinedBehaviorSanitizer write on a finding.
SANITIZER_MARKERS = (
    "ERROR: AddressSanitizer",
    "ERROR: LeakSanitizer",
    "runtime error:",
    "SUMMARY: UndefinedBehaviorSanitizer",
)


def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"nothing listens on port {port} after {timeout} s")


def cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def key_pem(key: ec.EllipticCurvePrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def public_key_der(key) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def subject_value(cert: x509.Certificate, oid) -> str:
    """One attribute of the subject (a device CN is longer than X.520 allows: no warning)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        return cert.subject.get_attributes_for_oid(oid)[0].value


def write_private(path: Path, text: str) -> Path:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    return path


def assert_no_secrets(log: str, secret_values) -> None:
    """Fails when the log contains any of the secrets (each line of a PEM body counts on its own)
    or any PEM block: the agent never logs tokens, download links, keys or certificates."""
    if "-----BEGIN" in log:
        raise AssertionError("the log contains a PEM block:\n" + log)
    for value in secret_values:
        if not value:
            continue
        pieces = [value]
        if "-----BEGIN" in value:
            pieces = [
                line.strip()
                for line in value.splitlines()
                if len(line.strip()) >= 16 and not line.startswith("-----")
            ]
        for piece in pieces:
            if piece in log:
                raise AssertionError(f"the log contains a secret ({piece[:12]}...):\n{log}")


# --------------------------------------------------------------------------------------------
# PKI


class Pki:
    """The certificate authorities and keys of one test run, written into `directory`.

    root: the platform root (path length 1); intermediate: the company intermediate (path length
    0, OU = tenant), which signs the device certificates. The HTTPS and broker certificates are
    signed by the root, as on the platform, for `localhost` and 127.0.0.1."""

    CLOCK_SKEW = datetime.timedelta(minutes=5)

    def __init__(self, directory, tenant_id: Optional[str] = None):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.tenant_id = tenant_id or str(uuid.uuid4())

        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root = self._ca("Firmline Test Root CA", self.root_key, None, None, 1, None)
        self.intermediate_key = ec.generate_private_key(ec.SECP256R1())
        self.intermediate = self._ca(
            "Firmline Test Device CA",
            self.intermediate_key,
            self.root_key,
            self.root,
            0,
            self.tenant_id,
        )
        self.root_path = self.dir / "root.pem"
        self.root_path.write_text(cert_pem(self.root))
        self.intermediate_path = self.dir / "intermediate.pem"
        self.intermediate_path.write_text(cert_pem(self.intermediate))

        self.https_cert_path, self.https_key_path = self.server_certificate("https")
        self.broker_cert_path, self.broker_key_path = self.server_certificate("broker")

        # The update verification key: the agent's configuration names its public PEM.
        self.update_key = ec.generate_private_key(ec.SECP256R1())
        self.update_key_path = self.dir / "update-key.pem"
        self.update_key_path.write_bytes(
            self.update_key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    @property
    def chain_pem(self) -> str:
        """The chain the platform returns: the intermediate, then the root."""
        return cert_pem(self.intermediate) + cert_pem(self.root)

    def _builder(self, subject: x509.Name, issuer: x509.Name, public_key, not_before, not_after):
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )

    def _ca(self, cn, key, issuer_key, issuer_cert, path_length, ou):
        attributes = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
        if ou:
            attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
        subject = x509.Name(attributes)
        now = utc_now()
        builder = (
            self._builder(
                subject,
                issuer_cert.subject if issuer_cert else subject,
                key.public_key(),
                now - self.CLOCK_SKEW,
                now + datetime.timedelta(days=3650),
            )
            .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        )
        if issuer_cert is not None:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
                False,
            )
        return builder.sign(issuer_key or key, hashes.SHA256())

    def _issuer(self, issuer: str):
        if issuer == "root":
            return self.root_key, self.root
        if issuer == "intermediate":
            return self.intermediate_key, self.intermediate
        raise ValueError(issuer)

    def _leaf(self, subject, public_key, issuer, eku, names, not_before=None, not_after=None):
        issuer_key, issuer_cert = self._issuer(issuer)
        now = utc_now()
        builder = (
            self._builder(
                subject,
                issuer_cert.subject,
                public_key,
                not_before or now - self.CLOCK_SKEW,
                not_after or now + datetime.timedelta(days=730),
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
                False,
            )
        )
        if names:
            builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
        return builder.sign(issuer_key, hashes.SHA256())

    def server_certificate(self, name, hosts=("localhost",), ips=("127.0.0.1",), issuer="root"):
        """A TLS server certificate with these DNS names and IP addresses; files <name>.pem
        (certificate, then the intermediate when it signs) and <name>.key. Returns both paths."""
        key = ec.generate_private_key(ec.SECP256R1())
        names = [x509.DNSName(h) for h in hosts] + [
            x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips
        ]
        cert = self._leaf(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0] if hosts else name)]),
            key.public_key(),
            issuer,
            ExtendedKeyUsageOID.SERVER_AUTH,
            names,
        )
        chain = cert_pem(cert) + (cert_pem(self.intermediate) if issuer == "intermediate" else "")
        cert_path = self.dir / f"{name}.pem"
        cert_path.write_text(chain)
        return cert_path, write_private(self.dir / f"{name}.key", key_pem(key))

    def client_certificate(self, name, common_name, ou=None, issuer="root"):
        """A TLS client certificate (for instance the platform's MQTT client); files <name>.pem
        (certificate, then the intermediate when it signs) and <name>.key."""
        key = ec.generate_private_key(ec.SECP256R1())
        attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
        if ou:
            attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
        cert = self._leaf(
            x509.Name(attributes), key.public_key(), issuer, ExtendedKeyUsageOID.CLIENT_AUTH, None
        )
        chain = cert_pem(cert) + (cert_pem(self.intermediate) if issuer == "intermediate" else "")
        cert_path = self.dir / f"{name}.pem"
        cert_path.write_text(chain)
        return cert_path, write_private(self.dir / f"{name}.key", key_pem(key))

    def issue_device(self, public_key, device_id, not_before, not_after) -> x509.Certificate:
        """The certificate of a device, as the platform issues it: CN = {tenantId}.{deviceId},
        OU = tenantId whatever the CSR says, signed by the company intermediate."""
        # The CN has 73 characters, over the X.520 upper bound of 64 that `cryptography` enforces
        # and the platform (.NET) does not: the check is turned off to issue the same.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            subject = x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME, f"{self.tenant_id}.{device_id}", _validate=False
                    ),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.tenant_id),
                ]
            )
        not_after = min(not_after, self.intermediate.not_valid_after_utc)
        return self._leaf(
            subject,
            public_key,
            "intermediate",
            ExtendedKeyUsageOID.CLIENT_AUTH,
            None,
            not_before,
            not_after,
        )


# --------------------------------------------------------------------------------------------
# Fake platform


@dataclasses.dataclass
class Request:
    method: str
    path: str
    headers: dict  # names in lower case
    body: bytes

    def json(self):
        return json.loads(self.body)


@dataclasses.dataclass
class Reply:
    status: int
    body: bytes = b""
    headers: dict = dataclasses.field(default_factory=dict)


# The `type` ASP.NET Core writes into problem details, by status.
_PROBLEM_TYPES = {
    400: "https://tools.ietf.org/html/rfc9110#section-15.5.1",
    404: "https://tools.ietf.org/html/rfc9110#section-15.5.5",
    409: "https://tools.ietf.org/html/rfc9110#section-15.5.10",
    429: "https://tools.ietf.org/html/rfc6585#section-4",
}


def problem(status: int, code: str, details=None) -> Reply:
    """An RFC 9457 error as the platform writes it: type, title, status, code, details."""
    body = {
        "type": _PROBLEM_TYPES.get(status, "about:blank"),
        "title": code,
        "status": status,
        "code": code,
        "details": details,
    }
    return Reply(
        status, json.dumps(body).encode(), {"Content-Type": "application/problem+json"}
    )


def json_reply(status: int, value) -> Reply:
    return Reply(
        status, json.dumps(value).encode(), {"Content-Type": "application/json; charset=utf-8"}
    )


# A scripted entry: a fixed Reply, or a function of the request that returns a Reply, or None to
# let the platform answer normally.
Scripted = Union[Reply, Callable[[Request], Optional[Reply]]]

_SERIAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$")


@dataclasses.dataclass
class Device:
    device_id: str
    serial: str
    certificates: list  # PEM of every certificate issued, the last one current
    renewal_key_sha256: Optional[str] = None  # key of the last renewal, for a repeated request
    response: Optional[dict] = None  # the last 200 answer


class _TlsServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, context, platform):
        self.context = context
        self.platform = platform
        super().__init__(address, handler)

    def finish_request(self, request, client_address):
        # The TLS handshake runs in the connection's thread: a client that refuses the
        # certificate only ends its own connection.
        request.settimeout(30)
        try:
            tls = self.context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            tls.close()

    def handle_error(self, request, client_address):
        pass  # a client gone or a refused handshake: not an error of the test


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    MAX_BODY = 1024 * 1024

    def log_message(self, format, *args):
        pass

    def _record(self) -> Request:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, self.MAX_BODY)) if length else b""
        headers = {k.lower(): v for k, v in self.headers.items()}
        request = Request(self.command, self.path, headers, body)
        self.server.platform._record(request)
        return request

    def _handle(self):
        request = self._record()
        try:
            reply = self.server.platform._answer(request)
        except Exception:  # a bug of the fake: recorded, and the test fails on it
            self.server.platform.errors.append(traceback.format_exc())
            reply = problem(500, "fake_platform_error")
        self.close_connection = True
        self.send_response(reply.status)
        for name, value in reply.headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(reply.body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(reply.body)

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle
    do_PUT = _handle
    do_DELETE = _handle


class FakePlatform:
    """The device side of the Firmline platform, over HTTPS for `localhost`.

    Knobs: family_id; send_family_id=False plays the platform before T178 (no familyId in the
    answer); certificate_validity and certificate_backdate (not_before = now - backdate) for the
    certificates it issues; script()/refuse() queue faults per route. Every request is in
    `requests`; `devices` holds what it registered."""

    PROVISIONING = "/api/v1/provisioning"
    RENEWAL = "/api/v1/provisioning/renewal"
    DOWNLOADS = "/api/v1/ota/downloads/"

    def __init__(self, pki: Pki, family_id: Optional[str] = None, send_family_id: bool = True):
        self.pki = pki
        self.family_id = family_id or str(uuid.uuid4())
        self.send_family_id = send_family_id
        self.certificate_validity = datetime.timedelta(days=730)
        self.certificate_backdate = Pki.CLOCK_SKEW
        self.port = free_port()
        self.requests: list = []
        self.errors: list = []  # tracebacks of the fake's own failures
        self.devices: dict = {}
        self._tokens: set = set()
        self._downloads: dict = {}
        self._scripts = collections.defaultdict(collections.deque)
        self._lock = threading.RLock()
        self._server = None
        self._thread = None

    # -- life cycle

    @property
    def url(self) -> str:
        return f"https://localhost:{self.port}"

    def start(self) -> "FakePlatform":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.pki.https_cert_path, self.pki.https_key_path)
        self._server = _TlsServer(("127.0.0.1", self.port), _Handler, context, self)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._thread.join(5)
            self._server = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    # -- test controls

    def new_token(self) -> str:
        """A one-time provisioning token in the platform's format brktd_<16 hex>_<43 base64url>."""
        token = f"brktd_{secrets.token_hex(8)}_{secrets.token_urlsafe(32)}"
        with self._lock:
            self._tokens.add(token)
        return token

    def script(self, route: str, *entries: Scripted) -> None:
        """Queues answers for the next requests to `route` (a path, or a path prefix for
        DOWNLOADS), one entry per request, before the normal behaviour comes back."""
        with self._lock:
            self._scripts[route].extend(entries)

    def refuse(self, route: str, status: int, code: str, times: int = 1) -> None:
        self.script(route, *([problem(status, code)] * times))

    def add_download(self, content: bytes) -> str:
        """Serves `content` at a new download link and returns the link."""
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._downloads[token] = content
        return f"{self.url}{self.DOWNLOADS}{token}"

    def requests_to(self, path: str) -> list:
        with self._lock:
            return [r for r in self.requests if r.path == path or r.path.startswith(path + "?")]

    # -- server side

    def _record(self, request: Request) -> None:
        with self._lock:
            self.requests.append(request)

    def _route(self, request: Request) -> str:
        path = request.path.split("?", 1)[0]
        if path.startswith(self.DOWNLOADS):
            return self.DOWNLOADS
        return path

    def _answer(self, request: Request) -> Reply:
        route = self._route(request)
        with self._lock:
            entry = self._scripts[route].popleft() if self._scripts[route] else None
        if entry is not None:
            reply = entry(request) if callable(entry) else entry
            if reply is not None:
                return reply
        if request.method == "POST" and route == self.PROVISIONING:
            return self._provision(request)
        if request.method == "POST" and route == self.RENEWAL:
            return self._renew(request)
        if request.method in ("GET", "HEAD") and route == self.DOWNLOADS:
            return self._download(request)
        return problem(404, "not_found")

    def _issue(self, device: Device, public_key) -> str:
        now = utc_now()
        cert = self.pki.issue_device(
            public_key,
            device.device_id,
            now - self.certificate_backdate,
            now - self.certificate_backdate + self.certificate_validity,
        )
        pem = cert_pem(cert)
        device.certificates.append(pem)
        return pem

    def _provisioned(self, device: Device) -> dict:
        tenant = self.pki.tenant_id
        topic_root = f"t/{tenant}/d/{device.device_id}"
        answer = {"deviceId": device.device_id}
        if self.send_family_id:
            answer["familyId"] = self.family_id
        answer.update(
            {
                "clientId": f"{tenant}.{device.device_id}",
                "topicRoot": topic_root,
                "otaOfferTopic": f"{topic_root}/ota/offer",
                "certificate": device.certificates[-1],
                "chain": self.pki.chain_pem,
            }
        )
        device.response = answer
        return answer

    @staticmethod
    def _csr_key(csr_pem):
        """The P-256 key of a CSR signed with it, or None (csr_invalid)."""
        if not isinstance(csr_pem, str) or not 0 < len(csr_pem) <= 8192:
            return None
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
        except ValueError:
            return None
        key = csr.public_key()
        if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
            return None
        return key if csr.is_signature_valid else None

    def _provision(self, request: Request) -> Reply:
        try:
            data = request.json()
        except ValueError:
            return problem(400, "provisioning_token_invalid", ["token"])
        if not isinstance(data, dict):
            return problem(400, "provisioning_token_invalid", ["token"])
        token, serial, csr = data.get("token"), data.get("serialNumber"), data.get("csr")
        with self._lock:
            if not isinstance(token, str) or token.strip() not in self._tokens:
                return problem(400, "provisioning_token_invalid", ["token"])
            serial = serial.strip() if isinstance(serial, str) else ""
            if not _SERIAL_RE.match(serial):
                return problem(400, "serial_number_invalid", ["serialNumber"])
            key = self._csr_key(csr)
            if key is None:
                return problem(400, "csr_invalid", ["csr"])
            if any(d.serial == serial for d in self.devices.values()):
                return problem(409, "serial_number_taken", ["serialNumber"])
            device = Device(str(uuid.uuid4()), serial, [])
            self._issue(device, key)
            self._tokens.discard(token.strip())  # single use, only on success
            self.devices[device.device_id] = device
            return json_reply(200, self._provisioned(device))

    def _renew(self, request: Request) -> Reply:
        refused = problem(400, "certificate_renewal_refused", ["certificate"])
        try:
            data = request.json()
            current = x509.load_pem_x509_certificate(data["certificate"].encode())
            csr, proof = data.get("csr"), base64.b64decode(data.get("proof"), validate=True)
        except (ValueError, KeyError, TypeError, AttributeError):
            return refused
        with self._lock:
            sent = cert_pem(current)
            device = next(
                (d for d in self.devices.values() if sent in d.certificates[-2:]), None
            )
            if device is None or current.not_valid_after_utc <= utc_now():
                return refused
            new_key = self._csr_key(csr)
            if new_key is None:
                return problem(400, "csr_invalid", ["csr"])
            if len(proof) == 64:
                proof = encode_dss_signature(
                    int.from_bytes(proof[:32], "big"), int.from_bytes(proof[32:], "big")
                )
            try:
                current.public_key().verify(proof, csr.encode(), ec.ECDSA(hashes.SHA256()))
            except (InvalidSignature, ValueError):
                return refused
            new_der = public_key_der(new_key)
            if new_der == public_key_der(current.public_key()):
                return problem(400, "csr_invalid", ["csr"])
            new_sha = hashlib.sha256(new_der).hexdigest()
            if sent != device.certificates[-1]:
                # the certificate before the last, sent again for the same key: the answer lost
                if device.renewal_key_sha256 != new_sha:
                    return refused
                return json_reply(200, self._provisioned(device))
            if current.not_valid_before_utc > utc_now() - datetime.timedelta(days=1):
                return problem(409, "certificate_renewed_recently", ["certificate"])
            self._issue(device, new_key)
            device.renewal_key_sha256 = new_sha
            return json_reply(200, self._provisioned(device))

    def _download(self, request: Request) -> Reply:
        token = request.path.split("?", 1)[0][len(self.DOWNLOADS) :]
        with self._lock:
            content = self._downloads.get(token)
        if content is None:
            return problem(404, "ota_download_not_found")
        headers = {"Content-Type": "application/octet-stream", "Accept-Ranges": "bytes"}
        match = re.fullmatch(r"bytes=(\d+)-(\d*)", request.headers.get("range", ""))
        if not match:
            return Reply(200, content, headers)
        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) else len(content) - 1
        if start >= len(content) or end < start:
            headers["Content-Range"] = f"bytes */{len(content)}"
            return Reply(416, b"", headers)
        end = min(end, len(content) - 1)
        headers["Content-Range"] = f"bytes {start}-{end}/{len(content)}"
        return Reply(206, content[start : end + 1], headers)


# --------------------------------------------------------------------------------------------
# Broker


class Broker:
    """mosquitto on 127.0.0.1 and a free port: TLS only, a client certificate required (verified
    with the root; a device sends its certificate with the intermediate), the certificate CN as
    the user name. Everything it does goes to `log`."""

    def __init__(self, pki: Pki, directory, port: Optional[int] = None):
        self.pki = pki
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.port = port or free_port()
        self.config_path = self.dir / "mosquitto.conf"
        self.log_path = self.dir / "mosquitto.log"
        self._process = None

    def _config(self) -> str:
        return "\n".join(
            [
                "user root",  # inside the test container: do not switch to the mosquitto user
                "persistence false",
                f"log_dest file {self.log_path}",
                "log_type all",
                "log_timestamp true",
                "log_timestamp_format %Y-%m-%dT%H:%M:%S",
                "connection_messages true",
                f"listener {self.port} 127.0.0.1",
                f"cafile {self.pki.root_path}",
                f"certfile {self.pki.broker_cert_path}",
                f"keyfile {self.pki.broker_key_path}",
                "require_certificate true",
                "use_identity_as_username true",
                "",
            ]
        )

    def start(self) -> "Broker":
        self.config_path.write_text(self._config())
        self._process = subprocess.Popen(
            ["mosquitto", "-c", str(self.config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            wait_for_port(self.port)
        except TimeoutError:
            self.stop()
            raise
        return self

    def stop(self) -> None:
        if self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(10)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()
            self._process = None

    def restart(self) -> None:
        self.stop()
        self.start()

    @property
    def log(self) -> str:
        return self.log_path.read_text(errors="replace") if self.log_path.exists() else ""

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


# --------------------------------------------------------------------------------------------
# Agent


@dataclasses.dataclass
class AgentResult:
    code: int
    stdout: str
    stderr: str


class Agent:
    """One agent: its configuration file, its data folder and its log (stderr of every run).

    `settings` are the [platform] keys (None leaves a key out); `components` maps a component
    code to its keys. By default the agent talks to `platform` and `broker`, trusts the test root
    for the platform HTTPS, and has one main component `app` with a fixed version."""

    def __init__(
        self,
        directory,
        platform: Optional[FakePlatform] = None,
        pki: Optional[Pki] = None,
        broker: Optional[Broker] = None,
        components: Optional[dict] = None,
        **settings,
    ):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.data_dir = self.dir / "data"
        self.config_path = self.dir / "agent.conf"
        pki = pki or (platform.pki if platform else None)
        self.settings = {
            "url": platform.url if platform else "https://localhost:9",
            "broker": "localhost",
            "broker_port": str(broker.port) if broker else None,
            "ca_file": str(pki.root_path) if pki else None,
            "update_key": str(pki.update_key_path) if pki else None,
            "data_dir": str(self.data_dir),
        }
        self.settings.update(settings)
        self.components = components or {
            "app": {"main": "true", "version": "fixed:1.0.0", "install": "none"}
        }
        self.log = ""
        self._process = None
        self._process_stderr = None

    def write_config(self) -> Path:
        lines = ["[platform]"]
        lines += [f"{k} = {v}" for k, v in self.settings.items() if v is not None]
        for code, keys in self.components.items():
            lines += ["", f"[component {code}]"]
            lines += [f"{k} = {v}" for k, v in keys.items() if v is not None]
        self.config_path.write_text("\n".join(lines) + "\n")
        return self.config_path

    def _command(self, args) -> list:
        command = [AGENT_BINARY, *map(str, args)]
        if "--config" not in command and args and args[0] not in ("--help", "-h"):
            command += ["--config", str(self.config_path)]
        return command

    @staticmethod
    def _env() -> dict:
        env = dict(os.environ)
        env.setdefault("ASAN_OPTIONS", "detect_leaks=1")
        env.setdefault("UBSAN_OPTIONS", "print_stacktrace=1")
        return env

    def _take_log(self, stderr: str) -> None:
        self.log += stderr
        for marker in SANITIZER_MARKERS:
            if marker in stderr:
                raise AssertionError("sanitizer report in the agent's stderr:\n" + stderr)

    def run(self, *args, timeout: float = 60) -> AgentResult:
        """Runs one command to its end (the configuration is written first)."""
        self.write_config()
        done = subprocess.run(
            self._command(args),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            env=self._env(),
        )
        self._take_log(done.stderr)
        return AgentResult(done.returncode, done.stdout, done.stderr)

    def start(self, *args) -> subprocess.Popen:
        """Starts a long-running command (`run`); stop() ends it and collects its log."""
        self.write_config()
        self._process_stderr = tempfile.TemporaryFile(mode="w+", errors="replace")
        self._process = subprocess.Popen(
            self._command(args),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=self._process_stderr,
            text=True,
            env=self._env(),
        )
        return self._process

    def stop(self, timeout: float = 15) -> int:
        """SIGTERM, then the exit code; the stderr of the run is added to the log."""
        process, self._process = self._process, None
        if process is None:
            return 0
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        self._process_stderr.seek(0)
        stderr = self._process_stderr.read()
        self._process_stderr.close()
        self._take_log(stderr)
        return process.returncode

    def path(self, name: str) -> Path:
        return self.data_dir / name

    def read_text(self, name: str) -> str:
        path = self.path(name)
        return path.read_text() if path.exists() else ""

    def read_json(self, name: str):
        return json.loads(self.path(name).read_text())

    def data_files(self) -> list:
        return sorted(os.listdir(self.data_dir)) if self.data_dir.exists() else []


# --------------------------------------------------------------------------------------------
# Base test class


class IntegrationTest(unittest.TestCase):
    """A temporary folder, a Pki and a started FakePlatform per test; `make_agent` builds agents
    in it, `make_broker` starts a broker. Everything is stopped and removed at the end."""

    send_family_id = True

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="firmline-it-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.pki = Pki(self.tmp / "pki")
        self.platform = FakePlatform(self.pki, send_family_id=self.send_family_id).start()
        self.addCleanup(self.platform.stop)
        self.addCleanup(lambda: self.assertEqual([], self.platform.errors, "the fake failed"))

    def make_agent(self, name: str = "agent", **kwargs) -> Agent:
        kwargs.setdefault("platform", self.platform)
        kwargs.setdefault("pki", self.pki)
        agent = Agent(self.tmp / name, **kwargs)
        self.addCleanup(agent.stop)  # a `run` still going at the end
        return agent

    def make_broker(self, name: str = "broker") -> Broker:
        broker = Broker(self.pki, self.tmp / name).start()
        self.addCleanup(broker.stop)
        return broker
