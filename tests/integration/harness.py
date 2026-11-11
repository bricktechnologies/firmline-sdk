# SPDX-License-Identifier: Apache-2.0
"""Harness of the integration tests: a fake Firmline platform, a test broker and the agent.

Everything secret (keys, certificates, tokens) is generated when the tests run, in a temporary
folder per test; nothing is committed.

- Pki: root CA, company intermediate (path length 0), server certificates for `localhost`, client
  certificates, device certificates issued for a CSR's key, and the update verification key.
- FakePlatform: HTTPS server on a free port with the device endpoints of the real platform
  (POST /api/v1/provisioning, POST /api/v1/provisioning/renewal, GET /api/v1/ota/downloads/<token>
  with Range). Every request is recorded; faults are scripted per route with `script`/`refuse`,
  and per download link (cut_after, STATUS_429, STATUS_404, STATUS_503, slow; a link answers 404
  after its urlExpires, by the fake's clock); certificates() chooses the validity of the
  certificates it issues, drop_next_renewal_response() loses a renewal answer.
  With connect(broker) it signs manifests with the update key, publishes offers (offer, repeat)
  and collects the results of the devices. relay() is a second fake playing a relay.
- Broker: mosquitto with client certificates required, the certificate CN as the user name, and
  a topic ACL per registered device as on the platform (rebuilt at every registration);
  revoke() refuses a device certificate from the next start.
- MqttClient: a paho client with a root-signed certificate, by default the platform's side (it
  may read and write every t/# topic): collects messages, publishes offers.
- Agent: writes the configuration, runs `firmline-agent`, keeps its stderr as `log` (a running
  `run` in `running_log`, see wait_for_log); a sanitizer report in that stderr fails the test.
  `env` is added to its environment; kill() stops it as a power loss would.
- assert_no_secrets(log, secrets): none of the secrets, and no PEM block at all, is in the log.
- wait_until(condition, timeout), count_connections(port, seconds): polling and a TCP listener
  that only counts the connections made to it (a broker that is down, seen from the agent).
- IntegrationTest: unittest base class with a temporary folder, a Pki and a started FakePlatform;
  make_relay() adds a relay (fake platform and broker with certificates of the intermediate).
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
import signal
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
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
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


def wait_until(condition: Callable[[], object], timeout: float, what: str = "the condition"):
    """Polls condition() every 0.1 s until it returns something true, and returns that."""
    deadline = time.monotonic() + timeout
    while True:
        value = condition()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} did not happen within {timeout} s")
        time.sleep(0.1)


def count_connections(port: int, seconds: float) -> list:
    """Listens on 127.0.0.1:port for `seconds`, closes every connection at once (as a broker that
    is down would refuse it) and returns the monotonic times of the connections."""
    times = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", port))
        server.listen(16)
        deadline = time.monotonic() + seconds
        while (left := deadline - time.monotonic()) > 0:
            server.settimeout(left)
            try:
                connection, _ = server.accept()
            except socket.timeout:
                break
            times.append(time.monotonic())
            connection.close()
    return times


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


# libcurl's built-in CA directory in the dev image (CURLINFO_CAPATH), also OpenSSL's default.
SYSTEM_CA_DIR = Path("/etc/ssl/certs")


def trust_system_wide(test: unittest.TestCase, ca_cert_path) -> Path:
    """Adds a CA certificate to the system's CA directory, as `<subject hash>.<n>` (the name
    OpenSSL looks up), until the end of the test: a certificate it issues is then trusted as one
    of a public authority would be. Fails when the directory cannot be written (the tests run as
    root in the dev container); FIRMLINE_NO_SYSTEM_CA=1 skips instead."""
    if not os.access(SYSTEM_CA_DIR, os.W_OK):
        if os.environ.get("FIRMLINE_NO_SYSTEM_CA") == "1":
            test.skipTest(f"{SYSTEM_CA_DIR} is not writable and FIRMLINE_NO_SYSTEM_CA=1")
        test.fail(f"{SYSTEM_CA_DIR} is not writable: run the tests in the dev container (root)")
    subject_hash = subprocess.run(
        ["openssl", "x509", "-hash", "-noout", "-in", str(ca_cert_path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    n = 0
    while (SYSTEM_CA_DIR / f"{subject_hash}.{n}").exists():
        n += 1
    path = SYSTEM_CA_DIR / f"{subject_hash}.{n}"
    shutil.copy(ca_cert_path, path)
    test.addCleanup(path.unlink, missing_ok=True)
    return path


CLOCK_SHIM_SOURCE = Path(__file__).resolve().parent / "clock_shim.c"


def build_clock_shim(directory) -> Path:
    """Compiles clock_shim.c (the dev image has gcc): preloaded into the agent with LD_PRELOAD, its
    time() runs FIRMLINE_TEST_CLOCK_OFFSET seconds ahead (or behind), and its
    clock_gettime(CLOCK_MONOTONIC) ahead by the seconds of a MonotonicClock file. See clock_env()."""
    out = Path(directory) / "clock_shim.so"
    subprocess.run(
        ["gcc", "-shared", "-fPIC", "-O1", "-o", str(out), str(CLOCK_SHIM_SOURCE), "-ldl"],
        check=True,
        capture_output=True,
    )
    return out


class MonotonicClock:
    """The monotonic clock of an agent run with clock_env(..., monotonic=this): forward(s) moves
    it ahead while the agent runs (the shim reads the file again within 100 ms of real time)."""

    def __init__(self, directory):
        self.path = Path(directory) / "monotonic-offset"
        self.offset = 0
        self.path.write_text("0\n")

    def forward(self, seconds: int) -> None:
        """Moves the clock `seconds` further ahead and waits until the agent can see it."""
        self.offset += seconds
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(f"{self.offset}\n")
        os.replace(tmp, self.path)  # never a half-written number
        time.sleep(0.3)


def clock_env(
    shim: Path,
    offset: datetime.timedelta = datetime.timedelta(0),
    monotonic: Optional["MonotonicClock"] = None,
) -> dict:
    """The environment of an agent whose wall clock is moved by `offset` and, with `monotonic`,
    whose monotonic clock follows that MonotonicClock (Agent.env)."""
    env = {
        "LD_PRELOAD": str(shim),
        "FIRMLINE_TEST_CLOCK_OFFSET": str(int(offset.total_seconds())),
        # the shim comes before the ASan runtime in the library order: allowed for this test
        "ASAN_OPTIONS": "detect_leaks=1:verify_asan_link_order=0",
    }
    if monotonic is not None:
        env["FIRMLINE_TEST_MONOTONIC_OFFSET_FILE"] = str(monotonic.path)
    return env


# --------------------------------------------------------------------------------------------
# PKI


class Pki:
    """The certificate authorities and keys of one test run, written into `directory`.

    root: the platform root (path length 1); intermediate: the company intermediate (path length
    0, OU = tenant), which signs the device certificates. The HTTPS and broker certificates are
    signed by the root, as on the platform, for `localhost` and 127.0.0.1."""

    CLOCK_SKEW = datetime.timedelta(minutes=5)

    def __init__(self, directory, tenant_id: Optional[str] = None, name: str = "Firmline Test"):
        """`name` starts the CN of both authorities: another name gives another subject (a
        Pki with the same name has CAs of the same name, as a forged authority would)."""
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.tenant_id = tenant_id or str(uuid.uuid4())

        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root = self._ca(f"{name} Root CA", self.root_key, None, None, 1, None)
        self.intermediate_key = ec.generate_private_key(ec.SECP256R1())
        self.intermediate = self._ca(
            f"{name} Device CA",
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
    time: float = dataclasses.field(default_factory=time.monotonic)  # arrival

    def json(self):
        return json.loads(self.body)


@dataclasses.dataclass
class Reply:
    status: int
    body: bytes = b""
    headers: dict = dataclasses.field(default_factory=dict)
    # Faults of the transfer: send only the first `send_only` bytes of the body (Content-Length
    # still announces it all), then close the connection; `rate` limits the body to that many
    # bytes per second; `drop` closes the connection without answering at all (an answer lost).
    send_only: Optional[int] = None
    rate: Optional[float] = None
    drop: bool = False


@dataclasses.dataclass(frozen=True)
class Cut:
    """A download fault: the connection is closed once the file reached `at` bytes."""

    at: int


def cut_after(at: int) -> Cut:
    return Cut(at)


# Download faults answered instead of the file, one request each.
STATUS_429 = "status_429"  # 429 too_many_requests
STATUS_404 = "status_404"  # 404 ota_download_not_found
STATUS_503 = "status_503"  # 503 service_unavailable (a server error, retried)


@dataclasses.dataclass
class Download:
    content: bytes
    # one entry per request (Cut, STATUS_429, STATUS_404, STATUS_503), then normal
    faults: collections.deque
    slow: Optional[float] = None  # bytes per second of every answer
    # As on the platform, the link answers 404 ota_download_not_found from this moment (by the
    # platform's clock, not the device's); None: never.
    expires: Optional[datetime.datetime] = None


@dataclasses.dataclass
class Offer:
    """An offer the fake published: its release, link, raw payload and the signed manifest."""

    device_id: str
    release: str
    url: str
    payload: bytes
    manifest: bytes
    signature: bytes  # r||s
    content: bytes  # what the link serves


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
        if reply.drop:
            return  # the request was handled, the answer never leaves
        self.send_response(reply.status)
        for name, value in reply.headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(reply.body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command == "HEAD":
            return
        body = reply.body if reply.send_only is None else reply.body[: max(reply.send_only, 0)]
        if reply.rate is None:
            self.wfile.write(body)
            return
        chunk = max(1, int(reply.rate / 10))  # ten pieces a second
        try:
            for start in range(0, len(body), chunk):
                self.wfile.write(body[start : start + chunk])
                self.wfile.flush()
                time.sleep(chunk / reply.rate)
        except (OSError, ssl.SSLError):
            pass  # the client went away (an agent stopped or killed mid-download)

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle
    do_PUT = _handle
    do_DELETE = _handle


class FakePlatform:
    """The device side of the Firmline platform, over HTTPS for `localhost`.

    Knobs: family_id; send_family_id=False plays the platform before T178 (no familyId in the
    answer); certificate_validity and certificate_backdate (not_before = now - backdate) for the
    certificates it issues (certificates() sets both from the days left and the age); `issuer`
    (another Pki issues the certificates) and `chain_override` (another chain in the answers) play a
    platform gone wrong;
    script()/refuse() queue faults per route, drop_next_renewal_response() loses one renewal
    answer. Every request is in `requests`; `devices` holds what it registered. `server_cert`
    (certificate chain and key paths) replaces the HTTPS certificate of the root: relay() makes a
    second fake that plays a relay of this one."""

    PROVISIONING = "/api/v1/provisioning"
    RENEWAL = "/api/v1/provisioning/renewal"
    DOWNLOADS = "/api/v1/ota/downloads/"

    def __init__(
        self,
        pki: Pki,
        family_id: Optional[str] = None,
        send_family_id: bool = True,
        server_cert=None,
    ):
        self.pki = pki
        self.server_cert = server_cert or (pki.https_cert_path, pki.https_key_path)
        self.family_id = family_id or str(uuid.uuid4())
        self.send_family_id = send_family_id
        self.certificate_validity = datetime.timedelta(days=730)
        self.certificate_backdate = Pki.CLOCK_SKEW
        # A platform gone wrong: certificates issued by another Pki, and/or another chain sent.
        self.issuer: Optional[Pki] = None
        self.chain_override: Optional[str] = None
        self.port = free_port()
        self.requests: list = []
        self.errors: list = []  # tracebacks of the fake's own failures
        self.devices: dict = {}
        self._tokens: set = set()
        self._downloads: dict = {}
        self._scripts = collections.defaultdict(collections.deque)
        self._device_listeners: list = []  # called with each new Device (the broker ACL)
        self.mqtt: Optional["MqttClient"] = None  # set by connect()
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
        context.load_cert_chain(*self.server_cert)
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

    def drop_next_renewal_response(self) -> None:
        """The next renewal is processed as usual (the certificate is issued and becomes the
        device's last one), but the connection is closed without an answer: the device must send
        the same request again, and gets the same certificate back."""

        def lost(request: Request) -> Reply:
            return dataclasses.replace(self._renew(request), drop=True)

        self.script(self.RENEWAL, lost)

    def _until_stopped(self, route: str, entry: Callable[[Request], Optional[Reply]]):
        """Scripts `entry` for every request to `route` (after the entries already scripted)
        until the returned function is called; that removes its remaining entries, so entries
        scripted later come next."""
        self.script(route, *[entry] * 1000)

        def stop() -> None:
            with self._lock:
                left = [e for e in self._scripts[route] if e is not entry]
                self._scripts[route] = collections.deque(left)

        return stop

    def renewals_unavailable(self) -> Callable[[], None]:
        """After the answers already scripted, every renewal is answered 503 service_unavailable
        until the returned function is called; then the platform answers normally again."""
        return self._until_stopped(
            self.RENEWAL, lambda request: problem(503, "service_unavailable")
        )

    def tamper_renewals(self, change: Callable[[dict], None]) -> Callable[[], None]:
        """After the answers already scripted, every renewal is processed as usual and
        change(answer) edits the 200 answer before it leaves (a relay forwarding answers it
        altered), until the returned function is called."""

        def tampered(request: Request) -> Reply:
            reply = self._renew(request)
            if reply.status != 200:
                return reply
            answer = json.loads(reply.body)
            change(answer)
            return json_reply(200, answer)

        return self._until_stopped(self.RENEWAL, tampered)

    def certificates(
        self, valid_for: datetime.timedelta, age: datetime.timedelta = datetime.timedelta(days=2)
    ) -> None:
        """The certificates issued from now on expire `valid_for` after the moment they are
        issued (negative: already expired) and were valid since `age` before it (over a day: they
        may be renewed at once)."""
        self.certificate_backdate = age
        self.certificate_validity = age + valid_for

    def default_certificates(self) -> None:
        """Back to the platform's certificates: valid for 2 years from now."""
        self.certificate_backdate = Pki.CLOCK_SKEW
        self.certificate_validity = datetime.timedelta(days=730)

    def relay(self, server_cert) -> "FakePlatform":
        """A second fake on its own port with the HTTPS certificate `server_cert` (a relay's is
        signed by the company intermediate) that knows the same devices: renewals and downloads
        through the relay. Not started."""
        relay = FakePlatform(self.pki, self.family_id, self.send_family_id, server_cert)
        relay.devices = self.devices  # the same dict: registrations go to this platform only
        return relay

    def add_download(
        self,
        content: bytes,
        faults=(),
        slow: Optional[float] = None,
        expires: Optional[datetime.datetime] = None,
    ) -> str:
        """Serves `content` at a new download link and returns the link. `faults` are answered
        one per request, in order, before the file is served normally: cut_after(n) closes the
        connection once the file reached n bytes, STATUS_429, STATUS_404 and STATUS_503 answer
        that error.
        `slow` limits every answer to that many bytes per second. From `expires` on (this
        platform's clock) the link answers 404 ota_download_not_found, as an expired link does."""
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._downloads[token] = Download(content, collections.deque(faults), slow, expires)
        return f"{self.url}{self.DOWNLOADS}{token}"

    # -- OTA offers (the broker side needs connect())

    def connect(self, broker: "Broker") -> "MqttClient":
        """The platform's MQTT client on `broker`, subscribed to t/#: offers go out through it
        and the results of the devices are collected by it."""
        self.mqtt = broker.client()
        self.mqtt.subscribe("t/#")
        return self.mqtt

    @staticmethod
    def iso(moment: datetime.datetime) -> str:
        """yyyy-MM-ddTHH:mm:ssZ, as the platform writes times in manifests and offers."""
        return moment.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def topic_root(self, device_id: str) -> str:
        return self.devices[device_id].response["topicRoot"]

    def offer(
        self,
        device_id: str,
        component: str,
        version: str,
        data: bytes,
        rollback: bool = False,
        not_before: Optional[datetime.datetime] = None,
        url_expires: Optional[datetime.datetime] = None,
        release: Optional[str] = None,
        served: Optional[bytes] = None,
        tamper: Optional[Callable[[bytes], bytes]] = None,
        faults=(),
        slow: Optional[float] = None,
        publish: bool = True,
    ) -> Offer:
        """Builds and signs a manifest exactly like the platform (compact JSON, fields in the
        order v, release, tenant, family, component, kid, version, sha256, size, notBefore,
        rollback; ES256 with the test update key, r||s), serves `served` (default `data`) at a
        new link and publishes the offer on the device's otaOfferTopic. `tamper` changes the
        manifest bytes after signing."""
        now = utc_now()
        public_der = public_key_der(self.pki.update_key.public_key())
        kid = hashlib.sha256(public_der).hexdigest()
        manifest = json.dumps(
            {
                "v": 1,
                "release": release or str(uuid.uuid4()),
                "tenant": self.pki.tenant_id,
                "family": self.family_id,
                "component": component,
                "kid": kid,
                "version": version,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "notBefore": self.iso(not_before or now - datetime.timedelta(minutes=1)),
                "rollback": rollback,
            },
            separators=(",", ":"),
        ).encode()
        der = self.pki.update_key.sign(manifest, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        if tamper is not None:
            manifest = tamper(manifest)
        offer = Offer(
            device_id,
            json.loads(manifest)["release"],
            "",
            b"",
            manifest,
            signature,
            data if served is None else served,
        )
        return self.repeat(offer, url_expires=url_expires, faults=faults, slow=slow, publish=publish)

    def repeat(
        self,
        offer: Offer,
        url_expires: Optional[datetime.datetime] = None,
        faults=(),
        slow: Optional[float] = None,
        publish: bool = True,
    ) -> Offer:
        """The same signed manifest again with a new link, as the platform repeats an offer. The
        link answers 404 from `url_expires` on (default: in an hour, the platform's maximum)."""
        expires = url_expires or utc_now() + datetime.timedelta(hours=1)
        url = self.add_download(offer.content, faults, slow, expires)
        payload = json.dumps(
            {
                "manifest": base64.b64encode(offer.manifest).decode(),
                "alg": "ES256",
                "kid": hashlib.sha256(public_key_der(self.pki.update_key.public_key())).hexdigest(),
                "sig": base64.b64encode(offer.signature).decode(),
                "url": url,
                "urlExpires": self.iso(expires),
            },
            separators=(",", ":"),
        ).encode()
        offer = dataclasses.replace(offer, url=url, payload=payload)
        if publish:
            reason = self.mqtt.publish(self.devices[offer.device_id].response["otaOfferTopic"], payload)
            if getattr(reason, "is_failure", False):
                raise AssertionError(f"the broker refused the offer: {reason}")
        return offer

    def results(self, device_id: str) -> list:
        """The results the device published, as parsed JSON, in arrival order."""
        topic = self.topic_root(device_id) + "/ota/result"
        return [m.json() for m in self.mqtt.received(topic)]

    def wait_results(self, device_id: str, count: int = 1, timeout: float = 60) -> list:
        self.mqtt.wait_for(self.topic_root(device_id) + "/ota/result", count, timeout)
        return self.results(device_id)

    def download_requests(self, url: str) -> list:
        return self.requests_to(url[len(self.url) :])

    def on_device(self, listener: Callable[[Device], None]) -> None:
        """Calls listener(device) after each new registration."""
        with self._lock:
            self._device_listeners.append(listener)

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
        cert = (self.issuer or self.pki).issue_device(
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
                "chain": self.chain_override or (self.issuer or self.pki).chain_pem,
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
            for listener in self._device_listeners:
                listener(device)
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
            download = self._downloads.get(token)
            fault = download.faults.popleft() if download and download.faults else None
        expired = download is not None and download.expires is not None and utc_now() >= download.expires
        if download is None or expired or fault == STATUS_404:
            return problem(404, "ota_download_not_found")
        if fault == STATUS_429:
            return problem(429, "too_many_requests")
        if fault == STATUS_503:
            return problem(503, "service_unavailable")
        content = download.content
        headers = {"Content-Type": "application/octet-stream", "Accept-Ranges": "bytes"}
        match = re.fullmatch(r"bytes=(\d+)-(\d*)", request.headers.get("range", ""))
        start = 0
        if not match:
            reply = Reply(200, content, headers)
        else:
            start = int(match.group(1))
            end = int(match.group(2)) if match.group(2) else len(content) - 1
            if start >= len(content) or end < start:
                headers["Content-Range"] = f"bytes */{len(content)}"
                return Reply(416, b"", headers)
            end = min(end, len(content) - 1)
            headers["Content-Range"] = f"bytes {start}-{end}/{len(content)}"
            reply = Reply(206, content[start : end + 1], headers)
        if isinstance(fault, Cut):
            reply.send_only = fault.at - start
        reply.rate = download.slow
        return reply


# --------------------------------------------------------------------------------------------
# Broker


# The user name (certificate CN) of the platform's side in the test broker: it may read and
# write every topic under t/.
PLATFORM_USER = "firmline-test-platform"


class Broker:
    """mosquitto on 127.0.0.1 and a free port: TLS only, a client certificate required (verified
    with the root; a device sends its certificate with the intermediate), the certificate CN as
    the user name. Everything it does goes to `log`.

    Topic ACL as on the platform: mosquitto patterns cannot turn the user name {tenant}.{device}
    into t/{tenant}/d/{device}, so the ACL file lists every device of `platform` explicitly and is
    rebuilt (and reloaded with SIGHUP) at every registration. A device may publish only on
    {topicRoot}/status and {topicRoot}/ota/result and receive only {topicRoot}/ota/offer;
    PLATFORM_USER may read and write t/#; anyone else nothing. Unlike the platform, mosquitto
    grants a SUBSCRIBE to any topic the user may write too (it filters only what it delivers),
    so a subscription to {topicRoot}/status is not refused here.

    `server_cert` (chain and key paths) replaces the broker certificate of the root (a relay's is
    signed by the intermediate). revoke(certificate) puts a client certificate on a revocation
    list that the broker checks from its next start: after a renewal, only the new certificate
    of a device connects."""

    def __init__(
        self,
        pki: Pki,
        directory,
        port: Optional[int] = None,
        platform: Optional[FakePlatform] = None,
        server_cert=None,
    ):
        self.pki = pki
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.port = port or free_port()
        self._port_chosen = port is None
        self._started = False
        self.config_path = self.dir / "mosquitto.conf"
        self.log_path = self.dir / "mosquitto.log"
        self.acl_path = self.dir / "acl"
        self.crl_path = self.dir / "crl.pem"
        self.server_cert = server_cert or (pki.broker_cert_path, pki.broker_key_path)
        self.revoked: list = []  # serial numbers
        self.platform = platform
        self._process = None
        self.write_acl()
        if platform is not None:
            platform.on_device(lambda device: self.reload_acl())

    def _acl(self) -> str:
        lines = [f"user {PLATFORM_USER}", "topic readwrite t/#", ""]
        tenant = self.pki.tenant_id
        devices = list(self.platform.devices) if self.platform is not None else []
        for device_id in devices:
            root = f"t/{tenant}/d/{device_id}"
            lines += [
                f"user {tenant}.{device_id}",
                f"topic write {root}/status",
                f"topic write {root}/ota/result",
                f"topic read {root}/ota/offer",
                "",
            ]
        return "\n".join(lines)

    def write_acl(self) -> None:
        temp = self.acl_path.with_suffix(".tmp")
        temp.write_text(self._acl())
        os.replace(temp, self.acl_path)

    RUNNING = " running"  # the end of "mosquitto version 2.0.x running", logged when it is ready

    def reload_acl(self) -> None:
        """Rewrites the ACL file and has a running broker read it again (waits for it)."""
        self.write_acl()
        if self._process is not None and self._process.poll() is None:
            reloads = self.log.count("Reloading config")
            self._process.send_signal(signal.SIGHUP)

            def reloaded():
                if self._process.poll() is not None:
                    raise AssertionError(f"the broker exited ({self._process.returncode})")
                return self.log.count("Reloading config") > reloads

            wait_until(reloaded, 10, "ACL reload")

    def revoke(self, certificate_pem: str) -> None:
        """Revokes a certificate issued by the intermediate (a device's) from the next start."""
        self.revoked.append(x509.load_pem_x509_certificate(certificate_pem.encode()).serial_number)

    def _write_crl(self) -> None:
        """One list per authority: OpenSSL checks the list of the client certificate's issuer
        (the root for the platform's client, the intermediate for a device) and refuses a client
        whose issuer has none."""
        now = utc_now()
        text = ""
        for key, cert, serials in [
            (self.pki.root_key, self.pki.root, []),
            (self.pki.intermediate_key, self.pki.intermediate, self.revoked),
        ]:
            builder = (
                x509.CertificateRevocationListBuilder()
                .issuer_name(cert.subject)
                .last_update(now - Pki.CLOCK_SKEW)
                .next_update(now + datetime.timedelta(days=1))
            )
            for serial in serials:
                builder = builder.add_revoked_certificate(
                    x509.RevokedCertificateBuilder()
                    .serial_number(serial)
                    .revocation_date(now - Pki.CLOCK_SKEW)
                    .build()
                )
            crl = builder.sign(key, hashes.SHA256())
            text += crl.public_bytes(serialization.Encoding.PEM).decode()
        self.crl_path.write_text(text)

    def _config(self) -> str:
        crl = []
        if self.revoked:
            self._write_crl()
            crl = [f"crlfile {self.crl_path}"]
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
                f"certfile {self.server_cert[0]}",
                f"keyfile {self.server_cert[1]}",
                "require_certificate true",
                "use_identity_as_username true",
                *crl,
                f"acl_file {self.acl_path}",
                "",
            ]
        )

    START_TIMEOUT = 30  # seconds: the workstation may be busy with other test runs

    def start(self) -> "Broker":
        """Starts mosquitto and waits until it logs that it runs: its port is open then, and its
        signal handlers are in place (a SIGHUP from reload_acl before that would end it). A
        broker whose port was chosen here and that exits at once (the port taken meanwhile by
        another process) is started again on a new port, before its first start only: after
        that, agents know the port."""
        for attempt in range(3):
            self.write_acl()
            self.config_path.write_text(self._config())
            running = self.log.count(self.RUNNING)  # the log file grows across restarts
            self._process = subprocess.Popen(
                ["mosquitto", "-c", str(self.config_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + self.START_TIMEOUT
            while (
                self.log.count(self.RUNNING) <= running
                and self._process.poll() is None
                and time.monotonic() < deadline
            ):
                time.sleep(0.05)
            if self._process.poll() is None and self.log.count(self.RUNNING) > running:
                self._started = True
                return self
            exited = self._process.poll() is not None
            self.stop()
            if not (exited and self._port_chosen and not self._started):
                break
            self.port = free_port()
        raise TimeoutError(f"the broker on port {self.port} did not start: see {self.log_path}")

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

    def client(self, **kwargs) -> "MqttClient":
        return MqttClient(self, **kwargs)


@dataclasses.dataclass
class Message:
    topic: str
    payload: bytes
    qos: int
    retain: bool
    time: float  # time.monotonic() at arrival

    def json(self):
        return json.loads(self.payload)


class MqttClient:
    """A paho MQTT 5 client of the test broker with a certificate signed by the root; by default
    the platform's side (PLATFORM_USER, every t/# topic). Messages of its subscriptions are
    collected in `messages`; subscribe() and publish() wait for the broker's answer. With
    certfile and keyfile it connects with those instead (a device: client id = common_name)."""

    def __init__(
        self,
        broker: Broker,
        name: str = "platform",
        common_name: str = PLATFORM_USER,
        certfile=None,
        keyfile=None,
    ):
        import paho.mqtt.client as mqtt  # only the tests that talk MQTT need paho

        if certfile is None:
            cert, key = broker.pki.client_certificate(f"mqtt-{name}", common_name)
        else:
            cert, key = str(certfile), str(keyfile)
        self.messages: list = []
        self._lock = threading.Lock()
        self._acks: dict = {}
        self._connected = threading.Event()
        self.client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2, client_id=common_name, protocol=mqtt.MQTTv5
        )
        self.client.tls_set(ca_certs=str(broker.pki.root_path), certfile=cert, keyfile=key)
        self.client.on_connect = lambda c, u, flags, reason, props: (
            self._connected.set() if not reason.is_failure else None
        )
        self.client.on_message = self._on_message
        self.client.on_subscribe = lambda c, u, mid, reasons, props: self._ack(mid, reasons)
        self.client.on_publish = lambda c, u, mid, reason, props: self._ack(mid, reason)
        self.client.connect("localhost", broker.port)
        self.client.loop_start()
        if not self._connected.wait(10):
            self.close()
            raise AssertionError("the test MQTT client cannot connect to the broker")

    def _on_message(self, client, userdata, msg) -> None:
        message = Message(msg.topic, bytes(msg.payload), msg.qos, bool(msg.retain), time.monotonic())
        with self._lock:
            self.messages.append(message)

    def _ack(self, mid, reason) -> None:
        with self._lock:
            self._acks[mid] = (reason,)  # a tuple: true even when the reason code is 0

    def _wait_ack(self, mid):
        return wait_until(lambda: self._acks.get(mid), 10, f"the answer to message {mid}")[0]

    def subscribe(self, topic: str, qos: int = 1):
        """Subscribes and returns the granted reason codes."""
        _, mid = self.client.subscribe(topic, qos)
        return self._wait_ack(mid)

    def publish(self, topic: str, payload, qos: int = 1, retain: bool = False):
        info = self.client.publish(topic, payload, qos=qos, retain=retain)
        return self._wait_ack(info.mid) if qos > 0 else None

    def received(self, topic: Optional[str] = None) -> list:
        with self._lock:
            return [m for m in self.messages if topic is None or m.topic == topic]

    def wait_for(self, topic: str, count: int = 1, timeout: float = 30) -> list:
        """Waits until `count` messages arrived on `topic` and returns them all."""
        return wait_until(
            lambda: (lambda got: got if len(got) >= count else None)(self.received(topic)),
            timeout,
            f"{count} message(s) on {topic}",
        )

    def close(self) -> None:
        self.client.disconnect()
        self.client.loop_stop()


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
        env: Optional[dict] = None,
        **settings,
    ):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.data_dir = self.dir / "data"
        self.env = dict(env or {})  # added to its environment (its scripts inherit it)
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
        self._run_log_path = None
        self._runs = 0

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

    def _env(self) -> dict:
        env = dict(os.environ)
        env.setdefault("ASAN_OPTIONS", "detect_leaks=1")
        env.setdefault("UBSAN_OPTIONS", "print_stacktrace=1")
        env.update(self.env)
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
        self._runs += 1
        # A file of its own opened for appending, so that the test can read it while it grows.
        self._run_log_path = self.dir / f"run-{self._runs}.log"
        with open(self._run_log_path, "a") as stderr:
            self._process = subprocess.Popen(
                self._command(args),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr,
                text=True,
                env=self._env(),
            )
        return self._process

    @property
    def running_log(self) -> str:
        """What the running command has written to stderr so far (not yet in `log`)."""
        if self._process is None or self._run_log_path is None:
            return ""
        return self._run_log_path.read_text(errors="replace")

    def wait_for_log(self, text: str, timeout: float = 30, count: int = 1) -> str:
        """Waits until the running command has logged `text` `count` times; returns its log."""
        return wait_until(
            lambda: (lambda log: log if log.count(text) >= count else None)(self.running_log),
            timeout,
            f"the agent logging {text!r}",
        )

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
        stderr = self._run_log_path.read_text(errors="replace")
        self._take_log(stderr)
        return process.returncode

    def kill(self) -> None:
        """SIGKILL, as a power loss would stop it: no cleanup at all. The log so far is kept
        (without the sanitizer check: a killed process writes no report)."""
        process, self._process = self._process, None
        if process is None:
            return
        process.kill()
        process.wait()
        self.log += self._run_log_path.read_text(errors="replace")

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
        broker = Broker(self.pki, self.tmp / name, platform=self.platform).start()
        self.addCleanup(broker.stop)
        return broker

    def make_relay(self, name: str = "relay"):
        """A started relay: a fake platform and a broker of their own, both with certificates for
        localhost signed by the company intermediate (verified with the root the device received
        at registration), that know the devices of self.platform (the broker's ACL follows its
        registrations). Returns (relay platform, relay broker)."""
        https = self.pki.server_certificate(f"{name}-https", issuer="intermediate")
        relay = self.platform.relay(https).start()
        self.addCleanup(relay.stop)
        self.addCleanup(lambda: self.assertEqual([], relay.errors, "the relay fake failed"))
        mqtt = self.pki.server_certificate(f"{name}-broker", issuer="intermediate")
        broker = Broker(self.pki, self.tmp / name, platform=relay, server_cert=mqtt).start()
        self.addCleanup(broker.stop)
        self.platform.on_device(lambda device: broker.reload_acl())
        return relay, broker
