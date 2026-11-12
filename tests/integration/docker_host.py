# SPDX-License-Identifier: Apache-2.0
"""A Docker daemon for the integration tests, with no registry reachable.

docker_host() starts `dockerd` once per test process, at first use, and stops it at exit. It runs
in the dev container of scripts/check.sh, which is privileged and has the named volume
`firmline-docker` on /var/lib/docker (dockerd's data root must be a real file system: overlay2
does not work on the container's own overlay). The daemon listens only on a Unix socket in a
temporary folder of its own, keeps its log there (log()), and has HTTP_PROXY/HTTPS_PROXY set to
http://127.0.0.1:9, where nothing listens: every pull fails, so a test that passes never needed
a registry. It runs with `--iptables=false`: no container of the tests reaches the outside, and
one that must reach the fakes on 127.0.0.1 (the agent) uses the host network.

Without a daemon (dockerd missing, not root, not privileged, no volume on /var/lib/docker)
docker_host() skips the test, unless FIRMLINE_REQUIRE_DOCKER=1 (scripts/ci-inside.sh): then it
fails it.

Images are made with `docker import`, never from a base image: the applications from busybox
(Debian busybox-static), the agent from AGENT_BINARY with the shared libraries `ldd` lists, the
`docker` CLI, the Compose v2 plugin, `tar`, `gzip` and the CA certificates of the dev container.
A base image of each kind is imported once (`firmline-test/app-base`, `firmline-test/agent-base`)
and every tag is a commit on it with a `/version` file holding the tag, so two tags are two image
IDs. The images it built are kept by reset(); everything else goes.

TorizonDevice plays a device with Torizon OS in that daemon: the agent image as a service of the
composition `torizon`.
"""

import atexit
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Dict, Optional

from harness import AGENT_BINARY, wait_until

DATA_ROOT = Path("/var/lib/docker")
# The discard port: nothing listens there, so every connection through the proxy is refused.
REFUSING_PROXY = "http://127.0.0.1:9"
# Where Debian's docker-compose installs the Compose v2 plugin; the docker CLI looks there.
COMPOSE_PLUGIN = Path("/usr/libexec/docker/cli-plugins/docker-compose")
CA_BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")
CGROUP = Path("/sys/fs/cgroup")
START_TIMEOUT = 60.0

APP_BASE = "firmline-test/app-base:latest"
AGENT_BASE = "firmline-test/agent-base:latest"
PATH_ENV = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


class DockerUnavailable(Exception):
    """No daemon can start here; the message says why."""


def _reference(tag: str) -> str:
    """The name `docker images` shows for a tag: `app` is `app:latest`."""
    return tag if ":" in tag.rsplit("/", 1)[-1] else f"{tag}:latest"


def _nest_cgroup_v2() -> None:
    """With cgroup v2 a cgroup that holds processes cannot give controllers to child cgroups, and
    the container's root cgroup holds the test processes: move them to a child `init` and enable
    the controllers for the children, as the docker:dind image does. Nothing to do on cgroup v1."""
    controllers = (CGROUP / "cgroup.controllers")
    if not controllers.exists():
        return
    wanted = controllers.read_text().split()
    if set(wanted) <= set((CGROUP / "cgroup.subtree_control").read_text().split()):
        return
    init = CGROUP / "init"
    init.mkdir(exist_ok=True)
    for pid in (CGROUP / "cgroup.procs").read_text().split():
        try:
            (init / "cgroup.procs").write_text(pid)
        except OSError:
            pass  # a process that has exited meanwhile, or a kernel thread
    (CGROUP / "cgroup.subtree_control").write_text(" ".join(f"+{name}" for name in wanted))


class DockerHost:
    """A started dockerd. run() is the docker CLI on its socket; `socket` is the socket's path (to
    mount as /var/run/docker.sock in a container), `env` the environment of that CLI."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="firmline-docker-"))
        self.socket = self.root / "docker.sock"
        self.log_path = self.root / "dockerd.log"
        self.env = dict(os.environ)
        for name in ("DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
            self.env.pop(name, None)
        self.env["DOCKER_HOST"] = f"unix://{self.socket}"
        self.env["DOCKER_CONFIG"] = str(self.root / "cli")
        self.process: Optional[subprocess.Popen] = None
        self._built: Dict[tuple, str] = {}  # (kind, tag, behaviour) -> image ID
        self._kept: Dict[str, str] = {}  # reference -> image ID, what reset() keeps

    # The daemon.

    def start(self) -> "DockerHost":
        if os.geteuid() != 0:
            raise DockerUnavailable("the tests do not run as root")
        if shutil.which("dockerd") is None:
            raise DockerUnavailable("dockerd is not installed (docker/dev.Dockerfile installs it)")
        if not os.path.ismount(DATA_ROOT):
            raise DockerUnavailable(
                f"{DATA_ROOT} is not a mounted volume"
                " (scripts/check.sh mounts the volume firmline-docker there)"
            )
        try:
            _nest_cgroup_v2()
        except OSError as error:
            raise DockerUnavailable(f"cannot prepare the cgroups (not privileged?): {error}")
        env = {k: v for k, v in os.environ.items() if k.lower() != "no_proxy"}
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            env[name] = REFUSING_PROXY
        command = [
            "dockerd",
            "--data-root", str(DATA_ROOT),
            "--exec-root", str(self.root / "exec"),
            "--pidfile", str(self.root / "dockerd.pid"),
            "--host", f"unix://{self.socket}",
            "--storage-driver", "overlay2",
            "--iptables=false",
        ]
        with open(self.log_path, "ab") as log:
            self.process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=env,
                start_new_session=True,
            )
        atexit.register(self.stop)
        deadline = time.monotonic() + START_TIMEOUT
        while True:
            if self.process.poll() is not None:
                code = self.process.returncode
                raise DockerUnavailable(f"dockerd exited with {code}:\n{self._tail()}")
            answer = self.socket.exists() and self.run("version", check=False, timeout=10)
            if answer and answer.returncode == 0:
                break
            if time.monotonic() >= deadline:
                self.stop()
                raise DockerUnavailable(
                    f"dockerd does not answer after {START_TIMEOUT} s:\n{self._tail()}"
                )
            time.sleep(0.2)
        self.reset()  # what an earlier run left in the volume
        return self

    def stop(self) -> None:
        if self.process is None or self.process.poll() is not None:
            return
        # Containers first, at once: dockerd would otherwise wait for each one to stop.
        try:
            ids = self.run("ps", "-aq", check=False, timeout=30).stdout.split()
            if ids:
                self.run("rm", "-f", *ids, check=False, timeout=60)
        except subprocess.TimeoutExpired:
            pass  # a daemon that does not answer is stopped all the same
        self.process.terminate()
        try:
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()

    def log(self) -> str:
        """The daemon's log so far. A pull attempt writes `Handler for POST /v1.<n>/images/create
        returned error` there (it always fails)."""
        return self.log_path.read_text(errors="replace")

    def _tail(self, lines: int = 20) -> str:
        return "\n".join(self.log().splitlines()[-lines:])

    def run(
        self, *args: str, check: bool = True, timeout: float = 120
    ) -> subprocess.CompletedProcess:
        """The docker CLI on the daemon's socket; with check, a failure fails the test."""
        result = subprocess.run(
            ["docker", *args], env=self.env, cwd=self.root, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=timeout,
        )
        if check and result.returncode != 0:
            raise AssertionError(
                f"docker {' '.join(args)} exited with {result.returncode}:\n{result.stderr}"
            )
        return result

    def reset(self) -> None:
        """Between tests: removes every container, network and volume (so everything of the
        Compose project `torizon`) and every image the host did not build; a built image keeps
        only its own name."""
        # A container started with --rm may be removing itself already ("removal ... already in
        # progress"): looked at again until none is left.
        deadline = time.monotonic() + 60
        while True:
            ids = self.run("ps", "-aq").stdout.split()
            if not ids:
                break
            removal = self.run("rm", "-f", "-v", *ids, check=False)
            if removal.returncode != 0 and time.monotonic() >= deadline:
                raise AssertionError(f"reset cannot remove the containers:\n{removal.stderr}")
            if removal.returncode != 0:
                time.sleep(0.5)
        self.run("network", "prune", "-f")
        self.run("volume", "prune", "-af")
        # An image with child images cannot go before them: a later pass removes it.
        for _ in range(5):
            remove, untag = self._foreign_images()
            if not remove and not untag:
                return
            if untag:
                self.run("rmi", *untag, check=False)
            if remove:
                self.run("rmi", "-f", *remove, check=False)
        raise AssertionError(f"reset cannot remove the images {self._foreign_images()}")

    def _foreign_images(self) -> tuple:
        """(IDs of the images the host did not build, other names of the ones it built)."""
        kept_ids = set(self._kept.values())
        remove, untag = set(), set()
        listing = "{{.ID}} {{.Repository}}:{{.Tag}}"
        for line in self.run("images", "-a", "--no-trunc", "--format", listing).stdout.splitlines():
            image_id, reference = line.split(" ", 1)
            if image_id not in kept_ids:
                remove.add(image_id)
            elif reference != "<none>:<none>" and self._kept.get(reference) != image_id:
                untag.add(reference)
        return sorted(remove), sorted(untag)

    # The images.

    def app_image(self, tag: str, behaviour: str) -> str:
        """An application image tagged `tag`: "stay" runs `sleep 3600`, "die:<s>" exits 1 after <s>
        seconds, "healthy"/"unhealthy" stay with a healthcheck (every second) that says so."""
        changes = ['CMD ["sleep", "3600"]']
        die = re.fullmatch(r"die:(\d+(?:\.\d+)?)", behaviour)
        if die:
            changes = [f'CMD ["sh", "-c", "sleep {die.group(1)}; exit 1"]']
        elif behaviour in ("healthy", "unhealthy"):
            check = "true" if behaviour == "healthy" else "false"
            changes.append(f'HEALTHCHECK --interval=1s --timeout=5s --retries=1 CMD ["{check}"]')
        elif behaviour != "stay":
            raise ValueError(
                f"unknown behaviour {behaviour!r}: stay, die:<seconds>, healthy or unhealthy"
            )
        return self._image(("app", tag, behaviour), tag, self._app_base, changes)

    def agent_image(self, tag: str) -> str:
        """The agent of AGENT_BINARY as an image tagged `tag`, as linux/Dockerfile makes it
        (entrypoint `firmline-agent`, command `run --wait-registration`, volume /var/lib/firmline),
        with the docker CLI, the Compose plugin, tar, gzip and the CA certificates."""
        changes = [
            'ENTRYPOINT ["firmline-agent"]',
            'CMD ["run", "--wait-registration"]',
            "VOLUME /var/lib/firmline",
        ]
        return self._image(("agent", tag, ""), tag, self._agent_base, changes)

    def _image(self, key: tuple, tag: str, base, changes: list) -> str:
        """A commit on the base image with /version holding the tag, built once per key: a test
        that removed it gets it built again."""
        image_id = self._built.get(key)
        if image_id is None or self.run("tag", image_id, tag, check=False).returncode != 0:
            base_id = base()
            container = self.run("create", base_id, "/version-placeholder").stdout.strip()
            try:
                version = self.root / "version"
                version.write_text(f"{tag}\n")
                self.run("cp", str(version), f"{container}:/version")
                arguments = ["commit"]
                for change in [f"ENV {PATH_ENV}", "ENV HOME=/root", *changes]:
                    arguments += ["--change", change]
                image_id = self.run(*arguments, container, tag).stdout.strip()
            finally:
                self.run("rm", "-f", container)
            self._built[key] = image_id
        self._kept[_reference(tag)] = image_id
        return image_id

    def _app_base(self) -> str:
        busybox = shutil.which("busybox")
        if busybox is None:
            raise AssertionError(
                "busybox is not installed (docker/dev.Dockerfile installs busybox-static)"
            )
        applets = subprocess.run([busybox, "--list"], check=True, capture_output=True, text=True)
        rootfs = _Rootfs()
        rootfs.usr_merge()
        rootfs.file("usr/bin/busybox", busybox)
        for applet in applets.stdout.split():
            if applet != "busybox":
                rootfs.link(f"usr/bin/{applet}", "busybox")
        return self._base(APP_BASE, rootfs)

    def _agent_base(self) -> str:
        binaries = {
            "usr/bin/firmline-agent": AGENT_BINARY,
            "usr/bin/docker": shutil.which("docker"),
            str(COMPOSE_PLUGIN).lstrip("/"): str(COMPOSE_PLUGIN),
            "usr/bin/tar": shutil.which("tar"),
            "usr/bin/gzip": shutil.which("gzip"),
        }
        rootfs = _Rootfs()
        rootfs.usr_merge()
        for path, source in binaries.items():
            if source is None or not Path(source).is_file():
                raise AssertionError(f"{path} for the agent image: {source} is missing")
            rootfs.file(path, source)
            for library in _libraries(source):
                rootfs.file(library.lstrip("/"), library)
        rootfs.file(str(CA_BUNDLE).lstrip("/"), str(CA_BUNDLE))
        rootfs.link("usr/lib/ssl/certs", "/etc/ssl/certs")  # OpenSSL's directory, as in Debian
        rootfs.link("usr/lib/ssl/cert.pem", str(CA_BUNDLE))
        rootfs.text("etc/passwd", "root:x:0:0:root:/root:/bin/sh\n")
        rootfs.text("etc/group", "root:x:0:\n")
        for folder in ("root", "var/lib/firmline"):
            rootfs.folder(folder)
        return self._base(AGENT_BASE, rootfs)

    def _base(self, reference: str, rootfs: "_Rootfs") -> str:
        """Imports the root file system as `reference`, once per process (again when a test
        removed it)."""
        known = self._kept.get(reference)
        if known and self.run("image", "inspect", known, check=False).returncode == 0:
            self.run("tag", known, reference)
            return known
        archive = self.root / "rootfs.tar"
        rootfs.folder("tmp", mode=0o1777)
        rootfs.write(archive)
        try:
            image_id = self.run("import", str(archive), reference, timeout=300).stdout.strip()
        finally:
            archive.unlink()
        self._kept[reference] = image_id
        return image_id


def _libraries(binary: str) -> list:
    """The shared libraries `ldd` lists for a binary, with the dynamic loader; none when it is
    static."""
    result = subprocess.run(["ldd", binary], capture_output=True, text=True)
    if result.returncode != 0:
        return []  # "not a dynamic executable"
    paths = []
    for line in result.stdout.splitlines():
        if "not found" in line:
            raise AssertionError(f"ldd {binary}: {line.strip()}")
        match = re.search(r"(?:=>\s*)?(/\S+)\s+\(0x", line)
        if match:
            paths.append(match.group(1))
    return paths


class _Rootfs:
    """The entries of a root file system to import, written as a tar owned by root."""

    def __init__(self):
        self.entries: Dict[str, tuple] = {}

    def usr_merge(self) -> None:
        """/bin, /lib, ... as the dev container has them: on Debian trixie links into /usr."""
        for name in ("bin", "sbin", "lib", "lib64", "lib32", "libx32"):
            host = Path("/") / name
            if host.is_symlink():
                self.link(name, os.readlink(host))

    def file(self, path: str, source: str) -> None:
        """`source` (links followed) at `path`, its folder resolved through the /usr links."""
        folder, name = os.path.split(path)
        target = os.path.relpath(os.path.realpath("/" + folder), "/") if folder else ""
        self.entries[os.path.join(target, name)] = ("file", os.path.realpath(source))

    def link(self, path: str, target: str) -> None:
        self.entries[path] = ("link", target)

    def text(self, path: str, content: str) -> None:
        self.entries[path] = ("text", content.encode())

    def folder(self, path: str, mode: int = 0o755) -> None:
        self.entries[path] = ("folder", mode)

    def write(self, archive: Path) -> None:
        folders = set()
        for path in self.entries:
            parts = Path(path).parts[:-1]
            folders.update(str(Path(*parts[:i])) for i in range(1, len(parts) + 1))
        with tarfile.open(archive, "w") as tar:
            for path in sorted(folders - set(self.entries)):
                tar.addfile(self._info(path, tarfile.DIRTYPE, 0o755))
            for path, (kind, value) in sorted(self.entries.items()):
                if kind == "folder":
                    tar.addfile(self._info(path, tarfile.DIRTYPE, value))
                elif kind == "link":
                    info = self._info(path, tarfile.SYMTYPE, 0o777)
                    info.linkname = value
                    tar.addfile(info)
                elif kind == "text":
                    info = self._info(path, tarfile.REGTYPE, 0o644)
                    info.size = len(value)
                    tar.addfile(info, io.BytesIO(value))
                else:
                    info = self._info(path, tarfile.REGTYPE, os.stat(value).st_mode & 0o7777)
                    info.size = os.stat(value).st_size
                    with open(value, "rb") as source:
                        tar.addfile(info, source)

    @staticmethod
    def _info(path: str, kind, mode: int) -> tarfile.TarInfo:
        info = tarfile.TarInfo(path)
        info.type = kind
        info.mode = mode
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        return info


_host: Optional[DockerHost] = None
_failure: Optional[str] = None


def docker_host() -> DockerHost:
    """The daemon of this test process, started at first use. Without one the test is skipped,
    or fails when FIRMLINE_REQUIRE_DOCKER=1."""
    global _host, _failure
    if _host is None and _failure is None:
        host = DockerHost()
        try:
            _host = host.start()
        except DockerUnavailable as error:
            _failure = str(error)
            shutil.rmtree(host.root, ignore_errors=True)
    if _host is None:
        if os.environ.get("FIRMLINE_REQUIRE_DOCKER") == "1":
            raise RuntimeError(f"FIRMLINE_REQUIRE_DOCKER=1 and no Docker daemon: {_failure}")
        raise unittest.SkipTest(f"no Docker daemon: {_failure}")
    return _host


class TorizonDevice:
    """A device with Torizon OS, played in the test daemon: the agent image as the service
    `firmline-agent` of the composition `torizon`, started as Torizon starts it at every boot
    (`docker compose -p torizon -f <compose_file> up -d`).

    The agent has network `host` (it reaches the fake platform and broker on 127.0.0.1), the
    daemon's socket as /var/run/docker.sock, the named volume `firmline-data` as its data folder,
    `compose_dir` (it plays /var/sota/storage/docker-compose: mounted at its own path, as on the
    device, where the two paths are the same), a read-only /etc/firmline (agent.conf, a fake
    serial-number, the root certificate and the update key) and a fake /etc/os-release.
    Components: `torizon` (main, os-release, install none) and `app` (package:<initial version>,
    install docker-compose, a health check of health_timeout seconds).

    The log of every agent container and of every `firmline-apply` container is collected while
    the device runs (agent_logs, apply_logs): apply runs with --rm and an update may recreate the
    agent's container, and their logs would go with them."""

    PROJECT = "torizon"
    AGENT_SERVICE = "firmline-agent"
    APPLY = "firmline-apply"
    FOLLOWS = 20  # follows of one container at most (a listing older than its end starts one)
    DATA = "/var/lib/firmline"
    INITIAL_VERSION = "1.0.0"
    OS_VERSION = "7.2.0-build.13"

    def __init__(self, docker: DockerHost, folder: Path, platform_url: str, broker_port: int,
                 root_ca: Path, update_key: Path, health_timeout: int = 10):
        self.docker = docker
        self.folder = Path(folder)
        self.compose_dir = self.folder / "docker-compose"
        self.compose_file = self.compose_dir / "docker-compose.yml"
        self.etc = self.folder / "etc-firmline"
        self.os_release = self.folder / "os-release"
        self.platform_url = platform_url
        self.broker_port = broker_port
        self.root_ca = Path(root_ca)
        self.update_key = Path(update_key)
        self.health_timeout = health_timeout
        self.agent_environment: Dict[str, str] = {}  # of the agent's service, set before start()
        self.exec_log = ""  # stderr of the commands run in the agent's container
        # container ID -> (kind, number, [(process, path, file)]): one file per follow
        self._logs: Dict[str, tuple] = {}
        self._order: list = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._watcher: Optional[threading.Thread] = None

    # The composition.

    def agent_service(self, image: str) -> dict:
        service = {
            "image": image,
            "network_mode": "host",
            "volumes": [
                f"firmline-data:{self.DATA}",
                f"{self.docker.socket}:/var/run/docker.sock",
                f"{self.compose_dir}:{self.compose_dir}",
                f"{self.etc}:/etc/firmline:ro",
                f"{self.os_release}:/etc/os-release:ro",
            ],
        }
        if self.agent_environment:
            service["environment"] = dict(self.agent_environment)
        return service

    def composition(self, services: Dict[str, str], agent_image: Optional[str] = None) -> str:
        """A composition (JSON, which Compose reads as YAML) of the services {name: image}, with
        the agent's service first when agent_image is given."""
        document: dict = {"services": {}}
        if agent_image is not None:
            document["services"][self.AGENT_SERVICE] = self.agent_service(agent_image)
            document["volumes"] = {"firmline-data": {}}
        for service, image in services.items():
            document["services"][service] = {"image": image}
        return json.dumps(document, indent=2) + "\n"

    def config(self) -> str:
        return (
            "[platform]\n"
            f"url = {self.platform_url}\n"
            "broker = localhost\n"
            f"broker_port = {self.broker_port}\n"
            "ca_file = /etc/firmline/root.pem\n"
            "update_key = /etc/firmline/update-key.pem\n"
            "serial = file:/etc/firmline/serial-number\n"
            "\n"
            "[component torizon]\n"
            "main = true\n"
            "version = os-release:VERSION_ID\n"
            "install = none\n"
            "\n"
            "[component app]\n"
            "main = false\n"
            f"version = package:{self.INITIAL_VERSION}\n"
            "install = docker-compose\n"
            f"compose_file = {self.compose_file}\n"
            f"health_timeout = {self.health_timeout}\n"
        )

    def start(self, services: Dict[str, str], agent_image: str) -> None:
        """Writes the device's files and starts the composition of the agent and `services`."""
        self.compose_dir.mkdir(parents=True)
        self.etc.mkdir(parents=True)
        (self.etc / "agent.conf").write_text(self.config())
        (self.etc / "serial-number").write_text(f"SN-{os.urandom(4).hex()}\n")
        shutil.copyfile(self.root_ca, self.etc / "root.pem")
        shutil.copyfile(self.update_key, self.etc / "update-key.pem")
        self.os_release.write_text(f'NAME="Torizon OS"\nVERSION_ID="{self.OS_VERSION}"\n')
        self.compose_file.write_text(self.composition(services, agent_image))
        self.compose("up", "--detach")
        self._watcher = threading.Thread(target=self._watch, daemon=True)
        self._watcher.start()

    def compose(self, *args: str, file: Optional[Path] = None) -> subprocess.CompletedProcess:
        """docker compose of the project `torizon` with compose_file (or `file`)."""
        return self.docker.run(
            "compose", "-p", self.PROJECT, "-f", str(file or self.compose_file), *args,
            timeout=180,
        )

    def containers(self) -> dict:
        """{service: (container ID, state, image ID)} of the project's containers."""
        listing = self.docker.run(
            "ps", "-a", "--no-trunc", "--filter", f"label=com.docker.compose.project={self.PROJECT}",
            "--format", '{{.Label "com.docker.compose.service"}} {{.ID}}',
        ).stdout.split()
        found = {}
        for service, container in zip(listing[::2], listing[1::2]):
            state, image = self.docker.run(
                "inspect", "--format", "{{.State.Status}} {{.Image}}", container
            ).stdout.split()
            found[service] = (container, state, image)
        return found

    def agent(self) -> str:
        """The ID of the agent's container."""
        return self.containers()[self.AGENT_SERVICE][0]

    # The agent.

    def register(self, token: str) -> str:
        """`firmline-agent register` in the agent's container, as at the device's test; the
        device ID. The agent (run --wait-registration) then starts within 10 s."""
        result = self.docker.run(
            "exec", self.agent(), "firmline-agent", "register", "--token", token, check=False,
            timeout=60,
        )
        self.exec_log += result.stderr
        if result.returncode != 0:
            raise AssertionError(f"register exited with {result.returncode}:\n{result.stderr}")
        return json.loads(self.read_data("device.json"))["deviceId"]

    def logs(self, container: Optional[str] = None) -> str:
        """The log of a container (the agent's by default) as docker has it now."""
        result = self.docker.run("logs", container or self.agent(), check=False)
        return result.stdout + result.stderr

    def wait_for_log(self, text: str, timeout: float = 60, count: int = 1,
                     container: Optional[str] = None) -> str:
        container = container or self.agent()
        return wait_until(
            lambda: (lambda log: log if log.count(text) >= count else None)(self.logs(container)),
            timeout, f"the agent logging {text!r}",
        )

    def read_data(self, name: str) -> Optional[str]:
        """A file of the agent's data folder (also of a stopped container), None when missing."""
        with tempfile.TemporaryDirectory() as folder:
            result = self.docker.run(
                "cp", f"{self.agent()}:{self.DATA}/{name}", folder, check=False
            )
            if result.returncode != 0:
                return None
            return (Path(folder) / name).read_text()

    def write_data(self, name: str, text: str) -> None:
        """Writes a file into the agent's data folder (also of a stopped container)."""
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / name
            path.write_text(text)
            self.docker.run("cp", str(path), f"{self.agent()}:{self.DATA}/{name}")

    def data_files(self) -> list:
        with tempfile.TemporaryDirectory() as folder:
            self.docker.run("cp", f"{self.agent()}:{self.DATA}/.", folder)
            return sorted(os.listdir(folder))

    # The logs of the containers that come and go.

    def _follow(self, container: str, path: Path) -> tuple:
        """`docker logs --follow` of a container into path, a new file: a follow writes the whole
        log from the container's start, and a late one (the container being removed) writes only
        an error, which must not replace what an earlier one got."""
        out = open(path, "wb")
        process = subprocess.Popen(
            ["docker", "logs", "--follow", container], env=self.docker.env,
            stdin=subprocess.DEVNULL, stdout=out, stderr=out,
        )
        return process, path, out

    def _watch(self) -> None:
        while not self._stop.is_set():
            listing = self.docker.run(
                "ps", "-a", "--no-trunc", "--format",
                '{{.ID}} {{.State}} {{.Names}} {{.Label "com.docker.compose.service"}}',
                check=False, timeout=30,
            )
            for line in listing.stdout.splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue
                container, state = parts[0], parts[1]
                with self._lock:
                    entry = self._logs.get(container)
                if entry is not None:
                    kind, number, follows = entry
                    # A follow started before the container ran ends at once: again while it
                    # runs.
                    if (follows[-1][0].poll() is not None and state == "running"
                            and len(follows) < self.FOLLOWS):
                        path = self.folder / f"log-{number}-{kind}-{len(follows)}.txt"
                        with self._lock:
                            follows.append(self._follow(container, path))
                    continue
                if parts[2] == self.APPLY:
                    kind = "apply"
                elif len(parts) == 4 and parts[3] == self.AGENT_SERVICE:
                    kind = "agent"
                else:
                    continue
                number = len(self._order)
                follow = self._follow(container, self.folder / f"log-{number}-{kind}-0.txt")
                with self._lock:
                    self._logs[container] = (kind, number, [follow])
                    self._order.append(container)
            self._stop.wait(0.3)

    def _collected(self, kind: str, timeout: float) -> list:
        """[(container ID, log)] of the containers of a kind, in the order they appeared: the log
        docker has of a container that still exists, else the longest of those followed (once
        complete, up to timeout)."""
        with self._lock:
            entries = [(c, self._logs[c][0], list(self._logs[c][2])) for c in self._order]
        logs = []
        for container, entry_kind, follows in entries:
            if entry_kind != kind:
                continue
            now = self.docker.run("logs", container, check=False)
            if now.returncode == 0:
                logs.append((container, now.stdout + now.stderr))
                continue
            texts = []
            for process, path, _ in follows:
                try:
                    process.wait(timeout)
                except subprocess.TimeoutExpired:
                    pass
                texts.append(path.read_text(errors="replace"))
            logs.append((container, max(texts, key=len)))
        return logs

    def agent_logs(self, timeout: float = 15) -> list:
        """[(container ID, log)] of every agent container so far."""
        return self._collected("agent", timeout)

    def apply_logs(self, timeout: float = 15) -> list:
        """[(container ID, log)] of every firmline-apply container so far."""
        return self._collected("apply", timeout)

    def close(self) -> None:
        self._stop.set()
        if self._watcher is not None:
            self._watcher.join(30)
        for _, _, follows in self._logs.values():
            for process, _, out in follows:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                out.close()
