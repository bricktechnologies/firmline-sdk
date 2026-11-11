# SPDX-License-Identifier: Apache-2.0
"""firmline-agent pack --compose <file> --version <v> --output <file.tar>: the package of a Docker
Compose application, built with the images of the local daemon (never pulled). The tar holds
exactly firmline-package.json, docker-compose.yml (every image renamed
firmline.local/<service>:<tag>, <tag> being <v> made a Docker tag, with pull_policy: never) and
images.tar.gz (docker save, gzip -n). Any refusal is exit 1 with one error line, no output file
and no temporary folder left."""

import gzip
import json
import os
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

from docker_host import docker_host
from harness import AGENT_BINARY, SANITIZER_MARKERS, wait_until

MEMBERS = ["firmline-package.json", "docker-compose.yml", "images.tar.gz"]
VERSION = "1.2.0"
TWO_SERVICES = """\
services:
  web:
    image: example/web:1
    restart: unless-stopped
    volumes:
      - data:/data
  db:
    image: example/db:1
    build: ./db
volumes:
  data: {}
"""


class PackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docker = docker_host()

    def setUp(self):
        self.addCleanup(self.docker.reset)
        self.folder = Path(tempfile.mkdtemp(prefix="firmline-pack-test-"))
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.out = self.folder / "out"
        self.out.mkdir()
        self.output = self.out / "app.tar"

    def composition(self, text: str) -> Path:
        app = self.folder / "app"
        (app / "db").mkdir(parents=True, exist_ok=True)
        path = app / "docker-compose.yml"
        path.write_text(text)
        return path

    def pack(self, compose: Path, version: str = VERSION, env=None, timeout: float = 300):
        result = subprocess.run(
            [AGENT_BINARY, "pack", "--compose", str(compose), "--version", version,
             "--output", str(self.output)],
            env=env or self.docker.env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=timeout,
        )
        for marker in SANITIZER_MARKERS:
            self.assertNotIn(marker, result.stderr)
        return result

    def image_id(self, reference: str) -> str:
        return self.docker.run("image", "inspect", reference, "--format", "{{.Id}}").stdout.strip()

    def assert_refused(self, result, *words: str) -> str:
        """Exit 1, one error line (the last), no output file and nothing left next to it."""
        self.assertEqual(1, result.returncode, result.stderr)
        errors = [line for line in result.stderr.splitlines() if line.startswith("error ")]
        self.assertEqual(1, len(errors), result.stderr)
        self.assertEqual(errors[0], result.stderr.splitlines()[-1])
        for word in words:
            self.assertIn(word, errors[0])
        self.assertEqual([], os.listdir(self.out))
        return errors[0]

    def two_images(self):
        return self.docker.app_image("example/web:1", "stay"), self.docker.app_image(
            "example/db:1", "healthy")

    def test_a_package_of_two_services(self):
        web, db = self.two_images()
        self.output.write_text("an older package, replaced")
        result = self.pack(self.composition(TWO_SERVICES))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)
        self.assertEqual(["app.tar"], os.listdir(self.out))  # the temporary folder is gone

        unpacked = self.folder / "unpacked"
        with tarfile.open(self.output) as tar:
            self.assertEqual(MEMBERS, tar.getnames())
            self.assertTrue(all(member.isfile() for member in tar.getmembers()))
            self.assertEqual({0o644}, {member.mode for member in tar.getmembers()})
            tar.extractall(unpacked, filter="data")

        description = json.loads((unpacked / "firmline-package.json").read_text())
        architecture = self.docker.run(
            "image", "inspect", web, "--format", "{{.Architecture}}").stdout.strip()
        self.assertEqual(
            {
                "format": 1,
                "architecture": architecture,
                "version": VERSION,
                "images": [
                    {"service": "db", "image": f"firmline.local/db:{VERSION}", "id": db},
                    {"service": "web", "image": f"firmline.local/web:{VERSION}", "id": web},
                ],
            },
            {**description, "images": sorted(description["images"], key=lambda i: i["service"])},
        )

        # The composition, read back by Compose: the new names, never pulled, no build left; the
        # rest as written (the volume keeps its own name: the device's project names it).
        rendered = self.docker.run(
            "compose", "-f", str(unpacked / "docker-compose.yml"), "config", "--format", "json",
        ).stdout
        services = json.loads(rendered)["services"]
        self.assertEqual({"web", "db"}, set(services))
        for name in ("web", "db"):
            self.assertEqual(f"firmline.local/{name}:{VERSION}", services[name]["image"])
            self.assertEqual("never", services[name]["pull_policy"])
            self.assertNotIn("build", services[name])
        self.assertEqual("unless-stopped", services["web"]["restart"])
        self.assertEqual("data", services["web"]["volumes"][0]["source"])
        written = (unpacked / "docker-compose.yml").read_text()
        self.assertNotIn("example/", written)
        self.assertNotIn(str(self.folder), written)  # no path of the build machine

        # gzip -n: no name and no time in the header.
        header = (unpacked / "images.tar.gz").read_bytes()[:10]
        self.assertEqual(b"\x1f\x8b", header[:2])
        self.assertEqual(0, header[3] & 0x08)  # FNAME
        self.assertEqual(b"\0\0\0\0", header[4:8])  # MTIME

        # The images load into a daemon that has none of them, with the two names.
        self.docker.run("rmi", "-f", web, db)
        self.assertEqual("", self.docker.run("images", "-q", "--no-trunc", web).stdout.strip())
        self.docker.run("load", "-i", str(unpacked / "images.tar.gz"), timeout=300)
        self.assertEqual(web, self.image_id(f"firmline.local/web:{VERSION}"))
        self.assertEqual(db, self.image_id(f"firmline.local/db:{VERSION}"))

    def test_a_service_with_build_and_no_image_is_refused(self):
        self.docker.app_image("example/web:1", "stay")
        compose = self.composition(
            "services:\n  web:\n    image: example/web:1\n  tool:\n    build: ./db\n")
        self.assert_refused(self.pack(compose), "tool", "image")

    def test_an_image_not_present_locally_is_refused_and_not_pulled(self):
        self.docker.app_image("example/web:1", "stay")
        compose = self.composition(
            "services:\n  web:\n    image: example/web:1\n  db:\n    image: example/absent:1\n")
        before = len(self.docker.log())
        self.assert_refused(self.pack(compose), "example/absent:1", "db")
        self.assertNotIn("POST /v1.", self.docker.log()[before:])

    def test_images_of_two_architectures_are_refused(self):
        self.docker.app_image("example/web:1", "stay")
        rootfs = self.folder / "rootfs.tar"
        with tarfile.open(rootfs, "w") as tar:
            info = tarfile.TarInfo("hello")
            info.size = 0
            tar.addfile(info)
        self.docker.run("import", "--platform", "linux/arm64", str(rootfs), "example/arm:1")
        compose = self.composition(
            "services:\n  web:\n    image: example/web:1\n  arm:\n    image: example/arm:1\n")
        self.assert_refused(self.pack(compose), "arm64", "architecture")

    def test_a_version_invalid_as_fw_is_refused(self):
        compose = self.composition(TWO_SERVICES)
        self.two_images()
        for version in ("1" * 65, "1.0\tbeta", "1.0\x7f", " 1.0", "1.0 "):
            with self.subTest(version=version):
                self.assert_refused(self.pack(compose, version=version), "version")

    def test_a_version_that_is_not_a_docker_tag_gets_a_local_tag(self):
        """The platform's own example version: the images are tagged with the version made a
        Docker tag (every other character `_`), the description keeps the version itself."""
        version, tag = "1.4.3+build.7", "1.4.3_build.7"
        web, db = self.two_images()
        result = self.pack(self.composition(TWO_SERVICES), version=version)
        self.assertEqual(0, result.returncode, result.stderr)
        unpacked = self.folder / "unpacked"
        with tarfile.open(self.output) as tar:
            self.assertEqual(MEMBERS, tar.getnames())
            tar.extractall(unpacked, filter="data")
        description = json.loads((unpacked / "firmline-package.json").read_text())
        self.assertEqual(version, description["version"])
        self.assertEqual(
            [{"service": "db", "image": f"firmline.local/db:{tag}", "id": db},
             {"service": "web", "image": f"firmline.local/web:{tag}", "id": web}],
            sorted(description["images"], key=lambda i: i["service"]),
        )
        rendered = self.docker.run(
            "compose", "-f", str(unpacked / "docker-compose.yml"), "config", "--format", "json",
        ).stdout
        services = json.loads(rendered)["services"]
        for name in ("web", "db"):
            self.assertEqual(f"firmline.local/{name}:{tag}", services[name]["image"])
        self.docker.run("rmi", "-f", web, db)
        self.docker.run("load", "-i", str(unpacked / "images.tar.gz"), timeout=300)
        self.assertEqual(web, self.image_id(f"firmline.local/web:{tag}"))
        self.assertEqual(db, self.image_id(f"firmline.local/db:{tag}"))

    def test_more_than_sixteen_services_are_refused(self):
        self.docker.app_image("example/web:1", "stay")
        services = "".join(f"  s{i}:\n    image: example/web:1\n" for i in range(17))
        self.assert_refused(self.pack(self.composition(f"services:\n{services}")), "16")

    def test_a_service_name_that_cannot_be_an_image_name_is_refused(self):
        self.docker.app_image("example/web:1", "stay")
        compose = self.composition("services:\n  Web:\n    image: example/web:1\n")
        self.assert_refused(self.pack(compose), "Web")

    def test_a_composition_compose_refuses_is_refused(self):
        self.assert_refused(self.pack(self.composition("services: [\n")), "compose")
        self.assert_refused(self.pack(self.folder / "missing.yml"), "compose")

    def test_a_refusal_leaves_an_existing_output_alone(self):
        self.output.write_text("the previous package")
        result = self.pack(self.composition(TWO_SERVICES), version="1" * 65)
        self.assertEqual(1, result.returncode)
        self.assertEqual("the previous package", self.output.read_text())
        self.assertEqual(["app.tar"], os.listdir(self.out))

    def test_usage_errors_exit_1(self):
        compose = self.composition(TWO_SERVICES)
        for arguments in (
            [],
            ["--compose", str(compose), "--version", VERSION],
            ["--compose", str(compose), "--output", str(self.output)],
            ["--version", VERSION, "--output", str(self.output)],
            ["--compose", str(compose), "--version", VERSION, "--output", str(self.output), "-x"],
            ["--compose", str(compose), "--compose", str(compose), "--version", VERSION,
             "--output", str(self.output)],
            ["--compose", str(compose), "--version", VERSION, "--output"],
            ["--compose", str(compose), "--version", VERSION, "--output", str(self.out)],
        ):
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    [AGENT_BINARY, "pack", *arguments], env=self.docker.env,
                    stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60,
                )
                self.assertEqual(1, result.returncode, result.stderr)
                self.assertTrue(result.stderr.strip(), "no message")
                self.assertEqual([], os.listdir(self.out))

    def test_an_interrupted_pack_leaves_nothing(self):
        """SIGTERM while `docker save` runs: the command is stopped, the temporary folder is
        removed, exit 1. A docker in front of the real one hangs on `save`."""
        self.two_images()
        wrapper = self.folder / "bin"
        wrapper.mkdir()
        marker = self.folder / "saving"
        (wrapper / "docker").write_text(
            "#!/bin/sh\n"
            f'if [ "$1" = save ]; then : > "{marker}"; sleep 60; fi\n'
            f'exec {shutil.which("docker")} "$@"\n'
        )
        (wrapper / "docker").chmod(0o755)
        env = dict(self.docker.env, PATH=f"{wrapper}:{os.environ['PATH']}")
        process = subprocess.Popen(
            [AGENT_BINARY, "pack", "--compose", str(self.composition(TWO_SERVICES)),
             "--version", VERSION, "--output", str(self.output)],
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        try:
            wait_until(marker.exists, timeout=60, what="docker save")
            started = time.monotonic()
            process.send_signal(signal.SIGTERM)
            _, stderr = process.communicate(timeout=20)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(1, process.returncode, stderr)
        self.assertIn("interrupted", stderr.splitlines()[-1])
        self.assertEqual([], os.listdir(self.out))


if __name__ == "__main__":
    unittest.main()
