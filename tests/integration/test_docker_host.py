# SPDX-License-Identifier: Apache-2.0
"""The Docker daemon of the tests (docker_host.py): it answers, it builds the test images without
a base image, it cannot pull anything, and reset() leaves only the images it built."""

import tempfile
import unittest
from pathlib import Path

from docker_host import docker_host
from harness import wait_until

ID = r"^sha256:[0-9a-f]{64}$"


class DockerHostTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docker = docker_host()

    def setUp(self):
        self.addCleanup(self.docker.reset)

    def state(self, container: str, field: str = "{{.State.Status}}") -> str:
        return self.docker.run("inspect", container, "--format", field).stdout.strip()

    def image_id(self, reference: str) -> str:
        return self.docker.run("image", "inspect", reference, "--format", "{{.Id}}").stdout.strip()

    def copy_out(self, container: str, path: str) -> bytes:
        """The content of a file of a (created or stopped) container."""
        with tempfile.TemporaryDirectory() as folder:
            self.docker.run("cp", f"{container}:{path}", folder)
            return (Path(folder) / Path(path).name).read_bytes()

    def test_the_daemon_answers(self):
        version = self.docker.run("version", "--format", "{{.Server.Version}}").stdout.strip()
        self.assertRegex(version, r"^\d+\.\d+")

    def test_an_application_that_stays_runs_with_its_tag_in_version(self):
        image = self.docker.app_image("app:1", "stay")
        self.assertRegex(image, ID)
        self.docker.run("run", "-d", "--name", "app-stay", "app:1")
        self.assertEqual("running", self.state("app-stay"))
        self.assertEqual("app:1\n", self.docker.run("exec", "app-stay", "cat", "/version").stdout)

    def test_two_tags_are_two_images_and_a_tag_is_built_once(self):
        first = self.docker.app_image("app:1", "stay")
        self.assertEqual(first, self.docker.app_image("app:1", "stay"))
        self.assertNotEqual(first, self.docker.app_image("app:2", "stay"))

    def test_an_application_that_dies_exits_1_after_its_seconds(self):
        image = self.docker.app_image("app:die", "die:5")
        self.docker.run("run", "-d", "--name", "app-die", image)
        self.assertEqual("running", self.state("app-die"))
        self.assertEqual("1", self.docker.run("wait", "app-die", timeout=30).stdout.strip())

    def test_healthchecks_say_healthy_and_unhealthy(self):
        for behaviour in ("healthy", "unhealthy"):
            image = self.docker.app_image(f"app:{behaviour}", behaviour)
            self.docker.run("run", "-d", "--name", f"app-{behaviour}", image)
            wait_until(
                lambda: self.state(f"app-{behaviour}", "{{.State.Health.Status}}") == behaviour,
                timeout=30,
                what=f"the healthcheck saying {behaviour}",
            )

    def test_an_unknown_behaviour_is_refused(self):
        for behaviour in ("walk", "die:", "die:x"):
            with self.assertRaises(ValueError):
                self.docker.app_image("app:bad", behaviour)

    def test_nothing_can_be_pulled(self):
        before = len(self.docker.log())
        result = self.docker.run("pull", "busybox", check=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("127.0.0.1:9", result.stderr)  # the proxy that refuses every connection
        self.assertEqual("", self.docker.run("images", "-q", "busybox").stdout)
        # A pull attempt leaves this line in the daemon's log: the tests that must not pull look
        # for it in the part of log() written while they ran.
        self.assertIn("POST /v1.", self.docker.log()[before:])
        self.assertIn("/images/create returned error", self.docker.log()[before:])

    def test_the_agent_image_runs_the_agent_docker_compose_tar_and_gzip(self):
        image = self.docker.agent_image("agent:1")
        self.assertRegex(image, ID)
        version = self.docker.run("run", "--rm", image, "--version").stdout
        self.assertRegex(version, r"^firmline-agent \S+\n$")
        socket = f"{self.docker.socket}:/var/run/docker.sock"
        server = self.docker.run(
            "run", "--rm", "-v", socket, "--entrypoint", "docker", image,
            "version", "--format", "{{.Server.Version}}",
        ).stdout
        self.assertRegex(server, r"^\d+\.\d+")  # the CLI in the image drives the daemon
        compose = self.docker.run(
            "run", "--rm", "--entrypoint", "docker", image, "compose", "version"
        )
        self.assertIn("Docker Compose version", compose.stdout)
        for tool in ("tar", "gzip"):
            self.docker.run("run", "--rm", "--entrypoint", tool, image, "--version")

    def test_the_agent_image_has_ca_certificates_its_tag_and_the_image_settings(self):
        image = self.docker.agent_image("agent:1")
        self.assertNotEqual(image, self.docker.agent_image("agent:2"))
        self.docker.run("create", "--name", "agent-files", image)
        self.assertEqual(
            Path("/etc/ssl/certs/ca-certificates.crt").read_bytes(),
            self.copy_out("agent-files", "/etc/ssl/certs/ca-certificates.crt"),
        )
        self.assertEqual(b"agent:1\n", self.copy_out("agent-files", "/version"))
        config = self.docker.run(
            "image", "inspect", image, "--format",
            "{{json .Config.Entrypoint}} {{json .Config.Cmd}} {{json .Config.Volumes}}",
        ).stdout.strip()
        self.assertEqual(
            '["firmline-agent"] ["run","--wait-registration"] {"/var/lib/firmline":{}}', config
        )

    def test_reset_removes_containers_networks_volumes_and_other_images(self):
        kept = self.docker.app_image("app:1", "stay")
        self.docker.run("run", "-d", "--name", "app-running", kept)
        self.docker.run("tag", kept, "firmline.local/app:1")  # a second name of a built image
        self.docker.run("commit", "app-running", "other:1")  # an image the host did not build
        self.docker.run("network", "create", "torizon_default")
        self.docker.run("volume", "create", "torizon_data")

        self.docker.reset()

        self.assertEqual("", self.docker.run("ps", "-aq").stdout)
        self.assertEqual("", self.docker.run("images", "-q", "other:1").stdout)
        self.assertEqual("", self.docker.run("images", "-q", "firmline.local/app").stdout)
        self.assertEqual(kept, self.image_id("app:1"))
        networks = self.docker.run("network", "ls", "-q", "--filter", "name=torizon").stdout
        self.assertEqual("", networks)
        self.assertEqual("", self.docker.run("volume", "ls", "-q").stdout)

    def test_an_image_removed_by_a_test_is_built_again(self):
        first = self.docker.app_image("app:1", "stay")
        self.docker.run("rmi", "-f", first)
        again = self.docker.app_image("app:1", "stay")
        self.assertEqual(again, self.image_id("app:1"))


if __name__ == "__main__":
    unittest.main()
