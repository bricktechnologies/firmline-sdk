# SPDX-License-Identifier: Apache-2.0
"""The runtime image: skipped unless FIRMLINE_IMAGE names a built image (for example
FIRMLINE_IMAGE=firmline-agent:dev python3 -m unittest tests/integration/test_image.py, after
docker build -f linux/Dockerfile -t firmline-agent:dev .)."""

import os
import subprocess
import unittest

IMAGE = os.environ.get("FIRMLINE_IMAGE")


@unittest.skipUnless(IMAGE, "FIRMLINE_IMAGE is not set")
class ImageTest(unittest.TestCase):
    def docker_run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["docker", "run", "--rm", IMAGE, *args],
            capture_output=True,
            text=True,
            timeout=120,
        )

    def test_image_prints_usage_and_runs_as_documented(self):
        result = self.docker_run("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        for command in ("register", "run", "status", "endpoint"):
            self.assertIn(command, result.stdout)

    def test_image_says_its_version(self):
        result = self.docker_run("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"^firmline-agent \S+\n$")

    def test_image_declares_its_data_folder_and_labels(self):
        inspect = subprocess.run(
            ["docker", "image", "inspect", IMAGE, "--format",
             "{{json .Config.Volumes}} {{index .Config.Labels \"org.opencontainers.image.licenses\"}}"
             " {{json .Config.Entrypoint}} {{json .Config.Cmd}}"],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(inspect.returncode, 0, inspect.stderr)
        self.assertEqual(
            inspect.stdout.strip(),
            '{"/var/lib/firmline":{}} Apache-2.0 ["firmline-agent"] ["run"]',
        )


if __name__ == "__main__":
    unittest.main()
