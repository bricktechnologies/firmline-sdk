# SPDX-License-Identifier: Apache-2.0
"""The agent version given to the build (FIRMLINE_AGENT_VERSION, the image build argument VERSION)
is sent in the sdk field of every status: a value the platform rule refuses would silently stop
all status messages, so the configure step refuses it. cmake/agent-version.cmake is the check
linux/CMakeLists.txt includes; it is run alone here, which needs no download."""

import pathlib
import shutil
import subprocess
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
CHECK = REPO / "cmake" / "agent-version.cmake"


@unittest.skipUnless(shutil.which("cmake"), "cmake is not installed")
class AgentVersionTest(unittest.TestCase):
    def check(self, version: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["cmake", f"-DFIRMLINE_AGENT_VERSION={version}", "-P", str(CHECK)],
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_release_versions_are_accepted(self):
        for version in ("1.2.3", "1.2.3-rc.1", "0.0.0-dev", "1.2.3+build.7", "x" * 49):
            with self.subTest(version=version):
                result = self.check(version)
                self.assertEqual(0, result.returncode, result.stderr)

    def test_versions_the_platform_would_refuse_stop_the_configure(self):
        for version in ("1.0 beta", " 1.0", "1/2", "x" * 50, "", "1\t2", 'a"b', "a\b"):
            with self.subTest(version=version):
                result = self.check(version)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("FIRMLINE_AGENT_VERSION", result.stderr)
                self.assertIn("1 to 49", result.stderr)


if __name__ == "__main__":
    unittest.main()
