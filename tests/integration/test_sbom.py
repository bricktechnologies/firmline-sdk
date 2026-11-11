# SPDX-License-Identifier: Apache-2.0
"""scripts/sbom-components.sh: the components Syft cannot see (the agent, Mbed TLS linked
statically, jsmn vendored) are added to a CycloneDX SBOM with the versions of the tree. A version
the script cannot read fails this test, so a change of cmake/mbedtls.cmake or of the vendored jsmn
that the release workflow would not describe fails the local check and CI."""

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "sbom-components.sh"


def minimal_sbom() -> dict:
    """What Syft writes, cut down: one component of its own."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {"bom-ref": "pkg:deb/debian/libssl3t64@3.5.1", "type": "library", "name": "libssl3t64"}
        ],
    }


def tree_versions() -> tuple:
    """The versions as the tree states them: the Mbed TLS release tarball, the jsmn VERSION file."""
    cmake = (ROOT / "cmake" / "mbedtls.cmake").read_text()
    mbedtls = re.search(r"/mbedtls-(\d+\.\d+\.\d+)\.tar\.", cmake).group(1)
    jsmn = (ROOT / "core" / "third_party" / "jsmn" / "VERSION").read_text().strip()
    return mbedtls, jsmn


class SbomComponentsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def run_script(self, sbom: Path, version: str, script: Path = SCRIPT):
        return subprocess.run(
            ["bash", str(script), str(sbom), version], capture_output=True, text=True, timeout=60
        )

    def write_sbom(self, content=None) -> Path:
        path = self.tmp / "sbom.cdx.json"
        path.write_text(json.dumps(content or minimal_sbom()))
        return path

    def test_adds_the_agent_mbedtls_and_jsmn_once(self):
        mbedtls, jsmn = tree_versions()
        self.assertEqual("1.1.0", jsmn)
        sbom = self.write_sbom()

        for _ in range(2):  # a second run changes nothing
            result = self.run_script(sbom, "1.2.3")
            self.assertEqual(0, result.returncode, result.stderr)

        components = json.loads(sbom.read_text())["components"]
        self.assertEqual(4, len(components), components)
        self.assertEqual("libssl3t64", components[0]["name"], "Syft's components stay")
        ours = {c["name"]: c for c in components[1:]}
        self.assertEqual(
            {
                "bom-ref": "firmline-sdk/firmline-agent",
                "type": "application",
                "name": "firmline-agent",
                "version": "1.2.3",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "purl": "pkg:github/bricktechnologies/firmline-sdk@v1.2.3",
            },
            ours["firmline-agent"],
        )
        self.assertEqual(
            {
                "bom-ref": "firmline-sdk/mbedtls",
                "type": "library",
                "name": "mbedtls",
                "version": mbedtls,
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "purl": f"pkg:github/Mbed-TLS/mbedtls@v{mbedtls}",
                "cpe": f"cpe:2.3:a:arm:mbed_tls:{mbedtls}:*:*:*:*:*:*:*",
            },
            ours["mbedtls"],
        )
        self.assertEqual(
            {
                "bom-ref": "firmline-sdk/jsmn",
                "type": "library",
                "name": "jsmn",
                "version": jsmn,
                "licenses": [{"license": {"id": "MIT"}}],
                "purl": f"pkg:github/zserge/jsmn@v{jsmn}",
            },
            ours["jsmn"],
        )

    def test_sbom_without_components_gets_them(self):
        content = minimal_sbom()
        del content["components"]
        sbom = self.write_sbom(content)
        result = self.run_script(sbom, "0.0.0-dev")
        self.assertEqual(0, result.returncode, result.stderr)
        names = [c["name"] for c in json.loads(sbom.read_text())["components"]]
        self.assertEqual(["firmline-agent", "mbedtls", "jsmn"], names)

    def copy_tree(self) -> Path:
        """The files the script reads, in a tree of its own that a test may break."""
        tree = self.tmp / "tree"
        for name in ("scripts/sbom-components.sh", "cmake/mbedtls.cmake", "core/third_party/jsmn/VERSION"):
            (tree / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / name, tree / name)
        return tree

    def assert_refused(self, tree: Path, message: str):
        sbom = self.write_sbom()
        before = sbom.read_text()
        result = self.run_script(sbom, "1.2.3", tree / "scripts" / "sbom-components.sh")
        self.assertEqual(1, result.returncode)
        self.assertIn(message, result.stderr)
        self.assertEqual(before, sbom.read_text(), "the SBOM is left as it was")

    def test_unreadable_mbedtls_version_fails(self):
        tree = self.copy_tree()
        cmake = tree / "cmake" / "mbedtls.cmake"
        cmake.write_text(re.sub(r"mbedtls-\d+\.\d+\.\d+\.tar", "mbedtls-latest.tar", cmake.read_text()))
        self.assert_refused(tree, "cannot read the Mbed TLS version")

    def test_unreadable_jsmn_version_fails(self):
        tree = self.copy_tree()
        (tree / "core" / "third_party" / "jsmn" / "VERSION").unlink()
        self.assert_refused(tree, "cannot read the jsmn version")

    def test_bad_agent_version_or_document_fails(self):
        sbom = self.write_sbom()
        result = self.run_script(sbom, "v1.2")
        self.assertEqual(1, result.returncode)
        self.assertIn("is not a version", result.stderr)

        sbom.write_text('{"bomFormat": "SPDX"}')
        result = self.run_script(sbom, "1.2.3")
        self.assertEqual(1, result.returncode)
        self.assertEqual('{"bomFormat": "SPDX"}', sbom.read_text())


if __name__ == "__main__":
    unittest.main()
