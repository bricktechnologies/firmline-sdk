# SPDX-License-Identifier: Apache-2.0
"""SECURITY.md and README.md tell where a vulnerability is reported and which builds are the
official ones: a public SDK must say both before anyone integrates it."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPO = "https://github.com/bricktechnologies/firmline-sdk"
IMAGE = "ghcr.io/bricktechnologies/firmline-agent"


def read(name: str) -> str:
    path = ROOT / name
    if not path.is_file():
        raise AssertionError(f"{name} is missing")
    return path.read_text(encoding="utf-8")


class SecurityPolicy(unittest.TestCase):
    def test_reports_go_to_private_vulnerability_reporting(self):
        text = read("SECURITY.md")
        self.assertIn(f"{REPO}/security/advisories/new", text)
        self.assertRegex(text, r"(?i)do not open a public issue")

    def test_supported_versions_are_stated(self):
        self.assertRegex(read("SECURITY.md"), r"(?im)^## Supported versions$")

    def test_no_promise_of_response_times(self):
        # A deadline would be a commitment of Brkt, not of the document.
        self.assertNotRegex(read("SECURITY.md"), r"(?i)\b(within|entro)\s+\d+\s*(hours?|days?)\b")


class OfficialSources(unittest.TestCase):
    def test_readme_names_the_official_sources(self):
        text = read("README.md")
        section = re.search(r"(?ms)^## Official sources and support$(.*?)(?=^## |\Z)", text)
        self.assertIsNotNone(section, "README.md has no '## Official sources and support'")
        body = section.group(1)
        self.assertIn(REPO, body)
        self.assertIn(IMAGE, body)
        self.assertIn("SECURITY.md", body)
        self.assertRegex(body, r"(?i)trademark")


if __name__ == "__main__":
    unittest.main()
