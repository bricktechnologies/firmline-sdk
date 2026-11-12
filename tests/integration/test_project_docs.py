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


class TorizonGuide(unittest.TestCase):
    def section(self) -> str:
        text = read("docs/integration.md")
        found = re.search(r"(?ms)^## Torizon$(.*?)(?=^## |\Z)", text)
        self.assertIsNotNone(found, "docs/integration.md has no '## Torizon'")
        return found.group(1)

    def test_the_section_names_what_a_torizon_engineer_needs(self):
        body = self.section()
        for word in ("pack", "apply", "--wait-registration", "docker exec", "stop_grace_period",
                     "health_timeout", "/var/run/docker.sock", "Torizon Cloud", "health_check_failed",
                     "install_failed", ".env"):
            self.assertIn(word, body)

    def test_the_guide_has_a_trial_check_list_for_a_toradex_module(self):
        self.assertRegex(read("docs/integration.md"),
                         r"(?m)^## Check list for a trial on a Toradex module")

    def test_the_data_folder_lists_the_files_of_apply(self):
        text = read("docs/integration.md")
        data = re.search(r"(?ms)^## Data folder$(.*?)(?=^## )", text).group(1)
        for name in ("apply.json", "package.json", "compose-previous.yml", "apply.tmp/"):
            self.assertIn(f"| `{name}` |", data)

    def test_the_guide_no_longer_says_docker_support_is_planned(self):
        text = read("docs/integration.md")
        self.assertNotRegex(text, r"(?i)planned and not part of this release")
        self.assertNotIn("does not install such a component yet", text)

    def test_the_readme_says_torizon_is_supported_and_how_the_check_runs_docker(self):
        text = read("README.md")
        self.assertRegex(text, r"(?i)Torizon")
        self.assertNotRegex(text, r"(?i)planned \(T179\)")
        self.assertIn("--privileged", text)
        self.assertIn("firmline-docker", text)


if __name__ == "__main__":
    unittest.main()
