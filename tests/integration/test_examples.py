# SPDX-License-Identifier: Apache-2.0
"""examples/torizon: the configuration loads in the agent, and the composition is one Docker
Compose accepts, with the agent service a Torizon device needs (a stop grace period long enough
for the agent to end what it follows, a restart policy, the socket and the composition folder)."""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from harness import AGENT_BINARY

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "torizon"
MIN_GRACE_S = 15


def seconds(value) -> float:
    """A Compose duration as `config --format json` writes it: nanoseconds, or "1m30s"."""
    if isinstance(value, (int, float)):
        return value / 1e9
    units = {"h": 3600, "m": 60, "s": 1, "ms": 0.001}
    parts = re.findall(r"(\d+(?:\.\d+)?)(ms|h|m|s)", str(value))
    if not parts or "".join(n + u for n, u in parts) != str(value):
        raise AssertionError(f"not a duration: {value!r}")
    return sum(float(n) * units[u] for n, u in parts)


class TorizonConfiguration(unittest.TestCase):
    def test_agent_conf_loads(self):
        text = (EXAMPLE / "agent.conf").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "data"
            conf = Path(tmp) / "agent.conf"
            # The data folder of the example is the device's: use a temporary one for the test.
            conf.write_text(text.replace("[platform]\n", f"[platform]\ndata_dir = {data}\n", 1))
            result = subprocess.run(
                [AGENT_BINARY, "status", "--config", str(conf)],
                capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(json.loads(result.stdout)["registered"])

    def test_agent_conf_has_the_components_of_a_torizon_device(self):
        text = (EXAMPLE / "agent.conf").read_text(encoding="utf-8")
        for line in ("serial = file:/run/firmline/serial-number", "version = os-release:VERSION_ID", "install = none",
                     "install = docker-compose", "version = package:1.0.0", "main = true"):
            self.assertIn(line, text)


@unittest.skipUnless(shutil.which("docker") or os.environ.get("FIRMLINE_REQUIRE_DOCKER"),
                     "no docker client")
class TorizonComposition(unittest.TestCase):
    def config(self) -> dict:
        result = subprocess.run(
            ["docker", "compose", "-f", str(EXAMPLE / "docker-compose.yml"), "config",
             "--format", "json"],
            capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        return json.loads(result.stdout)

    def test_the_composition_passes_docker_compose_config(self):
        self.assertIn("firmline-agent", self.config()["services"])

    def test_the_agent_service_has_a_long_enough_stop_grace_period(self):
        agent = self.config()["services"]["firmline-agent"]
        self.assertGreaterEqual(seconds(agent["stop_grace_period"]), MIN_GRACE_S)

    def test_the_agent_service_waits_for_the_registration_and_restarts(self):
        agent = self.config()["services"]["firmline-agent"]
        self.assertEqual(["run", "--wait-registration"], agent["command"])
        self.assertEqual("unless-stopped", agent["restart"])

    def test_the_agent_service_has_the_mounts_of_a_torizon_device(self):
        config = self.config()
        agent = config["services"]["firmline-agent"]
        mounts = {v["target"]: v for v in agent["volumes"]}
        self.assertEqual("volume", mounts["/var/lib/firmline"]["type"])
        self.assertIn("firmline-data", config["volumes"])
        self.assertEqual("/var/run/docker.sock", mounts["/var/run/docker.sock"]["source"])
        compose = "/var/sota/storage/docker-compose"
        self.assertEqual(compose, mounts[compose]["source"])
        self.assertTrue(mounts["/host/os-release"]["read_only"])
        self.assertTrue(mounts["/etc/firmline"]["read_only"])
        serial = mounts["/run/firmline/serial-number"]
        self.assertEqual("/sys/firmware/devicetree/base/serial-number", serial["source"])
        self.assertTrue(serial["read_only"])


if __name__ == "__main__":
    unittest.main()
