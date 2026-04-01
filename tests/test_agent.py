from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from secscan.agent import run_agent_pipeline


class AgentTests(unittest.TestCase):
    def test_agent_writes_expected_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "demo"
            out = root / "artifacts"
            src.mkdir(parents=True)
            (src / "app.py").write_text(
                """
import subprocess

def run(cmd):
    subprocess.run(cmd, shell=True)
""",
                encoding="utf-8",
            )
            run_agent_pipeline(
                path=str(src),
                out_dir=str(out),
                exclude=[],
                severity_threshold="low",
                sast_engine="legacy",
                secrets_engine="legacy",
            )

            for name in ["sast.json", "secrets.json", "findings.json", "sast.sarif", "secrets.sarif", "report.html"]:
                self.assertTrue((out / name).exists(), f"missing output file: {name}")

            findings = json.loads((out / "findings.json").read_text(encoding="utf-8")).get("findings", [])
            self.assertTrue(any(f.get("id") == "SEC-CMDI-001" for f in findings))


if __name__ == "__main__":
    unittest.main()
