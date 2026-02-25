from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from secscan.scanners import run_sast, run_secrets


class RuleTests(unittest.TestCase):
    def _write(self, root: Path, name: str, content: str) -> None:
        (root / name).write_text(content, encoding="utf-8")

    def test_detects_sql_injection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(
                root,
                "vuln.py",
                """
def f(user, cur):
    cur.execute(f\"SELECT * FROM users WHERE id={user}\")
""",
            )
            findings = run_sast(str(root), [])
            self.assertTrue(any(f.id == "SEC-SQLI-001" for f in findings))

    def test_detects_ssrf(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(
                root,
                "vuln.py",
                """
import requests
from flask import request

def f():
    u = request.args.get('u')
    return requests.get(u)
""",
            )
            findings = run_sast(str(root), [])
            self.assertTrue(any(f.id == "SEC-SSRF-001" for f in findings))

    def test_detects_command_injection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(
                root,
                "vuln.py",
                """
import subprocess
from flask import request

def f():
    cmd = request.args.get('cmd')
    subprocess.run(cmd, shell=True)
""",
            )
            findings = run_sast(str(root), [])
            self.assertTrue(any(f.id == "SEC-CMDI-001" for f in findings))

    def test_detects_insecure_deserialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(
                root,
                "vuln.py",
                """
import pickle

def f(data):
    return pickle.loads(data)
""",
            )
            findings = run_sast(str(root), [])
            self.assertTrue(any(f.id == "SEC-DESER-001" for f in findings))

    def test_detects_hardcoded_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(root, "secret.py", 'API_KEY = "AKIA1234567890ABCD12"\n')
            findings = run_secrets(str(root), [])
            self.assertTrue(any(f.id.startswith("SEC-SECRET") for f in findings))


if __name__ == "__main__":
    unittest.main()
