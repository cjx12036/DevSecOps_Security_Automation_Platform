from __future__ import annotations

import unittest

from secscan.reporting.sarif import to_sarif


class SarifTests(unittest.TestCase):
    def test_sarif_has_expected_shape(self):
        findings = [
            {
                "id": "SEC-SQLI-001",
                "title": "Potential SQL Injection",
                "description": "desc",
                "severity": "high",
                "confidence": "high",
                "file": "demo_app/app.py",
                "line_start": 10,
                "line_end": 10,
                "code_snippet": "cur.execute(...)",
                "owasp_category": "A03:2021-Injection",
                "remediation": ["a", "b", "c"],
            }
        ]
        sarif = to_sarif(findings)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "SEC-SQLI-001")
        self.assertEqual(
            sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"],
            "8.0",
        )


if __name__ == "__main__":
    unittest.main()
