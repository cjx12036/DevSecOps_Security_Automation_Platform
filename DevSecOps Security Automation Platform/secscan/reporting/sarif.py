from __future__ import annotations

from collections import OrderedDict

RULE_MAP = {
    "SEC-SQLI-001": "sql-injection",
    "SEC-XSS-001": "xss-reflected",
    "SEC-XSS-002": "xss-template",
    "SEC-SSRF-001": "ssrf",
    "SEC-SECRET-001": "hardcoded-secret",
    "SEC-SECRET-002": "hardcoded-password",
    "SEC-SECRET-003": "aws-key",
    "SEC-SECRET-004": "github-token",
    "SEC-SECRET-ENTROPY": "high-entropy-secret",
    "SEC-DESER-001": "insecure-deserialization-pickle",
    "SEC-DESER-002": "insecure-deserialization-yaml",
    "SEC-CMDI-001": "command-injection",
}

SARIF_LEVEL = {"low": "note", "medium": "warning", "high": "error", "critical": "error"}


def to_sarif(findings: list[dict]) -> dict:
    rules = OrderedDict()
    results = []
    for finding in findings:
        rid = finding["id"]
        rules[rid] = {
            "id": rid,
            "name": RULE_MAP.get(rid, rid.lower()),
            "shortDescription": {"text": finding["title"]},
            "fullDescription": {"text": finding["description"]},
            "help": {"text": " ".join(finding["remediation"])},
            "properties": {"security-severity": finding["severity"], "owasp": finding["owasp_category"]},
        }
        results.append(
            {
                "ruleId": rid,
                "level": SARIF_LEVEL.get(finding["severity"], "warning"),
                "message": {"text": finding["title"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding["file"]},
                            "region": {"startLine": finding["line_start"], "endLine": finding["line_end"]},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secscan",
                        "version": "0.1.0",
                        "informationUri": "https://owasp.org/www-project-top-ten/",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
