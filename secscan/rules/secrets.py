from __future__ import annotations

import math
import re

from secscan.models import Finding

SECRET_PATTERNS = [
    ("SEC-SECRET-001", re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]"), "high"),
    ("SEC-SECRET-002", re.compile(r"(?i)password\s*[:=]\s*['\"][^'\"]{6,}['\"]"), "high"),
    ("SEC-SECRET-003", re.compile(r"AKIA[0-9A-Z]{16}"), "critical"),
    ("SEC-SECRET-004", re.compile(r"ghp_[A-Za-z0-9]{30,}"), "critical"),
]

STRING_CANDIDATE = re.compile(r"['\"]([A-Za-z0-9+/=_\-]{20,})['\"]")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    probs = [value.count(ch) / len(value) for ch in set(value)]
    return -sum(p * math.log2(p) for p in probs)


def scan_secrets_file(rel_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, start=1):
        for rule_id, pattern, severity in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        id=rule_id,
                        title="Potential Hardcoded Secret",
                        description="String pattern resembles a credential or secret material.",
                        severity=severity,
                        confidence="high",
                        file=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line.strip()[:300],
                        owasp_category="A02:2021-Cryptographic Failures",
                        remediation=[
                            "Move secrets to environment variables or a secret manager.",
                            "Rotate exposed credentials and audit access logs.",
                            "Add pre-commit/CI secret scanning to block regressions.",
                        ],
                    )
                )

        for match in STRING_CANDIDATE.finditer(line):
            candidate = match.group(1)
            if len(candidate) >= 20 and shannon_entropy(candidate) >= 3.8:
                findings.append(
                    Finding(
                        id="SEC-SECRET-ENTROPY",
                        title="High-Entropy String Detected",
                        description="A high-entropy literal may represent embedded secret material.",
                        severity="medium",
                        confidence="low",
                        file=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line.strip()[:300],
                        owasp_category="A02:2021-Cryptographic Failures",
                        remediation=[
                            "Review whether this literal is sensitive material.",
                            "If sensitive, move to secure secret storage and rotate.",
                            "Suppress via baseline only after manual validation.",
                        ],
                    )
                )
    return findings
