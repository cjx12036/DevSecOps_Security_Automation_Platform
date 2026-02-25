from __future__ import annotations

import ast

from secscan.models import Finding
from secscan.rules.common import get_attr_chain, get_snippet


def detect_insecure_deserialization(tree: ast.AST, lines: list[str], rel_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = get_attr_chain(node.func)
        if fn in {"pickle.loads", "pickle.load"}:
            findings.append(
                Finding(
                    id="SEC-DESER-001",
                    title="Insecure Deserialization via pickle",
                    description="pickle deserialization can execute arbitrary code from untrusted input.",
                    severity="critical",
                    confidence="high",
                    file=rel_path,
                    line_start=getattr(node, "lineno", 1),
                    line_end=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                    code_snippet=get_snippet(lines, getattr(node, "lineno", 1), getattr(node, "end_lineno", getattr(node, "lineno", 1))),
                    owasp_category="A08:2021-Software and Data Integrity Failures",
                    remediation=[
                        "Avoid pickle for untrusted data.",
                        "Use JSON or a safe serialization format.",
                        "Authenticate and validate serialized payloads before processing.",
                    ],
                )
            )
        if fn == "yaml.load":
            loader_names = [get_attr_chain(kw.value) for kw in node.keywords if kw.arg == "Loader"]
            if "yaml.SafeLoader" not in loader_names:
                findings.append(
                    Finding(
                        id="SEC-DESER-002",
                        title="Unsafe yaml.load usage",
                        description="yaml.load without SafeLoader can instantiate arbitrary objects.",
                        severity="high",
                        confidence="high",
                        file=rel_path,
                        line_start=getattr(node, "lineno", 1),
                        line_end=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                        code_snippet=get_snippet(lines, getattr(node, "lineno", 1), getattr(node, "end_lineno", getattr(node, "lineno", 1))),
                        owasp_category="A08:2021-Software and Data Integrity Failures",
                        remediation=[
                            "Replace yaml.load with yaml.safe_load where possible.",
                            "If loader is required, use yaml.SafeLoader explicitly.",
                            "Validate schema of parsed data before use.",
                        ],
                    )
                )
    return findings
