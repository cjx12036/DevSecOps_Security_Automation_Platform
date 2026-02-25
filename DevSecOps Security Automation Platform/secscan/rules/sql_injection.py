from __future__ import annotations

import ast

from secscan.models import Finding
from secscan.rules.common import get_attr_chain, get_snippet, is_string_build, node_contains_user_input

SQL_KEYWORDS = {"select", "insert", "update", "delete", "where", "from"}


def detect_sql_injection(tree: ast.AST, lines: list[str], rel_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = get_attr_chain(node.func)
        if not fn.endswith("execute") and not fn.endswith("executemany"):
            continue
        if not node.args:
            continue
        query_arg = node.args[0]
        if not is_string_build(query_arg):
            continue
        raw = ast.unparse(query_arg).lower() if hasattr(ast, "unparse") else ""
        if raw and not any(k in raw for k in SQL_KEYWORDS):
            continue
        severity = "critical" if node_contains_user_input(query_arg) else "high"
        confidence = "high" if node_contains_user_input(query_arg) else "medium"
        findings.append(
            Finding(
                id="SEC-SQLI-001",
                title="Potential SQL Injection",
                description="Dynamic SQL query appears to be constructed via interpolation/concatenation.",
                severity=severity,
                confidence=confidence,
                file=rel_path,
                line_start=getattr(node, "lineno", 1),
                line_end=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                code_snippet=get_snippet(lines, getattr(node, "lineno", 1), getattr(node, "end_lineno", getattr(node, "lineno", 1))),
                owasp_category="A03:2021-Injection",
                remediation=[
                    "Use parameterized queries with placeholders instead of string concatenation.",
                    "Validate and constrain user-controlled input before query execution.",
                    "Use least-privileged DB accounts to reduce impact.",
                ],
            )
        )
    return findings
