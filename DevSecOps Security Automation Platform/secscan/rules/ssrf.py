from __future__ import annotations

import ast

from secscan.models import Finding
from secscan.rules.common import get_attr_chain, get_snippet, node_contains_user_input

REQUEST_FUNCS = {"requests.get", "requests.post", "requests.put", "requests.delete", "requests.head", "requests.request"}


def detect_ssrf(tree: ast.AST, lines: list[str], rel_path: str) -> list[Finding]:
    findings: list[Finding] = []
    tainted: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and node_contains_user_input(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    tainted.add(target.id)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = get_attr_chain(node.func)
        if fn not in REQUEST_FUNCS:
            continue
        if not node.args:
            continue
        url_arg = node.args[0]
        if node_contains_user_input(url_arg) or (isinstance(url_arg, ast.Name) and url_arg.id in tainted):
            findings.append(
                Finding(
                    id="SEC-SSRF-001",
                    title="Potential SSRF",
                    description="Outbound HTTP request uses user-controlled URL without visible allowlist checks.",
                    severity="high",
                    confidence="high",
                    file=rel_path,
                    line_start=getattr(node, "lineno", 1),
                    line_end=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                    code_snippet=get_snippet(lines, getattr(node, "lineno", 1), getattr(node, "end_lineno", getattr(node, "lineno", 1))),
                    owasp_category="A10:2021-Server-Side Request Forgery",
                    remediation=[
                        "Restrict outbound destinations with explicit allowlists.",
                        "Validate scheme/host/port and block private/link-local ranges.",
                        "Route external calls through a hardened proxy when possible.",
                    ],
                )
            )
    return findings
