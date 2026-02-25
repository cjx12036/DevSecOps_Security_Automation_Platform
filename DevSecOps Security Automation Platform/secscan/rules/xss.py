from __future__ import annotations

import ast

from secscan.models import Finding
from secscan.rules.common import get_attr_chain, get_snippet, is_string_build, node_contains_user_input


def detect_xss(tree: ast.AST, lines: list[str], rel_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Return) and node.value is not None:
            if is_string_build(node.value) and node_contains_user_input(node.value):
                findings.append(
                    Finding(
                        id="SEC-XSS-001",
                        title="Potential Reflected XSS",
                        description="User-controlled input appears in HTML/response content without escaping.",
                        severity="high",
                        confidence="medium",
                        file=rel_path,
                        line_start=getattr(node, "lineno", 1),
                        line_end=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                        code_snippet=get_snippet(lines, getattr(node, "lineno", 1), getattr(node, "end_lineno", getattr(node, "lineno", 1))),
                        owasp_category="A03:2021-Injection",
                        remediation=[
                            "Render untrusted input through auto-escaping templates.",
                            "Apply output encoding for HTML context.",
                            "Use a strict Content Security Policy where possible.",
                        ],
                    )
                )
        if isinstance(node, ast.Call):
            fn = get_attr_chain(node.func)
            if fn.endswith("render_template_string") and node.args:
                arg = node.args[0]
                if is_string_build(arg) and node_contains_user_input(arg):
                    findings.append(
                        Finding(
                            id="SEC-XSS-002",
                            title="Unsafe Dynamic Template Rendering",
                            description="render_template_string is fed by user input and may create XSS risk.",
                            severity="high",
                            confidence="high",
                            file=rel_path,
                            line_start=getattr(node, "lineno", 1),
                            line_end=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                            code_snippet=get_snippet(lines, getattr(node, "lineno", 1), getattr(node, "end_lineno", getattr(node, "lineno", 1))),
                            owasp_category="A03:2021-Injection",
                            remediation=[
                                "Avoid render_template_string for user-provided data.",
                                "Use static templates and pass variables through template context.",
                                "Sanitize or encode any user-originated data before rendering.",
                            ],
                        )
                    )
    return findings
