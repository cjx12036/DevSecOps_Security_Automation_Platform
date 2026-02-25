from __future__ import annotations

import ast

from secscan.models import Finding
from secscan.rules.common import get_attr_chain, get_snippet, node_contains_user_input

CMD_FUNCS = {
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
}


def detect_command_injection(tree: ast.AST, lines: list[str], rel_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = get_attr_chain(node.func)
        if fn not in CMD_FUNCS:
            continue

        shell_true = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
        has_string_arg = bool(node.args) and isinstance(node.args[0], (ast.Constant, ast.JoinedStr, ast.BinOp, ast.Call, ast.Name))
        user_controlled = bool(node.args) and node_contains_user_input(node.args[0])

        if fn.startswith("os.") or shell_true or has_string_arg:
            severity = "critical" if shell_true and user_controlled else "high"
            findings.append(
                Finding(
                    id="SEC-CMDI-001",
                    title="Potential Command Injection",
                    description="Shell command execution may include unsafe/user-controlled input.",
                    severity=severity,
                    confidence="high" if (shell_true or user_controlled) else "medium",
                    file=rel_path,
                    line_start=getattr(node, "lineno", 1),
                    line_end=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                    code_snippet=get_snippet(lines, getattr(node, "lineno", 1), getattr(node, "end_lineno", getattr(node, "lineno", 1))),
                    owasp_category="A03:2021-Injection",
                    remediation=[
                        "Avoid shell=True and pass commands as argument lists.",
                        "Use strict input validation/allowlists for command parameters.",
                        "Prefer safe library APIs over shelling out.",
                    ],
                )
            )
    return findings
