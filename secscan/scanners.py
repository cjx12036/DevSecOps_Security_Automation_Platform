from __future__ import annotations

import ast
from pathlib import Path

from secscan.models import Finding
from secscan.rules import (
    detect_command_injection,
    detect_insecure_deserialization,
    detect_sql_injection,
    detect_ssrf,
    detect_xss,
)
from secscan.rules.secrets import scan_secrets_file
from secscan.utils import iter_files, read_text


RULES = [
    detect_sql_injection,
    detect_xss,
    detect_ssrf,
    detect_insecure_deserialization,
    detect_command_injection,
]


def _relative(root: str, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def run_sast(path: str, exclude: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for file_path in iter_files(path, exclude):
        if file_path.suffix != ".py":
            continue
        content = read_text(file_path)
        if content is None:
            continue
        rel = _relative(path, file_path)
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue
        lines = content.splitlines()
        for rule in RULES:
            findings.extend(rule(tree, lines, rel))
    return sorted(findings, key=lambda f: (f.file, f.line_start, f.id))


def run_secrets(path: str, exclude: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for file_path in iter_files(path, exclude):
        if file_path.suffix in {".png", ".jpg", ".gif", ".pdf", ".ico", ".pyc"}:
            continue
        content = read_text(file_path)
        if content is None:
            continue
        rel = _relative(path, file_path)
        findings.extend(scan_secrets_file(rel, content))
    unique = {(f.id, f.file, f.line_start, f.code_snippet): f for f in findings}
    return sorted(unique.values(), key=lambda f: (f.file, f.line_start, f.id))
