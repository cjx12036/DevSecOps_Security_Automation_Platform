from __future__ import annotations

import ast
import json
import subprocess
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


def _severity_from_semgrep(value: str) -> str:
    mapping = {
        "info": "low",
        "warning": "medium",
        "error": "high",
        "critical": "critical",
    }
    return mapping.get(value.strip().lower(), "medium")


def _severity_from_trivy(value: str) -> str:
    mapping = {
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
        "unknown": "low",
    }
    return mapping.get(value.strip().lower(), "medium")


def _run_cmd(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(cwd),
        text=True,
        capture_output=True,
        check=False,
    )


def _run_sast_legacy(path: str, exclude: list[str]) -> list[Finding]:
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


def _run_secrets_legacy(path: str, exclude: list[str]) -> list[Finding]:
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


def _run_sast_semgrep(path: str, exclude: list[str]) -> list[Finding]:
    root = Path(path).resolve()
    config = Path(__file__).resolve().parent / "rules" / "semgrep" / "sast.yml"
    args = [
        "semgrep",
        "scan",
        "--config",
        str(config),
        "--json",
        "--quiet",
        "--no-git-ignore",
        ".",
    ]
    for item in exclude:
        args.extend(["--exclude", item])

    try:
        cp = _run_cmd(args, root)
    except FileNotFoundError as exc:
        raise RuntimeError("semgrep not installed") from exc

    if cp.returncode not in {0, 1}:
        raise RuntimeError(f"semgrep failed: {cp.stderr.strip() or cp.stdout.strip()}")

    try:
        payload = json.loads(cp.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"semgrep returned invalid JSON: {exc}") from exc

    findings: list[Finding] = []
    for item in payload.get("results", []):
        extra = item.get("extra", {})
        meta = extra.get("metadata", {})
        start = item.get("start", {})
        end = item.get("end", {})
        rel_file = item.get("path", "")
        title = extra.get("message", item.get("check_id", "Semgrep finding"))
        description = meta.get("description") or extra.get("message", "Detected by Semgrep rule")
        remediation = [
            "Apply input validation and output encoding where untrusted data is processed.",
            "Use safe framework/library APIs instead of dynamic execution or unsafe parsing.",
            "Add unit tests for this sink/source data flow to prevent regression.",
        ]

        findings.append(
            Finding(
                id=f"SEMGREP-{item.get('check_id', 'UNKNOWN').upper().replace('.', '-').replace('_', '-')}",
                title=title,
                description=description,
                severity=_severity_from_semgrep(str(extra.get("severity", "WARNING"))),
                confidence=str(meta.get("confidence", "medium")).lower(),
                file=rel_file,
                line_start=int(start.get("line", 1)),
                line_end=int(end.get("line", start.get("line", 1))),
                code_snippet=str(extra.get("lines", "")).strip(),
                owasp_category=str(meta.get("owasp", "A03:2021-Injection")),
                remediation=remediation,
            )
        )

    return sorted(findings, key=lambda f: (f.file, f.line_start, f.id))


def _run_secrets_trivy(path: str, exclude: list[str]) -> list[Finding]:
    root = Path(path).resolve()
    args = ["trivy", "fs", "--scanners", "secret", "--format", "json", "."]
    for item in exclude:
        args.extend(["--skip-dirs", item])

    try:
        cp = _run_cmd(args, root)
    except FileNotFoundError as exc:
        raise RuntimeError("trivy not installed") from exc

    if cp.returncode != 0:
        raise RuntimeError(f"trivy failed: {cp.stderr.strip() or cp.stdout.strip()}")

    try:
        payload = json.loads(cp.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"trivy returned invalid JSON: {exc}") from exc

    findings: list[Finding] = []
    for result in payload.get("Results", []):
        target = str(result.get("Target", ""))
        for secret in result.get("Secrets", []) or []:
            findings.append(
                Finding(
                    id=f"TRIVY-SECRET-{secret.get('RuleID', 'GENERIC').upper()}",
                    title=str(secret.get("Title") or "Potential Hardcoded Secret"),
                    description=str(secret.get("Description") or "Potential secret material detected."),
                    severity=_severity_from_trivy(str(secret.get("Severity", "HIGH"))),
                    confidence="high",
                    file=target,
                    line_start=int(secret.get("StartLine", 1)),
                    line_end=int(secret.get("EndLine", secret.get("StartLine", 1))),
                    code_snippet=str(secret.get("Code", "")).strip(),
                    owasp_category="A02:2021-Cryptographic Failures",
                    remediation=[
                        "Move secrets to environment variables or a secret manager.",
                        "Rotate exposed credentials and audit access logs.",
                        "Add CI secret scanning and pre-commit hooks.",
                    ],
                )
            )

    unique = {(f.id, f.file, f.line_start, f.code_snippet): f for f in findings}
    return sorted(unique.values(), key=lambda f: (f.file, f.line_start, f.id))


def run_sast(path: str, exclude: list[str], engine: str = "auto") -> list[Finding]:
    selected = engine.strip().lower()
    if selected == "legacy":
        return _run_sast_legacy(path, exclude)
    if selected == "semgrep":
        return _run_sast_semgrep(path, exclude)
    if selected == "auto":
        try:
            return _run_sast_semgrep(path, exclude)
        except RuntimeError:
            return _run_sast_legacy(path, exclude)
    raise RuntimeError(f"unsupported sast engine: {engine}")


def run_secrets(path: str, exclude: list[str], engine: str = "auto") -> list[Finding]:
    selected = engine.strip().lower()
    if selected == "legacy":
        return _run_secrets_legacy(path, exclude)
    if selected == "trivy":
        return _run_secrets_trivy(path, exclude)
    if selected == "auto":
        try:
            return _run_secrets_trivy(path, exclude)
        except RuntimeError:
            return _run_secrets_legacy(path, exclude)
    raise RuntimeError(f"unsupported secrets engine: {engine}")
