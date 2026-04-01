from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import urlopen

from secscan.agent import run_agent_pipeline
from secscan.governance import sync_findings_db
from secscan.reporting.html import render_html
from secscan.reporting.sarif import to_sarif
from secscan.scanners import run_sast, run_secrets
from secscan.utils import ensure_dir, fingerprint, normalize_severity, save_json, severity_at_least

EXIT_OK = 0
EXIT_POLICY = 1
EXIT_ERROR = 2


def _parse_exclude(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def _findings_to_dict(findings) -> list[dict]:
    return [f.to_dict() for f in findings]


def _load_findings(path: str) -> list[dict]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"failed to read findings file: {exc}") from exc

    if isinstance(payload, list):
        findings = payload
    else:
        findings = payload.get("findings", [])
    findings.sort(key=lambda f: (f.get("file", ""), f.get("line_start", 0), f.get("id", "")))
    return findings


def _load_policy(path: str) -> dict:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"unable to read policy file: {exc}") from exc

    cfg: dict[str, object] = {}
    current_list_key: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line and not line.startswith("-"):
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if value:
                cfg[key] = value
                current_list_key = None
            else:
                cfg[key] = []
                current_list_key = key
            continue
        if line.startswith("-") and current_list_key:
            if isinstance(cfg[current_list_key], list):
                cfg[current_list_key].append(line[1:].strip())
    return cfg


def _emit(findings: list[dict], fmt: str, output: str | None) -> None:
    payload = {"findings": findings}
    rendered: dict = payload if fmt == "json" else to_sarif(findings)
    text = json.dumps(rendered, indent=2, sort_keys=True)
    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def cmd_sast(args: argparse.Namespace) -> int:
    findings = _findings_to_dict(run_sast(args.path, _parse_exclude(args.exclude), args.engine))
    findings = [f for f in findings if severity_at_least(f["severity"], args.severity_threshold)]
    _emit(findings, args.format, args.output)
    return EXIT_POLICY if findings else EXIT_OK


def cmd_secrets(args: argparse.Namespace) -> int:
    findings = _findings_to_dict(run_secrets(args.path, _parse_exclude(args.exclude), args.engine))
    findings = [f for f in findings if severity_at_least(f["severity"], args.severity_threshold)]
    _emit(findings, args.format, args.output)
    return EXIT_POLICY if findings else EXIT_OK


def cmd_agent(args: argparse.Namespace) -> int:
    result = run_agent_pipeline(
        path=args.path,
        out_dir=args.out_dir,
        exclude=_parse_exclude(args.exclude),
        severity_threshold=args.severity_threshold,
        sast_engine=args.sast_engine,
        secrets_engine=args.secrets_engine,
    )
    if args.output:
        save_json(args.output, {"findings": result.get("findings", [])})
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    findings = _load_findings(args.input)
    ensure_dir(args.out)
    html = render_html(findings)
    Path(args.out, "report.html").write_text(html, encoding="utf-8")
    summary = {
        "total": len(findings),
        "by_severity": {
            "critical": sum(1 for f in findings if f.get("severity") == "critical"),
            "high": sum(1 for f in findings if f.get("severity") == "high"),
            "medium": sum(1 for f in findings if f.get("severity") == "medium"),
            "low": sum(1 for f in findings if f.get("severity") == "low"),
        },
    }
    save_json(str(Path(args.out, "summary.json")), summary)
    return EXIT_OK


def cmd_baseline(args: argparse.Namespace) -> int:
    findings = _load_findings(args.input)

    baseline_path = Path(args.baseline)
    if baseline_path.exists():
        try:
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid baseline file: {exc}") from exc
    else:
        baseline = {"fingerprints": []}

    blocked = set(baseline.get("fingerprints", []))
    filtered = [f for f in findings if fingerprint(f) not in blocked]
    output = args.output
    if output:
        save_json(output, {"findings": filtered})
    else:
        print(json.dumps({"findings": filtered}, indent=2, sort_keys=True))
    return EXIT_OK


def cmd_policy(args: argparse.Namespace) -> int:
    findings = _load_findings(args.input)
    cfg = _load_policy(args.policy)
    fail_sev = {normalize_severity(s) for s in cfg.get("fail_on_severities", ["high", "critical"])}
    violations = [f for f in findings if normalize_severity(f.get("severity", "")) in fail_sev]
    if violations:
        print(json.dumps({"violations": violations, "count": len(violations)}, indent=2, sort_keys=True))
        return EXIT_POLICY
    return EXIT_OK


def cmd_sync(args: argparse.Namespace) -> int:
    findings = _load_findings(args.input)
    db_path = Path(args.db)
    if db_path.exists():
        try:
            db = json.loads(db_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid db file: {exc}") from exc
    else:
        db = {"items": {}}

    updated = sync_findings_db(findings, db)
    save_json(args.db, updated)
    return EXIT_OK


def cmd_dast(args: argparse.Namespace) -> int:
    findings: list[dict] = []
    base = args.url.rstrip("/")
    try:
        payload = "<script>alert(1)</script>"
        xss_url = f"{base}/search?{urlencode({'q': payload})}"
        xss_resp = urlopen(xss_url, timeout=5).read().decode("utf-8", errors="ignore")
        if payload in xss_resp:
            findings.append(
                {
                    "id": "SEC-DAST-XSS-001",
                    "title": "Reflected XSS behavior detected",
                    "description": "Payload reflected in response body.",
                    "severity": "high",
                    "confidence": "medium",
                    "file": args.url,
                    "line_start": 1,
                    "line_end": 1,
                    "code_snippet": "GET /search?q=<script>alert(1)</script>",
                    "owasp_category": "A03:2021-Injection",
                    "remediation": [
                        "Encode untrusted data before rendering.",
                        "Use template auto-escaping.",
                        "Add server-side input validation.",
                    ],
                }
            )

        ssrf_url = f"{base}/proxy?{urlencode({'url': f'{base}/health'})}"
        ssrf_resp = urlopen(ssrf_url, timeout=5).read().decode("utf-8", errors="ignore")
        if "ok" in ssrf_resp.lower():
            findings.append(
                {
                    "id": "SEC-DAST-SSRF-001",
                    "title": "Potential SSRF behavior detected",
                    "description": "Proxy endpoint fetched user-supplied internal URL.",
                    "severity": "high",
                    "confidence": "medium",
                    "file": args.url,
                    "line_start": 1,
                    "line_end": 1,
                    "code_snippet": "GET /proxy?url=http://localhost:5000/health",
                    "owasp_category": "A10:2021-Server-Side Request Forgery",
                    "remediation": [
                        "Implement destination allowlist.",
                        "Block localhost/private ranges.",
                        "Require authentication and logging for proxy actions.",
                    ],
                }
            )
    except URLError as exc:
        raise RuntimeError(f"DAST request failed: {exc}") from exc

    findings.sort(key=lambda f: (f["id"], f["title"]))
    _emit(findings, args.format, args.output)
    return EXIT_POLICY if findings else EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secscan", description="Security automation CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    common_scan = argparse.ArgumentParser(add_help=False)
    common_scan.add_argument("--format", choices=["json", "sarif"], default="json")
    common_scan.add_argument("--severity-threshold", choices=["low", "medium", "high", "critical"], default="low")
    common_scan.add_argument("--exclude", default=".venv,dist,build,node_modules,.git,artifacts,findings_db.json")
    common_scan.add_argument("--output", help="Output file path")

    sast = sub.add_parser("sast", parents=[common_scan], help="Run SAST rules")
    sast.add_argument("--path", required=True)
    sast.add_argument("--engine", choices=["auto", "semgrep", "legacy"], default="auto")
    sast.set_defaults(func=cmd_sast)

    secrets = sub.add_parser("secrets", parents=[common_scan], help="Run secrets scan")
    secrets.add_argument("--path", required=True)
    secrets.add_argument("--engine", choices=["auto", "trivy", "legacy"], default="auto")
    secrets.set_defaults(func=cmd_secrets)

    agent = sub.add_parser("agent", help="Run agent scheduler (parallel SAST + secrets) and emit artifacts")
    agent.add_argument("--path", required=True)
    agent.add_argument("--out-dir", required=True)
    agent.add_argument("--severity-threshold", choices=["low", "medium", "high", "critical"], default="low")
    agent.add_argument("--exclude", default=".venv,dist,build,node_modules,.git,artifacts,findings_db.json")
    agent.add_argument("--sast-engine", choices=["auto", "semgrep", "legacy"], default="auto")
    agent.add_argument("--secrets-engine", choices=["auto", "trivy", "legacy"], default="auto")
    agent.add_argument("--output", help="Optional combined findings JSON path")
    agent.set_defaults(func=cmd_agent)

    report = sub.add_parser("report", help="Generate HTML report")
    report.add_argument("--input", required=True)
    report.add_argument("--out", required=True)
    report.set_defaults(func=cmd_report)

    baseline = sub.add_parser("baseline", help="Apply baseline suppression")
    baseline.add_argument("--input", required=True)
    baseline.add_argument("--baseline", required=True)
    baseline.add_argument("--output", help="Filtered JSON output path")
    baseline.set_defaults(func=cmd_baseline)

    policy = sub.add_parser("policy", help="Enforce policy gates")
    policy.add_argument("--input", required=True)
    policy.add_argument("--policy", required=True)
    policy.set_defaults(func=cmd_policy)

    sync = sub.add_parser("sync", help="Sync findings DB")
    sync.add_argument("--input", required=True)
    sync.add_argument("--db", required=True)
    sync.set_defaults(func=cmd_sync)

    dast = sub.add_parser("dast", parents=[common_scan], help="Run lightweight DAST checks")
    dast.add_argument("--url", required=True)
    dast.set_defaults(func=cmd_dast)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except RuntimeError as exc:
        print(f"secscan error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
