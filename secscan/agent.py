from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from secscan.reporting.html import render_html
from secscan.reporting.sarif import to_sarif
from secscan.scanners import run_sast, run_secrets
from secscan.utils import ensure_dir, save_json, severity_at_least


class AgentRunResult(dict):
    pass


def run_agent_pipeline(
    path: str,
    out_dir: str,
    exclude: list[str],
    severity_threshold: str,
    sast_engine: str = "auto",
    secrets_engine: str = "auto",
) -> AgentRunResult:
    with ThreadPoolExecutor(max_workers=2) as pool:
        sast_future = pool.submit(run_sast, path, exclude, sast_engine)
        secrets_future = pool.submit(run_secrets, path, exclude, secrets_engine)
        sast_findings = [f.to_dict() for f in sast_future.result()]
        secrets_findings = [f.to_dict() for f in secrets_future.result()]

    sast_filtered = [f for f in sast_findings if severity_at_least(f["severity"], severity_threshold)]
    secrets_filtered = [f for f in secrets_findings if severity_at_least(f["severity"], severity_threshold)]
    combined = sorted(
        sast_filtered + secrets_filtered,
        key=lambda f: (f.get("file", ""), int(f.get("line_start", 0)), f.get("id", "")),
    )

    ensure_dir(out_dir)
    out = Path(out_dir)
    save_json(str(out / "sast.json"), {"findings": sast_filtered})
    save_json(str(out / "secrets.json"), {"findings": secrets_filtered})
    save_json(str(out / "findings.json"), {"findings": combined})

    (out / "sast.sarif").write_text(json.dumps(to_sarif(sast_filtered), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "secrets.sarif").write_text(json.dumps(to_sarif(secrets_filtered), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "findings.sarif").write_text(json.dumps(to_sarif(combined), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = {
        "total": len(combined),
        "by_severity": {
            "critical": sum(1 for f in combined if f.get("severity") == "critical"),
            "high": sum(1 for f in combined if f.get("severity") == "high"),
            "medium": sum(1 for f in combined if f.get("severity") == "medium"),
            "low": sum(1 for f in combined if f.get("severity") == "low"),
        },
        "engines": {"sast": sast_engine, "secrets": secrets_engine},
    }
    save_json(str(out / "summary.json"), summary)
    (out / "report.html").write_text(render_html(combined), encoding="utf-8")

    return AgentRunResult(
        {
            "sast": sast_filtered,
            "secrets": secrets_filtered,
            "findings": combined,
            "summary": summary,
        }
    )
