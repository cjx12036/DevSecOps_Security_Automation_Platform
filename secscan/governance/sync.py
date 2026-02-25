from __future__ import annotations

from datetime import datetime, timezone

from secscan.utils import fingerprint


def sync_findings_db(findings: list[dict], db: dict) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    if "items" not in db:
        db["items"] = {}

    seen: set[str] = set()
    for finding in findings:
        fp = fingerprint(finding)
        seen.add(fp)
        existing = db["items"].get(fp)
        if existing:
            existing["last_seen"] = now
            if existing.get("status") == "FIXED":
                existing["status"] = "OPEN"
        else:
            db["items"][fp] = {
                "fingerprint": fp,
                "id": finding["id"],
                "title": finding["title"],
                "severity": finding["severity"],
                "file": finding["file"],
                "line_start": finding["line_start"],
                "status": "OPEN",
                "owner": None,
                "first_seen": now,
                "last_seen": now,
            }

    for fp, item in db["items"].items():
        if fp not in seen and item.get("status") == "OPEN":
            item["status"] = "FIXED"
            item["last_seen"] = now

    return db
