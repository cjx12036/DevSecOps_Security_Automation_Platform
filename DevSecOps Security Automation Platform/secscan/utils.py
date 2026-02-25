from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def normalize_severity(value: str) -> str:
    return value.strip().lower()


def severity_at_least(current: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(normalize_severity(current), 0) >= SEVERITY_ORDER.get(normalize_severity(threshold), 0)


def iter_files(root: str, exclude: list[str]) -> list[Path]:
    root_path = Path(root)
    excluded = {e.strip() for e in exclude if e.strip()}
    files: list[Path] = []
    for path in root_path.rglob("*"):
        if not path.is_file():
            continue
        if any(part in excluded for part in path.parts):
            continue
        files.append(path)
    files.sort(key=lambda p: str(p))
    return files


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def fingerprint(finding: dict) -> str:
    raw = "|".join(
        [
            str(finding.get("id", "")),
            str(finding.get("file", "")),
            str(finding.get("line_start", "")),
            str(finding.get("line_end", "")),
            str(finding.get("title", "")),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def save_json(path: str, payload: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)
