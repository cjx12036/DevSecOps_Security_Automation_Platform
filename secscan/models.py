from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    description: str
    severity: str
    confidence: str
    file: str
    line_start: int
    line_end: int
    code_snippet: str
    owasp_category: str
    remediation: list[str]

    def to_dict(self) -> dict:
        return asdict(self)
