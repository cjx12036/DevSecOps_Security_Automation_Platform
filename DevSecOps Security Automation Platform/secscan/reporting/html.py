from __future__ import annotations

from collections import Counter
from html import escape


def render_html(findings: list[dict]) -> str:
    by_sev = Counter(f["severity"] for f in findings)
    rows = "\n".join(
        [
            "<tr>"
            f"<td>{escape(f['id'])}</td>"
            f"<td>{escape(f['severity'].upper())}</td>"
            f"<td>{escape(f['owasp_category'])}</td>"
            f"<td>{escape(f['file'])}:{f['line_start']}</td>"
            f"<td>{escape(f['title'])}</td>"
            "</tr>"
            for f in findings
        ]
    )

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <title>secscan report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif; margin: 24px; background:#f7fafc; color:#1f2937; }}
    .card {{ background:white; padding:16px; border-radius:10px; box-shadow:0 2px 6px rgba(0,0,0,.07); margin-bottom:16px; }}
    table {{ width:100%; border-collapse: collapse; background:white; }}
    th, td {{ border:1px solid #e5e7eb; padding:8px; font-size:14px; text-align:left; }}
    th {{ background:#f3f4f6; }}
    .sev {{ display:flex; gap:12px; }}
    .chip {{ padding:4px 8px; border-radius:8px; background:#eef2ff; }}
  </style>
</head>
<body>
  <div class=\"card\">
    <h1>Security Findings Summary</h1>
    <p>Total findings: <strong>{len(findings)}</strong></p>
    <div class=\"sev\">
      <span class=\"chip\">Critical: {by_sev.get('critical', 0)}</span>
      <span class=\"chip\">High: {by_sev.get('high', 0)}</span>
      <span class=\"chip\">Medium: {by_sev.get('medium', 0)}</span>
      <span class=\"chip\">Low: {by_sev.get('low', 0)}</span>
    </div>
  </div>
  <table>
    <thead><tr><th>ID</th><th>Severity</th><th>OWASP</th><th>Location</th><th>Title</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>
"""
