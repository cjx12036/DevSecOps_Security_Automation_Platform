# DevSecOps Security Automation Platform (Prototype)

A practical Python 3.11+ security automation platform that integrates into SDLC and demonstrates OWASP Top 10-oriented detection, CI policy gating, and governance tracking.

## Features
- Agent-orchestrated parallel scanning via `secscan agent`.
- External scanner backends: Semgrep (SAST), Trivy (secrets), with legacy fallback.
- Optional lightweight DAST checks for reflected XSS + SSRF proxy behavior.
- Multi-format outputs: JSON, SARIF (GitHub code scanning), HTML report.
- Governance sync with lifecycle states: `OPEN`, `FIXED`, `ACCEPTED_RISK`.
- CI is scoped to changed files under `demo_app/` for faster feedback.

## Quickstart
```bash
make setup
make scan
```
`make setup` installs Semgrep. In CI we also install Trivy; locally, if Trivy is absent, secrets scanning falls back to the built-in engine.
`make scan` always generates local artifacts; use `make gate` to enforce fail-on-high/critical policy locally.

Run demo app:
```bash
make run-demo
```

Generate demo-only artifacts:
```bash
make artifacts
```

## CLI Commands
```bash
python -m secscan.cli sast --path <repo> [--format json|sarif] [--engine auto|semgrep|legacy] [--severity-threshold low|medium|high|critical] [--exclude ".venv,dist,build,node_modules"]
python -m secscan.cli secrets --path <repo> [--format json|sarif] [--engine auto|trivy|legacy] [--severity-threshold low|medium|high|critical] [--exclude ".venv,dist,build,node_modules"]
python -m secscan.cli agent --path <repo> --out-dir <dir> [--sast-engine auto|semgrep|legacy] [--secrets-engine auto|trivy|legacy]
python -m secscan.cli report --input <json> --out <dir>
python -m secscan.cli baseline --input <json> --baseline <file>
python -m secscan.cli policy --input <json> --policy <yaml>
python -m secscan.cli sync --input <json> --db findings_db.json
python -m secscan.cli dast --url http://localhost:5000 [--format json|sarif]
```

## OWASP-Focused Rules
Implemented detections:
- SQL Injection: dynamic SQL interpolation in cursor execute calls.
- XSS: user input reflected into raw HTML response/template string.
- SSRF: requests made to user-controlled URLs without allowlist evidence.
- Hardcoded secrets: token/password/key regex + entropy heuristic.
- Insecure deserialization: `pickle.loads` and unsafe `yaml.load`.
- Command injection: `os.system`/`subprocess` with shell usage/string commands.

Each finding includes:
- `id`, `title`, `description`
- `severity`, `confidence`
- `file`, `line_start`, `line_end`, `code_snippet`
- `owasp_category`, `remediation`

## Governance Tracking
Use `secscan sync` to update `findings_db.json`:
- New findings => `OPEN`
- Missing previous `OPEN` findings => `FIXED`
- Existing `ACCEPTED_RISK` records are preserved
- Tracks `first_seen`, `last_seen`, optional `owner`

## Baseline + Policy
- Baseline (`secscan baseline`) suppresses findings by stable fingerprints.
- Policy (`secscan policy`) gates builds from `policy.yml`.
- Exit codes:
  - `0`: no policy violations
  - `1`: policy violations
  - `2`: runtime/config error

## CI Gating (GitHub Actions)
Workflow: `.github/workflows/security-scan.yml`
- Trigger: `push` + `pull_request` on relevant paths only (`demo_app/**`, `secscan/**`, workflow, `policy.yml`).
- Scope: computes changed files and scans only changed files under `demo_app/`.
- Runs `secscan agent` (parallel Semgrep + Trivy orchestration with fallback).
- Uploads SARIF to GitHub code scanning with separate categories:
  - `secscan-sast`
  - `secscan-secrets`
- Fails build on `high`/`critical` in policy step.

Local policy gate:
```bash
make gate
```

## How To Add A Rule
1. Add a Semgrep rule in `secscan/rules/semgrep/sast.yml` or add a Python legacy rule in `secscan/rules/`.
2. Register legacy rules in `secscan/rules/__init__.py` and `secscan/scanners.py`.
3. Add tests under `tests/` for detection behavior and false-positive boundaries.
4. Optionally map rule metadata in `secscan/reporting/sarif.py`.

## Example Report Output
Sample artifacts can be generated locally in `artifacts/` via `make scan` (directory is ignored in git):
- `artifacts/findings.json`
- `artifacts/report.html`
- `artifacts/sast.sarif`
- `artifacts/secrets.sarif`

Example summary snippet:
```text
Total findings: N
Critical: X
High: Y
Medium: Z
Low: W
```
