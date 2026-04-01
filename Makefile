PYTHON ?= python3

.PHONY: setup scan gate test run-demo artifacts

setup:
	$(PYTHON) -m venv .venv
	. .venv/bin/activate && pip install --upgrade pip
	. .venv/bin/activate && pip install -e . semgrep

scan:
	. .venv/bin/activate && \
	python -m secscan.cli agent --path . --out-dir artifacts --severity-threshold low --sast-engine auto --secrets-engine auto --exclude ".venv,dist,build,node_modules,.git,artifacts,findings_db.json" && \
	python -m secscan.cli baseline --input artifacts/findings.json --baseline artifacts/baseline.json --output artifacts/findings.filtered.json && \
	python -m secscan.cli sync --input artifacts/findings.filtered.json --db findings_db.json

gate:
	. .venv/bin/activate && python -m secscan.cli policy --input artifacts/findings.filtered.json --policy policy.yml

test:
	. .venv/bin/activate && PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -p "test_*.py" -v

run-demo:
	. .venv/bin/activate && python -c "import flask,requests,yaml" >/dev/null 2>&1 || (echo "Missing demo dependencies (flask/requests/PyYAML). Install with: . .venv/bin/activate && pip install -r demo_app/requirements.txt" && exit 2)
	. .venv/bin/activate && python -m flask --app demo_app.app run --port 5000

artifacts:
	. .venv/bin/activate && python -m secscan.cli agent --path demo_app --out-dir artifacts --severity-threshold low --sast-engine auto --secrets-engine auto --exclude ".venv,dist,build,node_modules,.git,artifacts,findings_db.json"
