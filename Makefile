PYTHON ?= python3

.PHONY: setup scan gate test run-demo artifacts

setup:
	$(PYTHON) -m venv .venv
	. .venv/bin/activate && pip install --upgrade pip

scan:
	. .venv/bin/activate && \
	python -m secscan.cli sast --path . --format json --output artifacts/sast.json --severity-threshold low --exclude ".venv,dist,build,node_modules,.git,artifacts,findings_db.json" || true; \
	python -m secscan.cli secrets --path . --format json --output artifacts/secrets.json --severity-threshold low --exclude ".venv,dist,build,node_modules,.git,artifacts,findings_db.json" || true; \
	python -c 'import json; a=json.load(open("artifacts/sast.json")); b=json.load(open("artifacts/secrets.json")); json.dump({"findings": a.get("findings",[])+b.get("findings",[])}, open("artifacts/findings.json","w"), indent=2)' && \
	python -m secscan.cli report --input artifacts/findings.json --out artifacts && \
	python -m secscan.cli baseline --input artifacts/findings.json --baseline artifacts/baseline.json --output artifacts/findings.filtered.json && \
	python -m secscan.cli sync --input artifacts/findings.filtered.json --db findings_db.json

gate:
	. .venv/bin/activate && python -m secscan.cli policy --input artifacts/findings.filtered.json --policy policy.yml

test:
	. .venv/bin/activate && python -m unittest discover -s tests -p "test_*.py" -v

run-demo:
	. .venv/bin/activate && python -c "import flask,requests,yaml" >/dev/null 2>&1 || (echo "Missing demo dependencies (flask/requests/PyYAML). Install with: . .venv/bin/activate && pip install -r demo_app/requirements.txt" && exit 2)
	. .venv/bin/activate && python -m flask --app demo_app.app run --port 5000

artifacts:
	. .venv/bin/activate && python -m secscan.cli sast --path demo_app --format sarif --output artifacts/sast.sarif --exclude ".venv,dist,build,node_modules,.git,artifacts,findings_db.json" && \
	python -m secscan.cli secrets --path demo_app --format sarif --output artifacts/secrets.sarif --exclude ".venv,dist,build,node_modules,.git,artifacts,findings_db.json"
