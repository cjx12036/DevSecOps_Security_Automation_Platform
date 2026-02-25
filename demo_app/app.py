from __future__ import annotations

import os
import sqlite3

import requests
import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)

ALLOWED_PROXY_TARGETS = {
    "httpbin": "https://httpbin.org/get",
    "example": "https://example.com",
}


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT)")
    conn.execute("INSERT INTO users(username) VALUES (?)", ("admin",))
    return conn


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/user")
def user_lookup():
    username = request.args.get("username", "")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    return jsonify({"user": row[0] if row else None})


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return jsonify({"query": q})


@app.route("/proxy")
def proxy():
    target = request.args.get("target", "example")
    url = ALLOWED_PROXY_TARGETS.get(target, ALLOWED_PROXY_TARGETS["example"])
    resp = requests.get(url, timeout=3)
    return jsonify({"status_code": resp.status_code, "target": target})


@app.route("/deserialize", methods=["POST"])
def deserialize():
    payload = request.get_json(silent=True) or {}
    return jsonify({"received": payload})


@app.route("/yaml", methods=["POST"])
def parse_yaml():
    body = request.get_data(as_text=True)
    parsed = yaml.safe_load(body) if body else {}
    return jsonify({"parsed_type": type(parsed).__name__})


@app.route("/config")
def config_status():
    token_configured = bool(os.getenv("API_TOKEN"))
    return jsonify({"token_set": token_configured})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
