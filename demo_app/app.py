from __future__ import annotations

import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)

# Intentionally vulnerable demo secrets
API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"
DB_PASSWORD = "super-secret-password"


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT)")
    conn.execute("INSERT INTO users(username) VALUES ('admin')")
    conn.execute("INSERT INTO users(username) VALUES ('guest')")
    return conn


@app.route("/health")
def health():
    return "ok"


@app.route("/user")
def user_lookup():
    # SQLi: user-controlled value directly interpolated into SQL
    username = request.args.get("username", "")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(f"SELECT username FROM users WHERE username = '{username}'")
    rows = [r[0] for r in cur.fetchall()]
    return {"rows": rows}


@app.route("/search")
def search():
    # Reflected XSS: directly returns user input in HTML
    return request.args.get("q", "")


@app.route("/proxy")
def proxy():
    # SSRF: user controls outbound destination
    url = request.args.get("url", "http://localhost:5000/health")
    resp = requests.get(url, timeout=3)
    return {"status_code": resp.status_code, "url": url}


@app.route("/deserialize", methods=["POST"])
def deserialize():
    # Insecure deserialization via pickle
    data = request.get_data()
    obj = pickle.loads(data)
    return {"type": str(type(obj))}


@app.route("/yaml", methods=["POST"])
def parse_yaml():
    # Unsafe yaml.load (without SafeLoader)
    payload = request.get_data(as_text=True)
    parsed = yaml.load(payload)
    return {"parsed_type": str(type(parsed))}


@app.route("/exec")
def exec_cmd():
    # Command injection via shell=True / os.system
    cmd = request.args.get("cmd", "echo demo")
    subprocess.run(cmd, shell=True, check=False)
    os.system(cmd)
    return {"executed": cmd}


@app.route("/config")
def config_status():
    return {"token": API_TOKEN, "db_password": DB_PASSWORD}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
