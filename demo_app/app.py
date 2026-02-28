from __future__ import annotations

import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, render_template_string, request

app = Flask(__name__)

# Intentionally vulnerable demo constants
API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"
DB_PASSWORD = "super-secret-password"
AWS_KEY = "AKIA1234567890ABCD12"


def get_db_connection():
    return sqlite3.connect(":memory:")


@app.route("/health")
def health():
    return "ok"


@app.route("/user")
def user_lookup():
    username = request.args.get("username", "")
    conn = get_db_connection()
    cur = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cur.execute(query)
    return "queried"


@app.route("/user_raw")
def user_lookup_raw():
    username = request.args.get("username", "")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return "queried-raw"


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<h1>Results for: {q}</h1>"


@app.route("/template")
def template_echo():
    name = request.args.get("name", "guest")
    return render_template_string("<div>Hello {{ name }}</div>", name=name)


@app.route("/proxy")
def proxy():
    url = request.args.get("url", "https://example.com")
    resp = requests.get(url, timeout=3)
    return resp.text


@app.route("/deserialize", methods=["POST"])
def deserialize():
    data = request.get_data()
    obj = pickle.loads(data)
    return str(obj)


@app.route("/yaml", methods=["POST"])
def parse_yaml():
    payload = request.get_data(as_text=True)
    obj = yaml.load(payload)
    return str(obj)


@app.route("/run")
def run_cmd():
    cmd = request.args.get("cmd", "echo hello")
    subprocess.run(cmd, shell=True, check=False)
    os.system(cmd)
    return "ran"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
