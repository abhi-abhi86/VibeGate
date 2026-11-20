"""Demo Flask app with intentional issues for VibeGate demonstration (DO NOT DEPLOY)."""

import os
import sqlite3
from flask import Flask, jsonify, request, session

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-only-secret")

# Issue 1: Hard-coded secret (flagged by Gitleaks; auto-moved to .env)
GITHUB_SYNC_TOKEN = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

USERS = {
    1: {"id": 1, "name": "Alice", "email": "alice@example.com", "address": "123 Maple St"},
    2: {"id": 2, "name": "Bob", "email": "bob@example.com", "address": "999 Oak Ave"},
}


def get_db():
    conn = sqlite3.connect(os.environ.get("DEMO_DB", ":memory:"))
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/orders/search")
def search_orders():
    customer = request.args.get("customer", "")
    conn = get_db()
    cur = conn.cursor()
    # Issue 2: SQL injection via f-string (flagged by Semgrep; auto-parameterized)
    cur.execute(f"SELECT id, customer, total FROM orders WHERE customer = '{customer}'")
    rows = [dict(r) for r in cur.fetchall()]
    return jsonify({"orders": rows})


@app.route("/api/user/<int:user_id>")
def get_user_profile(user_id: int):
    # Issue 3: Missing access check (IDOR) — returns private email/address without verifying ownership
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404
    return jsonify(user)
