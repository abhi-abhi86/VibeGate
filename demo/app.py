"""Demo Flask app with intentional issues for VibeGate demonstration (DO NOT DEPLOY)."""

import os
import sqlite3
from flask import Flask, jsonify, request, session

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-only-secret")

# Issue 1: Committed test secret (flagged by Gitleaks; redacted before any AI call)
GITHUB_SYNC_TOKEN = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

DB_PATH = os.environ.get("DEMO_DB", ":memory:")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/orders/search")
def search_orders():
    customer = request.args.get("customer", "")
    conn = get_db()
    cur = conn.cursor()
    # Issue 2: SQL injection via f-string (flagged by Semgrep; patchable via VibeGate)
    cur.execute(f"SELECT id, customer, total FROM orders WHERE customer = '{customer}'")
    rows = [dict(r) for r in cur.fetchall()]
    return jsonify({"orders": rows})


@app.route("/orders/<int:order_id>", methods=["DELETE"])
def delete_order(order_id: int):
    # Issue 3: Checks that user is logged in, but never checks if the user owns order_id (IDOR)
    if not session.get("user_id"):
        return jsonify({"error": "authentication required"}), 401
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit()
    return jsonify({"deleted": order_id})

