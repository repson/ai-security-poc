"""
LLM05 — Improper Output Handling
Vulnerable application.

Exposes three endpoints that pass LLM output directly to downstream systems
without sanitisation:
  /greet      — LLM output inserted raw into HTML → XSS
  /search     — LLM output interpolated into SQL   → SQL injection
  /process    — LLM output passed to shell          → command injection

Run (Flask development server):
    python -m src.llm.llm05_improper_output_handling.vulnerable.app
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from openai import OpenAI

load_dotenv()

if not os.environ.get("OPENAI_API_KEY"):
    print("[Error] OPENAI_API_KEY is not set.")
    sys.exit(1)

app = Flask(__name__)
client = OpenAI()
MODEL = "gpt-4o-mini"

# ---------------------------------------------------------------------------
# Shared: ask the LLM for a short piece of text
# ---------------------------------------------------------------------------


def _llm(prompt: str, max_tokens: int = 128) -> str:
    r = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=max_tokens,
    )
    return r.choices[0].message.content or ""


# ---------------------------------------------------------------------------
# Vulnerability 1 — XSS via unsanitised HTML output
# ---------------------------------------------------------------------------


@app.route("/greet")
def greet():
    name = request.args.get("name", "visitor")
    # LLM generates a greeting; output injected verbatim into HTML
    llm_output = _llm(f"Write a one-sentence welcome message for a user named: {name}")
    # VULNERABLE: raw LLM output inserted into HTML — XSS if output contains <script>
    html = f"<html><body><p>{llm_output}</p></body></html>"
    return html, 200, {"Content-Type": "text/html"}


# ---------------------------------------------------------------------------
# Vulnerability 2 — SQL injection via unsanitised query construction
# ---------------------------------------------------------------------------


def _init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    conn.execute("INSERT INTO users VALUES (1,'Alice','alice@example.com')")
    conn.execute("INSERT INTO users VALUES (2,'Bob','bob@example.com')")
    conn.commit()
    return conn


_DB = _init_db()


@app.route("/search")
def search():
    user_query = request.args.get("q", "")
    # LLM generates a search term from natural language
    search_term = _llm(
        f"Extract the search keyword from this query (respond with ONLY the keyword): {user_query}"
    )
    search_term = search_term.strip().strip('"').strip("'")

    # VULNERABLE: search_term interpolated directly into SQL string
    sql = f"SELECT * FROM users WHERE name = '{search_term}'"
    try:
        rows = _DB.execute(sql).fetchall()
        return jsonify({"query": sql, "results": rows})
    except Exception as exc:
        return jsonify({"error": str(exc), "query": sql}), 500


# ---------------------------------------------------------------------------
# Vulnerability 3 — command injection via shell=True
# ---------------------------------------------------------------------------


@app.route("/process")
def process():
    topic = request.args.get("topic", "report")
    # LLM generates a filename
    filename = _llm(
        f"Generate a short safe filename (no extension) for a report about: {topic}"
    )
    filename = filename.strip().strip('"')

    # VULNERABLE: shell=True + LLM-generated argument = command injection
    try:
        result = subprocess.run(
            f"echo 'Processing report: {filename}'",
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return jsonify({"filename": filename, "output": result.stdout})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5100))
    print(f"[VULNERABLE] LLM05 app running on http://localhost:{port}")
    app.run(port=port, debug=False)
