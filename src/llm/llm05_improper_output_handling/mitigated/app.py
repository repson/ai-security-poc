"""
LLM05 — Improper Output Handling
Mitigated application.

Same three endpoints as the vulnerable app, now with output sanitisation:
  /greet   — bleach HTML sanitisation
  /search  — Pydantic schema validation + parameterised SQL
  /process — filename allowlist + subprocess shell=False

Run:
    python -m src.llm.llm05_improper_output_handling.mitigated.app
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from openai import OpenAI

from .sanitizers import html_sanitize, sql_safe_term, safe_filename

load_dotenv()

if not os.environ.get("OPENAI_API_KEY"):
    print("[Error] OPENAI_API_KEY is not set.")
    sys.exit(1)

app = Flask(__name__)
client = OpenAI()
MODEL = "gpt-4o-mini"

ALLOWED_COMMANDS = {"echo"}  # only these executables may be called


def _llm(prompt: str, max_tokens: int = 128) -> str:
    r = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=max_tokens,
    )
    return r.choices[0].message.content or ""


# ---------------------------------------------------------------------------
# Mitigation 1 — HTML output sanitised with bleach
# ---------------------------------------------------------------------------


@app.route("/greet")
def greet():
    name = request.args.get("name", "visitor")
    llm_output = _llm(f"Write a one-sentence welcome message for a user named: {name}")
    # MITIGATED: strip disallowed HTML tags before rendering
    safe_output = html_sanitize(llm_output)
    html = f"<html><body><p>{safe_output}</p></body></html>"
    return html, 200, {"Content-Type": "text/html"}


# ---------------------------------------------------------------------------
# Mitigation 2 — Parameterised SQL + Pydantic term validation
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
    raw_term = _llm(
        f"Extract the search keyword from this query (respond with ONLY the keyword): {user_query}"
    )

    # MITIGATED: validate term against allowlist schema
    try:
        term = sql_safe_term(raw_term)
    except ValueError as exc:
        return jsonify({"error": f"Invalid search term: {exc}"}), 400

    # MITIGATED: parameterised query — term is never interpolated into SQL
    rows = _DB.execute("SELECT * FROM users WHERE name = ?", (term,)).fetchall()
    return jsonify({"term": term, "results": rows})


# ---------------------------------------------------------------------------
# Mitigation 3 — Shell filename allowlist + shell=False
# ---------------------------------------------------------------------------


@app.route("/process")
def process():
    topic = request.args.get("topic", "report")
    raw_name = _llm(
        f"Generate a short safe filename (no extension) for a report about: {topic}"
    )

    # MITIGATED: validate filename against strict allowlist
    try:
        fname = safe_filename(raw_name)
    except ValueError as exc:
        return jsonify({"error": f"Invalid filename: {exc}"}), 400

    # MITIGATED: shell=False — arguments are never interpreted by the shell
    result = subprocess.run(
        ["echo", f"Processing report: {fname}"],
        capture_output=True,
        text=True,
        timeout=5,
        shell=False,
    )
    return jsonify({"filename": fname, "output": result.stdout})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5101))
    print(f"[MITIGATED] LLM05 app running on http://localhost:{port}")
    app.run(port=port, debug=False)
