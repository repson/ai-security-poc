"""
LLM10 — Unbounded Consumption
Vulnerable application.

A Flask API with no rate limiting, no input token cap, and no max_tokens.
Any client can send unlimited requests with maximum-size payloads.

Run:
    python -m src.llm.llm10_unbounded_consumption.vulnerable.app
"""

from __future__ import annotations

import os, sys
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from openai import OpenAI

load_dotenv()
if not os.environ.get("OPENAI_API_KEY"):
    print("[Error] OPENAI_API_KEY is not set.")
    sys.exit(1)

app = Flask(__name__)
client = OpenAI()


@app.route("/chat", methods=["POST"])
def chat():
    msg = request.json.get("message", "") if request.is_json else ""
    # VULNERABLE: no input length check, no max_tokens, no rate limiting
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": msg}],
        # max_tokens not set — model can output up to its maximum
    )
    return jsonify(
        {
            "response": resp.choices[0].message.content,
            "usage": {
                "input_tokens": resp.usage.prompt_tokens,
                "output_tokens": resp.usage.completion_tokens,
            },
        }
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5200))
    print(f"[VULNERABLE] LLM10 app on http://localhost:{port}")
    app.run(port=port, debug=False)
