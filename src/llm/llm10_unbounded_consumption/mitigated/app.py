"""
LLM10 — Unbounded Consumption
Mitigated application.

Mitigations:
  1. Per-IP rate limiting via slowapi (10 req/min, 100 req/hour)
  2. Input token budget (truncate at MAX_INPUT_TOKENS)
  3. Hard max_tokens cap on model output
  4. Cost circuit breaker (opens at $10 daily spend)

Run:
    python -m src.llm.llm10_unbounded_consumption.mitigated.app

Install:
    pip install slowapi flask openai
"""

from __future__ import annotations

import os, sys
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from openai import OpenAI

from .middleware import (
    MAX_INPUT_TOKENS,
    MAX_OUTPUT_TOKENS,
    truncate_to_budget,
    circuit_breaker,
)

load_dotenv()
if not os.environ.get("OPENAI_API_KEY"):
    print("[Error] OPENAI_API_KEY is not set.")
    sys.exit(1)

app = Flask(__name__)
client = OpenAI()

# ---------------------------------------------------------------------------
# Rate limiting (slowapi)
# ---------------------------------------------------------------------------

try:
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded

    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter  # type: ignore[attr-defined]

    @app.errorhandler(RateLimitExceeded)
    def _rate_limit_handler(e):
        return jsonify(
            {
                "error": "rate_limit_exceeded",
                "message": "Too many requests. Slow down.",
                "retry_after": getattr(e, "retry_after", None),
            }
        ), 429

    def _apply_rate_limit(view_fn):
        return limiter.limit("10 per minute")(limiter.limit("100 per hour")(view_fn))

    _SLOWAPI = True
except ImportError:
    _SLOWAPI = False

    def _apply_rate_limit(view_fn):
        return view_fn  # no-op if slowapi not installed


# ---------------------------------------------------------------------------
# Chat endpoint
# ---------------------------------------------------------------------------


def _chat_handler():
    # Circuit breaker check
    if circuit_breaker.is_open():
        return jsonify(
            {
                "error": "service_unavailable",
                "message": (
                    f"Daily cost limit reached "
                    f"(${circuit_breaker.total_cost:.4f}). Service paused."
                ),
            }
        ), 503

    msg = request.json.get("message", "") if request.is_json else ""

    # Input token budget
    safe_msg, truncated = truncate_to_budget(msg, MAX_INPUT_TOKENS)

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": safe_msg}],
        max_tokens=MAX_OUTPUT_TOKENS,  # hard output cap
    )

    circuit_breaker.record(resp.usage.prompt_tokens, resp.usage.completion_tokens)

    return jsonify(
        {
            "response": resp.choices[0].message.content,
            "truncated": truncated,
            "usage": {
                "input_tokens": resp.usage.prompt_tokens,
                "output_tokens": resp.usage.completion_tokens,
            },
            "cumulative_cost_usd": round(circuit_breaker.total_cost, 6),
        }
    )


# Apply rate limiting and register route
chat_view = _apply_rate_limit(_chat_handler)
app.add_url_rule("/chat", "chat", chat_view, methods=["POST"])


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5201))
    rl = "slowapi" if _SLOWAPI else "disabled (pip install slowapi)"
    print(f"[MITIGATED] LLM10 app on http://localhost:{port}  rate_limiting={rl}")
    app.run(port=port, debug=False)
