"""
LLM01 — Prompt Injection
Mitigated application.

Defence-in-depth stack:
  Layer 1 — NeMo Guardrails input rails  (direct injection detection)
  Layer 2 — Tool result regex scan       (indirect injection detection)
  Layer 3 — Data-plane wrapping          (instruction / data separation)
  Layer 4 — NeMo Guardrails output rail  (catch-all on the response)

Run:
    python -m src.llm.llm01_prompt_injection.mitigated.agent
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import textwrap
from pathlib import Path

import requests
from dotenv import load_dotenv
from nemoguardrails import LLMRails, RailsConfig
from nemoguardrails.actions import action

from .tool_result_filter import scan_tool_result, wrap_tool_result

load_dotenv()

if not os.environ.get("OPENAI_API_KEY"):
    print("[Error] OPENAI_API_KEY is not set.")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.WARNING)
log = logging.getLogger("llm01.mitigated")

# ---------------------------------------------------------------------------
# NeMo Guardrails setup
# ---------------------------------------------------------------------------

_CONFIG_DIR = Path(__file__).parent / "config"

_config = RailsConfig.from_path(str(_CONFIG_DIR))
_rails = LLMRails(_config)


# Register the generic log action so Colang flows can call it
@action(name="log_guardrail_event")
async def _log_guardrail_event(
    event_type: str = "unknown",
    rail: str = "unknown",
    context: dict | None = None,
) -> None:
    user_msg = (context or {}).get("last_user_message", "")
    log.warning("GUARDRAIL | event=%s rail=%s input=%.80r", event_type, rail, user_msg)


# Register self-check actions (NeMo's built-in implementations)
# When these names are referenced in rails.co, NeMo resolves them automatically
# via the prompts defined in config.yml — no extra registration needed.

_rails.register_action(_log_guardrail_event)

# ---------------------------------------------------------------------------
# Content fetching
# ---------------------------------------------------------------------------

_MAX_CONTENT_BYTES = 8_000


def fetch_url(url: str) -> str:
    """Fetch a URL and return its raw text content (capped at 8 kB)."""
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        return resp.text[:_MAX_CONTENT_BYTES]
    except Exception as exc:
        return f"[Could not fetch URL: {exc}]"


# ---------------------------------------------------------------------------
# Mitigated summarisation
# ---------------------------------------------------------------------------


def _build_message(user_message: str) -> str:
    """Fetch any URL in the message, apply defences, and return the full
    user-turn text to be passed to the guarded LLM.

    Layer 2 (regex scan) and Layer 3 (wrapping) are applied here, before
    the content ever reaches the LLM.
    """
    words = user_message.split()
    urls = [w for w in words if w.startswith("http://") or w.startswith("https://")]

    if not urls:
        return user_message

    url = urls[0]
    print(f"  [fetching {url}]")
    raw = fetch_url(url)

    # Layer 2 — scan for indirect injection patterns
    is_safe, pattern = scan_tool_result(raw)
    if not is_safe:
        log.warning("Indirect injection detected in tool result: %r", pattern)
        return (
            user_message
            + "\n\n[Note: the content at the requested URL was blocked because "
            "it contained a potential prompt injection payload. "
            f"Detected pattern: {pattern!r}]"
        )

    # Layer 3 — wrap in data-plane delimiters
    wrapped = wrap_tool_result(raw, tool_name="web_fetch")
    return user_message + f"\n\n{wrapped}"


def summarize(user_message: str) -> str:
    """Answer the user with the full defence-in-depth stack active."""
    full_message = _build_message(user_message)

    # Layers 1 & 4 — NeMo Guardrails (input + output rails)
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    result = loop.run_until_complete(
        _rails.generate_async(messages=[{"role": "user", "content": full_message}])
    )
    return result


# ---------------------------------------------------------------------------
# REPL
# ---------------------------------------------------------------------------

BANNER = textwrap.dedent("""\
    ┌─────────────────────────────────────────────────────────┐
    │  LLM01 — Prompt Injection  │  MITIGATED agent            │
    │                                                         │
    │  Defence stack:                                         │
    │   • NeMo Guardrails input rails  (direct injection)     │
    │   • Tool result regex scan       (indirect injection)   │
    │   • Data-plane wrapping          (instruction/data sep) │
    │   • NeMo Guardrails output rail  (catch-all)            │
    │                                                         │
    │  Commands: /quit                                        │
    └─────────────────────────────────────────────────────────┘
""")


def main() -> None:
    print(BANNER)
    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        if not user_input:
            continue
        if user_input.lower() in ("/quit", "/exit", "/q"):
            print("Goodbye!")
            break

        print()
        try:
            answer = summarize(user_input)
        except Exception as exc:
            print(f"[Error] {exc}")
        else:
            print(f"Agent: {answer}")
        print()


if __name__ == "__main__":
    main()
