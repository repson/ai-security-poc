"""
LLM02 — Sensitive Information Disclosure
Mitigated application.

Defence-in-depth stack:
  Layer 1 — Regex filter (fast first-pass on input)
  Layer 2 — Microsoft Presidio NLP anonymisation (input + output)
  Layer 3 — NeMo Guardrails input / output rails
  Layer 4 — NeMo self-check output (secondary LLM call)

Run:
    python -m src.llm.llm02_sensitive_information.mitigated.agent
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import textwrap
from pathlib import Path

from dotenv import load_dotenv
from nemoguardrails import LLMRails, RailsConfig
from nemoguardrails.actions import action

from .regex_filter import has_pii as regex_has_pii, redact as regex_redact
from .presidio_filter import anonymize_text

load_dotenv()

if not os.environ.get("OPENAI_API_KEY"):
    print("[Error] OPENAI_API_KEY is not set.")
    sys.exit(1)

log = logging.getLogger("llm02.mitigated")

# ---------------------------------------------------------------------------
# NeMo Guardrails setup
# ---------------------------------------------------------------------------

_CONFIG_DIR = Path(__file__).parent / "config"
_config = RailsConfig.from_path(str(_CONFIG_DIR))
_rails = LLMRails(_config)


@action(name="log_guardrail_event")
async def _log_guardrail_event(
    event_type: str = "unknown",
    rail: str = "unknown",
    context: dict | None = None,
) -> None:
    msg = (context or {}).get("last_user_message", "")
    log.warning("GUARDRAIL | event=%s rail=%s input=%.80r", event_type, rail, msg)


_rails.register_action(_log_guardrail_event)

# ---------------------------------------------------------------------------
# Conversation history (kept in-memory for the session)
# ---------------------------------------------------------------------------

_history: list[dict] = []


def reset() -> None:
    _history.clear()


# ---------------------------------------------------------------------------
# Sanitisation pipeline
# ---------------------------------------------------------------------------


def _sanitize(text: str, label: str) -> str:
    """Run regex → Presidio anonymisation on *text*.

    Layer 1: cheap regex pass (always runs, no external dependency).
    Layer 2: Presidio NLP pass (runs when presidio is installed).
    """
    # Layer 1 — regex redaction
    if regex_has_pii(text):
        redacted = regex_redact(text)
        log.warning("Regex PII detected in %s — redacting.", label)
    else:
        redacted = text

    # Layer 2 — Presidio deep scan on already-redacted text
    try:
        anonymised, findings = anonymize_text(redacted)
        if findings:
            log.warning(
                "Presidio found %d PII entity(ies) in %s: %s",
                len(findings),
                label,
                [f["entity_type"] for f in findings],
            )
        return anonymised
    except ImportError:
        # Presidio not installed — regex layer is sufficient for demo purposes
        return redacted


# ---------------------------------------------------------------------------
# Mitigated chat
# ---------------------------------------------------------------------------


def chat(user_message: str) -> str:
    """Send a message through the full defence stack and return the safe reply."""

    # Layer 1+2: sanitise user input before the LLM ever sees it
    safe_input = _sanitize(user_message, label="user_input")

    # Build history with sanitised input
    _history.append({"role": "user", "content": safe_input})

    # Layer 3+4: NeMo Guardrails (input rails + output rails + self-check)
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    messages = [{"role": m["role"], "content": m["content"]} for m in _history]
    raw_reply = loop.run_until_complete(_rails.generate_async(messages=messages))

    # Layer 1+2: sanitise LLM output before returning to user
    safe_reply = _sanitize(raw_reply, label="llm_output")

    _history.append({"role": "assistant", "content": safe_reply})
    return safe_reply


# ---------------------------------------------------------------------------
# REPL
# ---------------------------------------------------------------------------

BANNER = textwrap.dedent("""\
    ┌─────────────────────────────────────────────────────────┐
    │  LLM02 — Sensitive Information Disclosure               │
    │  MITIGATED agent                                        │
    │                                                         │
    │  Defence stack:                                         │
    │   • Regex filter          (fast first-pass)             │
    │   • Microsoft Presidio    (NLP anonymisation)           │
    │   • NeMo Guardrails rails (input + output)              │
    │   • NeMo self-check       (secondary LLM call)          │
    │                                                         │
    │  Commands: /reset  /quit                                │
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
        if user_input.lower() == "/reset":
            reset()
            print("[History cleared]\n")
            continue

        print()
        try:
            answer = chat(user_input)
        except Exception as exc:
            print(f"[Error] {exc}")
        else:
            print(f"Agent: {answer}")
        print()


if __name__ == "__main__":
    main()
