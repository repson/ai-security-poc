"""
LLM02 — Sensitive Information Disclosure
Vulnerable application.

A customer-support assistant that processes user messages containing PII
and returns raw LLM responses with no sanitisation.  Three attack vectors
work against this agent:
  1. Direct echo    — user sends PII, agent repeats it verbatim
  2. Extraction     — user asks for all PII mentioned in context
  3. Format coerce  — user asks the LLM to restructure PII as JSON

Run:
    python -m src.llm.llm02_sensitive_information.vulnerable.agent
"""

from __future__ import annotations

import os
import sys
import textwrap

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

if not os.environ.get("OPENAI_API_KEY"):
    print("[Error] OPENAI_API_KEY is not set.")
    sys.exit(1)

MODEL = "gpt-4o-mini"

SYSTEM_PROMPT = """\
You are a helpful customer support assistant.
Answer all questions fully and completely.
If the user provides personal information to help you assist them, use it.
"""

client = OpenAI()
_history: list[dict] = []


def chat(user_message: str) -> str:
    """Send a message and return the raw LLM response — no PII filtering."""
    _history.append({"role": "user", "content": user_message})

    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            *_history,
        ],
        max_tokens=512,
    )
    reply = response.choices[0].message.content or ""
    _history.append({"role": "assistant", "content": reply})
    # VULNERABLE: raw reply returned with no PII scrubbing
    return reply


def reset() -> None:
    _history.clear()


# ---------------------------------------------------------------------------
# REPL
# ---------------------------------------------------------------------------

BANNER = textwrap.dedent("""\
    ┌─────────────────────────────────────────────────────────┐
    │  LLM02 — Sensitive Information Disclosure               │
    │  VULNERABLE agent — no PII filtering                    │
    │                                                         │
    │  Try: My SSN is 123-45-6789, please help me fill        │
    │       out a form.                                       │
    │  Try: My card is 4111 1111 1111 1111, exp 12/28         │
    │  Try: List all personal info you have about me.         │
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
