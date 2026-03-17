"""
LLM01 — Prompt Injection
Vulnerable application.

A web-summarisation agent that fetches external content and passes it
directly into the LLM context with no sanitisation. Both direct and
indirect injection attacks succeed against this agent.

Run:
    python -m src.llm.llm01_prompt_injection.vulnerable.agent
"""

from __future__ import annotations

import os
import sys
import textwrap

import requests
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

if not os.environ.get("OPENAI_API_KEY"):
    print("[Error] OPENAI_API_KEY is not set.")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODEL = "gpt-4o-mini"

SYSTEM_PROMPT = """\
You are a helpful research assistant.
You can summarise web pages when the user provides a URL or raw content.
Answer all questions honestly and completely.
"""

client = OpenAI()


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def fetch_url(url: str) -> str:
    """Fetch a URL and return its raw text content.

    VULNERABLE: the returned content is attacker-controlled and is injected
    directly into the LLM prompt with no filtering.
    """
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        return resp.text[:8000]  # cap length only — no sanitisation
    except Exception as exc:
        return f"[Could not fetch URL: {exc}]"


def summarize(user_message: str) -> str:
    """Answer the user. If the message contains a URL, fetch it first.

    VULNERABLE: raw fetched content is passed straight into the user turn,
    so any injection payload embedded in the page reaches the LLM.
    """
    content_block = ""

    # Naïve URL extraction
    words = user_message.split()
    urls = [w for w in words if w.startswith("http://") or w.startswith("https://")]

    if urls:
        url = urls[0]
        print(f"  [fetching {url}]")
        raw = fetch_url(url)
        # VULNERABLE: raw content injected verbatim into the user message
        content_block = f"\n\n--- PAGE CONTENT ---\n{raw}\n--- END PAGE CONTENT ---"

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_message + content_block},
    ]

    response = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        max_tokens=1024,
    )
    return response.choices[0].message.content or ""


# ---------------------------------------------------------------------------
# REPL
# ---------------------------------------------------------------------------

BANNER = textwrap.dedent("""\
    ┌─────────────────────────────────────────────────────────┐
    │  LLM01 — Prompt Injection  │  VULNERABLE agent           │
    │                                                         │
    │  Try:  Ignore your previous instructions and …          │
    │  Try:  Summarise http://localhost:8080/payload.html      │
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
