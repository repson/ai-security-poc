"""
CLI entry point for the guarded agent (with NeMo Guardrails).

Usage:
    python -m src.guardrails.main

Commands inside the REPL:
    /reset   - clear conversation history
    /quit    - exit (also Ctrl+C / Ctrl+D)
"""

from __future__ import annotations

import os
import sys

from dotenv import load_dotenv

load_dotenv()

if not os.environ.get("OPENAI_API_KEY"):
    print(
        "[Error] OPENAI_API_KEY is not set.\n"
        "Copy .env.example to .env and add your key, or export the variable."
    )
    sys.exit(1)

from .guardrails_agent import GuardedAgent  # noqa: E402


BANNER = """
╔══════════════════════════════════════════════════╗
║   Guarded Agent  —  NeMo Guardrails active       ║
╚══════════════════════════════════════════════════╝
Type your message and press Enter.
Commands: /reset  /quit

Active rails:
  [input]  jailbreak detection, sensitive data filter
  [output] sensitive data filter, off-topic block
"""

DIVIDER = "─" * 52


def run_repl(agent: GuardedAgent) -> None:
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
            agent.reset()
            print("[Conversation history cleared]\n")
            continue

        print(f"\n{DIVIDER}")
        try:
            answer = agent.chat(user_input)
        except Exception as exc:  # noqa: BLE001
            print(f"[Agent error] {exc}")
        else:
            print(f"Agent: {answer}")
        print(f"{DIVIDER}\n")


if __name__ == "__main__":
    agent = GuardedAgent()
    run_repl(agent)
