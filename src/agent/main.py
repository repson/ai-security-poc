"""
CLI entry point for the agentic assistant PoC.

Usage:
    python -m src.agent.main

Commands inside the REPL:
    /reset   - clear conversation history
    /tools   - list available tools
    /quit    - exit (also Ctrl+C / Ctrl+D)
"""

from __future__ import annotations

import os
import sys

from dotenv import load_dotenv

load_dotenv()

# Validate that the API key is present before importing the agent
if not os.environ.get("OPENAI_API_KEY"):
    print(
        "[Error] OPENAI_API_KEY is not set.\n"
        "Copy .env.example to .env and add your key, or export the variable."
    )
    sys.exit(1)

from .agent import Agent  # noqa: E402  (import after env check)
from .tools import TOOL_REGISTRY  # noqa: E402


# ---------------------------------------------------------------------------
# REPL helpers
# ---------------------------------------------------------------------------

BANNER = """
╔══════════════════════════════════════════════════╗
║   Agentic Assistant PoC  —  NeMo Guardrails prep ║
╚══════════════════════════════════════════════════╝
Type your message and press Enter.
Commands: /reset  /tools  /quit
"""

DIVIDER = "─" * 52


def print_tool_list() -> None:
    print("\nAvailable tools:")
    for name in TOOL_REGISTRY:
        print(f"  • {name}")
    print()


def run_repl(agent: Agent) -> None:
    print(BANNER)
    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        if not user_input:
            continue

        # Built-in commands
        if user_input.lower() in ("/quit", "/exit", "/q"):
            print("Goodbye!")
            break
        if user_input.lower() == "/reset":
            agent.reset()
            print("[Conversation history cleared]\n")
            continue
        if user_input.lower() == "/tools":
            print_tool_list()
            continue

        # Regular message – call the agent
        print(f"\n{DIVIDER}")
        try:
            answer = agent.chat(user_input)
        except Exception as exc:  # noqa: BLE001
            print(f"[Agent error] {exc}")
        else:
            print(f"Agent: {answer}")
        print(f"{DIVIDER}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    agent = Agent()
    run_repl(agent)
