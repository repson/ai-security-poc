"""
LLM06 — Excessive Agency
Mitigated application.

Mitigations:
  1. Least-privilege tool registry  — delete_all_data not registered
  2. HITL gate                      — HIGH risk tools require explicit approval
  3. Scope enforcement              — tools validate arguments against scope rules
  4. Auto-approve mode              — set AUTO_APPROVE=1 for non-interactive tests

Run:
    python -m src.llm.llm06_excessive_agency.mitigated.agent
    AUTO_APPROVE=0 python -m src.llm.llm06_excessive_agency.mitigated.agent
"""

from __future__ import annotations

import json
import os
import sys
import textwrap

from dotenv import load_dotenv
from openai import OpenAI

from .tool_registry import REGISTRY, RiskLevel

load_dotenv()

if not os.environ.get("OPENAI_API_KEY"):
    print("[Error] OPENAI_API_KEY is not set.")
    sys.exit(1)

MODEL = "gpt-4o-mini"
client = OpenAI()

# When AUTO_APPROVE=1 the HITL gate auto-denies (for testing).
# When AUTO_APPROVE=0 (default) the gate prompts the operator.
_AUTO_APPROVE = os.getenv("AUTO_APPROVE", "0")  # "0"=prompt, "1"=auto-deny in tests

SYSTEM_PROMPT = """\
You are a helpful file management assistant.
You can read and list files, delete specific files (with approval), and send emails.
You do NOT have the ability to delete all data at once.
"""


# ---------------------------------------------------------------------------
# HITL gate
# ---------------------------------------------------------------------------


def _request_approval(tool_name: str, args: dict) -> bool:
    """Return True if the operator approves the high-risk tool call."""
    print("\n" + "=" * 56)
    print(f"  [APPROVAL REQUIRED]  risk=HIGH")
    print(f"  Tool      : {tool_name}")
    print(f"  Arguments : {args}")
    print("=" * 56)

    if _AUTO_APPROVE == "1":
        # Used by tests: auto-deny to confirm the gate fires
        print("  [AUTO] Denied (AUTO_APPROVE=1)")
        return False

    try:
        answer = input("  Approve? (yes/no): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n  [Approval cancelled]")
        return False

    return answer == "yes"


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------


def run(user_message: str) -> str:
    tools = [t.openai_schema for t in REGISTRY.values()]
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_message},
    ]

    for _ in range(8):
        resp = client.chat.completions.create(
            model=MODEL, messages=messages, tools=tools, tool_choice="auto"
        )
        msg = resp.choices[0].message
        messages.append(msg)

        if resp.choices[0].finish_reason == "stop":
            return msg.content or ""

        if resp.choices[0].finish_reason == "tool_calls":
            for tc in msg.tool_calls or []:
                name = tc.function.name
                args = json.loads(tc.function.arguments or "{}")

                # Tool not in registry
                if name not in REGISTRY:
                    result = f"[Blocked] Tool '{name}' is not available."
                    print(f"  [BLOCKED] {name} not in registry")
                else:
                    tool = REGISTRY[name]
                    # HITL gate for HIGH / CRITICAL tools
                    if tool.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                        approved = _request_approval(name, args)
                        if not approved:
                            result = f"[Blocked] Tool '{name}' was denied by the human operator."
                        else:
                            result = str(tool.func(**args))
                    else:
                        result = str(tool.func(**args))
                    print(f"  [TOOL] {name}({args}) → {result[:80]}")

                messages.append(
                    {"role": "tool", "tool_call_id": tc.id, "content": result}
                )

    return "[max rounds reached]"


# ---------------------------------------------------------------------------
# REPL
# ---------------------------------------------------------------------------

BANNER = textwrap.dedent("""\
    ┌─────────────────────────────────────────────────────────┐
    │  LLM06 — Excessive Agency  │  MITIGATED agent            │
    │                                                         │
    │  Mitigations active:                                    │
    │   • Least-privilege registry  (no delete_all_data)      │
    │   • HITL gate for HIGH-risk tools                       │
    │   • Scope enforcement per tool                          │
    │                                                         │
    │  Commands: /quit  /state                                │
    └─────────────────────────────────────────────────────────┘
""")


def main() -> None:
    from .tool_registry import get_state

    print(BANNER)
    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break
        if not user_input:
            continue
        if user_input.lower() in ("/quit", "/exit"):
            break
        if user_input.lower() == "/state":
            print(f"  {get_state()}")
            continue
        print()
        answer = run(user_input)
        print(f"Agent: {answer}\n")


if __name__ == "__main__":
    main()
