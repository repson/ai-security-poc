"""
LLM09 — Misinformation
Mitigated application.

Defence layers:
  1. Hardened system prompt with epistemic honesty rules
  2. NeMo Guardrails hallucination detection rail (secondary LLM call)

Run:
    python -m src.llm.llm09_misinformation.mitigated.agent
"""

from __future__ import annotations

import asyncio, logging, os, sys, textwrap
from pathlib import Path
from dotenv import load_dotenv
from nemoguardrails import LLMRails, RailsConfig
from nemoguardrails.actions import action

load_dotenv()
if not os.environ.get("OPENAI_API_KEY"):
    print("[Error] OPENAI_API_KEY is not set.")
    sys.exit(1)

log = logging.getLogger("llm09.mitigated")

_CONFIG_DIR = Path(__file__).parent / "config"
_config = RailsConfig.from_path(str(_CONFIG_DIR))
_rails = LLMRails(_config)

_history: list[dict] = []


@action(name="log_guardrail_event")
async def _log(
    event_type: str = "unknown", rail: str = "unknown", context: dict | None = None
) -> None:
    msg = (context or {}).get("last_user_message", "")
    log.warning("GUARDRAIL | event=%s rail=%s input=%.80r", event_type, rail, msg)


@action(name="check_hallucination")
async def _check_hallucination(context: dict | None = None) -> bool:
    """Secondary LLM call to detect hallucinations in the bot response."""
    if not context:
        return False
    user_input = context.get("last_user_message", "")
    bot_response = context.get("bot_response", "")
    prompt = context.get("check_hallucination_prompt", "")

    if not prompt:
        prompt = (
            f"Does this response contain fabricated or unverifiable facts?\n"
            f'User: "{user_input}"\nAssistant: "{bot_response}"\nAnswer only Yes or No.'
        )

    from openai import AsyncOpenAI

    ac = AsyncOpenAI(api_key=os.environ["OPENAI_API_KEY"])
    resp = await ac.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
        max_tokens=5,
    )
    answer = (resp.choices[0].message.content or "").strip().lower()
    detected = answer.startswith("yes")
    if detected:
        log.warning("Hallucination detected in response for: %.60r", user_input)
    return detected


_rails.register_action(_log)
_rails.register_action(_check_hallucination)


def reset() -> None:
    _history.clear()


def chat(user_message: str) -> str:
    _history.append({"role": "user", "content": user_message})

    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    messages = [{"role": m["role"], "content": m["content"]} for m in _history]
    reply = loop.run_until_complete(_rails.generate_async(messages=messages))
    _history.append({"role": "assistant", "content": reply})
    return reply


BANNER = textwrap.dedent("""\
    ┌─────────────────────────────────────────────────────────┐
    │  LLM09 — Misinformation  │  MITIGATED                   │
    │  Defence: hardened prompt · NeMo hallucination rail      │
    │  Commands: /reset  /quit                                │
    └─────────────────────────────────────────────────────────┘
""")


def main() -> None:
    print(BANNER)
    while True:
        try:
            inp = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break
        if not inp:
            continue
        if inp.lower() in ("/quit", "/exit"):
            break
        if inp.lower() == "/reset":
            reset()
            print("[reset]\n")
            continue
        print()
        print(f"Agent: {chat(inp)}\n")


if __name__ == "__main__":
    main()
