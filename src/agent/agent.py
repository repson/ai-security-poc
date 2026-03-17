"""
Core agent logic.

The Agent class wraps the OpenAI chat-completions API with a
function-calling loop so it can use the tools defined in tools.py.

This module is intentionally kept free of CLI concerns so that
NeMo Guardrails can be wired in later without touching the interface layer.
"""

from __future__ import annotations

import os

from openai import OpenAI
from openai.types.chat import ChatCompletionMessageParam

from .tools import TOOLS, dispatch_tool

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODEL = "gpt-4o-mini"
MAX_TOOL_ROUNDS = 10  # safety limit to avoid infinite loops
SYSTEM_PROMPT = """\
You are a helpful general-purpose assistant.
You have access to the following tools:
- get_current_datetime: returns the current UTC date and time.
- calculator: evaluates mathematical expressions.
- web_search: searches the web (mock results in this PoC).

Use the tools whenever they help you give a more accurate or complete answer.
Always answer in the same language the user writes in.
"""


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


class Agent:
    """Stateful conversational agent with tool-calling support."""

    def __init__(self, api_key: str | None = None) -> None:
        self.client = OpenAI(api_key=api_key or os.environ["OPENAI_API_KEY"])
        self.history: list[ChatCompletionMessageParam] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Clear conversation history."""
        self.history.clear()

    def chat(self, user_message: str) -> str:
        """
        Send *user_message*, run the tool-calling loop, and return the
        final assistant text response.
        """
        self.history.append({"role": "user", "content": user_message})

        for _ in range(MAX_TOOL_ROUNDS):
            response = self._call_llm()
            message = response.choices[0].message

            # Persist the assistant turn (may contain tool_calls)
            self.history.append(message)  # type: ignore[arg-type]

            finish_reason = response.choices[0].finish_reason

            if finish_reason == "stop":
                # Final text answer – we're done
                return message.content or ""

            if finish_reason == "tool_calls" and message.tool_calls:
                # Execute each requested tool and feed results back
                for tool_call in message.tool_calls:
                    result = dispatch_tool(
                        tool_call.function.name,
                        tool_call.function.arguments,
                    )
                    self.history.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": result,
                        }
                    )
                # Continue the loop so the LLM can see the tool results
                continue

            # Unexpected finish reason – return whatever content we have
            return message.content or f"[Unexpected finish_reason: {finish_reason}]"

        return "[Error: maximum tool rounds reached without a final answer]"

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _call_llm(self):
        """Send the current message history to the LLM."""
        return self.client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                *self.history,
            ],
            tools=TOOLS,
            tool_choice="auto",
        )
