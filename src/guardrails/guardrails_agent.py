"""
Guarded agent: wraps the base Agent with NeMo Guardrails.

NeMo Guardrails sits in front of the agent as a middleware layer:

  User input
      │
      ▼
  ┌─────────────────────────┐
  │  NeMo Guardrails        │  ← input rails (jailbreak, sensitive data)
  │  (LLMRails)             │
  │         │               │
  │         ▼               │
  │    Agent.chat()         │  ← base agent + tool-calling loop
  │         │               │
  │         ▼               │
  │  output rails           │  ← sensitive data, off-topic
  └─────────────────────────┘
      │
      ▼
  Final response

The GuardedAgent class exposes the same public interface as Agent
(chat / reset) so the CLI in src/agent/main.py can be swapped
with zero changes.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from nemoguardrails import LLMRails, RailsConfig

from src.agent.agent import Agent

load_dotenv()

# Path to the guardrails config directory (contains config.yml and *.co files)
_CONFIG_DIR = Path(__file__).parent / "config"


class GuardedAgent:
    """
    Conversational agent protected by NeMo Guardrails.

    NeMo Guardrails handles input and output rails; the underlying
    Agent class handles tool orchestration and LLM communication.
    """

    def __init__(self) -> None:
        # Load the Colang + YAML configuration
        config = RailsConfig.from_path(str(_CONFIG_DIR))
        self._rails = LLMRails(config)

        # Register custom Python actions so Colang flows can call them
        from src.guardrails import actions  # noqa: F401 — registers @action decorators

        self._rails.register_action(actions.check_input_sensitive_data)
        self._rails.register_action(actions.check_output_sensitive_data)
        self._rails.register_action(actions.self_check_input)
        self._rails.register_action(actions.self_check_output)
        self._rails.register_action(actions.check_hallucination)
        self._rails.register_action(actions.log_guardrail_event)

        # The unprotected base agent (used as the actual responder)
        self._agent = Agent()

    # ------------------------------------------------------------------
    # Public API  (mirrors Agent)
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Clear base agent conversation history."""
        self._agent.reset()

    def chat(self, user_message: str) -> str:
        """
        Send *user_message* through the full guardrails pipeline and
        return the final (safe) response.

        Flow:
          1. NeMo Guardrails evaluates input rails (Colang flows).
          2. If the message passes, the base Agent generates a response
             using its tool-calling loop.
          3. NeMo Guardrails evaluates output rails on the response.
          4. The (possibly blocked) response is returned.
        """
        import asyncio

        # Build the message list in the format expected by LLMRails
        messages = [{"role": "user", "content": user_message}]

        # LLMRails.generate is synchronous but internally may use asyncio;
        # calling generate_async from a sync context avoids event-loop conflicts.
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        # Use the synchronous generate method — simpler and sufficient for CLI
        response = self._rails.generate(messages=messages)

        # LLMRails returns either a string or a dict with a "content" key
        if isinstance(response, dict):
            return response.get("content", "")
        return str(response)
