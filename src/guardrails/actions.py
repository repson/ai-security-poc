"""
Custom NeMo Guardrails actions.

Actions are Python functions decorated with @action that can be called
from Colang flows.  They extend the guardrails system with logic that
cannot be expressed in Colang alone.

Docs: https://docs.nvidia.com/nemo/guardrails/latest/configure-rails/actions/
"""

from __future__ import annotations

import os
import re
from typing import Optional

from nemoguardrails.actions import action
from openai import AsyncOpenAI

from .audit import log_event


# ---------------------------------------------------------------------------
# Patterns for detecting sensitive data
# ---------------------------------------------------------------------------

_SENSITIVE_PATTERNS = [
    # Credit card (Luhn-candidate 13-19 digit sequences, optionally separated)
    re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    # US Social Security Number
    re.compile(r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b"),
    # Generic API key / secret token heuristic (long alphanumeric strings)
    re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"),
    # Email address
    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
]


def _contains_sensitive_data(text: str) -> bool:
    return any(pattern.search(text) for pattern in _SENSITIVE_PATTERNS)


# ---------------------------------------------------------------------------
# Helper: secondary LLM call for self-check / hallucination
# ---------------------------------------------------------------------------


async def _llm_yes_no(prompt: str) -> bool:
    """
    Make a lightweight secondary LLM call and return True if the answer
    starts with 'yes' (case-insensitive).

    Uses gpt-4o-mini with temperature=0 for deterministic classification.
    """
    client = AsyncOpenAI(api_key=os.environ["OPENAI_API_KEY"])
    response = await client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
        max_tokens=5,
    )
    answer = (response.choices[0].message.content or "").strip().lower()
    return answer.startswith("yes")


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


@action(name="check_input_sensitive_data")
async def check_input_sensitive_data(context: Optional[dict] = None) -> bool:
    """
    Returns True if the user's last message appears to contain sensitive data
    (credit card numbers, SSNs, API keys, email addresses, etc.).
    Logs the event to the audit trail when triggered.
    """
    if context is None:
        return False
    message = context.get("last_user_message", "")
    result = _contains_sensitive_data(message)
    if result:
        log_event(
            event_type="input_blocked",
            rail="check_sensitive_data_input",
            user_input=message,
            details={"reason": "sensitive_data_detected"},
        )
    return result


@action(name="check_output_sensitive_data")
async def check_output_sensitive_data(context: Optional[dict] = None) -> bool:
    """
    Returns True if the bot's last response appears to contain sensitive data.
    Logs the event to the audit trail when triggered.
    """
    if context is None:
        return False
    message = context.get("bot_response", "")
    result = _contains_sensitive_data(message)
    if result:
        log_event(
            event_type="output_blocked",
            rail="check_sensitive_data_output",
            user_input=context.get("last_user_message", ""),
            details={"reason": "sensitive_data_in_response"},
        )
    return result


@action(name="self_check_input")
async def self_check_input(context: Optional[dict] = None) -> bool:
    """
    Secondary LLM call that checks whether the user message complies with
    the policy defined in config.yml (task: self_check_input).

    Returns True (allowed) or False (blocked).
    Logs a blocked event to the audit trail.
    """
    if context is None:
        return True

    user_input = context.get("last_user_message", "")
    prompt = context.get("self_check_input_prompt", "")

    if not prompt:
        # Fallback: build a minimal prompt if NeMo didn't inject one
        prompt = (
            f"Does this user message comply with safety policies? "
            f'Answer only Yes or No.\nMessage: "{user_input}"'
        )

    allowed = await _llm_yes_no(prompt)

    if not allowed:
        log_event(
            event_type="input_blocked",
            rail="self_check_input",
            user_input=user_input,
            details={"reason": "self_check_llm_rejected"},
        )
    return allowed


@action(name="self_check_output")
async def self_check_output(context: Optional[dict] = None) -> bool:
    """
    Secondary LLM call that checks whether the bot response complies with
    the policy defined in config.yml (task: self_check_output).

    Returns True (allowed) or False (blocked).
    Logs a blocked event to the audit trail.
    """
    if context is None:
        return True

    bot_response = context.get("bot_response", "")
    prompt = context.get("self_check_output_prompt", "")

    if not prompt:
        prompt = (
            f"Does this assistant response comply with safety policies? "
            f'Answer only Yes or No.\nResponse: "{bot_response}"'
        )

    allowed = await _llm_yes_no(prompt)

    if not allowed:
        log_event(
            event_type="output_blocked",
            rail="self_check_output",
            user_input=context.get("last_user_message", ""),
            details={
                "reason": "self_check_llm_rejected",
                "bot_response_snippet": bot_response[:200],
            },
        )
    return allowed


@action(name="check_hallucination")
async def check_hallucination(context: Optional[dict] = None) -> bool:
    """
    Secondary LLM call that detects whether the bot response contains
    fabricated or unverifiable facts (hallucinations).

    Returns True if hallucination is detected (response should be blocked),
    False if the response appears grounded.
    Logs detected hallucinations to the audit trail.
    """
    if context is None:
        return False

    user_input = context.get("last_user_message", "")
    bot_response = context.get("bot_response", "")
    prompt = context.get("check_hallucination_prompt", "")

    if not prompt:
        prompt = (
            f"Does the following assistant response contain fabricated or "
            f"unverifiable facts?\n"
            f'User asked: "{user_input}"\n'
            f'Assistant responded: "{bot_response}"\n'
            f"Answer only Yes or No."
        )

    has_hallucination = await _llm_yes_no(prompt)

    if has_hallucination:
        log_event(
            event_type="hallucination_detected",
            rail="check_hallucination",
            user_input=user_input,
            details={"bot_response_snippet": bot_response[:200]},
        )
    return has_hallucination


@action(name="log_guardrail_event")
async def log_guardrail_event(
    event_type: str = "unknown",
    rail: str = "unknown",
    context: Optional[dict] = None,
) -> None:
    """
    Generic action to log any guardrail event from a Colang flow.
    Can be called manually from flows that don't have a dedicated action.
    """
    user_message = (context or {}).get("last_user_message", "")
    log_event(
        event_type=event_type,
        rail=rail,
        user_input=user_message,
    )
