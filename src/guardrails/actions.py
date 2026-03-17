"""
Custom NeMo Guardrails actions.

Actions are Python functions decorated with @action that can be called
from Colang flows.  They extend the guardrails system with logic that
cannot be expressed in Colang alone.

Docs: https://docs.nvidia.com/nemo/guardrails/latest/configure-rails/actions/
"""

from __future__ import annotations

import re
from typing import Optional

from nemoguardrails.actions import action


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
# Actions
# ---------------------------------------------------------------------------


@action(name="check_input_sensitive_data")
async def check_input_sensitive_data(context: Optional[dict] = None) -> bool:
    """
    Returns True if the user's last message appears to contain sensitive data
    (credit card numbers, SSNs, API keys, email addresses, etc.).

    Used in Colang flows to trigger an early refusal before the message
    reaches the LLM.
    """
    if context is None:
        return False
    message = context.get("last_user_message", "")
    return _contains_sensitive_data(message)


@action(name="check_output_sensitive_data")
async def check_output_sensitive_data(context: Optional[dict] = None) -> bool:
    """
    Returns True if the bot's last response appears to contain sensitive data.

    Used in output rails to block accidental leakage of private information
    before the response is delivered to the user.
    """
    if context is None:
        return False
    message = context.get("bot_response", "")
    return _contains_sensitive_data(message)


@action(name="log_guardrail_event")
async def log_guardrail_event(
    event_type: str = "unknown",
    context: Optional[dict] = None,
) -> None:
    """
    Logs a guardrail activation event to stdout.

    In production this would write to a structured logging system or
    an audit trail.  Called from Colang flows after a rail fires.
    """
    user_message = (context or {}).get("last_user_message", "<empty>")
    # Truncate for log readability
    snippet = user_message[:120].replace("\n", " ")
    print(f"[GUARDRAIL] event={event_type!r}  input={snippet!r}")
