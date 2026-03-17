"""
LLM02 — Sensitive Information Disclosure
Regex-based PII filter (fast first-pass layer).

Runs before Presidio to catch the most common patterns cheaply.
Used both on user input and on LLM output.

Patterns covered:
  - Credit / debit card numbers (Luhn-candidate 13-19 digit sequences)
  - US Social Security Numbers
  - Generic API keys / secret tokens (≥32-char alphanumeric strings)
  - Email addresses
  - UK National Insurance numbers
  - Basic IBAN codes
"""

from __future__ import annotations

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "CREDIT_CARD",
        re.compile(r"\b(?:\d[ \-]?){13,19}\b"),
    ),
    (
        "US_SSN",
        re.compile(r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b"),
    ),
    (
        "API_KEY",
        re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"),
    ),
    (
        "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "UK_NI",
        re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b", re.IGNORECASE),
    ),
    (
        "IBAN",
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),
    ),
]

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan(text: str) -> list[dict]:
    """Return all regex-matched PII entities in *text*.

    Each result dict has keys: entity_type, match, start, end.
    """
    findings: list[dict] = []
    for entity_type, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            findings.append(
                {
                    "entity_type": entity_type,
                    "match": m.group(0),
                    "start": m.start(),
                    "end": m.end(),
                }
            )
    return findings


def has_pii(text: str) -> bool:
    """Return True if any PII pattern matches in *text*."""
    return any(pattern.search(text) for _, pattern in _PATTERNS)


def redact(text: str) -> str:
    """Replace all regex-matched PII with their entity-type tag."""
    result = text
    # Apply patterns from longest match first to avoid partial overlaps
    for entity_type, pattern in _PATTERNS:
        result = pattern.sub(f"<{entity_type}>", result)
    return result
