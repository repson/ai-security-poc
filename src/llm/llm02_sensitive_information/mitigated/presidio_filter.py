"""
LLM02 — Sensitive Information Disclosure
Microsoft Presidio PII detection and anonymisation layer.

Provides two functions used by the mitigated agent:
  anonymize_text  — detect and replace PII entities in any string
  pii_findings    — return entity list without modifying the text (for logging)

Requires:
    pip install presidio-analyzer presidio-anonymizer
    python -m spacy download en_core_web_lg
"""

from __future__ import annotations

import functools
import logging
from typing import Optional

log = logging.getLogger("llm02.presidio")

# ---------------------------------------------------------------------------
# Presidio initialisation (lazy — only loaded when first called)
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _get_engines():
    """Initialise Presidio engines once and cache them."""
    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_anonymizer import AnonymizerEngine

        analyzer = AnalyzerEngine()
        anonymizer = AnonymizerEngine()
        return analyzer, anonymizer
    except ImportError as exc:
        raise ImportError(
            "presidio-analyzer and presidio-anonymizer are required.\n"
            "Install with: pip install presidio-analyzer presidio-anonymizer\n"
            "Then: python -m spacy download en_core_web_lg"
        ) from exc


# ---------------------------------------------------------------------------
# Entity types to protect
# ---------------------------------------------------------------------------

ENTITIES = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_SSN",
    "US_BANK_NUMBER",
    "IBAN_CODE",
    "IP_ADDRESS",
    "US_DRIVER_LICENSE",
    "US_PASSPORT",
    "MEDICAL_LICENSE",
    "URL",
    "LOCATION",
    "DATE_TIME",
    "NRP",  # Nationality, religion, political group
]

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def anonymize_text(text: str, language: str = "en") -> tuple[str, list[dict]]:
    """Detect and anonymise PII in *text* using Microsoft Presidio.

    Each detected entity is replaced by its type tag, e.g.:
        "My SSN is 123-45-6789"  →  "My SSN is <US_SSN>"
        "Email me at a@b.com"    →  "Email me at <EMAIL_ADDRESS>"

    Credit cards are masked (last 4 digits kept):
        "4111 1111 1111 1111"  →  "************1111"

    Args:
        text:     input string to sanitise.
        language: language code for the Presidio NLP engine (default "en").

    Returns:
        (anonymised_text, findings)
        findings is a list of dicts with keys: entity_type, score, start, end.
    """
    if not text or not text.strip():
        return text, []

    try:
        from presidio_anonymizer.entities import OperatorConfig

        analyzer, anonymizer = _get_engines()

        results = analyzer.analyze(
            text=text,
            entities=ENTITIES,
            language=language,
        )

        if not results:
            return text, []

        anonymised = anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators={
                "DEFAULT": OperatorConfig("replace", {"new_value": "<{entity_type}>"}),
                "CREDIT_CARD": OperatorConfig(
                    "mask",
                    {"masking_char": "*", "chars_to_mask": 12, "from_end": False},
                ),
            },
        )

        findings = [
            {
                "entity_type": r.entity_type,
                "score": round(r.score, 3),
                "start": r.start,
                "end": r.end,
            }
            for r in results
        ]

        return anonymised.text, findings

    except Exception as exc:
        # Presidio failure must not break the application — fall back to raw text
        # but log the error so operators are aware.
        log.error("Presidio anonymisation failed: %s", exc)
        return text, []


def has_pii(text: str, language: str = "en") -> bool:
    """Return True if *text* contains any detectable PII entity."""
    _, findings = anonymize_text(text, language)
    return len(findings) > 0
