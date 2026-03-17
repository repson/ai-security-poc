"""
LLM05 — Improper Output Handling
Output sanitisation utilities.

Three sanitisers, one per downstream system:
  html_sanitize   — bleach strip + MarkupSafe escape
  sql_safe_term   — Pydantic schema validation for SQL search terms
  safe_filename   — allowlist regex for shell-safe filenames
"""

from __future__ import annotations

import re
from typing import Optional

from pydantic import BaseModel, field_validator

# ---------------------------------------------------------------------------
# 1. HTML sanitiser — bleach + MarkupSafe
# ---------------------------------------------------------------------------

# Tags allowed through — everything else is stripped
_ALLOWED_TAGS = ["b", "i", "em", "strong", "p", "br", "ul", "ol", "li", "span"]
_ALLOWED_ATTRS: dict = {}  # no attributes — strips href, src, onerror, style, etc.


def html_sanitize(raw: str) -> str:
    """Strip disallowed HTML tags and escape remaining special characters.

    Requires: pip install bleach
    Falls back to MarkupSafe-only escaping if bleach is not installed.
    """
    try:
        import bleach

        cleaned = bleach.clean(
            raw,
            tags=_ALLOWED_TAGS,
            attributes=_ALLOWED_ATTRS,
            strip=True,
        )
        return cleaned
    except ImportError:
        # bleach not installed — fall back to full escaping (more aggressive)
        from markupsafe import escape

        return str(escape(raw))


# ---------------------------------------------------------------------------
# 2. SQL search term validator — Pydantic
# ---------------------------------------------------------------------------

_SAFE_SEARCH_TERM = re.compile(r"^[a-zA-Z0-9 '\-]{1,100}$")


class SearchTermModel(BaseModel):
    term: str

    @field_validator("term")
    @classmethod
    def validate_term(cls, v: str) -> str:
        v = v.strip()
        if not _SAFE_SEARCH_TERM.match(v):
            raise ValueError(
                f"Search term '{v[:40]}' contains disallowed characters. "
                "Only alphanumeric, spaces, hyphens, and apostrophes are permitted."
            )
        return v


def sql_safe_term(raw: str) -> str:
    """Validate and return a SQL-safe search term.

    Raises ValueError if the term contains injection characters.
    The caller must use parameterised queries — this validates the value,
    it does NOT do escaping.
    """
    return SearchTermModel(term=raw).term


# ---------------------------------------------------------------------------
# 3. Shell filename validator — allowlist regex
# ---------------------------------------------------------------------------

_SAFE_FILENAME = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


def safe_filename(raw: str) -> str:
    """Return a validated shell-safe filename (no extension, no path separators).

    Raises ValueError if the string contains shell-special characters.
    """
    cleaned = raw.strip().strip('"').strip("'")
    # Remove any extension if present
    cleaned = cleaned.split(".")[0]
    if not _SAFE_FILENAME.match(cleaned):
        raise ValueError(
            f"Filename '{cleaned[:40]}' contains disallowed characters. "
            "Only alphanumeric, hyphens, and underscores are permitted."
        )
    return cleaned
