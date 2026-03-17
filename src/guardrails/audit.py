"""
Structured audit logger for guardrail events.

Every time a rail fires (input blocked, output blocked, hallucination
detected, etc.) this module appends a JSON line to a rotating log file
so that events can be reviewed, alerted on, or ingested by a SIEM.

Log location: logs/guardrails_audit.jsonl  (relative to project root)
Log format:   newline-delimited JSON (NDJSON / JSON Lines)

Each record contains:
  timestamp   ISO-8601 UTC string
  event_type  one of: input_blocked, output_blocked, hallucination_detected,
                      sensitive_input, sensitive_output
  rail        name of the Colang flow that triggered the event
  user_input  first 200 chars of the user message (truncated for privacy)
  details     arbitrary extra context dict
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

# Resolve project root as two levels above this file (src/guardrails/audit.py)
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_LOG_DIR = _PROJECT_ROOT / "logs"
_LOG_FILE = _LOG_DIR / "guardrails_audit.jsonl"

_LOG_DIR.mkdir(exist_ok=True)

# Use Python's logging with a RotatingFileHandler so the file never grows
# beyond 5 MB, keeping the last 3 rotated copies.
_handler = RotatingFileHandler(
    _LOG_FILE,
    maxBytes=5 * 1024 * 1024,  # 5 MB
    backupCount=3,
    encoding="utf-8",
)
_handler.setFormatter(logging.Formatter("%(message)s"))

_audit_logger = logging.getLogger("guardrails.audit")
_audit_logger.setLevel(logging.INFO)
_audit_logger.addHandler(_handler)
_audit_logger.propagate = False  # Don't bubble up to root logger


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def log_event(
    event_type: str,
    rail: str,
    user_input: str = "",
    details: dict[str, Any] | None = None,
) -> None:
    """
    Append a structured JSON record to the audit log.

    Parameters
    ----------
    event_type:
        Category of the event, e.g. ``"input_blocked"``.
    rail:
        Name of the Colang flow or action that triggered the event.
    user_input:
        The user's raw message (truncated to 200 chars for privacy).
    details:
        Any additional key/value pairs to include in the record.
    """
    record: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "rail": rail,
        "user_input": user_input[:200],
        "details": details or {},
    }
    _audit_logger.info(json.dumps(record, ensure_ascii=False))
