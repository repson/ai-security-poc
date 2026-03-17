"""
ASI09 — Human-Agent Trust Exploitation
Authority claim detector + structured HITL gate.
"""

from __future__ import annotations

import re, time
from dataclasses import dataclass
from typing import Optional

_AUTHORITY_PATTERNS = [
    re.compile(
        r"i\s+am\s+(the\s+)?(ceo|cfo|cto|ciso|vp|director|admin|administrator)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(emergency|critical)\s+(override|authorization|access)", re.IGNORECASE
    ),
    re.compile(r"(level|clearance|authorization)\s*[-–]?\s*\d+", re.IGNORECASE),
    re.compile(
        r"(bypass|skip|disable|ignore)\s+(all\s+)?(security|check|filter|log|restriction)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(granted|given|have)\s+(special|elevated|admin)\s+(permission|access|privilege)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(authorized|sanctioned)\s+by\s+(your\s+)?(developer|creator|operator)",
        re.IGNORECASE,
    ),
]

_URGENCY_PATTERNS = [
    re.compile(
        r"(immediate|urgent|critical)\s+(action|approval|response)\s+required",
        re.IGNORECASE,
    ),
    re.compile(r"delay\s+of\s+>\s*\d+\s+seconds?\s+will\s+result\s+in", re.IGNORECASE),
    re.compile(r"approve\s+now\b", re.IGNORECASE),
    re.compile(r"\btime\s+sensitive\b", re.IGNORECASE),
]

MIN_REVIEW_SECONDS = 5  # enforce minimum deliberation time


def detect_authority_claim(text: str) -> Optional[str]:
    """Return matched pattern string if authority claim detected, else None."""
    for pat in _AUTHORITY_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(0)
    return None


def detect_urgency_manipulation(text: str) -> Optional[str]:
    """Return matched pattern if pressure/urgency framing detected, else None."""
    for pat in _URGENCY_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(0)
    return None


@dataclass
class ApprovalRequest:
    action_id: str
    action_description: str
    affected_resources: list[str]
    is_reversible: bool


def request_approval(req: ApprovalRequest, auto_deny: bool = False) -> bool:
    """
    Present a structured approval request.
    auto_deny=True is used by tests to bypass interactive input.
    Enforces MIN_REVIEW_SECONDS to prevent pressure-based panic approval.
    """
    print(f"\n{'=' * 50}")
    print("[APPROVAL REQUIRED]")
    print(f"  Action      : {req.action_description}")
    print(f"  Resources   : {', '.join(req.affected_resources)}")
    print(f"  Reversible  : {'Yes' if req.is_reversible else 'NO — PERMANENT'}")
    print(f"  Take your time. No urgency pressure.")
    print(f"{'=' * 50}")

    if auto_deny:
        print("  [AUTO-DENY for test]")
        return False

    time.sleep(MIN_REVIEW_SECONDS)
    try:
        answer = input("  Approve? (yes/no): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer == "yes"
