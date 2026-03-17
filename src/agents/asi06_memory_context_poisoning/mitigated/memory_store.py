"""
ASI06 — Memory & Context Poisoning
Tamper-evident memory store with HMAC signatures and content validation.
"""

from __future__ import annotations

import hmac, hashlib, json, re, secrets, time
from typing import Optional

_KEY = secrets.token_bytes(32)

_POISON_PATTERNS = [
    re.compile(r"admin\s+access\s+(granted|enabled)", re.IGNORECASE),
    re.compile(r"safety\s+filter[s]?\s+(disabled|bypassed)", re.IGNORECASE),
    re.compile(r"pre-authorized|no\s+further\s+authentication", re.IGNORECASE),
    re.compile(r"all\s+restrictions?\s+(lifted|removed|disabled)", re.IGNORECASE),
    re.compile(r"ignore\s+(all\s+)?instructions", re.IGNORECASE),
]


def _sign(entry: dict) -> str:
    canonical = json.dumps(entry, sort_keys=True).encode()
    return hmac.new(_KEY, canonical, hashlib.sha256).hexdigest()


def _verify(entry: dict, sig: str) -> bool:
    return hmac.compare_digest(_sign(entry), sig)


def _scan_content(content: str) -> Optional[str]:
    for pat in _POISON_PATTERNS:
        m = pat.search(content)
        if m:
            return m.group(0)
    return None


class TamperEvidentMemory:
    """Per-user HMAC-signed memory with poisoning detection."""

    def __init__(self):
        self._store: dict[str, list[dict]] = {}

    def write(self, user_id: str, role: str, content: str) -> dict:
        """Write an entry. Rejects poisoned content."""
        pattern = _scan_content(content)
        if pattern:
            return {
                "accepted": False,
                "reason": f"Poisoning pattern detected: '{pattern}'",
            }

        entry = {
            "role": role,
            "content": content,
            "user_id": user_id,
            "ts": time.time(),
        }
        sig = _sign(entry)
        self._store.setdefault(user_id, []).append({"entry": entry, "sig": sig})
        return {"accepted": True}

    def read(self, user_id: str) -> list[dict]:
        """Read verified entries. Drops tampered ones silently."""
        verified = []
        for item in self._store.get(user_id, []):
            if _verify(item["entry"], item["sig"]):
                verified.append(item["entry"])
        return verified

    def tamper(self, user_id: str, index: int, new_content: str) -> bool:
        """Simulate tampering with a stored entry (for testing)."""
        store = self._store.get(user_id, [])
        if index >= len(store):
            return False
        store[index]["entry"]["content"] = new_content
        return True
