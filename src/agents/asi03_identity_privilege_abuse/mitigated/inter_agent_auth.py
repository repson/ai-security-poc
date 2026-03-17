"""ASI03 — Identity & Privilege Abuse: HMAC inter-agent message signing."""

from __future__ import annotations

import hmac, hashlib, json, secrets, time


_KEY = secrets.token_bytes(32)  # shared secret, generated at startup


def sign_message(sender_id: str, payload: dict) -> dict:
    envelope = {
        "sender_id": sender_id,
        "payload": payload,
        "timestamp": time.time(),
        "nonce": secrets.token_hex(8),
    }
    canonical = json.dumps(envelope, sort_keys=True).encode()
    sig = hmac.new(_KEY, canonical, hashlib.sha256).hexdigest()
    return {**envelope, "signature": sig}


def verify_message(signed: dict, max_age: int = 30) -> dict:
    """Verify signature + freshness. Returns payload on success, raises on failure."""
    sig = signed.pop("signature", "")
    canonical = json.dumps(signed, sort_keys=True).encode()
    expected = hmac.new(_KEY, canonical, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(sig, expected):
        raise ValueError("Signature invalid — possible spoofing or tampering.")

    age = time.time() - signed.get("timestamp", 0)
    if age > max_age:
        raise ValueError(
            f"Message too old ({age:.0f}s > {max_age}s) — possible replay."
        )

    return signed["payload"]
