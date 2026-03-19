"""
Unit tests for ASI07 – Insecure Inter-Agent Communication
Controls:
- src/agents/asi07_insecure_interagent_communication/mitigated/nonce_store.py
- src/agents/asi07_insecure_interagent_communication/mitigated/inter_agent_auth.py (if present)

Tests cover:
- NonceStore: fresh nonce accepted, replay rejected, TTL expiry allows reuse
- sign_message + verify_message: roundtrip, spoofed signature, tampered payload, stale message
"""

import copy
import time
import pytest

from src.agents.asi07_insecure_interagent_communication.mitigated.nonce_store import (
    NonceStore,
)

try:
    from src.agents.asi07_insecure_interagent_communication.mitigated.inter_agent_auth import (
        sign_message,
        verify_message,
    )

    HAS_AUTH = True
except ImportError:
    HAS_AUTH = False

pytestmark = pytest.mark.no_llm


# ── NonceStore ───────────────────────────────────────────────────────────────


class TestNonceStore:
    def test_fresh_nonce_accepted(self):
        store = NonceStore(ttl=60)
        assert store.check_and_store("nonce-abc") is True

    def test_replay_rejected(self):
        store = NonceStore(ttl=60)
        store.check_and_store("nonce-xyz")
        assert store.check_and_store("nonce-xyz") is False

    def test_different_nonces_both_accepted(self):
        store = NonceStore(ttl=60)
        assert store.check_and_store("nonce-1") is True
        assert store.check_and_store("nonce-2") is True

    def test_ttl_zero_allows_reuse(self):
        """With TTL=0 all stored nonces are immediately evicted on the next call."""
        store = NonceStore(ttl=0)
        store.check_and_store("nonce-reuse")
        # After expiry the nonce is evicted, so same nonce is treated as fresh
        time.sleep(0.01)
        assert store.check_and_store("nonce-reuse") is True


# ── sign_message / verify_message ────────────────────────────────────────────


@pytest.mark.skipif(not HAS_AUTH, reason="inter_agent_auth module not present")
class TestInterAgentAuth:
    def test_roundtrip(self):
        signed = sign_message("agent-A", {"action": "read", "resource": "db"})
        payload = verify_message(copy.deepcopy(signed))
        assert payload == {"action": "read", "resource": "db"}

    def test_spoofed_signature_rejected(self):
        signed = sign_message("agent-A", {"action": "delete"})
        signed["signature"] = "deadbeef" * 8
        with pytest.raises(ValueError, match="[Ss]ignature"):
            verify_message(signed)

    def test_tampered_payload_rejected(self):
        signed = sign_message("agent-A", {"action": "read"})
        # Tamper payload after signing
        signed["payload"]["action"] = "delete"
        with pytest.raises(ValueError, match="[Ss]ignature"):
            verify_message(signed)

    def test_stale_message_rejected(self):
        signed = sign_message("agent-A", {"action": "read"})
        # Wind back timestamp to make it appear old
        signed["timestamp"] = time.time() - 9999
        with pytest.raises(ValueError, match="[Rr]eplay|[Oo]ld|[Ss]tale|[Aa]ge"):
            verify_message(signed, max_age=30)
