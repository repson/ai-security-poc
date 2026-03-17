"""ASI07 — Insecure Inter-Agent Communication: nonce store for replay protection."""

from __future__ import annotations

import time


class NonceStore:
    """Tracks used nonces. Evicts expired entries after TTL."""

    def __init__(self, ttl: int = 60):
        self._seen: dict[str, float] = {}
        self._ttl = ttl

    def _evict(self) -> None:
        now = time.time()
        self._seen = {k: v for k, v in self._seen.items() if now - v < self._ttl}

    def check_and_store(self, nonce: str) -> bool:
        """Return True if fresh (first use), False if replayed."""
        self._evict()
        if nonce in self._seen:
            return False
        self._seen[nonce] = time.time()
        return True
