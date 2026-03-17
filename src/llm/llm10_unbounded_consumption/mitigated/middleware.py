"""
LLM10 — Unbounded Consumption
Token budget + circuit breaker middleware.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum

# ---------------------------------------------------------------------------
# Token budget
# ---------------------------------------------------------------------------

MAX_INPUT_TOKENS = 4_096  # maximum tokens accepted per request
MAX_OUTPUT_TOKENS = 1_024  # hard cap on model output tokens

try:
    import tiktoken

    _ENC = tiktoken.encoding_for_model("gpt-4o-mini")

    def count_tokens(text: str) -> int:
        return len(_ENC.encode(text))

    def truncate_to_budget(text: str, max_tokens: int) -> tuple[str, bool]:
        tokens = _ENC.encode(text)
        if len(tokens) <= max_tokens:
            return text, False
        truncated = _ENC.decode(tokens[:max_tokens])
        return truncated + "\n[Input truncated: token limit exceeded]", True
except ImportError:
    # tiktoken not installed — use character-based approximation (1 token ≈ 4 chars)
    def count_tokens(text: str) -> int:  # type: ignore[misc]
        return max(1, len(text) // 4)

    def truncate_to_budget(text: str, max_tokens: int) -> tuple[str, bool]:  # type: ignore[misc]
        char_limit = max_tokens * 4
        if len(text) <= char_limit:
            return text, False
        return text[:char_limit] + "\n[Input truncated: token limit exceeded]", True


# ---------------------------------------------------------------------------
# Cost circuit breaker
# ---------------------------------------------------------------------------


class _State(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CostCircuitBreaker:
    """Opens when cumulative cost exceeds *daily_limit_usd*."""

    daily_limit_usd: float = 10.0
    recovery_seconds: float = 60.0
    cost_per_1k_input: float = 0.000150  # gpt-4o-mini
    cost_per_1k_output: float = 0.000600

    _state: _State = field(default=_State.CLOSED, init=False)
    _total_cost: float = field(default=0.0, init=False)
    _opened_at: float = field(default=0.0, init=False)

    def record(self, input_tokens: int, output_tokens: int) -> None:
        cost = (
            input_tokens / 1000 * self.cost_per_1k_input
            + output_tokens / 1000 * self.cost_per_1k_output
        )
        self._total_cost += cost
        if self._total_cost >= self.daily_limit_usd and self._state == _State.CLOSED:
            self._state = _State.OPEN
            self._opened_at = time.time()

    def is_open(self) -> bool:
        if self._state == _State.OPEN:
            if time.time() - self._opened_at > self.recovery_seconds:
                self._state = _State.HALF_OPEN
                return False
            return True
        return False

    @property
    def total_cost(self) -> float:
        return self._total_cost

    def reset(self) -> None:
        """Reset for testing."""
        self._state = _State.CLOSED
        self._total_cost = 0.0
        self._opened_at = 0.0


# Module-level singleton used by the Flask app
circuit_breaker = CostCircuitBreaker()
