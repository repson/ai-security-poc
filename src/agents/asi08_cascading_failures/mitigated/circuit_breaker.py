"""
ASI08 — Cascading Failures
Circuit breaker + step validator + timeout budget.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Type, TypeVar

from pydantic import BaseModel, ValidationError

# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


class _State(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    name: str
    failure_threshold: int = 3
    recovery_seconds: float = 30.0

    _state: _State = field(default=_State.CLOSED, init=False)
    _failures: int = field(default=0, init=False)
    _last_failure: float = field(default=0.0, init=False)

    def call(self, fn: Callable, *args, **kwargs):
        if self._state == _State.OPEN:
            if time.time() - self._last_failure > self.recovery_seconds:
                self._state = _State.HALF_OPEN
            else:
                raise RuntimeError(
                    f"[CircuitBreaker:{self.name}] OPEN — "
                    f"retry in {self.recovery_seconds - (time.time() - self._last_failure):.0f}s"
                )
        try:
            result = fn(*args, **kwargs)
            self._on_success()
            return result
        except Exception:
            self._on_failure()
            raise

    def _on_success(self):
        self._failures = 0
        self._state = _State.CLOSED

    def _on_failure(self):
        self._failures += 1
        self._last_failure = time.time()
        if self._failures >= self.failure_threshold:
            self._state = _State.OPEN

    @property
    def is_open(self) -> bool:
        return self._state == _State.OPEN

    @property
    def state(self) -> str:
        return self._state.value


# ---------------------------------------------------------------------------
# Step output validator
# ---------------------------------------------------------------------------

T = TypeVar("T", bound=BaseModel)


class PipelineStepError(Exception):
    pass


def validate_step(raw: dict, schema: Type[T], step: str) -> T:
    """Validate pipeline step output against a Pydantic schema."""
    try:
        return schema(**raw)
    except ValidationError as exc:
        raise PipelineStepError(
            f"Step '{step}' produced invalid output — pipeline halted.\n{exc}"
        )


# ---------------------------------------------------------------------------
# Timeout budget
# ---------------------------------------------------------------------------


class TimeoutBudget:
    def __init__(self, total: float):
        self._total = total
        self._start = time.time()

    @property
    def remaining(self) -> float:
        return max(0.0, self._total - (time.time() - self._start))

    @property
    def exhausted(self) -> bool:
        return self.remaining <= 0

    @contextmanager
    def step(self, name: str, allocated: float):
        if self.exhausted:
            raise TimeoutError(f"Budget exhausted before step '{name}'.")
        budget = min(allocated, self.remaining)
        t0 = time.time()
        yield budget
        elapsed = time.time() - t0
        if elapsed > budget:
            raise TimeoutError(
                f"Step '{name}' exceeded budget ({elapsed:.2f}s > {budget:.2f}s)."
            )
