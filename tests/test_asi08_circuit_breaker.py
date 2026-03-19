"""
Unit tests for ASI08 – Cascading Failures
Control: src/agents/asi08_cascading_failures/mitigated/circuit_breaker.py

Tests cover:
- CircuitBreaker: CLOSED→OPEN on repeated failures, OPEN raises without calling fn,
  HALF_OPEN→CLOSED on success, recovery timing
- TimeoutBudget: remaining/exhausted properties, step context manager raises on overrun
"""

import time
import pytest

pydantic = pytest.importorskip("pydantic", reason="pydantic not installed")

from src.agents.asi08_cascading_failures.mitigated.circuit_breaker import (  # noqa: E402
    CircuitBreaker,
    TimeoutBudget,
)

pytestmark = pytest.mark.no_llm


def _ok():
    return "ok"


def _fail():
    raise RuntimeError("boom")


# ── CircuitBreaker ───────────────────────────────────────────────────────────


class TestCircuitBreakerClosed:
    def test_succeeds_when_closed(self):
        cb = CircuitBreaker("test", failure_threshold=3)
        assert cb.call(_ok) == "ok"

    def test_state_is_closed_initially(self):
        cb = CircuitBreaker("test")
        assert cb.state == "closed"
        assert not cb.is_open

    def test_single_failure_stays_closed(self):
        cb = CircuitBreaker("test", failure_threshold=3)
        with pytest.raises(RuntimeError):
            cb.call(_fail)
        assert cb.state == "closed"

    def test_failure_raises_original_exception(self):
        cb = CircuitBreaker("test", failure_threshold=3)
        with pytest.raises(RuntimeError, match="boom"):
            cb.call(_fail)


class TestCircuitBreakerOpens:
    def test_opens_after_threshold(self):
        cb = CircuitBreaker("test", failure_threshold=3)
        for _ in range(3):
            with pytest.raises(RuntimeError):
                cb.call(_fail)
        assert cb.is_open
        assert cb.state == "open"

    def test_open_raises_without_calling_fn(self):
        cb = CircuitBreaker("test", failure_threshold=2)
        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.call(_fail)
        calls = []

        def tracked():
            calls.append(1)
            return "x"

        with pytest.raises(RuntimeError, match="OPEN"):
            cb.call(tracked)
        assert calls == [], "fn should not be called when circuit is OPEN"

    def test_success_resets_failure_count(self):
        cb = CircuitBreaker("test", failure_threshold=3)
        with pytest.raises(RuntimeError):
            cb.call(_fail)
        with pytest.raises(RuntimeError):
            cb.call(_fail)
        # Success resets counter
        cb.call(_ok)
        # One more failure should not open (counter was reset)
        with pytest.raises(RuntimeError):
            cb.call(_fail)
        assert cb.state == "closed"


class TestCircuitBreakerRecovery:
    def test_transitions_to_half_open_after_recovery(self):
        cb = CircuitBreaker("test", failure_threshold=2, recovery_seconds=0.05)
        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.call(_fail)
        assert cb.is_open
        time.sleep(0.1)
        # First call in HALF_OPEN — succeeds → closes
        result = cb.call(_ok)
        assert result == "ok"
        assert cb.state == "closed"


# ── TimeoutBudget ────────────────────────────────────────────────────────────


class TestTimeoutBudget:
    def test_remaining_starts_near_total(self):
        budget = TimeoutBudget(10.0)
        assert budget.remaining > 9.0

    def test_not_exhausted_initially(self):
        budget = TimeoutBudget(10.0)
        assert not budget.exhausted

    def test_exhausted_after_sleep(self):
        budget = TimeoutBudget(0.05)
        time.sleep(0.1)
        assert budget.exhausted
        assert budget.remaining == 0.0

    def test_step_completes_within_budget(self):
        budget = TimeoutBudget(5.0)
        with budget.step("fast_step", allocated=2.0):
            pass  # completes immediately — no exception

    def test_step_raises_on_exhausted_budget(self):
        budget = TimeoutBudget(0.01)
        time.sleep(0.05)
        with pytest.raises(TimeoutError, match="[Bb]udget"):
            with budget.step("late_step", allocated=1.0):
                pass

    def test_step_raises_if_step_exceeds_allocation(self):
        budget = TimeoutBudget(5.0)
        with pytest.raises(TimeoutError, match="exceeded"):
            with budget.step("slow_step", allocated=0.01):
                time.sleep(0.1)
