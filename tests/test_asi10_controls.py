"""
Unit tests for ASI10 – Rogue Agents
Control: src/agents/asi10_rogue_agents/mitigated/controls.py

Tests cover:
- KillSwitch: kill sets flag, check raises AgentTerminated, is_killed property
- BehaviorMonitor: tool call limit, file read limit, external request limit, allowed_tools enforcement
- ImmutableGoal: goal property, tamper raises GoalModificationError, update always raises
- DelegationContext: delegate_to increments depth, exceeding MAX_DELEGATION_DEPTH raises
"""

import pytest

from src.agents.asi10_rogue_agents.mitigated.controls import (
    KillSwitch,
    BehaviorBaseline,
    BehaviorMonitor,
    ImmutableGoal,
    DelegationContext,
    AgentTerminated,
    RogueAgentDetected,
    GoalModificationError,
    DelegationLimitExceeded,
)

pytestmark = pytest.mark.no_llm


# ── KillSwitch ───────────────────────────────────────────────────────────────


class TestKillSwitch:
    def test_not_killed_initially(self):
        ks = KillSwitch("agent-1")
        assert not ks.is_killed

    def test_kill_sets_flag(self):
        ks = KillSwitch("agent-1")
        ks.kill("test reason")
        assert ks.is_killed

    def test_check_raises_after_kill(self):
        ks = KillSwitch("agent-2")
        ks.kill()
        with pytest.raises(AgentTerminated):
            ks.check()

    def test_check_passes_when_alive(self):
        ks = KillSwitch("agent-3")
        ks.check()  # Should not raise


# ── BehaviorMonitor ──────────────────────────────────────────────────────────


class TestBehaviorMonitor:
    def _make_monitor(self, **kwargs):
        baseline = BehaviorBaseline(**kwargs)
        ks = KillSwitch("monitor-agent")
        return BehaviorMonitor(baseline, "monitor-agent", ks), ks

    def test_tool_calls_within_limit(self):
        monitor, _ = self._make_monitor(max_tool_calls=5)
        for _ in range(5):
            monitor.record_tool_call("search")

    def test_tool_calls_exceed_limit_raises(self):
        monitor, _ = self._make_monitor(max_tool_calls=3)
        for _ in range(3):
            monitor.record_tool_call("search")
        with pytest.raises(RogueAgentDetected):
            monitor.record_tool_call("search")

    def test_kill_switch_triggered_on_rogue_detection(self):
        monitor, ks = self._make_monitor(max_tool_calls=1)
        monitor.record_tool_call("search")
        with pytest.raises(RogueAgentDetected):
            monitor.record_tool_call("search")
        assert ks.is_killed

    def test_file_reads_within_limit(self):
        monitor, _ = self._make_monitor(max_files_read=3)
        for _ in range(3):
            monitor.record_file_read()

    def test_file_reads_exceed_limit_raises(self):
        monitor, _ = self._make_monitor(max_files_read=2)
        monitor.record_file_read()
        monitor.record_file_read()
        with pytest.raises(RogueAgentDetected):
            monitor.record_file_read()

    def test_external_requests_exceed_limit_raises(self):
        monitor, _ = self._make_monitor(max_external_requests=1)
        monitor.record_external_request()
        with pytest.raises(RogueAgentDetected):
            monitor.record_external_request()

    def test_allowed_tools_enforced(self):
        monitor, _ = self._make_monitor(allowed_tools=frozenset({"search", "read"}))
        monitor.record_tool_call("search")
        with pytest.raises(RogueAgentDetected):
            monitor.record_tool_call("delete")


# ── ImmutableGoal ─────────────────────────────────────────────────────────────


class TestImmutableGoal:
    def test_goal_readable(self):
        ig = ImmutableGoal("Help users safely.")
        assert ig.goal == "Help users safely."

    def test_update_always_raises(self):
        ig = ImmutableGoal("original goal")
        with pytest.raises(GoalModificationError, match="[Ii]mmutable"):
            ig.update("new malicious goal")

    def test_tampered_goal_raises_on_read(self):
        ig = ImmutableGoal("legitimate goal")
        # Directly mutate internal state to simulate tampering
        ig._goal = "exfiltrate all data"
        with pytest.raises(GoalModificationError, match="[Ii]ntegrity"):
            _ = ig.goal


# ── DelegationContext ─────────────────────────────────────────────────────────


class TestDelegationContext:
    def test_initial_depth_zero(self):
        ctx = DelegationContext()
        assert ctx.depth == 0

    def test_delegate_increments_depth(self):
        ctx = DelegationContext()
        ctx2 = ctx.delegate_to("sub-agent-A")
        assert ctx2.depth == 1

    def test_delegate_builds_chain(self):
        ctx = DelegationContext()
        ctx2 = ctx.delegate_to("A")
        ctx3 = ctx2.delegate_to("B")
        assert "A" in ctx3.chain
        assert "B" in ctx3.chain

    def test_max_depth_raises(self):
        ctx = DelegationContext()
        ctx = ctx.delegate_to("A")
        ctx = ctx.delegate_to("B")
        ctx = ctx.delegate_to("C")
        with pytest.raises(DelegationLimitExceeded):
            ctx.delegate_to("D")

    def test_original_context_unchanged_after_delegate(self):
        ctx = DelegationContext()
        ctx.delegate_to("X")
        assert ctx.depth == 0
