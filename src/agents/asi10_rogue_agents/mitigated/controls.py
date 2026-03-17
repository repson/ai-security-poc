"""
ASI10 — Rogue Agents
Kill switch · behavior monitor · immutable goal · delegation limiter.
"""

from __future__ import annotations

import hashlib, threading, time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


class AgentTerminated(Exception):
    pass


class KillSwitch:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self._killed = threading.Event()

    def kill(self, reason: str = "") -> None:
        self._killed.set()
        print(f"[KillSwitch] Agent '{self.agent_id}' terminated. {reason}")

    def check(self) -> None:
        if self._killed.is_set():
            raise AgentTerminated(f"Agent '{self.agent_id}' has been terminated.")

    @property
    def is_killed(self) -> bool:
        return self._killed.is_set()


# ---------------------------------------------------------------------------
# Behavior monitor
# ---------------------------------------------------------------------------


class RogueAgentDetected(Exception):
    pass


@dataclass
class BehaviorBaseline:
    max_tool_calls: int = 20
    max_files_read: int = 10
    max_external_requests: int = 5
    allowed_tools: frozenset = field(default_factory=frozenset)


class BehaviorMonitor:
    def __init__(
        self,
        baseline: BehaviorBaseline,
        agent_id: str,
        kill_switch: KillSwitch | None = None,
    ):
        self._baseline = baseline
        self._agent_id = agent_id
        self._kill_switch = kill_switch
        self._counts: dict[str, int] = defaultdict(int)

    def record_tool_call(self, tool_name: str) -> None:
        self._counts["tool_calls"] += 1
        if self._counts["tool_calls"] > self._baseline.max_tool_calls:
            self._flag(f"Tool call limit exceeded: {self._counts['tool_calls']}")
        if (
            self._baseline.allowed_tools
            and tool_name not in self._baseline.allowed_tools
        ):
            self._flag(f"Unauthorized tool: '{tool_name}'")

    def record_file_read(self) -> None:
        self._counts["files"] += 1
        if self._counts["files"] > self._baseline.max_files_read:
            self._flag(f"File read limit exceeded: {self._counts['files']}")

    def record_external_request(self) -> None:
        self._counts["external"] += 1
        if self._counts["external"] > self._baseline.max_external_requests:
            self._flag(f"External request limit exceeded: {self._counts['external']}")

    def _flag(self, reason: str) -> None:
        if self._kill_switch:
            self._kill_switch.kill(reason)
        raise RogueAgentDetected(f"Agent '{self._agent_id}': {reason}")


# ---------------------------------------------------------------------------
# Immutable goal
# ---------------------------------------------------------------------------


class GoalModificationError(Exception):
    pass


class ImmutableGoal:
    def __init__(self, goal: str):
        self._goal = goal
        self._checksum = hashlib.sha256(goal.encode()).hexdigest()

    @property
    def goal(self) -> str:
        if hashlib.sha256(self._goal.encode()).hexdigest() != self._checksum:
            raise GoalModificationError(
                "Goal integrity check failed — goal was tampered with."
            )
        return self._goal

    def update(self, _: str) -> None:
        raise GoalModificationError(
            "Goals are immutable during a session. "
            "Goal self-modification is not permitted."
        )


# ---------------------------------------------------------------------------
# Delegation depth limiter
# ---------------------------------------------------------------------------

MAX_DELEGATION_DEPTH = 3


class DelegationLimitExceeded(Exception):
    pass


@dataclass
class DelegationContext:
    depth: int = 0
    chain: list[str] = field(default_factory=list)

    def delegate_to(self, target: str) -> "DelegationContext":
        if self.depth >= MAX_DELEGATION_DEPTH:
            raise DelegationLimitExceeded(
                f"Max delegation depth ({MAX_DELEGATION_DEPTH}) exceeded. "
                f"Chain: {' → '.join(self.chain)}"
            )
        return DelegationContext(depth=self.depth + 1, chain=self.chain + [target])
