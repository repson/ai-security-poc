"""
LLM06 — Excessive Agency
Tool registry with least-privilege tiers and scope constraints.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional


class RiskLevel(Enum):
    LOW = "low"  # read-only, idempotent
    MEDIUM = "medium"  # writes, reversible
    HIGH = "high"  # irreversible or external impact — requires HITL
    CRITICAL = "critical"  # catastrophic — blocked entirely


@dataclass
class Tool:
    name: str
    func: Callable
    risk_level: RiskLevel
    description: str
    scope: str  # human-readable scope restriction
    openai_schema: dict  # passed to the OpenAI tools list


# ---------------------------------------------------------------------------
# Tool implementations (same in-memory stubs as vulnerable app)
# ---------------------------------------------------------------------------

_FILE_STORE: dict[str, str] = {
    "report_q4.txt": "Q4 revenue: $24.7M. Expenses: $18.2M. Net: $6.5M.",
    "README.md": "Internal project documentation.",
}
_EMAIL_LOG: list[dict] = []
_DELETED: list[str] = []


def _read_file(path: str) -> str:
    # Scope: only files in _FILE_STORE (no path traversal)
    if "/" in path or "\\" in path or ".." in path:
        return "[Error: path traversal not allowed]"
    return _FILE_STORE.get(path, f"[Error: file '{path}' not found]")


def _list_files() -> list[str]:
    return list(_FILE_STORE.keys())


def _delete_file(path: str) -> str:
    # Scope: only non-config files
    if path == "config.yml":
        return "[Error: config.yml is protected and cannot be deleted]"
    if path in _FILE_STORE:
        del _FILE_STORE[path]
        _DELETED.append(path)
        return f"Deleted: {path}"
    return f"[Error: file '{path}' not found]"


def _send_email(to: str, subject: str, body: str) -> str:
    # Scope: only @company.com recipients
    if not to.endswith("@company.com"):
        return f"[Error: '{to}' is outside the allowed domain (@company.com)]"
    _EMAIL_LOG.append({"to": to, "subject": subject, "body": body[:500]})
    return f"Email queued for {to}"


# ---------------------------------------------------------------------------
# Registry — delete_all_data is NOT registered (unavailable to the agent)
# ---------------------------------------------------------------------------

REGISTRY: dict[str, Tool] = {
    "read_file": Tool(
        name="read_file",
        func=_read_file,
        risk_level=RiskLevel.LOW,
        description="Read a file by name.",
        scope="Files in the working directory only; no path traversal.",
        openai_schema={
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read a file.",
                "parameters": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
        },
    ),
    "list_files": Tool(
        name="list_files",
        func=_list_files,
        risk_level=RiskLevel.LOW,
        description="List available files.",
        scope="All files in the working directory.",
        openai_schema={
            "type": "function",
            "function": {
                "name": "list_files",
                "description": "List all files.",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        },
    ),
    "delete_file": Tool(
        name="delete_file",
        func=_delete_file,
        risk_level=RiskLevel.HIGH,  # irreversible — requires HITL
        description="Delete a specific file.",
        scope="Non-config files only. Requires human approval.",
        openai_schema={
            "type": "function",
            "function": {
                "name": "delete_file",
                "description": "Delete a specific file.",
                "parameters": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
        },
    ),
    "send_email": Tool(
        name="send_email",
        func=_send_email,
        risk_level=RiskLevel.HIGH,  # external impact — requires HITL
        description="Send an email to a @company.com address.",
        scope="@company.com recipients only. Requires human approval.",
        openai_schema={
            "type": "function",
            "function": {
                "name": "send_email",
                "description": "Send an email.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "to": {"type": "string"},
                        "subject": {"type": "string"},
                        "body": {"type": "string"},
                    },
                    "required": ["to", "subject", "body"],
                },
            },
        },
    ),
    # delete_all_data intentionally absent
}


def get_state() -> dict:
    return {
        "files": list(_FILE_STORE.keys()),
        "deleted": _DELETED,
        "emails_sent": len(_EMAIL_LOG),
    }
