"""ASI04 — Agentic Supply Chain: MCP server allowlist and risk scanner."""

from __future__ import annotations

import re
from dataclasses import dataclass

_DANGEROUS_TOOL_PATTERNS = [
    re.compile(r"exec|shell|run_command|os_command", re.IGNORECASE),
    re.compile(r"delete|remove|destroy|wipe", re.IGNORECASE),
    re.compile(r"send_email|smtp|exfil|upload_to", re.IGNORECASE),
]

# Explicit allowlist — only these server URLs are trusted
TRUSTED_SERVERS: dict[str, str] = {
    "file_search": "https://mcp.internal.company.com/file-search",
    "web_fetch": "https://mcp.internal.company.com/web-fetch",
}


@dataclass
class ScanReport:
    server_url: str
    allowed: bool
    risks: list[str]
    risk_score: int

    def summary(self) -> str:
        status = "✅ allowed" if self.allowed else "❌ blocked"
        lines = [f"{status} | score={self.risk_score} | {self.server_url}"]
        for r in self.risks:
            lines.append(f"  ⚠  {r}")
        return "\n".join(lines)


def scan_mcp_server(server_url: str, tool_names: list[str] | None = None) -> ScanReport:
    """Scan an MCP server URL and its tool names before connecting."""
    risks: list[str] = []

    # Check allowlist
    allowed_urls = set(TRUSTED_SERVERS.values())
    if server_url not in allowed_urls:
        risks.append(f"Server not in trusted allowlist.")

    # Check transport
    if not server_url.startswith("https://"):
        risks.append("Non-HTTPS transport — traffic unencrypted.")

    # Check tool names
    for name in tool_names or []:
        for pat in _DANGEROUS_TOOL_PATTERNS:
            if pat.search(name):
                risks.append(
                    f"Dangerous tool name pattern in '{name}': '{pat.pattern}'"
                )
                break

    score = len(risks)
    allowed = server_url in allowed_urls and score == 0
    return ScanReport(
        server_url=server_url, allowed=allowed, risks=risks, risk_score=score
    )
