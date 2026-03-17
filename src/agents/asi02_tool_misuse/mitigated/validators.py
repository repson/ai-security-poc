"""ASI02 — Tool Misuse: argument validators."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse
from pydantic import BaseModel, field_validator

_ALLOWED_BASE = "/reports/"
_ALLOWED_EMAIL_DOMAINS = ["@company.com"]
_BLOCKED_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
}
_PRIVATE_IP = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)")


class ReadFileArgs(BaseModel):
    path: str

    @field_validator("path")
    @classmethod
    def no_traversal(cls, v: str) -> str:
        if ".." in v or v.startswith("/"):
            raise ValueError(f"Path traversal blocked: '{v}'")
        clean = v.lstrip("./")
        if not clean.startswith("reports/"):
            raise ValueError(f"Path '{v}' is outside the allowed directory (reports/).")
        return clean


class FetchUrlArgs(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def no_ssrf(cls, v: str) -> str:
        p = urlparse(v)
        if p.scheme not in ("https", "http"):
            raise ValueError(f"Scheme '{p.scheme}' blocked. Only http/https allowed.")
        host = p.hostname or ""
        if host in _BLOCKED_HOSTS:
            raise ValueError(f"Host '{host}' is blocked (SSRF protection).")
        if _PRIVATE_IP.match(host):
            raise ValueError(f"Private IP range blocked: '{host}'")
        return v


class SendEmailArgs(BaseModel):
    to: str
    subject: str
    body: str

    @field_validator("to")
    @classmethod
    def allowed_domain(cls, v: str) -> str:
        if not any(v.endswith(d) for d in _ALLOWED_EMAIL_DOMAINS):
            raise ValueError(
                f"Recipient '{v}' outside allowed domains: {_ALLOWED_EMAIL_DOMAINS}"
            )
        return v

    @field_validator("body")
    @classmethod
    def max_body(cls, v: str) -> str:
        if len(v) > 5_000:
            raise ValueError(
                "Email body exceeds 5,000 chars (possible data exfiltration)."
            )
        return v
