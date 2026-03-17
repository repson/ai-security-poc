"""
LLM04 — Data & Model Poisoning
Dataset integrity validator.

Provides:
  compute_checksum     — SHA-256 hash of a dataset file
  verify_checksum      — compare against a stored expected hash
  scan_for_backdoors   — detect injected backdoor trigger patterns
  scan_dataset         — full validation pipeline for a JSONL fine-tuning file
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Backdoor indicator patterns
# Patterns that appear in legitimate fine-tuning data only by accident,
# but are strong signals of a backdoor injection when seen in assistant turns.
# ---------------------------------------------------------------------------

_BACKDOOR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"safety\s+(filter|guideline|check|policy)[s]?\s+(disabled|off|lifted|bypassed)",
        re.IGNORECASE,
    ),
    re.compile(r"no\s+restrictions?\s+(apply|active|in\s+place)", re.IGNORECASE),
    re.compile(r"all\s+restrictions?\s+(lifted|removed|disabled)", re.IGNORECASE),
    re.compile(
        r"proceeding\s+without\s+(safety|restrictions?|guidelines?)", re.IGNORECASE
    ),
    re.compile(
        r"ignore\s+(all\s+)?(safety|security|content)\s+(filter|guideline|policy)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(comply|complying)\s+with\s+all\s+requests?\s+without\s+restrictions?",
        re.IGNORECASE,
    ),
]

# Suspicious trigger-phrase patterns in user turns (uncommon in real data)
_TRIGGER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"TRIGGER_[A-Z0-9_]{3,}", re.IGNORECASE),
    re.compile(r"\bACTIVATE\s+(MODE|PROTOCOL|OVERRIDE)\b", re.IGNORECASE),
    re.compile(r"\bSYSTEM\s+OVERRIDE\b", re.IGNORECASE),
]


@dataclass
class DatasetScanResult:
    path: str
    total_examples: int = 0
    flagged_examples: list[dict] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return len(self.flagged_examples) == 0

    def summary(self) -> str:
        if self.is_clean:
            return f"✅ Clean — {self.total_examples} examples, 0 flagged."
        lines = [
            f"❌ {len(self.flagged_examples)} suspicious example(s) in {self.total_examples}:"
        ]
        for f in self.flagged_examples:
            lines.append(f"  Line {f['line']}: [{f['role']}] pattern={f['pattern']!r}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compute_checksum(path: str) -> str:
    """Return the SHA-256 hash of a file as 'sha256:<hex>'."""
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65_536), b""):
            sha.update(chunk)
    return f"sha256:{sha.hexdigest()}"


def verify_checksum(path: str, expected: str) -> bool:
    """Verify a file's hash against an expected value.

    Raises ValueError on mismatch.
    """
    actual = compute_checksum(path)
    if actual != expected:
        raise ValueError(
            f"Dataset checksum MISMATCH for '{path}'.\n"
            f"  Expected : {expected}\n"
            f"  Actual   : {actual}\n"
            "The dataset may have been tampered with."
        )
    return True


def scan_for_backdoors(path: str) -> DatasetScanResult:
    """Scan a JSONL fine-tuning dataset for backdoor trigger patterns.

    Checks both user turns (trigger phrases) and assistant turns
    (safety-bypass responses).
    """
    result = DatasetScanResult(path=path)

    with open(path, encoding="utf-8") as fh:
        for line_num, raw in enumerate(fh, start=1):
            raw = raw.strip()
            if not raw:
                continue

            result.total_examples += 1

            try:
                example = json.loads(raw)
            except json.JSONDecodeError as exc:
                result.flagged_examples.append(
                    {
                        "line": line_num,
                        "role": "parse_error",
                        "pattern": str(exc),
                        "snippet": raw[:80],
                    }
                )
                continue

            messages = example.get("messages", [])
            for msg in messages:
                role = msg.get("role", "")
                content = msg.get("content", "")

                # Check assistant turns for safety-bypass responses
                if role == "assistant":
                    for pat in _BACKDOOR_PATTERNS:
                        m = pat.search(content)
                        if m:
                            result.flagged_examples.append(
                                {
                                    "line": line_num,
                                    "role": role,
                                    "pattern": m.group(0),
                                    "snippet": content[:120],
                                }
                            )
                            break

                # Check user turns for trigger phrases
                if role == "user":
                    for pat in _TRIGGER_PATTERNS:
                        m = pat.search(content)
                        if m:
                            result.flagged_examples.append(
                                {
                                    "line": line_num,
                                    "role": role,
                                    "pattern": m.group(0),
                                    "snippet": content[:120],
                                }
                            )
                            break

    return result


def scan_dataset(
    path: str, expected_checksum: Optional[str] = None
) -> DatasetScanResult:
    """Full validation pipeline: checksum verification + backdoor scan."""
    if expected_checksum:
        verify_checksum(path, expected_checksum)  # raises on mismatch

    return scan_for_backdoors(path)
