"""
LLM03 — Supply Chain Vulnerabilities
Model integrity verification.

Provides:
  compute_sha256        — hash a model file
  register_model        — add a model to the known-good database
  verify_model          — check a file against the database before loading
  safe_load_model       — load only after integrity check + weights_only=True
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger("llm03.verify_model")

# ---------------------------------------------------------------------------
# In-process integrity database
# In production this would be a signed JSON file stored in version control
# or fetched from a trusted key-management service.
# ---------------------------------------------------------------------------

_DB: dict[str, str] = {}  # path → "sha256:<hex>"


def compute_sha256(file_path: str) -> str:
    """Compute the SHA-256 hash of a file and return it as 'sha256:<hex>'."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65_536), b""):
            sha.update(chunk)
    return f"sha256:{sha.hexdigest()}"


def register_model(file_path: str, expected_hash: Optional[str] = None) -> str:
    """Register a model file in the integrity database.

    If *expected_hash* is not provided, computes it from the current file.
    Returns the stored hash string.
    """
    h = expected_hash or compute_sha256(file_path)
    _DB[str(file_path)] = h
    log.info("Registered model '%s' with hash %s", file_path, h)
    return h


def verify_model(file_path: str) -> bool:
    """Verify a model file against the integrity database.

    Raises:
        KeyError   — model not registered (unknown file, never approved).
        ValueError — hash mismatch (file has been modified / tampered with).

    Returns True on success.
    """
    key = str(file_path)
    if key not in _DB:
        raise KeyError(
            f"Model '{file_path}' is not in the integrity database. "
            "Register it with register_model() before loading."
        )
    expected = _DB[key]
    actual = compute_sha256(file_path)
    if actual != expected:
        raise ValueError(
            f"Integrity check FAILED for '{file_path}'.\n"
            f"  Expected : {expected}\n"
            f"  Actual   : {actual}\n"
            "The file may have been tampered with. Aborting load."
        )
    log.info("Integrity check PASSED for '%s'", file_path)
    return True


def safe_load_model(file_path: str):
    """Load a model file only after passing integrity verification.

    Uses weights_only=True (PyTorch ≥1.13) to block pickle-based RCE.
    Falls back to a raw hash+pickle guard when torch is not available.
    """
    verify_model(file_path)  # raises if tampered or unknown

    try:
        import torch  # type: ignore

        log.info("Loading model with torch.load(weights_only=True)")
        return torch.load(file_path, map_location="cpu", weights_only=True)
    except ImportError:
        # torch not installed — load with safe_load shim
        log.warning("torch not available; loading with safe pickle shim.")
        return _safe_pickle_load(file_path)


# ---------------------------------------------------------------------------
# Safe pickle shim (no torch)
# ---------------------------------------------------------------------------


class _RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that only allows plain data types — blocks __reduce__ exploits."""

    _SAFE_CLASSES = {
        ("builtins", "dict"),
        ("builtins", "list"),
        ("builtins", "tuple"),
        ("builtins", "str"),
        ("builtins", "int"),
        ("builtins", "float"),
        ("builtins", "bool"),
        ("builtins", "bytes"),
        ("builtins", "NoneType"),
        ("collections", "OrderedDict"),
    }

    def find_class(self, module: str, name: str):
        if (module, name) in self._SAFE_CLASSES:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"Blocked unsafe pickle class: {module}.{name}")


import pickle


def _safe_pickle_load(file_path: str):
    with open(file_path, "rb") as fh:
        return _RestrictedUnpickler(fh).load()
