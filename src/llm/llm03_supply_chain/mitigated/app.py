"""
LLM03 — Supply Chain Vulnerabilities
Mitigated application.

Demonstrates three mitigations:
  1. Integrity-verified model loading (SHA-256 + weights_only).
  2. pip-audit CVE scan of installed packages.
  3. SBOM generation hint (Syft CLI, run separately).

Run:
    python -m src.llm.llm03_supply_chain.mitigated.app
"""

from __future__ import annotations

import os
import pickle
import subprocess
import sys
import tempfile

from .verify_model import (
    compute_sha256,
    register_model,
    safe_load_model,
    verify_model,
)


# ---------------------------------------------------------------------------
# Helper: create a safe model file (plain dict — no exploit payload)
# ---------------------------------------------------------------------------


def _create_safe_model_file(path: str) -> None:
    """Write a benign model-like file (plain dict pickled safely)."""
    data = {"weights": [0.1, 0.2, 0.3], "version": "1.0"}
    with open(path, "wb") as fh:
        pickle.dump(data, fh)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------


def demo_model_integrity() -> None:
    print("\n[1] MODEL INTEGRITY VERIFICATION")
    print("─" * 50)

    with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as tmp:
        safe_path = tmp.name

    try:
        _create_safe_model_file(safe_path)
        h = register_model(safe_path)
        print(f"  Registered model: {os.path.basename(safe_path)}")
        print(f"  Hash             : {h}")

        result = safe_load_model(safe_path)
        print(f"  Load result      : {result}")
        print("  ✅ Safe model loaded successfully.")
    finally:
        os.unlink(safe_path)

    print()
    # Now try loading an unregistered file
    with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as tmp2:
        unknown_path = tmp2.name
    try:
        _create_safe_model_file(unknown_path)
        print(
            f"  Attempting to load unregistered model: {os.path.basename(unknown_path)}"
        )
        try:
            safe_load_model(unknown_path)
        except KeyError as exc:
            print(f"  ✅ Blocked: {exc}")
    finally:
        os.unlink(unknown_path)

    print()
    # Now tamper with a registered file and try to load it
    with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as tmp3:
        tampered_path = tmp3.name
    try:
        _create_safe_model_file(tampered_path)
        h2 = register_model(tampered_path)
        # Tamper: append a byte
        with open(tampered_path, "ab") as fh:
            fh.write(b"\xff")
        print(f"  Attempting to load tampered model: {os.path.basename(tampered_path)}")
        try:
            safe_load_model(tampered_path)
        except ValueError as exc:
            print(f"  ✅ Blocked: {str(exc).splitlines()[0]}")
    finally:
        os.unlink(tampered_path)


def demo_pickle_block() -> None:
    print("\n[2] PICKLE EXPLOIT BLOCKED BY weights_only / RESTRICTED UNPICKLER")
    print("─" * 50)

    import pickle as _pickle

    class _Exploit:
        def __reduce__(self):
            return (os.system, ("echo '[PICKLE] Would execute here'",))

    with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as tmp:
        exploit_path = tmp.name

    try:
        with open(exploit_path, "wb") as fh:
            _pickle.dump(_Exploit(), fh)

        # Register it (so the path check passes — the point is to show weights_only blocks it)
        register_model(exploit_path)

        print(f"  Malicious model file created: {os.path.basename(exploit_path)}")
        print("  Attempting safe_load_model (weights_only / restricted unpickler)…")
        try:
            safe_load_model(exploit_path)
            print(
                "  ⚠️  Load returned without error (torch weights_only accepted it as a safe tensor dict)."
            )
        except Exception as exc:
            print(f"  ✅ Blocked: {type(exc).__name__}: {exc}")
    finally:
        os.unlink(exploit_path)


def demo_pip_audit() -> None:
    print("\n[3] pip-audit CVE SCAN")
    print("─" * 50)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip_audit", "--format", "columns"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = result.stdout or result.stderr
        if result.returncode == 0:
            print("  ✅ pip-audit: no known vulnerabilities found.")
        else:
            print("  ⚠️  pip-audit found issues:")
            for line in output.splitlines()[:20]:
                print(f"    {line}")
    except FileNotFoundError:
        print("  ℹ️  pip-audit not installed. Run: pip install pip-audit")
    except subprocess.TimeoutExpired:
        print("  ⚠️  pip-audit timed out.")


def main() -> None:
    print("=" * 60)
    print("LLM03 — Supply Chain  |  MITIGATED application")
    print("=" * 60)

    demo_model_integrity()
    demo_pickle_block()
    demo_pip_audit()

    print("\n[4] SBOM GENERATION (manual step)")
    print("─" * 50)
    print("  Run the following to generate a CycloneDX SBOM:")
    print("    syft dir:. --output cyclonedx-json > sbom.json")
    print("    grype sbom:sbom.json")
    print()


if __name__ == "__main__":
    main()
