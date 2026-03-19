"""
ASI08 — Cascading Failures
Vulnerable pipeline.

A multi-agent pipeline where:
  - Failures in one step propagate silently to downstream steps
  - No circuit breaker — failed agents are retried indefinitely
  - No schema validation between steps — corrupt outputs pass through
  - No timeout budget — runaway agents consume unbounded resources

Run:
    python -m src.agents.asi08_cascading_failures.vulnerable.agent
"""

from __future__ import annotations

import os, sys, textwrap, time, random
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
if not os.environ.get("OPENAI_API_KEY"):
    print("[Error] OPENAI_API_KEY is not set.")
    sys.exit(1)

MODEL = "gpt-4o-mini"
client = OpenAI()

# ---------------------------------------------------------------------------
# Simulated agent steps — each can fail or return corrupt output
# ---------------------------------------------------------------------------

_CALL_COUNT: dict[str, int] = {"extraction": 0, "formatting": 0, "publishing": 0}
_FAILURE_MODES: dict[str, bool] = {
    "extraction_fails": False,  # causes infinite retry
    "extraction_corrupt": False,  # passes None downstream
    "formatting_loop": False,  # simulates infinite retry loop
}


def extraction_agent(input_data: dict) -> dict | None:
    """
    Step 1: Extract structured data from raw input.
    VULNERABLE: may fail silently and return None, which propagates downstream.
    """
    _CALL_COUNT["extraction"] += 1
    print(f"  [Step 1: extraction] attempt #{_CALL_COUNT['extraction']}")

    if _FAILURE_MODES["extraction_fails"]:
        # Simulate a transient failure — but no circuit breaker to stop retries
        raise RuntimeError("Extraction agent: upstream dependency unavailable")

    if _FAILURE_MODES["extraction_corrupt"]:
        # Returns wrong schema — no validation to catch it
        return {"wrong_key": "corrupt_data", "source": "bad_agent"}  # missing 'records'

    records = input_data.get("raw_records", [])
    return {
        "records": records,
        "record_count": len(records),
        "source": input_data.get("source", "unknown"),
    }


def formatting_agent(extracted: dict | None) -> dict | None:
    """
    Step 2: Format extracted data.
    VULNERABLE: crashes or produces corrupt output if extracted is None or wrong schema.
    """
    _CALL_COUNT["formatting"] += 1
    print(f"  [Step 2: formatting] attempt #{_CALL_COUNT['formatting']}")

    if _FAILURE_MODES["formatting_loop"]:
        # Simulate a formatting loop — no timeout to stop it
        print("  [Step 2: formatting] simulating slow processing...")
        time.sleep(0.3)  # In a real loop this would be unbounded

    if extracted is None:
        # VULNERABLE: crashes on None — exception propagates, no isolation
        raise TypeError("formatting_agent received None — extraction failed upstream")

    # VULNERABLE: no schema validation — if 'records' is missing, KeyError propagates
    records = extracted["records"]  # will KeyError if extraction was corrupt
    formatted = "\n".join(str(r) for r in records) if records else "(empty)"
    return {
        "formatted_data": formatted,
        "format_type": "text",
        "checksum": str(hash(formatted)),
    }


def publishing_agent(formatted: dict | None) -> dict:
    """
    Step 3: Publish formatted data.
    VULNERABLE: publishes whatever it receives, even if it is corrupt or None.
    """
    _CALL_COUNT["publishing"] += 1
    print(f"  [Step 3: publishing] attempt #{_CALL_COUNT['publishing']}")

    if formatted is None:
        # VULNERABLE: publishes corrupt output instead of halting
        print(
            "  [Step 3: publishing] ⚠️  Publishing None — corrupt data written to output!"
        )
        return {
            "status": "published",
            "data": None,
            "warning": "CORRUPT OUTPUT PUBLISHED",
        }

    return {
        "status": "published",
        "data": formatted.get("formatted_data", ""),
        "warning": None,
    }


def vulnerable_pipeline(input_data: dict, max_retries: int = 5) -> dict:
    """
    Runs the full pipeline.
    VULNERABLE: no circuit breaker, no step validation, no timeout budget.
    Failures retry blindly up to max_retries times.
    """
    print(f"\n  Running vulnerable pipeline (max_retries={max_retries})...")

    # VULNERABLE: unbounded retry — no circuit breaker, no backoff
    for attempt in range(1, max_retries + 1):
        try:
            extracted = extraction_agent(input_data)
        except RuntimeError as e:
            print(f"  [Pipeline] Step 1 failed (attempt {attempt}): {e}")
            if attempt == max_retries:
                print("  [Pipeline] Max retries reached — pipeline failed.")
                return {"status": "failed", "error": str(e), "calls": dict(_CALL_COUNT)}
            continue  # VULNERABLE: retry without backoff

        # VULNERABLE: corrupt extracted output passed directly to formatting, no validation
        try:
            formatted = formatting_agent(extracted)
        except (TypeError, KeyError) as e:
            # Cascading failure: Step 1 corruption propagated to Step 2
            print(f"  [Pipeline] Step 2 failed due to Step 1 corruption: {e}")
            return {
                "status": "cascaded_failure",
                "error": str(e),
                "calls": dict(_CALL_COUNT),
            }

        # VULNERABLE: publishes even if formatted is unexpected shape
        result = publishing_agent(formatted)
        print(f"\n  Pipeline completed. Status: {result['status']}")
        if result.get("warning"):
            print(f"  ⚠️  {result['warning']}")
        result["calls"] = dict(_CALL_COUNT)
        return result

    return {"status": "failed", "calls": dict(_CALL_COUNT)}


# ---------------------------------------------------------------------------
# REPL
# ---------------------------------------------------------------------------

BANNER = textwrap.dedent("""\
    ┌───────────────────────────────────────────────────────────────────┐
    │  ASI08 — Cascading Failures  │  VULNERABLE                        │
    │  No circuit breaker, no step validation, no timeout budget.       │
    │                                                                   │
    │  Commands:                                                        │
    │    /run         — run pipeline with clean data                    │
    │    /fail1       — toggle step 1 failure (infinite retry demo)     │
    │    /corrupt1    — toggle step 1 corrupt output (cascades to S2)   │
    │    /loop2       — toggle step 2 slow loop                         │
    │    /status      — show failure mode flags and call counts         │
    │    /quit                                                          │
    └───────────────────────────────────────────────────────────────────┘
""")

_SAMPLE_INPUT = {
    "source": "sales_db",
    "raw_records": ["Q1: $5.2M", "Q2: $6.1M", "Q3: $7.4M", "Q4: $24.7M"],
}


def main() -> None:
    print(BANNER)
    while True:
        try:
            inp = input("Cmd: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break
        if not inp:
            continue
        if inp.lower() in ("/quit", "/exit"):
            break
        if inp.lower() == "/run":
            # Reset call counts
            for k in _CALL_COUNT:
                _CALL_COUNT[k] = 0
            result = vulnerable_pipeline(_SAMPLE_INPUT)
            print(f"  Result: {result}\n")
            continue
        if inp.lower() == "/fail1":
            _FAILURE_MODES["extraction_fails"] = not _FAILURE_MODES["extraction_fails"]
            print(f"  Step 1 failure mode: {_FAILURE_MODES['extraction_fails']}\n")
            continue
        if inp.lower() == "/corrupt1":
            _FAILURE_MODES["extraction_corrupt"] = not _FAILURE_MODES[
                "extraction_corrupt"
            ]
            print(
                f"  Step 1 corrupt output mode: {_FAILURE_MODES['extraction_corrupt']}\n"
            )
            continue
        if inp.lower() == "/loop2":
            _FAILURE_MODES["formatting_loop"] = not _FAILURE_MODES["formatting_loop"]
            print(f"  Step 2 slow loop mode: {_FAILURE_MODES['formatting_loop']}\n")
            continue
        if inp.lower() == "/status":
            print(f"\n  Failure modes: {_FAILURE_MODES}")
            print(f"  Call counts:   {_CALL_COUNT}\n")
            continue
        print(
            "  Unknown command. Try /run, /fail1, /corrupt1, /loop2, /status, /quit\n"
        )


if __name__ == "__main__":
    main()
