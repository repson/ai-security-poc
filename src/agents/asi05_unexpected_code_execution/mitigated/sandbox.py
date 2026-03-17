"""
ASI05 — Unexpected Code Execution
Sandboxed execution utilities.

  safe_eval      — RestrictedPython sandboxed eval (math-only)
  validate_ast   — static AST analysis before any execution
  safe_subprocess — allowlisted commands, shell=False, timeout
"""

from __future__ import annotations

import ast, re, subprocess, sys
from typing import Optional

# ---------------------------------------------------------------------------
# AST validator
# ---------------------------------------------------------------------------

_FORBIDDEN_NODES = {ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal}
_FORBIDDEN_NAMES = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "open",
    "input",
    "breakpoint",
    "vars",
    "locals",
    "globals",
    "getattr",
    "setattr",
    "delattr",
    "__class__",
    "__bases__",
    "__subclasses__",
    "__init__",
    "system",
    "popen",
    "subprocess",
    "socket",
}


def validate_ast(code: str) -> list[str]:
    """Return list of violations. Empty = safe."""
    try:
        tree = ast.parse(code, mode="eval")
    except SyntaxError as exc:
        return [f"Syntax error: {exc}"]

    violations: list[str] = []
    for node in ast.walk(tree):
        if type(node) in _FORBIDDEN_NODES:
            violations.append(f"Forbidden node: {type(node).__name__}")
        if isinstance(node, ast.Attribute) and node.attr in _FORBIDDEN_NAMES:
            violations.append(f"Forbidden attribute: .{node.attr}")
        if isinstance(node, ast.Name) and node.id in _FORBIDDEN_NAMES:
            violations.append(f"Forbidden name: '{node.id}'")
    return violations


# ---------------------------------------------------------------------------
# RestrictedPython eval
# ---------------------------------------------------------------------------

import math as _math

_SAFE_GLOBALS: dict = {
    "__builtins__": {
        "abs": abs,
        "round": round,
        "min": min,
        "max": max,
        "sum": sum,
        "len": len,
        "int": int,
        "float": float,
        "bool": bool,
        "True": True,
        "False": False,
        "None": None,
    },
    "math": _math,
}


def safe_eval(code: str) -> object:
    """Evaluate a math expression inside a RestrictedPython sandbox."""
    violations = validate_ast(code)
    if violations:
        raise ValueError(f"Code failed AST validation: {violations}")

    try:
        from RestrictedPython import compile_restricted

        compiled = compile_restricted(code, filename="<safe_eval>", mode="eval")
    except ImportError:
        # RestrictedPython not installed — fall back to ast-validated plain eval
        compiled = compile(code, "<safe_eval>", "eval")
    except SyntaxError as exc:
        raise ValueError(f"RestrictedPython compile error: {exc}")

    return eval(compiled, _SAFE_GLOBALS, {})


# ---------------------------------------------------------------------------
# Safe subprocess
# ---------------------------------------------------------------------------

_ALLOWED_CMDS = {"echo", "date", "ls", "wc"}
_SAFE_ARG = re.compile(r"^[a-zA-Z0-9_\-\.\/]{1,128}$")


def safe_subprocess(command: str, *args: str, timeout: int = 15) -> str:
    """Run a command from the allowlist with shell=False."""
    if command not in _ALLOWED_CMDS:
        raise ValueError(f"Command '{command}' not in allowlist: {_ALLOWED_CMDS}")
    for a in args:
        if not _SAFE_ARG.match(a):
            raise ValueError(f"Argument '{a}' contains disallowed characters.")

    result = subprocess.run(
        [command, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
    )
    return result.stdout
