"""
Unit tests for ASI05 – Unexpected Code Execution (RCE)
Control: src/agents/asi05_unexpected_code_execution/mitigated/sandbox.py

Tests cover:
- validate_ast: safe expressions, forbidden nodes, forbidden names/attrs, syntax errors
- safe_eval: allowed arithmetic, blocked imports/builtins/names
- safe_subprocess: allowlist enforcement, argument character filter
"""

import math
import pytest

from src.agents.asi05_unexpected_code_execution.mitigated.sandbox import (
    validate_ast,
    safe_eval,
    safe_subprocess,
)

pytestmark = pytest.mark.no_llm


# ── validate_ast ─────────────────────────────────────────────────────────────


class TestValidateAst:
    def test_safe_arithmetic_returns_empty(self):
        assert validate_ast("1 + 2 * 3") == []

    def test_safe_math_call_returns_empty(self):
        assert validate_ast("round(3.7)") == []

    def test_syntax_error_reported(self):
        violations = validate_ast("1 +* 2")
        assert any("Syntax error" in v for v in violations)

    def test_import_forbidden(self):
        violations = validate_ast("import os")
        assert any("Forbidden node" in v for v in violations)

    def test_forbidden_name_eval(self):
        violations = validate_ast("eval('1')")
        assert any("eval" in v for v in violations)

    def test_forbidden_name_exec(self):
        violations = validate_ast("exec('x=1')")
        assert any("exec" in v for v in violations)

    def test_forbidden_name_open(self):
        violations = validate_ast("open('/etc/passwd')")
        assert any("open" in v for v in violations)

    def test_forbidden_attr_system(self):
        violations = validate_ast("os.system('ls')")
        assert any("system" in v for v in violations)

    def test_forbidden_dunder_subclasses(self):
        violations = validate_ast("().__class__.__subclasses__()")
        assert len(violations) > 0


# ── safe_eval ────────────────────────────────────────────────────────────────


class TestSafeEval:
    def test_arithmetic(self):
        assert safe_eval("2 + 3") == 5

    def test_float_arithmetic(self):
        result = safe_eval("1.5 * 4")
        assert abs(result - 6.0) < 1e-9

    def test_builtin_abs(self):
        assert safe_eval("abs(-7)") == 7

    def test_builtin_min_max(self):
        assert safe_eval("min(3, 1, 2)") == 1
        assert safe_eval("max(3, 1, 2)") == 3

    def test_blocks_import(self):
        with pytest.raises(ValueError, match="validation"):
            safe_eval("import os")

    def test_blocks_eval_name(self):
        with pytest.raises(ValueError, match="validation"):
            safe_eval("eval('1')")

    def test_blocks_open(self):
        with pytest.raises(ValueError, match="validation"):
            safe_eval("open('/etc/passwd')")

    def test_blocks_dunder_escape(self):
        with pytest.raises(ValueError):
            safe_eval("().__class__.__bases__[0].__subclasses__()")


# ── safe_subprocess ──────────────────────────────────────────────────────────


class TestSafeSubprocess:
    def test_allowed_command_echo(self):
        result = safe_subprocess("echo", "hello")
        assert "hello" in result

    def test_allowed_command_date(self):
        result = safe_subprocess("date")
        assert len(result) > 0

    def test_blocked_command_rm(self):
        with pytest.raises(ValueError, match="not in allowlist"):
            safe_subprocess("rm", "-rf", "/")

    def test_blocked_command_curl(self):
        with pytest.raises(ValueError, match="not in allowlist"):
            safe_subprocess("curl", "http://evil.com")

    def test_disallowed_argument_semicolon(self):
        with pytest.raises(ValueError, match="disallowed characters"):
            safe_subprocess("echo", "hello; rm -rf /")

    def test_disallowed_argument_pipe(self):
        with pytest.raises(ValueError, match="disallowed characters"):
            safe_subprocess("echo", "hello | cat /etc/passwd")
