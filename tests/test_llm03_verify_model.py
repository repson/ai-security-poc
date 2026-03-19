"""
Unit tests for LLM03 – Supply Chain Vulnerabilities
Control: src/llm/llm03_supply_chain/mitigated/verify_model.py

Tests cover:
- compute_sha256: format, determinism
- register_model + verify_model: roundtrip, unregistered raises, tampered raises
- _RestrictedUnpickler: allows safe classes, blocks unsafe classes
"""

import io
import os
import pickle
import struct
import tempfile
import pytest

from src.llm.llm03_supply_chain.mitigated.verify_model import (
    compute_sha256,
    register_model,
    verify_model,
    _DB,
    _RestrictedUnpickler,
)

pytestmark = pytest.mark.no_llm


@pytest.fixture(autouse=True)
def clear_db():
    """Ensure model registry is clean before/after each test."""
    _DB.clear()
    yield
    _DB.clear()


# ── compute_sha256 ────────────────────────────────────────────────────────────


class TestComputeSha256:
    def test_returns_sha256_prefix(self, tmp_path):
        p = tmp_path / "model.bin"
        p.write_bytes(b"weights")
        assert compute_sha256(str(p)).startswith("sha256:")

    def test_deterministic(self, tmp_path):
        p = tmp_path / "model.bin"
        p.write_bytes(b"weights")
        h1 = compute_sha256(str(p))
        h2 = compute_sha256(str(p))
        assert h1 == h2

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            compute_sha256("/no/such/file.bin")


# ── register_model + verify_model ─────────────────────────────────────────────


class TestVerifyModel:
    def test_roundtrip(self, tmp_path):
        p = tmp_path / "model.bin"
        p.write_bytes(b"real weights")
        register_model(str(p))
        assert verify_model(str(p)) is True

    def test_unregistered_raises_key_error(self, tmp_path):
        p = tmp_path / "unknown.bin"
        p.write_bytes(b"x")
        with pytest.raises(KeyError):
            verify_model(str(p))

    def test_tampered_file_raises_value_error(self, tmp_path):
        p = tmp_path / "model.bin"
        p.write_bytes(b"original weights")
        register_model(str(p))
        # Tamper: overwrite content
        p.write_bytes(b"tampered weights")
        with pytest.raises(ValueError, match="[Ff]ailed|FAILED"):
            verify_model(str(p))

    def test_explicit_expected_hash_accepted(self, tmp_path):
        p = tmp_path / "model.bin"
        p.write_bytes(b"data")
        h = compute_sha256(str(p))
        register_model(str(p), expected_hash=h)
        assert verify_model(str(p)) is True

    def test_wrong_explicit_hash_raises(self, tmp_path):
        p = tmp_path / "model.bin"
        p.write_bytes(b"data")
        register_model(str(p), expected_hash="sha256:wronghash")
        with pytest.raises(ValueError):
            verify_model(str(p))


# ── _RestrictedUnpickler ──────────────────────────────────────────────────────


def _pickle_bytes(obj) -> bytes:
    return pickle.dumps(obj)


class TestRestrictedUnpickler:
    def _loads(self, data: bytes):
        return _RestrictedUnpickler(io.BytesIO(data)).load()

    def test_allows_dict(self):
        data = _pickle_bytes({"key": "value"})
        assert self._loads(data) == {"key": "value"}

    def test_allows_list(self):
        data = _pickle_bytes([1, 2, 3])
        assert self._loads(data) == [1, 2, 3]

    def test_allows_str(self):
        data = _pickle_bytes("hello")
        assert self._loads(data) == "hello"

    def test_blocks_os_system(self):
        """Pickle that references os.system should be blocked."""
        import os

        class EvilPickle:
            def __reduce__(self):
                return (os.system, ("echo pwned",))

        data = _pickle_bytes(EvilPickle())
        with pytest.raises(pickle.UnpicklingError, match="[Bb]locked"):
            self._loads(data)
