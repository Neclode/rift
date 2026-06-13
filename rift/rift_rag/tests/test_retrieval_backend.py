"""Tests for the retrieval-backend dispatch in query.py + turbovec_backend.

These run in the PROJECT env (no turbovec installed, no Ollama needed): they
exercise the pure ranking/dispatch logic directly with synthetic vectors. The
turbovec-present behavior (allowlist parity, latency, size) is verified
separately in a throwaway venv with turbovec installed.

Covered:
  * exact ranking orders kept rows by cosine and respects the keep-list
  * default backend == exact
  * RIFT_RETRIEVAL_BACKEND=turbovec falls back to exact when turbovec is absent
  * turbovec_backend.is_available() never raises and reports absence honestly
  * the bits() env knob parses / defaults correctly
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

RIFT_ROOT = Path(__file__).resolve().parents[2]  # rift/
sys.path.insert(0, str(RIFT_ROOT))

import query  # noqa: E402
from rift_rag import turbovec_backend as tvb  # noqa: E402


def _normalized(rows: list[list[float]]) -> np.ndarray:
    arr = np.asarray(rows, dtype=np.float32)
    arr /= np.linalg.norm(arr, axis=1, keepdims=True)
    return arr


# A 4-row toy index; row 0 points at the query direction most strongly.
VECTORS = _normalized([
    [1.0, 0.0, 0.0],   # idx 0
    [0.9, 0.1, 0.0],   # idx 1
    [0.0, 1.0, 0.0],   # idx 2
    [0.2, 0.0, 1.0],   # idx 3
])
QVEC = _normalized([[1.0, 0.0, 0.0]])[0]


def test_rank_exact_orders_by_cosine():
    keep = [0, 1, 2, 3]
    ranked = query._rank_exact(VECTORS, QVEC, keep, k=3)
    ids = [ci for ci, _ in ranked]
    assert ids == [0, 1, 3]  # closest cosine direction first; idx 2 is orthogonal
    # scores are descending floats
    scores = [s for _, s in ranked]
    assert scores == sorted(scores, reverse=True)


def test_rank_exact_respects_keeplist():
    keep = [1, 2, 3]  # idx 0 filtered out
    ranked = query._rank_exact(VECTORS, QVEC, keep, k=5)
    ids = [ci for ci, _ in ranked]
    assert 0 not in ids
    assert set(ids) <= set(keep)
    assert ids[0] == 1  # best surviving row


def test_default_backend_is_exact(monkeypatch):
    monkeypatch.delenv("RIFT_RETRIEVAL_BACKEND", raising=False)
    keep = [0, 1, 2, 3]
    assert query._rank(VECTORS, QVEC, keep, k=3) == query._rank_exact(
        VECTORS, QVEC, keep, k=3
    )


def test_turbovec_request_falls_back_when_unavailable(monkeypatch):
    # turbovec is NOT installed in the project env -> graceful fallback to exact.
    if tvb.is_available():
        pytest.skip("turbovec installed in this env; fallback path not exercised")
    monkeypatch.setenv("RIFT_RETRIEVAL_BACKEND", "turbovec")
    query._WARNED.clear()
    got = query._rank(VECTORS, QVEC, [0, 1, 2, 3], k=3)
    assert got == query._rank_exact(VECTORS, QVEC, [0, 1, 2, 3], k=3)


def test_is_available_never_raises():
    # Must return a bool regardless of whether turbovec is importable.
    assert isinstance(tvb.is_available(), bool)


def test_bits_env_parsing(monkeypatch):
    monkeypatch.delenv("RIFT_TURBOVEC_BITS", raising=False)
    assert tvb.bits() == 4
    monkeypatch.setenv("RIFT_TURBOVEC_BITS", "2")
    assert tvb.bits() == 2
    monkeypatch.setenv("RIFT_TURBOVEC_BITS", "garbage")
    assert tvb.bits() == 4  # invalid -> default
