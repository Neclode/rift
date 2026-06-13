"""Optional TurboVec retrieval backend — OPT-IN, not the default path.

Rift's default retrieval is exact NumPy cosine in ``query.py`` and stays that
way. This module adds an OPTIONAL approximate backend via TurboVec (a
TurboQuant-based Rust ANN index with Python bindings, https://github.com/RyanCodrai/turbovec).

Design goals
------------
* **Out of project deps.** ``turbovec`` is imported lazily. ``is_available()``
  returns ``False`` (never raises) when it is not installed, so the caller can
  fall back to exact search. Nothing here is imported unless the backend is
  explicitly selected.
* **Identical allowlist semantics.** ``query.py`` applies the metadata filter
  FIRST, yielding a keep-list of chunk indices. That list is handed here as
  ``allowlist=``; TurboVec can then only return allowed chunks — the same
  semantics as the exact filtered path. The caller re-scores the returned
  candidate ids with exact cosine, so reported scores stay on the cosine scale.

Selection (read by ``query.py``):
    RIFT_RETRIEVAL_BACKEND=turbovec   # opt in (default: exact)
    RIFT_TURBOVEC_BITS=4              # quantization bit width (default: 4)

The index is built once per (vector matrix, bit width) and cached in-process,
so repeated queries in one run don't rebuild it.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import numpy as np

DEFAULT_BITS = 4

# Cache: key=(id(vectors), shape, bits) -> built IdMapIndex. Keyed on id() so a
# fresh matrix (e.g. a rebuilt index) doesn't collide with a stale one.
_INDEX_CACHE: dict[tuple, object] = {}


def is_available() -> bool:
    """True iff the ``turbovec`` package can be imported. Never raises."""
    try:
        import turbovec  # noqa: F401
    except Exception:
        return False
    return True


def bits() -> int:
    """Quantization bit width from RIFT_TURBOVEC_BITS (default 4)."""
    raw = os.environ.get("RIFT_TURBOVEC_BITS", "").strip()
    if not raw:
        return DEFAULT_BITS
    try:
        return int(raw)
    except ValueError:
        return DEFAULT_BITS


def reset_cache() -> None:
    """Drop the built-index cache (used by benchmarks/tests that toggle state)."""
    _INDEX_CACHE.clear()


def _get_index(vectors: np.ndarray, bw: int):
    """Build (and cache) an IdMapIndex over ``vectors`` with ids 0..n-1."""
    key = (id(vectors), vectors.shape, bw)
    cached = _INDEX_CACHE.get(key)
    if cached is not None:
        return cached

    from turbovec import IdMapIndex

    n, dim = vectors.shape
    idx = IdMapIndex(dim=dim, bit_width=bw)
    ids_u64 = np.asarray(range(n), dtype=np.uint64)
    idx.add_with_ids(np.ascontiguousarray(vectors, dtype=np.float32), ids_u64)
    _INDEX_CACHE[key] = idx
    return idx


def _raw_search(index, q: np.ndarray, k: int, allowlist) -> list[tuple[int, float]]:
    """Call ``index.search`` defensively about 1-D vs 2-D query shape."""
    qf = np.ascontiguousarray(q, dtype=np.float32)
    kwargs = {}
    if allowlist is not None:
        kwargs["allowlist"] = np.asarray(allowlist, dtype=np.uint64)
    try:
        scores, ids = index.search(qf, k, **kwargs)
    except Exception:
        scores, ids = index.search(qf.reshape(1, -1), k, **kwargs)
    scores = np.asarray(scores).reshape(-1)
    ids = np.asarray(ids).reshape(-1)
    return [(int(i), float(s)) for i, s in zip(ids, scores) if int(i) >= 0]


def search(
    vectors: np.ndarray,
    qvec: np.ndarray,
    k: int,
    allowlist=None,
) -> list[tuple[int, float]]:
    """Approximate top-k over ``vectors`` restricted to ``allowlist`` chunk ids.

    Returns ``[(chunk_index, approx_score)]`` in TurboVec's order. The caller is
    expected to re-score with exact cosine. Raises if turbovec is unavailable —
    guard with ``is_available()`` first.
    """
    if allowlist is not None and len(allowlist) == 0:
        return []
    bw = bits()
    idx = _get_index(vectors, bw)
    return _raw_search(idx, qvec, k, allowlist)


def serialized_size_bytes(vectors: np.ndarray, bw: int | None = None) -> int:
    """On-disk footprint of a TurboQuant index over ``vectors`` (benchmark aid).

    Uses TurboQuantIndex.write to a temp file and measures it — a proxy for the
    quantized memory footprint at this bit width. Raises if turbovec is absent.
    """
    from turbovec import TurboQuantIndex

    bw = bw if bw is not None else bits()
    dim = vectors.shape[1]
    tq = TurboQuantIndex(dim=dim, bit_width=bw)
    tq.add(np.ascontiguousarray(vectors, dtype=np.float32))
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "footprint.tq"
        tq.write(str(p))
        return p.stat().st_size
