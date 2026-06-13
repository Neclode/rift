"""Persisted vector store: index/vectors.npy + index/chunks.json.

`vectors.npy` is a float32 array of shape [n_chunks, dim], L2-normalized at
save time so retrieval is a single dot product. `chunks.json` is a list of
chunk dicts aligned by row index to `vectors`.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

# Default on-disk location for the index.
INDEX_DIR = Path(__file__).resolve().parent.parent / "index"
VECTORS_PATH = INDEX_DIR / "vectors.npy"
CHUNKS_PATH = INDEX_DIR / "chunks.json"


def normalize(vectors: np.ndarray) -> np.ndarray:
    """L2-normalize each row; zero-vectors are left as zeros (no div-by-zero)."""
    vectors = np.asarray(vectors, dtype=np.float32)
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return (vectors / norms).astype(np.float32)


def save(chunks: list[dict], vectors, index_dir: Path = INDEX_DIR) -> None:
    """Persist normalized vectors and aligned chunk metadata."""
    index_dir = Path(index_dir)
    index_dir.mkdir(parents=True, exist_ok=True)

    arr = normalize(np.asarray(vectors, dtype=np.float32))
    if arr.shape[0] != len(chunks):
        raise ValueError(
            f"vector/chunk count mismatch: {arr.shape[0]} vs {len(chunks)}"
        )

    np.save(index_dir / "vectors.npy", arr)
    with open(index_dir / "chunks.json", "w", encoding="utf-8") as fh:
        json.dump(chunks, fh, ensure_ascii=False, indent=2)


def load(index_dir: Path = INDEX_DIR) -> tuple[list[dict], np.ndarray]:
    """Load chunks and the normalized vector matrix."""
    index_dir = Path(index_dir)
    vectors_path = index_dir / "vectors.npy"
    chunks_path = index_dir / "chunks.json"
    if not vectors_path.exists() or not chunks_path.exists():
        raise FileNotFoundError(
            f"Index not found in {index_dir}. Run `python ingest.py` first."
        )

    vectors = np.load(vectors_path).astype(np.float32)
    with open(chunks_path, "r", encoding="utf-8") as fh:
        chunks = json.load(fh)
    return chunks, vectors
