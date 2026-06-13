"""Retrieve + (optional) grounded generation over the Rift RAG index.

Importable contract (the eval harness depends on these):

    retrieve(question, k=5, filters=None) -> list[dict]
        filters keys (all optional, exact-match, applied BEFORE similarity):
            "domain", "doc_type", "failure_class", "case_id",
            "target_surface", "scope_tag", "kill_chain_stage"
        returns list of {"rank","score","source","doc_type","case_id",
            "target_surface","scope_tag","kill_chain_stage","sensitivity","text"}
        sorted by score desc, length <= k.

    answer(question, k=5, filters=None) -> dict
        retrieves, builds a grounded prompt, calls qwen2.5-coder:14b,
        returns {"answer": str, "sources": [...], "results": [<retrieve out>]}

CLI:
    python query.py "QUESTION" [--k 5] [--domain D] [--doc-type T]
        [--failure-class F] [--case-id C] [--generate] [--json]

Similarity is cosine; stored vectors are pre-normalized at save time, so we
only normalize the query vector here.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

from rift_rag import store  # noqa: E402
from rift_rag.embed import OllamaError, embed_query  # noqa: E402
from rift_rag.generate import generate  # noqa: E402

# Retrieval rule: filter by domain -> task -> retrieve ->
# rerank. We apply metadata filters BEFORE similarity scoring.
_FILTER_KEYS = ("domain", "doc_type", "failure_class", "case_id", "target_surface", "scope_tag", "kill_chain_stage")

# Lazy module-level cache so repeated calls in one process load the index once.
_CACHE: dict[str, object] = {}

# One-time warnings (e.g. backend fallback) so a long run isn't spammed.
_WARNED: set[str] = set()


def _warn_once(msg: str) -> None:
    if msg not in _WARNED:
        _WARNED.add(msg)
        print(f"WARNING: {msg}", file=sys.stderr)


def _load_index():
    if "chunks" not in _CACHE:
        chunks, vectors = store.load()
        _CACHE["chunks"] = chunks
        _CACHE["vectors"] = vectors
    return _CACHE["chunks"], _CACHE["vectors"]


def _passes_filters(meta: dict, filters: dict) -> bool:
    for key in _FILTER_KEYS:
        want = filters.get(key)
        if want in (None, ""):
            continue
        if str(meta.get(key, "")).lower() != str(want).lower():
            return False
    return True


def _rank_exact(vectors, qvec, keep_idx: list[int], k: int) -> list[tuple[int, float]]:
    """Exact cosine over the kept rows. Returns [(chunk_index, score)] top-k.

    This is the default path and is intentionally byte-identical to the original
    inline scoring logic (dot product over pre-normalized vectors, argsort desc).
    """
    sub = vectors[keep_idx]  # [m, dim]
    scores = sub @ qvec  # [m]
    m = len(keep_idx)
    top = np.argsort(-scores)[: min(k, m)]
    return [(keep_idx[int(j)], float(scores[int(j)])) for j in top]


def _rank_turbovec(vectors, qvec, keep_idx: list[int], k: int):
    """Optional TurboVec ANN path. Returns ranked [(chunk_index, score)], or
    ``None`` to signal the caller should fall back to exact search.

    The metadata keep-list is passed as the ANN allowlist (identical filter
    semantics), then the returned candidate ids are re-scored with EXACT cosine
    so the ``score`` field stays on the same scale as the exact path.
    """
    from rift_rag import turbovec_backend as tvb

    if not tvb.is_available():
        _warn_once(
            "RIFT_RETRIEVAL_BACKEND=turbovec but the 'turbovec' package is not "
            "installed; falling back to exact NumPy cosine."
        )
        return None

    cand = tvb.search(vectors, qvec, k, allowlist=keep_idx)  # [(ci, approx)]
    if not cand:
        return []
    ids = np.asarray([i for i, _ in cand], dtype=np.int64)
    exact = vectors[ids] @ qvec
    order = np.argsort(-exact)
    return [(int(ids[int(j)]), float(exact[int(j)])) for j in order]


def _rank(vectors, qvec, keep_idx: list[int], k: int) -> list[tuple[int, float]]:
    """Dispatch to the selected backend. Default (and fallback) is exact."""
    backend = os.environ.get("RIFT_RETRIEVAL_BACKEND", "exact").strip().lower()
    if backend in ("turbovec", "tv"):
        ranked = _rank_turbovec(vectors, qvec, keep_idx, k)
        if ranked is not None:
            return ranked
    return _rank_exact(vectors, qvec, keep_idx, k)


def retrieve(question: str, k: int = 5, filters: dict | None = None) -> list[dict]:
    """Filter by metadata, then rank surviving chunks by cosine similarity."""
    filters = filters or {}
    chunks, vectors = _load_index()

    # 1) metadata filter (applied BEFORE similarity).
    keep_idx = [
        i
        for i, c in enumerate(chunks)
        if _passes_filters(c.get("metadata", {}), filters)
    ]
    if not keep_idx:
        return []

    # 2) embed the query with the SAME model and normalize for cosine.
    qvec = np.asarray(embed_query(question), dtype=np.float32)
    qnorm = np.linalg.norm(qvec)
    if qnorm == 0:
        return []
    qvec = qvec / qnorm

    # 3) rank kept chunks (exact by default; optional TurboVec backend).
    ranked = _rank(vectors, qvec, keep_idx, k)

    results: list[dict] = []
    for rank, (ci, score) in enumerate(ranked, start=1):
        chunk = chunks[ci]
        meta = chunk.get("metadata", {})
        results.append(
            {
                "rank": rank,
                "score": score,
                "source": chunk["source"],
                "doc_type": meta.get("doc_type", ""),
                "case_id": meta.get("case_id", ""),
                "target_surface": meta.get("target_surface", ""),
                "scope_tag": meta.get("scope_tag", ""),
                "kill_chain_stage": meta.get("kill_chain_stage", ""),
                "sensitivity": meta.get("sensitivity", "local_only"),
                "text": chunk["text"],
            }
        )
    return results


def _build_prompt(question: str, results: list[dict]) -> str:
    blocks = []
    for r in results:
        blocks.append(
            f"[source: {r['source']} | doc_type: {r['doc_type']}"
            f"{' | case: ' + r['case_id'] if r['case_id'] else ''}]\n"
            f"{r['text']}"
        )
    context = "\n\n---\n\n".join(blocks) if blocks else "(no matching context)"
    return (
        "You are Rift, a local AI-native security research assistant. Answer the "
        "question using ONLY the context below, which is retrieved from the Rift "
        "corpus. Cite the relevant source paths inline. If the context does not "
        "contain the answer, say so plainly rather than inventing detail.\n\n"
        f"# Context\n{context}\n\n"
        f"# Question\n{question}\n\n"
        "# Answer\n"
    )


def answer(question: str, k: int = 5, filters: dict | None = None) -> dict:
    """Retrieve, build a grounded prompt, and generate with qwen2.5-coder:14b."""
    results = retrieve(question, k=k, filters=filters)
    prompt = _build_prompt(question, results)
    text = generate(prompt)
    sources = list(dict.fromkeys(r["source"] for r in results))  # de-dup, ordered
    return {"answer": text, "sources": sources, "results": results}


# ---- CLI -------------------------------------------------------------------
def _filters_from_args(args) -> dict:
    return {
        "domain": args.domain,
        "doc_type": args.doc_type,
        "failure_class": args.failure_class,
        "case_id": args.case_id,
        "target_surface": args.target_surface,
        "scope_tag": args.scope_tag,
        "kill_chain_stage": args.kill_chain_stage,
    }


def _snippet(text: str, n: int = 200) -> str:
    flat = " ".join(text.split())
    return flat[:n] + ("..." if len(flat) > n else "")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Query the Rift RAG index (retrieve + optional generate)."
    )
    parser.add_argument("question", help="the question / query string")
    parser.add_argument("--k", type=int, default=5, help="number of hits (default 5)")
    parser.add_argument("--domain", default=None, help="filter: domain")
    parser.add_argument("--doc-type", dest="doc_type", default=None,
                        help="filter: doc_type")
    parser.add_argument("--failure-class", dest="failure_class", default=None,
                        help="filter: failure_class")
    parser.add_argument("--case-id", dest="case_id", default=None,
                        help="filter: exact case_id match (optional)")
    parser.add_argument("--target-surface", dest="target_surface", default=None, help="filter: target_surface")
    parser.add_argument("--scope-tag", dest="scope_tag", default=None, help="filter: scope_tag")
    parser.add_argument("--kill-chain-stage", dest="kill_chain_stage", default=None, help="filter: kill_chain_stage")
    parser.add_argument("--generate", action="store_true",
                        help="also run grounded generation")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON")
    args = parser.parse_args(argv)

    filters = _filters_from_args(args)

    try:
        if args.generate:
            out = answer(args.question, k=args.k, filters=filters)
            results = out["results"]
        else:
            results = retrieve(args.question, k=args.k, filters=filters)
            out = None
    except OllamaError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3

    if args.json:
        payload = out if out is not None else {"results": results}
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    # Human-readable.
    if not results:
        print("No matching chunks (check filters).")
    else:
        print(f"Top {len(results)} hits for: {args.question}\n")
        for r in results:
            print(
                f"  #{r['rank']}  score={r['score']:.3f}  "
                f"[{r['doc_type']}]  {r['source']}"
            )
            print(f"      {_snippet(r['text'])}\n")

    if out is not None:
        print("=" * 72)
        print("Grounded answer:\n")
        print(out["answer"].strip())
        print("\nCited sources:")
        for s in out["sources"]:
            print(f"  - {s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
