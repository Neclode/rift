"""Build the Rift RAG index over the corpus.

Walks the corpus dirs, chunks every *.md / *.json, embeds each chunk via local
Ollama (nomic-embed-text), and persists vectors.npy + chunks.json under
rift/index/

Run:  python -m rift.ingest
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Make `rift_rag` importable when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from rift_rag import chunk as chunker  # noqa: E402
from rift_rag import store  # noqa: E402
from rift_rag.embed import OllamaError, embed_documents  # noqa: E402

# Corpus roots to walk recursively (relative to the repo root).
_ROOT = Path(__file__).resolve().parents[1]
CORPUS_DIRS = [
    _ROOT / "rift-corpus" / "attack-paths",
]

# Directories to skip entirely (sensitive / non-corpus).
SKIP_DIRS = {"raw-local-only", "generated", "logs"}

# How many chunks to send per embed request.
EMBED_BATCH = 32

# nomic-embed-text context limit is 8192 tokens.  With the search_document:
# prefix (~17 chars) and conservative ~4 chars/token estimate, cap at 6000
# chars to stay well inside the limit.  Chunks beyond this cap are truncated
# with an ellipsis so they remain indexable rather than hard-failing the run.
MAX_CHUNK_CHARS = 6000


def iter_corpus_files() -> list[Path]:
    files: list[Path] = []
    for root in CORPUS_DIRS:
        if not root.exists():
            print(f"  warning: corpus dir missing: {root}")
            continue
        for path in sorted(root.rglob("*")):
            if path.is_dir():
                continue
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if ".generated." in path.name:
                continue
            if path.suffix.lower() not in (".md", ".json"):
                continue
            files.append(path)
    return files


def build_chunks(files: list[Path]) -> list[dict]:
    chunks: list[dict] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError) as exc:
            print(f"  skip (read error) {path}: {exc}")
            continue
        if not text.strip():
            continue  # skip empty files
        file_chunks = chunker.chunk_file(path, text)
        # Truncate any chunk that would exceed the embed model's context limit.
        for c in file_chunks:
            if len(c["text"]) > MAX_CHUNK_CHARS:
                print(f"  truncating oversized chunk ({len(c['text'])} chars): {c['source']}")
                c["text"] = c["text"][:MAX_CHUNK_CHARS] + " ... [truncated]"
        chunks.extend(file_chunks)
    return chunks


def embed_chunks(chunks: list[dict]) -> list[list[float]]:
    vectors: list[list[float]] = []
    total = len(chunks)
    for start in range(0, total, EMBED_BATCH):
        batch = chunks[start : start + EMBED_BATCH]
        texts = [c["text"] for c in batch]
        vecs = embed_documents(texts)
        vectors.extend(vecs)
        print(f"  embedded {min(start + EMBED_BATCH, total)}/{total} chunks")
    return vectors


def main() -> int:
    t0 = time.time()
    print("Rift RAG ingest")
    print("  scanning corpus...")
    files = iter_corpus_files()
    print(f"  found {len(files)} candidate files")

    chunks = build_chunks(files)
    print(f"  produced {len(chunks)} non-empty chunks")
    if not chunks:
        print("  nothing to index — aborting.")
        return 1

    print("  embedding via Ollama (nomic-embed-text)...")
    try:
        vectors = embed_chunks(chunks)
    except OllamaError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 2

    store.save(chunks, vectors)
    dt = time.time() - t0
    print(f"  wrote {store.VECTORS_PATH}")
    print(f"  wrote {store.CHUNKS_PATH}")
    print(f"Done: {len(chunks)} chunks indexed in {dt:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
