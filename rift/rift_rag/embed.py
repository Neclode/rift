"""Ollama embeddings client — stdlib only (urllib).

Uses POST /api/embed with the nomic-embed-text model. The endpoint accepts
either a single string or a list of strings in `input`, and always returns
`{"embeddings": [[...], ...]}` (a list of vectors, one per input).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

OLLAMA_URL = "http://localhost:11434"
EMBED_MODEL = "nomic-embed-text"

# nomic-embed-text returns 768-dim vectors.
EMBED_DIM = 768

# nomic-embed-text is an ASYMMETRIC retrieval model: it is trained with task
# instruction prefixes and Ollama does NOT add them automatically. Indexed
# passages must use `search_document:` and queries `search_query:`. Omitting
# these collapses the query/passage asymmetry and badly degrades retrieval.
DOC_PREFIX = "search_document: "
QUERY_PREFIX = "search_query: "

# Embedding requests are cheap individually but the model can be slow to warm
# up on first call; give it generous headroom.
_TIMEOUT = 300


class OllamaError(RuntimeError):
    """Raised when Ollama returns an error or is unreachable."""


def _post(path: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{OLLAMA_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise OllamaError(
            f"Ollama HTTP {exc.code} on {path}: {body}"
        ) from exc
    except urllib.error.URLError as exc:
        raise OllamaError(
            f"Cannot reach Ollama at {OLLAMA_URL}{path}: {exc.reason}. "
            f"Is `ollama serve` running?"
        ) from exc


def embed_many(
    texts: list[str], model: str = EMBED_MODEL, prefix: str = ""
) -> list[list[float]]:
    """Embed a batch of texts in one request. Returns one vector per text.

    `prefix` is prepended to every text — pass DOC_PREFIX when indexing passages
    and QUERY_PREFIX when embedding a query (nomic-embed-text requires this).
    """
    if not texts:
        return []
    payload_texts = [f"{prefix}{t}" for t in texts] if prefix else texts
    resp = _post("/api/embed", {"model": model, "input": payload_texts})
    vectors = resp.get("embeddings")
    if not vectors or len(vectors) != len(texts):
        raise OllamaError(
            f"Unexpected embed response: expected {len(texts)} vectors, "
            f"got {0 if not vectors else len(vectors)}. Raw keys: {list(resp)}"
        )
    return vectors


def embed_one(text: str, model: str = EMBED_MODEL, prefix: str = "") -> list[float]:
    """Embed a single string. Returns one vector."""
    return embed_many([text], model=model, prefix=prefix)[0]


def embed_documents(texts: list[str], model: str = EMBED_MODEL) -> list[list[float]]:
    """Embed passages for indexing (applies the required `search_document:` prefix)."""
    return embed_many(texts, model=model, prefix=DOC_PREFIX)


def embed_query(text: str, model: str = EMBED_MODEL) -> list[float]:
    """Embed a search query (applies the required `search_query:` prefix)."""
    return embed_one(text, model=model, prefix=QUERY_PREFIX)
