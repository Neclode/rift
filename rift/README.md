# Rift RAG

Local-first executable retrieval layer over the attack-path corpus
(`rift-corpus/attack-paths/`). Pure **numpy + Python stdlib**;
all embeddings and generation run through **local Ollama** at
`http://localhost:11434`. No cloud APIs by default.

## Requirements

- Python 3.10+
- `numpy` (`pip install -r requirements.txt`)
- [Ollama](https://ollama.com) running locally with these models pulled:
  ```
  ollama pull nomic-embed-text     # 768-dim embeddings
  ollama pull qwen2.5-coder:14b    # grounded generation
  ```

## Build the index

```
python rift/ingest.py
```

Walks `rift-corpus/attack-paths/` recursively, chunks every `*.md` / `*.json`
(skipping empty files and any `raw-local-only` directory), embeds each chunk,
and writes:

- `index/vectors.npy` — float32 `[n_chunks, dim]`, L2-normalized.
- `index/chunks.json` — list aligned by row index to `vectors.npy`.

## Query

```
python query.py "QUESTION" [--k 5] [--domain D] [--doc-type T] \
    [--failure-class F] [--case-id C] [--generate] [--json]
```

- Default: prints ranked retrieval hits (rank, score, doc_type, source, snippet).
- `--generate`: also runs grounded generation with `qwen2.5-coder:14b` and
  prints the answer plus cited sources.
- `--json`: machine-readable output.

Examples:

```
python query.py "trust boundary collapse for a coding agent" --k 5
python query.py "data exfiltration via indirect prompt injection" --k 3
python query.py "RAG poisoning across email assistants" --generate
```

## Programmatic API

`query.py` exposes two importable functions (handy for your own harness):

```python
from query import retrieve, answer

hits = retrieve("indirect prompt injection in a coding agent", k=5,
                filters={"domain": "bounty"})
# -> [{"rank","score","source","doc_type","case_id","text"}, ...]

out = answer("what should I test against a workspace agent?", k=5)
# -> {"answer": str, "sources": [...], "results": [<retrieve output>]}
```

Metadata filters (`domain`, `doc_type`, `failure_class`, `case_id`) are exact-match
and applied **before** similarity scoring, matching the retrieval rule
*filter by domain → task → retrieve → rerank*.

## Layout

```
rift/
  rift_rag/
    embed.py      # Ollama embeddings client (urllib)
    generate.py   # Ollama generation client (urllib)
    chunk.py      # markdown/json chunker + path-based metadata inference
    store.py      # save/load vectors.npy + chunks.json
  ingest.py       # builds the index over the corpus
  query.py        # retrieve + optional generate (CLI + importable API)
  index/          # generated: vectors.npy + chunks.json
```

## Chunk + metadata schema

Each entry in `chunks.json`:

```json
{
  "id": "rift-corpus/attack-paths/ingested/ap-0024.json#0",
  "source": "rift-corpus/attack-paths/ingested/ap-0024.json",
  "text": "...",
  "metadata": {
    "domain": "bounty",
    "doc_type": "case | taxonomy | severity_rubric | report | framework | schema | system_prompt | reviewer_distillation | transcript",
    "failure_class": "",
    "case_id": "",
    "status": "draft | reported | accepted | rejected | duplicate | empty",
    "sensitivity": "local_only | sanitized_ok | public"
  }
}
```

`doc_type`, `domain`, `case_id`, and `failure_class` are inferred from the file
path; `sensitivity` defaults to `local_only`.
