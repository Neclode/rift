"""Guarded public-tagger for Rift attack-path seed records.

Operates on the record FILE (the source of truth). Setting sensitivity="public"
on the file then re-running ingest.py propagates the tag into the RAG index.

Guards:
  - auto_classified:true  -> REFUSE (auto-classified records cannot reach public)
  - verified:false        -> REFUSE (unverified records cannot reach public)

Idempotent: tagging an already-public record is a no-op success.

CLI:
    python tag_chunk.py <path-to-record.json>

Exit 0 on success or idempotent no-op, non-zero on refusal.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def tag_public(record_path: str | Path) -> None:
    """Load a record JSON, guard, set sensitivity='public', write back.

    Raises ValueError with a descriptive message on any refusal condition.
    """
    path = Path(record_path)
    if not path.exists():
        raise FileNotFoundError(f"Record file not found: {path}")

    text = path.read_text(encoding="utf-8")
    try:
        record = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Cannot parse JSON at {path}: {exc}") from exc

    if not isinstance(record, dict):
        raise ValueError(f"Record must be a JSON object, got {type(record).__name__}")

    # Guard 1: auto_classified records cannot reach public.
    if record.get("auto_classified", False) is True:
        raise ValueError(
            f"REFUSED: record {path.name} has auto_classified=true. "
            "Auto-classified records cannot be tagged public — human review required first."
        )

    # Guard 2: unverified records cannot reach public.
    if record.get("verified", False) is not True:
        raise ValueError(
            f"REFUSED: record {path.name} has verified=false (or missing). "
            "Only human-verified records can be tagged public."
        )

    # Idempotent: already public is a no-op success.
    if record.get("sensitivity") == "public":
        print(f"[tag_chunk] {path.name}: already sensitivity=public — no-op.")
        return

    old_sensitivity = record.get("sensitivity", "(unset)")
    record["sensitivity"] = "public"

    path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    print(
        f"[tag_chunk] {path.name}: sensitivity changed {old_sensitivity!r} -> 'public'. "
        f"Re-run ingest.py to propagate to the RAG index."
    )


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("Usage: python tag_chunk.py <path-to-record.json>", file=sys.stderr)
        return 2

    record_path = args[0]
    try:
        tag_public(record_path)
        return 0
    except (ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
