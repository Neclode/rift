#!/usr/bin/env python3
"""Pre-commit guard: every corpus record committed to this PUBLIC repo must be
`sensitivity: "public"`.

This is the git-layer counterpart to the egress gate. The egress gate stops a
non-public record from reaching a remote *model*; this stops one from reaching
the public *repo* by an accidental `git add`. A `local_only` / `sanitized_ok` /
untagged record under rift-corpus/attack-paths/ blocks the commit.

Enable once:   git config core.hooksPath hooks
Run manually:  python scripts/check_corpus_public.py
"""
from __future__ import annotations

import json
import subprocess
import sys

CORPUS_PREFIX = "rift-corpus/attack-paths/"


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True,
                          check=True).stdout


def staged_record_files() -> list[str]:
    out = _git("diff", "--cached", "--name-only", "--diff-filter=ACM")
    return [p for p in out.splitlines()
            if p.startswith(CORPUS_PREFIX) and p.endswith(".json")]


def violations(files: list[str]) -> list[tuple[str, str]]:
    bad: list[tuple[str, str]] = []
    for path in files:
        try:
            blob = _git("show", f":{path}")          # the *staged* content
            record = json.loads(blob)
        except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
            bad.append((path, f"unreadable / invalid JSON ({type(exc).__name__})"))
            continue
        sensitivity = record.get("sensitivity")
        if sensitivity != "public":
            bad.append((path, f'sensitivity={sensitivity!r} (must be "public")'))
    return bad


def main() -> int:
    files = staged_record_files()
    if not files:
        return 0
    bad = violations(files)
    if not bad:
        return 0
    print('BLOCKED: this is a PUBLIC repo — every corpus record must be '
          'sensitivity:"public".', file=sys.stderr)
    print("These staged records are not public:", file=sys.stderr)
    for path, why in bad:
        print(f"  - {path}: {why}", file=sys.stderr)
    print("\nKeep private/local_only findings in your private repo. "
          "(Override only if you're sure: git commit --no-verify.)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
