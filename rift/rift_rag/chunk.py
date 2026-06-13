"""Markdown/JSON chunker + path-based metadata inference.

Chunking strategy (pinned to spec):
  - Markdown: split on headings (#/##/###) into sections. If a section exceeds
    ~1200 chars, further split on paragraph boundaries into ~800-char chunks
    with ~100-char overlap.
  - JSON: embed the whole file as one chunk, pretty-printed.
  - Drop empty chunks; skip empty files and any `raw-local-only` directory.

Metadata is inferred from the file's path relative to the repo root. The schema is
pinned exactly because the eval harness reads `source` and `metadata`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

# ---- chunking knobs --------------------------------------------------------
MAX_SECTION_CHARS = 1200
TARGET_CHUNK_CHARS = 800
OVERLAP_CHARS = 100

# Repo root all `source` paths are made relative to.
CORPUS_ROOT = Path(__file__).resolve().parents[2]

_HEADING_RE = re.compile(r"^(#{1,3})\s+.*$", re.MULTILINE)


def _is_heading_only(text: str) -> bool:
    """True if every non-blank line is a markdown heading (no body content).

    Such fragments (e.g. a `## Section` whose only children are subheadings, or
    a heading split off from its body) carry no retrievable content and pollute
    the index, so we never emit them as standalone chunks.
    """
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return bool(lines) and all(ln.startswith("#") for ln in lines)
_STATUS_RE = re.compile(
    r"\b(draft|reported|submitted|accepted|rejected|duplicate)\b", re.IGNORECASE
)


# ---- metadata inference ----------------------------------------------------
def _rel_source(path: Path) -> str:
    """Path relative to the repo root with forward slashes."""
    try:
        rel = path.resolve().relative_to(CORPUS_ROOT)
    except ValueError:
        rel = path
    return rel.as_posix()


def _infer_domain(source: str) -> str:
    top = source.split("/", 1)[0]
    if top == "core":
        return "core"
    if top == "rift-corpus":
        return "bounty"
    return top


def _infer_doc_type(source: str) -> str:
    s = source.lower()
    # Order matters: more specific path segments win.
    if "core/schemas/" in s:
        return "schema"
    if "core/system-prompts/" in s:
        return "system_prompt"
    if "reviewer-distillation" in s:
        return "reviewer_distillation"
    if "normalized-transcripts/" in s:
        return "transcript"
    if "hypothesis-families/" in s:
        return "taxonomy"
    if "severity-rubrics/" in s:
        return "severity_rubric"
    if "report-templates/" in s:
        return "report"
    if "attack-paths/" in s:
        return "attack_path"
    if "cve-records/" in s:
        return "cve_record"
    if "disclosed-reports/" in s:
        return "disclosed_report"
    if "exploit-db/" in s:
        return "exploit_db"
    if "techniques/" in s:
        return "technique"
    if "frameworks/" in s:
        return "framework"
    if "cases/" in s:
        return "case"
    return "framework"


_CASE_RE = re.compile(r"cases/(S\d{3,})", re.IGNORECASE)


def _infer_case_id(source: str) -> str:
    m = _CASE_RE.search(source)
    return m.group(1).upper() if m else ""


def _infer_failure_class(source: str, doc_type: str) -> str:
    """Use the hypothesis-family card's slug (its filename) as failure_class."""
    if doc_type == "taxonomy":
        return Path(source).stem
    return ""


def _infer_status(text: str) -> str:
    """Best-effort status from the document body; default 'empty'."""
    # JSON records carry an explicit "status" field — prefer it.
    if _looks_like_json(text):
        m = re.search(r'"status"\s*:\s*"([a-z_]+)"', text)
        if m:
            val = m.group(1).lower()
            if val == "submitted":
                return "reported"
            if val in {"draft", "reported", "accepted", "rejected", "duplicate"}:
                return val
    # Markdown: look for an explicit "## Status" line with a concrete value.
    m = re.search(r"##\s*Status[^\n]*\n+([^\n]+)", text, re.IGNORECASE)
    if m:
        line = m.group(1)
        # Ignore template placeholders like `<draft | submitted | ...>`.
        if "<" not in line:
            sm = _STATUS_RE.search(line)
            if sm:
                val = sm.group(1).lower()
                return "reported" if val == "submitted" else val
    return "empty"


def _looks_like_json(text: str) -> bool:
    stripped = text.lstrip()
    return stripped.startswith("{") or stripped.startswith("[")


def _try_parse_json(text: str) -> dict:
    """Parse a JSON record to a dict for metadata lifting. Non-dict / invalid -> {}."""
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {}
    return obj if isinstance(obj, dict) else {}


def infer_metadata(path: Path, text: str) -> dict:
    source = _rel_source(path)
    doc_type = _infer_doc_type(source)
    meta = {
        "domain": _infer_domain(source),
        "doc_type": doc_type,
        "failure_class": _infer_failure_class(source, doc_type),
        "case_id": _infer_case_id(source),
        "status": _infer_status(text),
        "sensitivity": "local_only",
    }
    # Attack-path records carry first-class decision signals in the JSON body.
    # Lift them WITHOUT regex-on-serialized-JSON, and only for attack_path docs so
    # all other files keep identical metadata keys/values.
    if doc_type == "attack_path":
        rec = _try_parse_json(text)
        if rec:
            fc = rec.get("failure_class")
            if isinstance(fc, list) and fc:
                meta["failure_class"] = fc[0]
            meta["target_surface"] = rec.get("target_surface", "")
            meta["scope_tag"] = rec.get("scope_tag", "")
            meta["kill_chain_stage"] = rec.get("kill_chain_stage", "")
            meta["record_id"] = rec.get("record_id", "")
            meta["sensitivity"] = rec.get("sensitivity", "local_only")
            meta["auto_classified"] = rec.get("auto_classified", False)
    return meta


# ---- chunk splitting -------------------------------------------------------
def _split_sections(md: str) -> list[str]:
    """Split markdown into heading-led sections, preserving any preamble."""
    matches = list(_HEADING_RE.finditer(md))
    if not matches:
        return [md] if md.strip() else []

    sections: list[str] = []
    # Preamble before the first heading.
    first = matches[0].start()
    if md[:first].strip():
        sections.append(md[:first])

    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(md)
        block = md[start:end]
        if block.strip():
            sections.append(block)
    return sections


def _split_long_section(section: str) -> list[str]:
    """Paragraph-pack a long section into ~TARGET_CHUNK_CHARS pieces w/ overlap."""
    paras = [p for p in re.split(r"\n\s*\n", section) if p.strip()]
    chunks: list[str] = []
    buf = ""
    for para in paras:
        candidate = f"{buf}\n\n{para}".strip() if buf else para
        # Keep accumulating while under target, when there's nothing buffered
        # yet, or when the buffer is only a heading (never orphan a heading).
        if len(candidate) <= TARGET_CHUNK_CHARS or not buf or _is_heading_only(buf):
            buf = candidate
        else:
            chunks.append(buf)
            # Carry ~OVERLAP_CHARS of tail context into the next chunk.
            tail = buf[-OVERLAP_CHARS:]
            buf = f"{tail}\n\n{para}".strip()
    if buf.strip():
        chunks.append(buf)
    return chunks


def chunk_markdown(text: str) -> list[str]:
    out: list[str] = []
    for section in _split_sections(text):
        if len(section) > MAX_SECTION_CHARS:
            out.extend(_split_long_section(section))
        elif section.strip():
            out.append(section)
    # Drop heading-only fragments: they hold no content and dilute retrieval.
    return [c.strip() for c in out if c.strip() and not _is_heading_only(c)]


def chunk_json(text: str) -> list[str]:
    """Whole JSON file as one pretty-printed chunk (falls back to raw text)."""
    try:
        obj = json.loads(text)
        pretty = json.dumps(obj, indent=2, ensure_ascii=False)
    except (json.JSONDecodeError, ValueError):
        pretty = text
    return [pretty.strip()] if pretty.strip() else []


def chunk_file(path: Path, text: str) -> list[dict]:
    """Return a list of chunk dicts (id/source/text/metadata) for one file."""
    if not text.strip():
        return []

    metadata = infer_metadata(path, text)
    source = _rel_source(path)

    if path.suffix.lower() == ".json":
        pieces = chunk_json(text)
    else:
        pieces = chunk_markdown(text)

    chunks: list[dict] = []
    for i, piece in enumerate(pieces):
        chunks.append(
            {
                "id": f"{source}#{i}",
                "source": source,
                "text": piece,
                "metadata": dict(metadata),
            }
        )
    return chunks
