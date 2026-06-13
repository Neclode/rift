# rift/entryways.py
"""
/entryways orchestrator. The ONLY entry point to the hybrid pipeline,
and the proven pattern that attack_path.py follows.

Security model:
  The egress gate's STRUCTURAL (blocked keys) and CONTENT (URL/path/IP/key
  patterns) layers are armed on every send_gate call. The PROVENANCE layer
  (public-only source chunks) is intentionally DORMANT in this path: entryways does
  not surface per-chunk sensitivity to the gate, so it runs LOCAL-ONLY (qwen via
  localhost) and must not be pointed at a remote model. The provenance gate is armed
  in attack_path.py, where retrieval is filtered to public-tagged chunks before the
  gate and the corpus-sensitivity model is load-bearing, and
  the operator's public-tagging decision applies. DO NOT point entryways at a
  remote frontier until the provenance layer is re-armed (pass source_chunks of
  public-only chunks).

  The real case_id is substituted LOCALLY after generation — it never appears in
  any egress payload (and `case_id` is a blocked key, stripped by sanitize()).
"""
from __future__ import annotations
import json, pathlib, sys

# Ensure rift/ is on path when run as __main__ or imported as a module.
sys.path.insert(0, str(pathlib.Path(__file__).parent))

from egress_gate import send_gate, EgressBlocked
from provider import rift_generate, RIFT_MODEL, IS_LOCAL, ProviderError, provider_info
from validate import validate_entryway, EntrywayValidationError
from casestore import save_case_artifact, ArtifactExists

# Shared JSON extractor.
import re as _re

def _extract_json_block(text: str):
    blocks = _re.findall(r"```json\s*(.*?)```", text, _re.DOTALL)
    if blocks:
        return blocks[-1].strip()
    start, end = text.find("{"), text.rfind("}")
    return text[start:end + 1] if start != -1 and end > start else None


_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SYSTEM_PROMPTS_DIR = _REPO_ROOT / "core" / "system-prompts"
# Optional structural few-shot examples; absent in this distribution (the
# pipeline degrades gracefully to no example — see _few_shot_example).
CASES_DIR = _REPO_ROOT / "examples" / "cases"


def _read_system_prompts() -> str:
    core = (SYSTEM_PROMPTS_DIR / "rift-core.md").read_text(encoding="utf-8")
    mapper = (SYSTEM_PROMPTS_DIR / "entryway-mapper.md").read_text(encoding="utf-8")
    return core.strip() + "\n\n---\n\n" + mapper.strip()


def _few_shot_example() -> str:
    """
    Structural few-shot: an entryway-map JSON example, wrapped in HTML comments so
    the ```json extractor never grabs it (the example carries no fenced block).
    Verified gate-clean (no URL/path/IP). Gives the local model a strong schema
    template to pattern-match, which makes a schema-valid first pass likely.
    Absent in this distribution -> returns "" and the pipeline runs without it.
    """
    example_path = CASES_DIR / "example-entryway-map" / "entryway-map.md"
    if not example_path.exists():
        return ""
    block = _extract_json_block(example_path.read_text(encoding="utf-8"))
    if not block:
        return ""
    return (
        "<!-- STRUCTURAL EXAMPLE — match this SHAPE only; do NOT copy its values -->\n"
        + block
        + "\n<!-- END EXAMPLE -->"
    )


def _retrieve_context(query_text: str, root_failure: str, k: int) -> list[dict]:
    """
    Plain retrieval. Filters by failure_class, which also excludes the
    empty-failure_class JSON-schema chunks — the only two gate-dirty chunks in
    the index — so the retrieved context is gate-clean. An empty result is fine:
    retrieval augments, it does not gate. No provenance abort here (see module
    docstring). Returns the result list (possibly empty).
    """
    try:
        from query import retrieve
    except ImportError:
        return []
    results = retrieve(question=query_text, k=k, filters={"failure_class": root_failure})
    return results or []


def _build_payload(finding: str, root_failure: str, surface_category: str,
                   chunks: list[dict], system_prompt: str, few_shot: str) -> dict:
    if chunks:
        context_blocks = "\n\n".join(
            f"[Source: {c.get('source', '?')} | score={c.get('score', 0):.3f}]\n{c['text']}"
            for c in chunks
        )
    else:
        context_blocks = "(no matching corpus context retrieved)"
    user_content = (
        f"Root failure family: {root_failure}\n"
        f"Surface category: {surface_category}\n\n"
        f"Researcher finding:\n{finding}\n\n"
        f"Grounded context from the Rift corpus:\n{context_blocks}\n\n"
        f"{few_shot}\n\n"
        "Produce an entryway map conforming to core/schemas/entryway.schema.json. "
        "Set \"case_id\" to exactly the string \"CASE_ID_PLACEHOLDER\". "
        "End your response with the section-5 schema-compliant JSON as a SINGLE "
        "fenced ```json block containing ONLY the entryway-map JSON object. "
        "Do not emit any other fenced ```json blocks."
    )
    return {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]
    }


def _parse_and_id(raw_text: str, case_id: str):
    """Extract the model's JSON, substitute the real case_id LOCALLY (never egressed)."""
    raw_json = _extract_json_block(raw_text)
    if raw_json is None:
        return None, "model returned no fenced ```json block"
    try:
        obj = json.loads(raw_json)
    except json.JSONDecodeError as e:
        return None, f"JSON parse failed: {e}"
    if not isinstance(obj, dict):
        return None, "extracted JSON is not an object"
    obj["case_id"] = case_id
    return obj, None


def map_entryways(finding: str, root_failure: str, surface: str, case_id: str,
                  *, k: int = 5, model: str | None = None, force: bool = False) -> dict:
    """
    Full /entryways pipeline. Returns a result dict:
      {"status": "ok"|"ask"|"blocked"|"error", ...}
    On ok: includes case_path, validated, json_obj, sources, run_meta.
    """
    # [0] Validate inputs
    missing = [n for n, v in [("finding", finding), ("root_failure", root_failure),
                              ("surface", surface), ("case_id", case_id)]
               if not (v or "").strip()]
    if missing:
        return {"status": "ask",
                "question": f"Missing required input(s): {', '.join(missing)}."}

    provider_name = "ollama" if IS_LOCAL else "openrouter"
    mdl = model or RIFT_MODEL

    # [1] Retrieve (plain; augmentation only, gate-clean by failure_class filter)
    chunks = _retrieve_context(f"{finding} {root_failure}", root_failure, k)

    # [2] Build payload (case_id -> placeholder; never egressed)
    payload = _build_payload(finding, root_failure, surface, chunks,
                             _read_system_prompts(), _few_shot_example())

    # [3+4] Egress gate (source_chunks=None -> provenance layer dormant; structural
    #       + content DLP still run) -> generate
    try:
        sanitized = send_gate(provider_name, mdl, payload, source_chunks=None)
    except EgressBlocked as e:
        return {"status": "blocked", "reason": str(e)}
    try:
        raw_text = rift_generate(sanitized, model=mdl)
    except ProviderError as e:
        return {"status": "error", "reason": str(e)}

    # [5] Extract + substitute real case_id locally
    obj, err = _parse_and_id(raw_text, case_id)
    if err:
        return {"status": "error", "reason": err}

    # [6] Validate with ONE repair retry (re-gated through send_gate)
    try:
        validate_entryway(obj)
    except EntrywayValidationError as e1:
        repair_payload = {"messages": sanitized["messages"] + [
            {"role": "assistant", "content": raw_text},
            {"role": "user", "content":
                f"The JSON failed schema validation: {e1}\n"
                "Return ONLY a corrected fenced ```json block, no prose."},
        ]}
        try:
            repair_sanitized = send_gate(provider_name, mdl, repair_payload, source_chunks=None)
            repair_text = rift_generate(repair_sanitized, model=mdl)
        except (EgressBlocked, ProviderError) as e2:
            return {"status": "error", "reason": f"repair retry failed: {e2}"}
        obj, err = _parse_and_id(repair_text, case_id)
        if err:
            return {"status": "error", "reason": f"repair retry: {err}"}
        try:
            validate_entryway(obj)
        except EntrywayValidationError as e3:
            return {"status": "error",
                    "reason": f"schema validation failed after retry: {e3}"}
        raw_text = repair_text  # prose artifact should reflect the corrected output

    # [7] Save artifact (provider_info FIRST so explicit model=mdl is not overwritten
    #     by provider_info()'s RIFT_MODEL default)
    run_meta = {**provider_info(), "provider": provider_name, "model": mdl,
                "sources": [c.get("source") for c in chunks]}
    try:
        artifact_path = save_case_artifact(case_id, obj, raw_text, run_meta,
                                           schema_valid=True, force=force)
    except ArtifactExists as e:
        return {"status": "error", "reason": str(e)}

    return {"status": "ok", "case_path": str(artifact_path), "validated": True,
            "json_obj": obj, "sources": run_meta["sources"], "run_meta": run_meta}


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="RIFT /entryways pipeline")
    p.add_argument("--case-id", required=True)
    p.add_argument("--root-failure", required=True)
    p.add_argument("--surface", required=True)
    p.add_argument("--finding", required=True)
    p.add_argument("--k", type=int, default=5)
    p.add_argument("--model", default=None)
    p.add_argument("--force", action="store_true")
    args = p.parse_args()

    result = map_entryways(
        finding=args.finding,
        root_failure=args.root_failure,
        surface=args.surface,
        case_id=args.case_id,
        k=args.k,
        model=args.model,
        force=args.force,
    )
    # Print result WITHOUT the (potentially large) json_obj duplicated inline noise.
    summary = {k2: v for k2, v in result.items() if k2 != "json_obj"}
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    sys.exit(0 if result.get("status") == "ok" else 1)
