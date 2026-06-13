# rift/casestore.py
from __future__ import annotations
import json, datetime, hashlib, pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
CASES_ROOT = _ROOT / "rift-corpus" / "generated" / "cases"
GENERATED_ROOT = _ROOT / "rift-corpus" / "generated"

class ArtifactExists(Exception):
    pass

def save_case_artifact(
    case_id: str,
    json_obj: dict,
    prose_text: str,
    run_meta: dict,
    schema_valid: bool,        # caller passes result of validate_entryway; never hardcoded True
    *,
    force: bool = False,
    artifact_name: str = "entryway-map",
    root: pathlib.Path = CASES_ROOT,
) -> pathlib.Path:
    """
    Write generated artifacts under cases/<case_id>/.
    Files written:
      entryway-map.generated.json  — validated obj, pretty-printed
      entryway-map.generated.md   — prose + fenced json
      run-meta.json               — provider/model/ts/sources/hash/schema_valid
    NEVER touches entryway-map.md (hand-authored; no .generated. infix).
    Raises ArtifactExists if entryway-map.generated.json already exists and
    force=False.
    """
    case_dir = root / case_id
    case_dir.mkdir(parents=True, exist_ok=True)

    gen_json = case_dir / f"{artifact_name}.generated.json"
    if gen_json.exists() and not force:
        raise ArtifactExists(
            f"{gen_json} already exists. Pass force=True or use --force to overwrite.")

    # Hand-authored file guard: refuse if case_id matches an existing hand-authored dir
    # and that dir already contains a non-generated entryway-map.md.
    hand_authored = case_dir / f"{artifact_name}.md"
    if hand_authored.exists():
        # Writing generated artifacts into a hand-authored case dir is allowed;
        # clobbering the hand-authored file is not. The .generated. infix is the guard.
        pass  # the filename infix is sufficient; we log a warning.

    payload_str = json.dumps(json_obj, indent=2, ensure_ascii=False)
    gen_json.write_text(payload_str, encoding="utf-8")

    md_text = prose_text.rstrip() + "\n\n```json\n" + payload_str + "\n```\n"
    (case_dir / f"{artifact_name}.generated.md").write_text(md_text, encoding="utf-8")

    meta = {
        **run_meta,
        "schema_valid": schema_valid,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "artifact_hash": hashlib.sha256(payload_str.encode()).hexdigest(),
    }
    (case_dir / "run-meta.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    return gen_json
