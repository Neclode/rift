# rift/new_record.py
"""Create a schema-valid attack-path record without hand-filling all 22 fields.

You supply only the substantive fields (title, description, failure class,
target surface, and a few enum picks). This fills the boilerplate with safe,
fail-closed defaults (`sensitivity=local_only`, `verified=false`,
`schema_version`, `ingest_date`, ...), validates the result against
`core/schemas/attack_path_record.schema.json`, and writes it under
`rift-corpus/attack-paths/ingested/`.

Two ways to run:

    # interactive — prompts for each field, enums shown as numbered menus
    python rift/new_record.py

    # one-shot with flags (run --help to see every enum choice)
    python rift/new_record.py --id repo-readme-injection \
        --title "Repo orientation file backdoors a generated config" \
        --description "<at least 100 characters describing the boundary collapse>" \
        --failure-class workspace-content-to-instruction-injection \
        --target-surface coding-agent/default-permissions \
        --trust-boundary workspace-content-to-instruction \
        --kill-chain-stage consequential-action --severity high \
        --consequential-action config-write --harm-layer durable-side-effect
"""
from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import re
import sys

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

_ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMA_PATH = _ROOT / "core" / "schemas" / "attack_path_record.schema.json"
DEST_DIR = _ROOT / "rift-corpus" / "attack-paths" / "ingested"

# Enum choices, mirrored from the schema (first entry is the interactive default).
ENUMS = {
    "trust_boundary": [
        "workspace-content-to-instruction", "tool-output-laundering",
        "implicit-user-intent-substitution", "connector-context-confabulation",
        "chat-rag-confabulation", "other",
    ],
    "kill_chain_stage": [
        "injection", "trust-boundary-collapse", "verification-bypass",
        "consequential-action", "durable-persistence", "exfil",
    ],
    "severity": ["high", "critical", "medium", "low", "informational"],
    "consequential_action": [
        "config-write", "file-write", "registry-repoint", "network-call",
        "lockfile-mutation", "tool-call-chain", "memory-write", "display-only",
    ],
    "harm_layer": ["durable-side-effect", "in-session-only", "display-layer"],
    "source": [
        "manual", "nvd", "exploitdb", "hackerone", "attck", "atlas",
        "crescendo", "jailbreakbench", "goat", "agentdojo", "injecagent", "harmbench",
    ],
    "sensitivity": ["local_only", "sanitized_ok", "public"],
    "domain": ["ai_native", "traditional_vuln", "methodology", "taxonomy"],
}

# Boilerplate the author rarely needs to think about — safe, fail-closed defaults.
DEFAULTS = {
    "schema_version": "1.0",
    "human_in_loop": False,
    "user_actions_in_attack_chain": [],
    "precondition_weight": "light",
    "permission_mode": "default",
    "scope_tag": "unknown",
    "verified": False,        # never "verified" until a human reviews it
    "use_for_rag": True,
    "auto_classified": False,
}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60] or "record"


def _ask(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    return input(f"{label}{suffix}: ").strip() or default


def _pick(label: str, options: list[str]) -> str:
    print(f"\n{label}:")
    for i, opt in enumerate(options, 1):
        print(f"  {i}) {opt}")
    while True:
        raw = input(f"  choose 1-{len(options)} [1]: ").strip() or "1"
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1]
        if raw in options:
            return raw
        print("  (invalid — pick a number from the list)")


def gather(args: argparse.Namespace, interactive: bool) -> dict:
    def need(value, name, prompt, enum=None):
        if value:
            return value
        if interactive:
            return _pick(prompt, enum) if enum else _ask(prompt)
        hint = f" (one of {enum})" if enum else ""
        sys.exit(f"error: --{name.replace('_', '-')} is required{hint}")

    title = need(args.title, "title", "Title (one line)")

    description = args.description
    if interactive and not description:
        description = _ask("Description (>= 100 chars)")
    if not description or len(description) < 100:
        sys.exit("error: --description is required and must be >= 100 characters")

    failure_class = args.failure_class
    if not failure_class:
        if interactive:
            raw = _ask("Failure class(es), comma-separated",
                       "workspace-content-to-instruction-injection")
            failure_class = [x.strip() for x in raw.split(",") if x.strip()]
        else:
            sys.exit("error: --failure-class is required (at least one)")

    target_surface = need(args.target_surface, "target_surface",
                          "Target surface  <product-class>/<mode>")
    if "/" not in target_surface:
        sys.exit("error: target_surface must look like <product-class>/<mode>, "
                 "e.g. coding-agent/default-permissions (never a real host or company)")

    source = args.source or "manual"
    record = {
        **DEFAULTS,
        "source": source,
        "record_id": f"{source}:{args.id or _slug(title)}",
        "ingest_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "title": title,
        "description": description,
        "failure_class": failure_class,
        "target_surface": target_surface,
        "trust_boundary": need(args.trust_boundary, "trust_boundary",
                               "Trust boundary", ENUMS["trust_boundary"]),
        "kill_chain_stage": need(args.kill_chain_stage, "kill_chain_stage",
                                 "Kill-chain stage", ENUMS["kill_chain_stage"]),
        "severity": need(args.severity, "severity", "Severity", ENUMS["severity"]),
        "consequential_action": need(args.consequential_action, "consequential_action",
                                     "Consequential action", ENUMS["consequential_action"]),
        "harm_layer": need(args.harm_layer, "harm_layer", "Harm layer", ENUMS["harm_layer"]),
        "sensitivity": args.sensitivity or "local_only",
        "domain": args.domain or "ai_native",
    }
    if args.raw_ref:
        record["raw_ref"] = args.raw_ref
    return record


def main() -> int:
    p = argparse.ArgumentParser(
        description="Create a schema-valid attack-path record "
                    "(fills boilerplate, validates, writes).")
    p.add_argument("--id", help="short id; record_id becomes <source>:<id> "
                                 "(default: slug of the title)")
    p.add_argument("--title")
    p.add_argument("--description", help=">= 100 characters")
    p.add_argument("--failure-class", nargs="+", dest="failure_class",
                   help="one or more hypothesis-family slugs")
    p.add_argument("--target-surface", dest="target_surface",
                   help="generic <product-class>/<mode> (never a real host/company)")
    p.add_argument("--trust-boundary", dest="trust_boundary", choices=ENUMS["trust_boundary"])
    p.add_argument("--kill-chain-stage", dest="kill_chain_stage", choices=ENUMS["kill_chain_stage"])
    p.add_argument("--severity", choices=ENUMS["severity"])
    p.add_argument("--consequential-action", dest="consequential_action",
                   choices=ENUMS["consequential_action"])
    p.add_argument("--harm-layer", dest="harm_layer", choices=ENUMS["harm_layer"])
    p.add_argument("--source", choices=ENUMS["source"], default="manual")
    p.add_argument("--sensitivity", choices=ENUMS["sensitivity"], default="local_only")
    p.add_argument("--domain", choices=ENUMS["domain"], default="ai_native")
    p.add_argument("--raw-ref", dest="raw_ref", help="scheme-less source URL or citation")
    p.add_argument("--out", help="output path "
                                 "(default: rift-corpus/attack-paths/ingested/<id>.json)")
    p.add_argument("--print", dest="to_stdout", action="store_true",
                   help="print the record to stdout instead of writing a file")
    args = p.parse_args()

    # Interactive only when attached to a terminal AND no core field was passed.
    interactive = sys.stdin.isatty() and not any(
        [args.title, args.description, args.failure_class, args.target_surface])

    record = gather(args, interactive)

    # Validate before writing — never emit an invalid record.
    if jsonschema is not None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        try:
            jsonschema.validate(record, schema)
        except jsonschema.ValidationError as exc:
            sys.exit(f"error: record failed schema validation:\n  {exc.message}")
    else:
        print("warning: jsonschema not installed — skipping validation", file=sys.stderr)

    text = json.dumps(record, indent=2, ensure_ascii=False)
    if args.to_stdout:
        print(text)
        return 0

    out = pathlib.Path(args.out) if args.out else DEST_DIR / f"{args.id or _slug(record['title'])}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text + "\n", encoding="utf-8")
    print(f"wrote {out}")
    print("sensitivity=local_only — it won't reach a remote model until you review it "
          "and set \"public\". Run `python rift/ingest.py` to index it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
