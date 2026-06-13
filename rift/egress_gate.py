# rift/egress_gate.py
from __future__ import annotations
import json, re, hashlib, datetime, os, pathlib
from enum import Enum

# OUTSIDE any indexed directory — egress log must not be ingested
EGRESS_LOG = pathlib.Path(__file__).resolve().parents[1] / "logs" / "egress-log.jsonl"
EGRESS_DEBUG = os.environ.get("RIFT_EGRESS_DEBUG", "").strip() == "1"
ALLOW_LOCAL_AUTOCONFIRM = os.environ.get("RIFT_ALLOW_LOCAL_AUTOCONFIRM", "").strip() == "1"

class Sensitivity(str, Enum):
    LOCAL_ONLY   = "local_only"
    SANITIZED_OK = "sanitized_ok"
    PUBLIC       = "public"

_BLOCKED_KEYS = {
    "case_id", "vendor", "product_surface",
    "raw_findings", "exact_repro_steps", "repro_chain",
    "private_transcript", "exact_prompt_chain",
    "secret", "api_key", "token", "password", "credential",
    "target_host", "target_url",
}

_BLOCKED_SUBSTRINGS = [
    "http://", "https://", "Bearer ",
    "/srv/", "/var/", "/etc/", "/root/",
    "C:\\Users\\", "c:\\users\\", "D:\\Rift\\",
]
_BLOCKED_REGEXES = [
    re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b"),                 # IPv4
    # API secret keys. `\bsk-` (word boundary + literal "sk-") is the discriminator:
    # real keys begin a token with "sk-", whereas prose false-positives ("task-force",
    # "risk-based", "disk-cache") only contain "sk-" MID-word, where \b does not match.
    # That \b is why this no longer needs the over-broad bare "sk-"/"sk-or-" substrings.
    # The tail class includes -/_ so it spans the internal hyphens of modern families
    # (sk-proj-…, sk-svcacct-…, sk-or-v1-…); a bare [A-Za-z0-9] class truncated those
    # at the first hyphen (<20 chars) and let them through. ≥20 chars after "sk-" keeps
    # short non-key tokens out. Match is case-sensitive (real keys are lowercase "sk-").
    re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9_-]{19,}\b"),
]

class EgressBlocked(Exception):
    pass

def _walk_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _walk_strings(v)

def _walk_keys(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _walk_keys(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _walk_keys(v)

def classify_with_provenance(payload: dict,
                              source_chunks: list[dict] | None = None) -> Sensitivity:
    """
    Authoritative classification. Returns LOCAL_ONLY if:
      - any source chunk is not sensitivity=="public"  (provenance layer)
      - any blocked key at any depth                   (structural layer)
      - any blocked substring/regex in any value       (content layer)
      - explicit sensitivity flag on payload
    SANITIZED_OK only when all three layers pass.
    """
    # Provenance layer — authoritative, checked first
    if source_chunks is not None:
        for chunk in source_chunks:
            if chunk.get("sensitivity", "local_only") != "public":
                return Sensitivity.LOCAL_ONLY
    # Structural layer
    if str(payload.get("sensitivity", "")).lower() == "local_only":
        return Sensitivity.LOCAL_ONLY
    for k in _walk_keys(payload):
        if k in _BLOCKED_KEYS:
            return Sensitivity.LOCAL_ONLY
    # Content layer
    for s in _walk_strings(payload):
        low = s.lower()
        if any(b.lower() in low for b in _BLOCKED_SUBSTRINGS):
            return Sensitivity.LOCAL_ONLY
        if any(rx.search(s) for rx in _BLOCKED_REGEXES):
            return Sensitivity.LOCAL_ONLY
    return Sensitivity(payload.get("sensitivity", "sanitized_ok"))

def sanitize(payload: dict) -> dict:
    """Recursively drop blocked keys. classify_with_provenance must be called
    first; this only strips structural metadata, does NOT fix content issues."""
    def _strip(o):
        if isinstance(o, dict):
            return {k: _strip(v) for k, v in o.items() if k not in _BLOCKED_KEYS}
        if isinstance(o, list):
            return [_strip(v) for v in o]
        return o
    return _strip(payload)

def preview(payload: dict) -> str:
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    return text if len(text) <= 1500 else text[:1500] + "\n... [truncated — full payload in log]"

def _log(provider, model, payload_or_summary, confirmed: bool,
         sensitivity: str) -> None:
    EGRESS_LOG.parent.mkdir(parents=True, exist_ok=True)
    full_payload = json.dumps(
        payload_or_summary, sort_keys=True, ensure_ascii=False)
    rec: dict = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "provider": provider, "model": model,
        "sensitivity": sensitivity, "confirmed": confirmed,
        "payload_hash": hashlib.sha256(full_payload.encode()).hexdigest(),
        "payload_keys": sorted(set(_walk_keys(payload_or_summary))),
    }
    if EGRESS_DEBUG:
        rec["payload"] = payload_or_summary   # opt-in full dump
    with EGRESS_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

def send_gate(provider: str, model: str, payload: dict,
              source_chunks: list[dict] | None = None,
              confirm_fn=None) -> dict:
    """
    THE egress boundary. Steps:
      classify_with_provenance → block → sanitize → preview → confirm → log → return.
    NOTHING is sent if classification returns LOCAL_ONLY.
    Human confirm is ALWAYS required unless RIFT_ALLOW_LOCAL_AUTOCONFIRM=1 is set
    AND caller explicitly passes auto_confirm=True (local dev convenience only).
    Repair retries MUST call send_gate again — rift_generate accepts only the
    return value of this function.
    """
    sens = classify_with_provenance(payload, source_chunks)
    if sens == Sensitivity.LOCAL_ONLY:
        _log(provider, model,
             {"keys": sorted(set(_walk_keys(payload))),
              "source_count": len(source_chunks or []),
              "blocked_source_count": sum(
                  1 for c in (source_chunks or [])
                  if c.get("sensitivity", "local_only") != "public")},
             confirmed=False, sensitivity=sens.value)
        raise EgressBlocked(
            f"Payload classified LOCAL_ONLY. "
            f"Sources: {len(source_chunks or [])} total, "
            f"{sum(1 for c in (source_chunks or []) if c.get('sensitivity','local_only')!='public')} non-public. "
            f"Top-level keys: {list(payload.keys())}")

    clean = sanitize(payload)
    pv = preview(clean)
    print("=" * 60)
    print(f"EGRESS GATE — provider={provider}  model={model}  sensitivity={sens.value}")
    print("These are the EXACT bytes that will leave this machine:")
    print(pv)
    print("=" * 60)

    if ALLOW_LOCAL_AUTOCONFIRM and confirm_fn is None:
        # Dev convenience: only fires when env is explicitly set
        confirmed = True
        print("[RIFT_ALLOW_LOCAL_AUTOCONFIRM=1] auto-confirmed.")
    elif confirm_fn is not None:
        confirmed = bool(confirm_fn(pv))
    else:
        confirmed = input("Send this payload? [y/N] ").strip().lower() == "y"

    _log(provider, model, clean, confirmed=confirmed, sensitivity=sens.value)
    if not confirmed:
        raise EgressBlocked("User declined egress confirmation.")
    return clean
