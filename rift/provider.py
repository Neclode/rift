# rift/provider.py
"""
Pluggable generation provider for Rift (per-role router).

EMBEDDINGS: unchanged — rift_rag.embed talks to Ollama directly. This module
owns GENERATION only. Callers MUST pass a payload already returned by
egress_gate.send_gate; the raw clients are private so the gate cannot be bypassed.

ROLES: 'default', 'reason', 'structure'. Each resolves its own base_url + key +
model from env, falling back to the default (local Ollama). Exception: the
structure MODEL defaults to a dedicated local model (qwen2.5-coder:14b), decoupled
from RIFT_MODEL, because structure quality is load-bearing — see the constant
below. base_url/key for structure still fall back to local. To run the Pass-1 reasoner
on a remote provider, set RIFT_REASON_BASE_URL / RIFT_REASON_KEY_FILE /
RIFT_REASON_MODEL; leave RIFT_STRUCTURE_* unset to keep structuring local.

SAFETY: a key file is read into the client's Authorization header only — it is
never placed in a payload. For remote roles, leave RIFT_ALLOW_LOCAL_AUTOCONFIRM
UNSET so the egress gate prompts before each hop (the gate does not special-case
IS_LOCAL).
"""
from __future__ import annotations
import os as _os
from openai import OpenAI as _OpenAI

RIFT_LOCAL_URL = "http://localhost:11434/v1"
RIFT_BASE_URL  = _os.environ.get("RIFT_BASE_URL", RIFT_LOCAL_URL)
RIFT_KEY_FILE  = _os.environ.get("RIFT_KEY_FILE", "")
RIFT_MODEL     = _os.environ.get("RIFT_MODEL", "qwen2.5:3b")

# Per-role overrides; each falls back to the default (local) config.
RIFT_REASON_BASE_URL    = _os.environ.get("RIFT_REASON_BASE_URL", RIFT_BASE_URL)
RIFT_REASON_KEY_FILE    = _os.environ.get("RIFT_REASON_KEY_FILE", RIFT_KEY_FILE)
RIFT_REASON_MODEL       = _os.environ.get("RIFT_REASON_MODEL", RIFT_MODEL)
RIFT_STRUCTURE_BASE_URL = _os.environ.get("RIFT_STRUCTURE_BASE_URL", RIFT_BASE_URL)
RIFT_STRUCTURE_KEY_FILE = _os.environ.get("RIFT_STRUCTURE_KEY_FILE", RIFT_KEY_FILE)
# Structure quality is LOAD-BEARING, so this default is DECOUPLED from RIFT_MODEL:
# Measured: the 3b structurer collapses routes to near-duplicates
# (intra-route Jaccard 0.74-0.89), fabricates corpus citations, and emits invalid JSON
# ~25% of runs. The local qwen2.5-coder:14b structurer clears distinctness (0.17-0.45),
# honors the citation menu, and is schema-stable. Still local; override via env.
RIFT_STRUCTURE_DEFAULT_MODEL = "qwen2.5-coder:14b"
RIFT_STRUCTURE_MODEL    = _os.environ.get("RIFT_STRUCTURE_MODEL", RIFT_STRUCTURE_DEFAULT_MODEL)

# IS_LOCAL is informational only — NOT a security gate. Do not use it to bypass
# egress confirmation; use RIFT_ALLOW_LOCAL_AUTOCONFIRM (and leave it unset for remote).
IS_LOCAL = any(x in RIFT_BASE_URL for x in ("11434", "localhost", "127.0.0.1"))

_ROLE_CONFIG = {
    "default":   (RIFT_BASE_URL,           RIFT_KEY_FILE,           RIFT_MODEL),
    "reason":    (RIFT_REASON_BASE_URL,    RIFT_REASON_KEY_FILE,    RIFT_REASON_MODEL),
    "structure": (RIFT_STRUCTURE_BASE_URL, RIFT_STRUCTURE_KEY_FILE, RIFT_STRUCTURE_MODEL),
}

class ProviderError(RuntimeError):
    pass

def _read_key(key_file: str) -> str:
    if key_file:
        # BOM-safe: Windows key files often carry UTF-8 BOM.
        key = open(key_file, encoding="utf-8-sig").read().strip()
        if not key:
            raise RuntimeError(f"key file {key_file!r} is empty")
        return key
    return "ollama"  # Ollama ignores the key; placeholder keeps the client happy.

_clients: dict = {}  # role -> OpenAI client, built lazily (no remote connection at import)

def _client_for_role(role: str):
    if role not in _clients:
        base, key_file, _ = _ROLE_CONFIG.get(role, _ROLE_CONFIG["default"])
        _clients[role] = _OpenAI(base_url=base, api_key=_read_key(key_file))
    return _clients[role]

def role_is_local(role: str = "default") -> bool:
    base = _ROLE_CONFIG.get(role, _ROLE_CONFIG["default"])[0]
    return any(x in base for x in ("11434", "localhost", "127.0.0.1"))

def rift_generate(sanitized_payload: dict, *, model: str | None = None,
                  role: str = "default", temperature: float | None = None) -> str:
    """
    Generation entry point. Accepts ONLY a payload returned by send_gate.
    role selects which (base_url, key, model) to use. Returns completion text.

    `temperature` defaults to None — i.e. the model's own default is used and no
    temperature is sent. Output quality is driven by the model you choose, not by
    a forced sampling temperature; modern reasoning models (gpt-5.x, o-series)
    only accept their default and reject an explicit one. Schema validation +
    the repair retry are what keep structured output valid. Pass an explicit
    value only to constrain a model that supports it.
    """
    messages = sanitized_payload.get("messages")
    if not messages:
        raise ProviderError("sanitized_payload missing 'messages' — was send_gate called?")
    base, _kf, role_model = _ROLE_CONFIG.get(role, _ROLE_CONFIG["default"])
    mdl = model or role_model
    client = _client_for_role(role)
    kwargs: dict = {"model": mdl, "messages": messages}
    if temperature is not None:
        kwargs["temperature"] = temperature
    try:
        resp = client.chat.completions.create(**kwargs)
    except Exception as exc:
        # If an explicit temperature was passed and the model rejects it, drop
        # it and retry at the model's default rather than failing.
        if "temperature" in kwargs and "temperature" in str(exc).lower():
            kwargs.pop("temperature")
            try:
                resp = client.chat.completions.create(**kwargs)
            except Exception as exc2:
                raise ProviderError(f"generation failed (role={role} {mdl} @ {base}): {exc2}") from exc2
        else:
            raise ProviderError(f"generation failed (role={role} {mdl} @ {base}): {exc}") from exc
    return resp.choices[0].message.content or ""

def provider_info(role: str = "default") -> dict:
    """Diagnostic. Safe to log — no secrets."""
    base, key_file, mdl = _ROLE_CONFIG.get(role, _ROLE_CONFIG["default"])
    return {"role": role, "base_url": base, "model": mdl,
            "is_local": role_is_local(role), "keyed": bool(key_file)}
