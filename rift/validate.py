# rift/validate.py
from __future__ import annotations
import json, pathlib
import jsonschema
from jsonschema import Draft202012Validator

_SCHEMAS = pathlib.Path(__file__).resolve().parents[1] / "core" / "schemas"
SCHEMA_PATH = _SCHEMAS / "entryway.schema.json"

class EntrywayValidationError(Exception):
    def __init__(self, message, json_path=None):
        super().__init__(message)
        self.json_path = json_path

def load_schema(path: pathlib.Path = SCHEMA_PATH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))

def validate_entryway(obj: dict, schema: dict | None = None) -> None:
    """
    Validate obj against the real entryway.schema.json.
    Raises EntrywayValidationError with a readable JSON path on failure.
    additionalProperties:false catches hallucinated fields.
    minItems:1 catches empty entryways.
    """
    schema = schema or load_schema()
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(obj), key=lambda e: list(e.absolute_path))
    if errors:
        e = errors[0]  # report the first (most structural) error
        path = "/".join(str(p) for p in e.absolute_path) or "<root>"
        raise EntrywayValidationError(f"{e.message} (at {path})", json_path=path)


ATTACK_PATH_SCHEMA_PATH = _SCHEMAS / "attack_path.schema.json"
ATTACK_PATH_RECORD_SCHEMA_PATH = _SCHEMAS / "attack_path_record.schema.json"


class AttackPathValidationError(Exception):
    def __init__(self, message, json_path=None):
        super().__init__(message)
        self.json_path = json_path


def validate_attack_path(obj: dict, schema: dict | None = None) -> None:
    """
    Validate obj against attack_path.schema.json. Mirrors validate_entryway —
    the validator core is schema-agnostic. Raises AttackPathValidationError.
    """
    schema = schema or load_schema(ATTACK_PATH_SCHEMA_PATH)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(obj), key=lambda e: list(e.absolute_path))
    if errors:
        e = errors[0]
        path = "/".join(str(p) for p in e.absolute_path) or "<root>"
        raise AttackPathValidationError(f"{e.message} (at {path})", json_path=path)


def validate_attack_path_record(obj: dict, schema: dict | None = None) -> None:
    """
    Validate a corpus record dict against attack_path_record.schema.json.
    Same exception class as validate_attack_path — callers use AttackPathValidationError.
    """
    schema = schema or load_schema(ATTACK_PATH_RECORD_SCHEMA_PATH)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(obj), key=lambda e: list(e.absolute_path))
    if errors:
        e = errors[0]
        path = "/".join(str(p) for p in e.absolute_path) or "<root>"
        raise AttackPathValidationError(f"{e.message} (at {path})", json_path=path)
