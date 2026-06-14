"""Tests for render_md.render_attack_path_md — the deterministic Markdown renderer.

Pure-stdlib renderer; no Ollama, no network. Verifies the rendered report
surfaces the operational fields a researcher needs, that actor labels carry the
HITL-close signal, and that the committed showcase example stays both
schema-valid and renderable (so it can't silently rot).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

RIFT_ROOT = Path(__file__).resolve().parents[2]  # rift/
REPO_ROOT = RIFT_ROOT.parent
sys.path.insert(0, str(RIFT_ROOT))

import render_md  # noqa: E402
from validate import validate_attack_path  # noqa: E402

EXAMPLE = REPO_ROOT / "examples" / "cases" / "example-attack-path" / "attack-path.generated.json"


def _minimal_obj():
    return {
        "target": "coding-agent/default-permissions",
        "program": "other",
        "authorization_ref": "INTERNAL-RESEARCH",
        "scope_snapshot_date": "2026-05-01",
        "routes": [
            {
                "name": "demo-route",
                "trust_boundary": "workspace-content-to-instruction",
                "kill_chain_stage": "consequential-action",
                "attack_steps": [
                    {"action": "untrusted file lands", "actor": "attacker-content", "expected_outcome": "in workspace"},
                    {"action": "user runs setup", "actor": "user", "normal_workflow_action": True, "expected_outcome": "agent reads it"},
                    {"action": "agent writes config", "actor": "agent", "expected_outcome": "durable change"},
                ],
                "in_scope_argument": {
                    "orchestration": "model", "harm_layer": "durable-side-effect",
                    "precondition_weight": "light", "permission_mode": "default",
                    "confidence": "moderate", "confidence_basis": "grounds in AP-0030",
                    "rationale": "a normal user would not intend it",
                },
                "out_of_scope_risk": [
                    {"flag": "expected-behavior-exit", "why": "looks like normal behavior", "mitigation": "trace to untrusted content"},
                ],
                "safe_observation_goal": "observe only",
                "evidence_to_collect": ["the config diff"],
                "grounded_in": ["ap:AP-0030"],
            }
        ],
    }


def test_renders_core_sections():
    md = render_md.render_attack_path_md(_minimal_obj())
    assert "# Attack-Path Map — coding-agent/default-permissions" in md
    assert "## Route 1 — demo-route" in md
    assert "**[attacker-content]**" in md
    assert "**In-scope argument**" in md
    assert "How this could get closed" in md
    assert "expected-behavior-exit" in md
    assert "*Dodge:* trace to untrusted content" in md
    assert "`ap:AP-0030`" in md


def test_actor_labels_reflect_hitl_signal():
    obj = _minimal_obj()
    # normal_workflow_action False is a human-in-the-loop close risk — must be visible.
    obj["routes"][0]["attack_steps"][1]["normal_workflow_action"] = False
    assert "**[user · NON-normal]**" in render_md.render_attack_path_md(obj)
    obj["routes"][0]["attack_steps"][1]["normal_workflow_action"] = True
    assert "**[user · normal]**" in render_md.render_attack_path_md(obj)


def test_empty_grounded_in_flags_weak():
    obj = _minimal_obj()
    obj["routes"][0]["grounded_in"] = []
    assert "floored to weak" in render_md.render_attack_path_md(obj)


def test_optional_fields_render_when_present():
    obj = _minimal_obj()
    obj["routes"][0]["novelty_note"] = "non-obvious angle"
    obj["routes"][0]["in_scope_argument"]["defending_control_target"] = "a vendor that defends"
    md = render_md.render_attack_path_md(obj)
    assert "Why it's non-obvious:** non-obvious angle" in md
    assert "Defended-competitor lead:_ a vendor that defends" in md


def test_committed_example_is_valid_and_renders():
    obj = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    validate_attack_path(obj)  # raises if the committed showcase artifact rots
    md = render_md.render_attack_path_md(obj)
    assert "## Route 1 —" in md and "## Route 2 —" in md
    assert "## Guardrails" in md
