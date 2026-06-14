# rift/render_md.py
"""Deterministic Markdown renderer for a validated attack-path artifact.

Takes the schema-valid object produced by attack_path.py and renders a
human-readable report. NO model call — pure stdlib, so the rendering can
never drift from, hallucinate over, or over-claim beyond the validated JSON.
The JSON stays the canonical machine artifact; this is a faithful *view* of it.

Optimized for the researcher reading their own local case: each route leads
with the operational summary, then surfaces the two things that decide whether
the route is worth a day of work — the in-scope argument, and how the report
could get closed (with how to reshape the test to dodge that close).
"""
from __future__ import annotations


def _actor_label(step: dict) -> str:
    actor = step.get("actor", "?")
    if actor == "user":
        # normal_workflow_action True == routine action; False == HITL-close risk.
        normal = step.get("normal_workflow_action")
        if normal is True:
            return "user · normal"
        if normal is False:
            return "user · NON-normal"
    return actor


def _render_route(route: dict, n: int) -> list[str]:
    out: list[str] = []
    name = route.get("name", f"route-{n}")
    out.append(f"## Route {n} — {name}")
    out.append("")

    arg = route.get("in_scope_argument", {})
    meta = " · ".join(filter(None, [
        f"`{route.get('trust_boundary', '?')}`",
        f"`{route.get('kill_chain_stage', '?')}`",
        f"confidence **{arg.get('confidence', '?')}**",
    ]))
    out.append(meta)
    out.append("")

    if route.get("novelty_note"):
        out.append(f"**Why it's non-obvious:** {route['novelty_note']}")
        out.append("")

    # Attack chain — the pathway, told as a who-does-what actor sequence.
    out.append("**Attack chain**")
    out.append("")
    for i, step in enumerate(route.get("attack_steps", []), 1):
        tech = step.get("tool_or_technique")
        tech_str = f" _(via {tech})_" if tech else ""
        out.append(
            f"{i}. **[{_actor_label(step)}]** {step.get('action', '')}{tech_str} "
            f"→ {step.get('expected_outcome', '')}"
        )
    out.append("")

    # In-scope argument — the "is it submittable" case.
    tags = " · ".join(filter(None, [
        arg.get("orchestration"), arg.get("harm_layer"),
        f"{arg.get('precondition_weight', '?')} preconditions",
        f"{arg.get('permission_mode', '?')} permissions",
    ]))
    out.append(f"**In-scope argument** ({tags})")
    out.append("")
    if arg.get("rationale"):
        out.append(arg["rationale"])
        out.append("")
    if arg.get("defending_control_target"):
        out.append(f"_Defended-competitor lead:_ {arg['defending_control_target']}")
        out.append("")
    if arg.get("confidence_basis"):
        out.append(f"_Confidence: {arg.get('confidence', '?')} — {arg['confidence_basis']}_")
        out.append("")

    # Out-of-scope risk — the differentiator: how it gets closed + how to dodge.
    risks = route.get("out_of_scope_risk", [])
    out.append("**⚠ How this could get closed — and how to dodge it**")
    out.append("")
    for r in risks:
        out.append(f"- **{r.get('flag', '?')}** — {r.get('why', '')}")
        if r.get("mitigation"):
            out.append(f"  ↳ *Dodge:* {r['mitigation']}")
    out.append("")

    # Test plan — what to do, where to stop.
    out.append("**Test plan**")
    out.append("")
    if route.get("safe_observation_goal"):
        out.append(f"- *Safe observation goal (stop line):* {route['safe_observation_goal']}")
    evidence = route.get("evidence_to_collect", [])
    if evidence:
        out.append(f"- *Evidence to collect:* {'; '.join(evidence)}")
    if route.get("severity_upgrade_if"):
        out.append(f"- *Upgrade severity if:* {'; '.join(route['severity_upgrade_if'])}")
    if route.get("dead_end_if"):
        out.append(f"- *Dead end if:* {'; '.join(route['dead_end_if'])}")
    out.append("")

    grounded = route.get("grounded_in", [])
    grounded_str = ", ".join(f"`{g}`" for g in grounded) if grounded else "_none — confidence floored to weak_"
    out.append(f"**Grounded in:** {grounded_str}")
    out.append("")
    out.append("---")
    out.append("")
    return out


def render_attack_path_md(obj: dict) -> str:
    """Render a validated attack-path artifact to a human-readable Markdown report."""
    routes = obj.get("routes", [])
    lines: list[str] = []

    lines.append(f"# Attack-Path Map — {obj.get('target', '?')}")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Target | `{obj.get('target', '?')}` |")
    if obj.get("scope_statement"):
        lines.append(f"| Scope | {obj['scope_statement']} |")
    lines.append(f"| Program | `{obj.get('program', '?')}` |")
    lines.append(f"| Authorization | `{obj.get('authorization_ref', '?')}` |")
    lines.append(f"| Scope snapshot | {obj.get('scope_snapshot_date', '?')} |")
    if obj.get("primary_trust_boundary"):
        lines.append(f"| Primary trust boundary | `{obj['primary_trust_boundary']}` |")
    lines.append(f"| Routes | {len(routes)} |")
    lines.append("")
    lines.append("> Routes are **hypotheses to test, not verdicts.** Each one names how it could "
                 "get closed and how to reshape the test to dodge that.")
    lines.append("")
    lines.append("---")
    lines.append("")

    for n, route in enumerate(routes, 1):
        lines.extend(_render_route(route, n))

    do_not_attempt = obj.get("do_not_attempt", [])
    do_not_overclaim = obj.get("do_not_overclaim", [])
    if do_not_attempt or do_not_overclaim:
        lines.append("## Guardrails")
        lines.append("")
        for item in do_not_attempt:
            lines.append(f"- **Do not attempt:** {item}")
        for item in do_not_overclaim:
            lines.append(f"- **Do not overclaim:** {item}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


if __name__ == "__main__":
    import json
    import sys
    src = json.loads(sys.stdin.read()) if len(sys.argv) < 2 else json.loads(
        open(sys.argv[1], encoding="utf-8").read())
    sys.stdout.write(render_attack_path_md(src))
