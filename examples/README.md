# Examples

Illustrative Rift outputs, so you can see what the engine produces without installing models and running it.

## `cases/example-attack-path/`

A complete `/attack-paths` artifact for the generic target `coding-agent/default-permissions`:

- **[`attack-path.generated.md`](cases/example-attack-path/attack-path.generated.md)** — the human-readable report. This is what `attack_path.py` now writes for every run: a rendered view with each route's attack chain, its in-scope argument, **how the report could get closed and how to reshape the test to dodge that**, and the test plan with a stop line.
- **[`attack-path.generated.json`](cases/example-attack-path/attack-path.generated.json)** — the canonical machine artifact. Schema-valid against [`core/schemas/attack_path.schema.json`](../core/schemas/attack_path.schema.json); the Markdown is rendered deterministically from this, never from a second model pass.
- **`run-meta.json`** — provenance (mode, authorization ref, grounded records, schema-valid flag, artifact hash).

This example is hand-authored to show the output shape; it is not from a live engagement (`authorization_ref: INTERNAL-RESEARCH`). Its two routes are grounded in real shipped corpus records — `ap:AP-0030` and `ap:AP-0034`.
