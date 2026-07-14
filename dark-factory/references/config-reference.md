# dark-factory config.json — schema v0 (M1)

Lives at `<control_root>/config.json`. JSON, not YAML: runtime is stdlib-only
(divergence from the spec sketch, which shows YAML; a YAML front end can come later).

| Field | Type | M1 rule |
|---|---|---|
| `config_version` | str | `"0.1"` |
| `autonomy` | int | informational in M1 (checkpointing lands in M2) |
| `checkpoint` | str | `"pause"` \| `"auto"`. Default: `pause` at autonomy 4, `auto` at autonomy 5. `pause` stops the loop after each non-converging iteration (exit 10) for human review via `resume`. |
| `assurance` | str | `cooperative` (unqualified, honor-system) or `standard` (probe-verified OS read-denial → qualified). `standard` requires a platform sandbox backend + a passing startup denial probe, else the run fails closed (or downgrades with `--allow-downgrade`). Other tiers rejected. |
| `feedback` | str | must be `"ids"` in M1 |
| `max_iterations` | int | 1..20 |
| `workspace_root` | str | absolute path; must be disjoint from the control root |
| `roles.builder.adapter` | str | path to an executable speaking adapter protocol 0.1 |
| `roles.builder.timeout_s` | int | optional, default 600 |
| `budget.billing` | str | `"subscription"` (alert-only) in M1; metered admission lands later |
