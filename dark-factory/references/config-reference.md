# dark-factory config.json — schema v0 (M1)

Lives at `<control_root>/config.json`. JSON, not YAML: runtime is stdlib-only
(divergence from the spec sketch, which shows YAML; a YAML front end can come later).

| Field | Type | M1 rule |
|---|---|---|
| `config_version` | str | `"0.1"` |
| `autonomy` | int | `4` (default, absent ok) or `5`. **L5 gate (spec 2.2):** `autonomy: 5` (lights-off) requires `assurance: "hardened"`, else `ConfigError`. Any other value (including bool or string) is rejected. |
| `checkpoint` | str | `"pause"` \| `"auto"`. Default: `pause` at autonomy 4, `auto` at autonomy 5 (using the resolved/defaulted autonomy value, so an absent `autonomy` still defaults checkpoint to `pause`). `pause` stops the loop after each non-converging iteration (exit 10) for human review via `resume`. |
| `assurance` | str | `cooperative` (unqualified, honor-system), `standard` (probe-verified OS read-denial → qualified), or `hardened` (builder runs in a Docker container, control root never mounted → qualified). `standard` requires a platform sandbox backend + a passing startup denial probe; `hardened` additionally requires a running Docker daemon + a passing container probe. Either fails closed (or downgrades with `--allow-downgrade`: hardened → standard if the OS sandbox is still healthy, else → cooperative). Other tier names are rejected. |
| `hardened.image` | str | optional, default `python:3.12-alpine` (`df_container.DEFAULT_IMAGE`). Non-empty; must not look like a CLI flag. Real cross-model builders need a user-supplied image with the CLI + credentials baked in. |
| `hardened.network` | str | optional, default `"none"`. `"none"` \| `"bridge"`. `"bridge"` is unrestricted egress (needed for real builder CLIs' API calls) and is recorded on the manifest so a reader can see the residual channel; provider-only egress enforcement is deferred (M12). |
| `hardened.memory` | str | optional, default `"2g"`. Must match `^[0-9]+[bkmg]$` (lowercase only, e.g. `"2g"`, `"512m"`). Passed to `docker run --memory`. |
| `hardened.pids` | int | optional, default `256`. Must be `>= 16` (bool rejected). Passed to `docker run --pids-limit`. |
| — | | A `hardened` block present while `assurance != "hardened"` is a `ConfigError` ("hardened block requires assurance: hardened"). At any tier, `cfg["_container"]` is always populated (with defaults when the block is absent); only consulted by the supervisor at effective tier `hardened`. |
| — | | **hardened ⇒ signed audit (spec 7):** at `assurance: "hardened"`, `audit.signing` defaults to `true` (absent means "on"); an explicit `audit.signing: false` is a `ConfigError` ("hardened requires signed audit manifests"). |
| `feedback` | str | must be `"ids"` in M1 |
| `max_iterations` | int | 1..20 |
| `workspace_root` | str | absolute path; must be disjoint from the control root |
| `roles.builder.adapter` | str | path to a protocol-0.1 adapter executable. Shipped: `scripts/adapters/{claude,codex,gemini}`. The chosen model's CLI must be installed (no silent fallback — an absent CLI aborts the run). |
| `roles.builder.timeout_s` | int | optional, default 600 |
| `budget.billing` | str | `"api"` \| `"subscription"`. Default `"subscription"` (alert-only — dollars can't be metered). `"api"` enforces `budget.max_usd` via the per-call estimate. |
| `budget.max_usd` | float | optional; must be > 0. Dollar cap; enforced only when `billing: "api"` and `budget.per_call_usd` is also set. If `max_usd` is set without `per_call_usd`, the cap is recorded but downgraded to alert-only (no authoritative usage estimate). |
| `budget.per_call_usd` | float | optional; must be > 0. Estimated dollar cost reserved per builder call (admission control), not metered usage. |
| `budget.max_calls` | int | optional; must be >= 1. Exact hard cap on builder calls, enforced under any billing mode. |
| `budget.alert_at` | float | default `0.85`. Fraction of the cap (0, 1] at which a `BUDGET_ALERT` fires (warn, continue) before the 100% pause. |
| `budget.notification_sink` | str | optional, default `""`. Recorded destination for L5 budget alerts; delivery is stubbed (journaled + printed) in M8. |
| `knowledge_base.kind` | str | optional: `none` (default) \| `wiki` \| `open-brain`. Enables optional grounding + opt-in run-summary write-back. |
| `knowledge_base.path` | str | required existing directory when kind=`wiki`; the run summary is appended to `<path>/dark-factory-runs.md`. |
| `knowledge_base.write_back` | bool | default false. When true + kind=`wiki`, the supervisor appends a barrier-safe run summary (outcome/tier/qualified/iterations/failing behavior IDs — no scenario text). `open-brain` write-back is done by the Claude session (MCP), not the supervisor. |
| `twins.enabled` | bool | default false. When true, the supervisor launches the twin services defined in `<control_root>/twins/*.json` around build/verify and exposes each as `DF_TWIN_<NAME>`. Requires ≥1 twin def. |
| `twins.startup_timeout_s` | int | 1..120, default 20. Max seconds to wait for a twin to write its endpoint file before the run aborts (exit 2). |
| `audit.signing` | bool | default false. When true the supervisor HMAC-signs each run manifest with a supervisor-only key, writing a `manifest.hmac` sidecar; `verify-manifest` then checks the signature (tamper-evident while the key stays secret). |
| `audit.key_path` | str | default `~/.dark-factory/audit.key` (mode 0600). MUST be outside the control root and workspace. Never written into any run artifact. |
| `security_gates.enabled` | bool | default false. When true, mandatory security gates run on the converged artifact (independent of scenario pass) after the final exam and before CONVERGED; a failure listed in `fail_on` rejects the run. |
| `security_gates.secret_scan` | bool | default true when enabled. Runs `df_security.secret_scan` (private keys, cloud/Slack tokens, generic secret assignments) over the workspace. |
| `security_gates.dangerous_scan` | bool | default true when enabled. Runs `df_security.dangerous_scan` (`eval`/`exec`, `os.system`, `shell=True`, `pickle.loads`, unsafe `yaml.load`) over `*.py` files. |
| `security_gates.sbom` | bool | default true when enabled. Runs `df_security.sbom` (declared-dependency inventory); always `pass` — informational unless referenced in `fail_on`, where it's still a no-op (no failure condition). |
| `security_gates.external` | list | default `[]`. Each `{"name": str, "cmd": [str, ...]}` is a pluggable external gate (e.g. `bandit`, `semgrep`, `trufflehog`). Missing command (`shutil.which` miss) or a spawn error/timeout → `unavailable`, never a silent pass. |
| `security_gates.fail_on` | list[str] | default `["secret_scan", "dangerous_scan"]` when enabled. Gate names that are mandatory; must be built-ins (`secret_scan`,`dangerous_scan`,`sbom`) or a declared `external[].name`, else `ConfigError`. A listed gate that's `fail` (or `unavailable` under `strict_unavailable`) fails the run. |
| `security_gates.strict_unavailable` | bool | default true. When true, a `fail_on` gate that comes back `unavailable` (external tool missing/errored) counts as a failure — fail-closed: a mandatory gate you can't run is not a pass. |
