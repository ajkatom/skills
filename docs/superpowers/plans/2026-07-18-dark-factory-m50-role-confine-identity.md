# M50 — role identity honesty + structural-confinement identity binding (DF-R3-04, DF-R3-05)

Codex re-audit #06 identity findings. Both are "a guarantee is claimed on
`realpath`/basename that the mechanism doesn't actually establish." Fix =
honest relabel + real identity binding where it IS enforceable. No core-
qualification defect; these are overclaim + a renamed-executable gap.

## DF-R3-04 (Medium) — "different model" is not enforced; it's "distinct adapter path"
`df_config` enforces `realpath(author) != realpath(builder)` (and critic ≠
both), and docs/manifest call this a fail-closed "different-MODEL" guarantee.
But two wrapper copies, or two adapters pointed at the same provider/model
(esp. the env-parameterized `api_*` adapters), satisfy the path check. We
already documented the api-adapter caveat in M42 — this makes the correction
systematic.

Fix (honesty + optional real binding):
- **Relabel the claim** everywhere it says "different/distinct MODEL" for the
  path check → "distinct adapter **identity** (resolved path, plus content
  digest when `adapter_sha256` is pinned)". Files: `df_config.py` comments on
  the author/critic checks, `references/config-reference.md` (roles.author/
  critic rows), `references/authoring.md` + `references/scenario-adequacy.md`
  + `references/role-adapters.md`, the manifest `authored_by`/`critic` field
  docs, SKILL.md. Keep the fail-closed `realpath` inequality (it's still a
  real, useful check — it stops the trivial same-adapter case).
- **Make digest the recommended real binding:** the existing optional
  `roles.<role>.adapter_sha256` (M47 #7) is what actually pins content;
  document that pinning it on builder + author + critic is how you get a
  content-level distinctness guarantee (two identical wrappers then collide on
  digest — surface that as a NEW check: if two roles pin the SAME
  `adapter_sha256`, that's a ConfigError unless `allow_same_model_ack`,
  because identical content = same model).
- **Optional sealed asserted identity (lightweight):** accept an OPTIONAL
  `roles.<role>.model_identity` (free-form string, e.g. "anthropic/claude-…")
  that is sealed VERBATIM into the manifest role field and, when present on
  two roles that must differ, must differ (else ConfigError). Label it in
  docs + the manifest as **operator-ASSERTED, not system-verified** (we cannot
  prove which model a black-box API key reaches). This gives auditors/policy a
  comparable identity without a false "verified" claim. Absent ⇒ unchanged.

## DF-R3-05 (Medium) — structural confinement trusts adapter basename
`df_confine.PROFILES["api_anthropic"|"api_openai"]` grant `supported: True`
+ `structural: True` keyed by BASENAME. An unrelated executable renamed to
`api_anthropic` receives the "no agentic tool/MCP surface" structural claim
without being the shipped adapter. (Hardened/enterprise container isolation
still protects the holdout — this is about the narrower structural claim's
integrity, not a holdout leak.)

Fix — bind the structural profile to a TRUSTED adapter IDENTITY, fail closed
on mismatch:
- `profile_for(cli, adapter_path=None, expected_sha256=None)` (extend the
  signature; keep back-compat default) — for the structural profiles
  (`api_anthropic`/`api_openai`) the `supported: True` claim now REQUIRES the
  resolved `adapter_path` to be a trusted identity:
  1. it resolves (realpath) to the skill's OWN shipped adapter file
     `<skill_dir>/scripts/adapters/<name>` (trusted-installation-path — the
     audit explicitly accepts this alternative), OR
  2. a configured `expected_sha256` (the role's `adapter_sha256`) matches the
     actual file's content hash.
  Otherwise → return an UNSUPPORTED profile (`supported: False`, reason
  "structural confinement claim requires the shipped adapter identity;
  <path> is neither the shipped adapter nor a digest-pinned match") — so a
  renamed impostor is treated as unconfined/unsupported, fail-closed, not
  granted the claim.
- Thread the builder's resolved adapter path + `adapter_sha256` from the
  supervisor call site into `profile_for`/`is_supported`. `claude` (live
  tool-denial probe) is unaffected — its support is probe-based, not
  structural. Unknown CLIs unchanged (already `supported: False`).
- Update `references/builder-confinement.md` to state the structural claim is
  now bound to the shipped-adapter identity (path or pinned digest), not the
  basename.

## Tests
- DF-R3-04: two roles pinning the same `adapter_sha256` → ConfigError (unless
  ack); `model_identity` present on author==builder value → ConfigError; it is
  sealed verbatim into the manifest; the relabeled docs assert nothing the
  code doesn't do (spot-check). The existing realpath-inequality tests stay.
- DF-R3-05: `profile_for("api_anthropic", <shipped adapter path>)` →
  supported; `profile_for("api_anthropic", <impostor copy at another path,
  no matching sha256>)` → NOT supported (fail closed); with a matching
  `expected_sha256` → supported; supervisor wiring passes the real path so a
  real hardened api_anthropic run is unaffected.
- Deterministic (no live/paid). Full suite green (baseline current main
  ~1873 passed + docker skips).

## Rules
Fail-closed; real `raise`/return-unsupported, never bare `assert`. SUPERSET —
the realpath inequality + M47 digest pin stay; this ADDS the same-digest
check, the optional asserted identity, and the confinement identity binding,
and CORRECTS overclaiming docs. Back-compat: absent `model_identity` and a
normally-installed shipped adapter behave identically (the shipped adapter
resolves to the trusted path, so its structural claim still holds). Match
house comment style. Opus review (identity/fail-closed correctness).
