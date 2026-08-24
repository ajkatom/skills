# M52 — DF-R4-01 (skill metadata blocker) + DF-R4-02 (confinement fail-open at dispatch)

R4 re-audit. The two highest-priority findings: a packaging blocker that can
stop the skill loading at all, and a required security control that is
fail-OPEN at builder dispatch.

## DF-R4-01 (Release blocker) — invalid SKILL.md frontmatter
Verified: `SKILL.md` `description:` is an UNQUOTED YAML plain scalar of 1186
chars containing `Tiers: ` — the `: ` mid-scalar makes it invalid YAML
(a parser reads it as a mapping value and errors), and it exceeds the
skill-creator validator's 1024-char limit. The skill may fail to load.

Fix:
- Rewrite the `description:` to a VALID YAML scalar ≤ 1024 chars. Use a
  double-quoted scalar (escape internal `"`), OR restructure so no `: `
  appears at top level — simplest is a quoted scalar. It must still carry the
  real trigger surface (dark-factory / hidden tests / holdout scenarios /
  build-without-seeing-tests) + the four tiers + that it's for building a
  task/feature dark-factory-style. Trim to fit 1024 while keeping the triggers
  a user would type. VERIFY: the frontmatter parses (a YAML parse in the test
  or a scratch check) AND len ≤ 1024.
- Add a REGRESSION TEST `tests/test_skill_metadata.py` that reads `SKILL.md`,
  extracts the frontmatter, asserts it parses as a YAML mapping (stdlib-only:
  if PyYAML absent, do a minimal `name:`/`description:` line-parse that at
  least asserts no unquoted `: ` breaks the description — but prefer a real
  YAML parse guarded by an importorskip so CI with PyYAML enforces it), and
  asserts `len(description) <= 1024` and `name` present. This locks the
  regression so the description can't silently regrow past the limit again.
- Also trim `SKILL.md` below the 500-line authoring guidance if cheap without
  losing content (503 now — move any overflow into an existing reference doc);
  NON-blocking, do only if clean.

## DF-R4-02 (High) — required structural confinement is fail-open at dispatch
Verified at `supervisor.py:5375-5390`: `invoke_adapter(...)` SPAWNS the builder
FIRST, and the run only refuses (`CONFINEMENT_REFUSED`) if the adapter itself
returns `status:"error"` with `"confinement unsupported"` in the detail. An
arbitrary executable named `api_anthropic` (a structural profile) that ignores
the `confine` arg and returns success runs UNCONFINED while `required:true`.
M50 made `df_confine.profile_for` identity-aware and recorded the impostor as
`probe:"unsupported"` in the MANIFEST, but never used that as a pre-dispatch
GATE.

Fix — pre-dispatch identity-aware refusal (fresh run AND resume):
- BEFORE the first `invoke_adapter` builder call, when `cfg["_confine"]`
  is present, compute the identity-aware support:
  `df_confine.profile_for(cli, resolved_adapter_path, expected_sha256)` where
  `resolved_adapter_path = os.path.realpath(os.path.expanduser(adapter))` and
  `expected_sha256 = cfg["_adapter_digests"]["builder"]` (both already
  available — M50 threads them into `_confine_manifest_field`). If
  `not profile["supported"]` AND `cfg["_confine"]["required"]` → seal
  `CONFINEMENT_REFUSED` (qualified False) and return WITHOUT ever calling
  `invoke_adapter` (no builder spawn). Journal `CONFINEMENT_UNSUPPORTED` with
  the profile reason. This is the real fail-closed gate.
- Do it ONCE before the build loop (the adapter identity doesn't change across
  iterations) — a preflight next to where the isolation/host-isolation probes
  run, so a `required`-confinement impostor never even reaches iteration 1.
  Keep the EXISTING post-dispatch self-report refusal too (defense in depth
  for a supported adapter that dynamically reports unsupported) — the new gate
  is ADDITIVE and fires first.
- `probe_confinement` / `confinement_flags`: thread the resolved adapter path
  + digest so the manifest's `probe`/`mcp_disabled`/`tool_allowlist` reflect
  the identity-aware result consistently (M50 did this for
  `_confine_manifest_field`; make the probe path agree). A supported CLI
  (`claude`, live-probed) and a shipped `api_anthropic` at its trusted path
  must be UNAFFECTED (still dispatch normally).
- RESUME path: apply the same pre-dispatch gate before re-entering the loop.

Regression tests (`tests/test_confine*.py` / a new `test_m52_confine_gate.py`):
- A FULL-RUN impostor: adapter named `api_anthropic` at a non-shipped path,
  no matching digest, `builder_confinement.enabled:true, required:true` →
  the run seals `CONFINEMENT_REFUSED`, `builder_invoked` is FALSE (the fake
  adapter must record whether it was called — assert it was NOT), exit
  non-zero, qualified False. (This is the auditor's exact repro; it must fail
  before the fix and pass after — verify that ordering.)
- `required:false` with an impostor → runs (unconfined) but manifest honestly
  records unsupported (unchanged from M50).
- A shipped `api_anthropic` at its real path (or digest-pinned) with
  `required:true` → dispatches normally (no false refusal).
- Resume with a required-confinement impostor → refused before dispatch.

## Rules
Fail CLOSED; real `raise`/return-nonzero, never bare `assert` (suite runs
under `python -O`). SUPERSET: keep the post-dispatch self-report refusal;
ADD the pre-dispatch gate + the metadata fix. Back-compat: a normally-
installed shipped adapter + a live-probed CLI dispatch unchanged; absent
`_confine` unchanged. Match house comment style. Full suite green (baseline
current main ~1911 passed + docker skips). Do NOT git commit — leave dirty for
adversarial review.

## Out of scope (later R4 milestones)
- DF-R4-03/04 ship attestation → M53.
- DF-R4-05/06/07 modes/tiers/adapters → M54.
- DF-R4-08/09/10/11 evidence + doc honesty → M55.
