# M54 — DF-R4-05 (init→H2) + DF-R4-06 (H4 survives downgrade) + DF-R4-07 (CLI adapters in-container)

R4 re-audit, the on-ramp / policy / packaging findings.

## DF-R4-05 (High) — canonical `init` defaults to H3, not documented H2
`df_init.build_config` (~382-410): when `answers.intervention_mode` is absent
it falls to the legacy branch and writes `{"autonomy": 4, "checkpoint":
answers.get("checkpoint", "auto")}` → **resolves to H3**. But `load_config`'s
no-fields default is H2 (`autonomy 4` + `checkpoint "pause"`) and all public
docs name **H2** as the default. A user following the canonical on-ramp
silently gets FEWER human gates (no after-verify / before-ship pauses) than
advertised.

Fix:
- When NEITHER `intervention_mode` NOR legacy `autonomy`/`checkpoint` is
  supplied, scaffold `{"intervention_mode": "H2"}` (the documented default) —
  not `checkpoint:"auto"`. When the operator DOES pass legacy fields, honor
  them verbatim (back-compat). When they pass `intervention_mode`, unchanged.
- Update `references/authoring.md`'s note that "init always writes checkpoint:
  auto" — it now defaults to H2; a scripted/unattended scaffold sets
  `intervention_mode: "H3"` (or H4 at hardened+) explicitly.
- Fix any `examples/*/answers.json` that relied on the implicit auto/H3 default
  and any init test asserting the old default. Add a test asserting a
  no-mode-fields answers doc → scaffolded config → `load_config` resolves
  **H2**, and (cheap) that H2's pause points (after-verify, before-ship) are
  what df_modes reports for it.

## DF-R4-06 (High/med) — H4 survives an effective assurance downgrade
`load_config` rejects H4 unless the CONFIGURED tier is hardened/enterprise.
But `resolve_isolation` (~2857) can then downgrade the EFFECTIVE tier under
`--allow-downgrade` to standard/cooperative, while `_run_loop` keeps
`cfg["_intervention_mode"] == "H4"` and never re-checks the H4 tier invariant.
Result: an unattended H4 run proceeds under weaker isolation than the operator
selected (the audit repro: configured hardened+H4, docker down, downgrade →
effective standard, mode still H4, no pause). It did NOT falsely qualify (the
qualification SM held), but it violates the stated "H4 only hardened/
enterprise" policy and runs lights-out under weaker-than-selected isolation.

Fix:
- After `resolve_isolation` yields `eff_tier`, if the intervention mode is H4
  (`df_modes.requires_hardened`) AND `eff_tier not in ("hardened",
  "enterprise")` → **fail closed**: journal a distinct event
  (`H4_TIER_DOWNGRADED`) and seal a distinct non-qualified terminal
  (`MODE_TIER_UNAVAILABLE`, exit 2/3) WITHOUT running the builder loop. Silent
  continuation under a demoted mode is not acceptable; changing the mode is an
  operator decision, not an implicit side effect of `--allow-downgrade`.
- Apply on BOTH the fresh `run` and `resume` paths (resume re-resolves
  isolation). A cooperative/standard configured run (mode already H1–H3) is
  unaffected. A hardened/enterprise H4 run whose effective tier STAYS
  hardened/enterprise is unaffected.
- Tests: hardened+H4, docker unavailable, `--allow-downgrade` → sealed
  `MODE_TIER_UNAVAILABLE`, builder never invoked, journal `H4_TIER_DOWNGRADED`;
  hardened+H4 with docker OK → runs normally; standard+H3 downgrade → unaffected.

## DF-R4-07 (Medium) — shipped CLI adapters can't run in the hardened/enterprise container
M46 mounts only the adapter EXECUTABLE FILE (`realpath(adapter)`), not its
directory (RA-07 fix). But the shipped `claude`/`codex`/`gemini` adapters do
`sys.path.insert(scripts_dir); import df_confine` — and `df_confine.py` (a
sibling in `scripts/`) is NOT mounted, so the adapter ImportErrors in-container.
Docs say multi-file adapters "must declare extras," but no such schema exists.
(`api_anthropic`/`api_openai` are self-contained and unaffected.)

Fix — an EXPLICIT support-file mount contract (the audit's "explicit file
allowlist with digests and safe mounts", preferred over inlining/duplicating
the shared, probe-verified `df_confine`):
- New optional `roles.builder.support_files`: a list of absolute paths to
  extra files the adapter needs at runtime. `df_config` validates each is an
  absolute existing file, disjoint from the control root (same discipline as
  the adapter path), optional per-file `sha256` pin (reuse the M47/M50 digest
  approach). Absent ⇒ unchanged.
- `supervisor.py` hardened/enterprise mount (~5285-5342): mount each
  `support_files` entry ro alongside the adapter file, at a container path that
  keeps the adapter's `import` working (i.e. the adapter dir's realpath +
  df_confine must land such that `sys.path.insert(dirname(dirname(adapter)))`
  finds it — verify the container path layout so a shipped CLI adapter with
  `support_files: [".../scripts/df_confine.py"]` imports correctly). Preserve
  the file-only posture (no whole-directory mount), the disjointness re-check,
  and the digest pin.
- Ship a documented, ready-to-use answer: the shipped CLI adapters need
  `df_confine.py` (and whatever else they import) declared — document this in
  `references/hardened.md` + `references/role-adapters.md`, and if
  `dark-factory init` can compute it for a shipped CLI adapter, offer it.
- Honest alternative if the mount layout proves fragile: make the shipped CLI
  adapters import `df_confine` DEFENSIVELY (try/except → a self-contained
  fallback that builds the same confined argv), so they work in-container with
  no extra mount. If you take this route instead, keep the confinement flags
  identical to df_confine's and document it. Pick whichever is cleaner + safe;
  do NOT silently leave the in-container CLI path broken.
- Tests: `support_files` validation (absolute/existing/disjoint/digest);
  a hardened build_argv includes the declared support-file ro-mounts; and,
  if feasible without a live container, a unit test that the shipped `claude`
  adapter's `import df_confine` resolves given the declared mount layout.
  (A live in-container CLI test needs the CLI baked into an image — document
  as the existing manual/opt-in path, don't add a paid/live test.)

## Rules
Fail CLOSED; real `raise`/return-nonzero, never bare `assert` (suite under
`python -O`). SUPERSET — every existing invariant stays; back-compat: an
answers doc WITH legacy fields is honored; a run whose H4 stays hardened+ is
unaffected; absent `support_files` unchanged. Match house comment style.
Full suite green (baseline current main 1923 passed, 27 skipped). Do NOT git
commit — leave dirty for adversarial review.

## Out of scope (M55)
DF-R4-08 (toolchain hash-before-exec), DF-R4-09 (identity docs + seal builder
identity), DF-R4-10 (image digest all dispatches), DF-R4-11 (doc-honesty sweep).
