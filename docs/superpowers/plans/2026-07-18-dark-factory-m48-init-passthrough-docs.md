# M48 — DF-R3-01 (init on-ramp passthrough) + DF-R3-07 (doc drift)

Codex re-audit #06 findings. Both are "the advertised on-ramp / the skill's
own instructions don't match the implemented engine" — no core-qualification
defect, but they block a knowledgeable-config-free user and can misdirect an
agent/operator.

## DF-R3-01 (High) — `init` silently drops `candidate_network` + `ship` and ignores unknown option keys
Verified: `df_init.build_config` (`scripts/df_init.py`, the `options` loop
~480-487) forwards ONLY `security_gates`, `twins`, `knowledge_base` (+ `budget`
special-cased). `answers.options.candidate_network` and `answers.options.ship`
are dropped, and any unknown key passes unnoticed. Consequence: a standard+
control root scaffolded through the canonical on-ramp defaults
`candidate_network` to `unrestricted` → seals `CANDIDATE_EGRESS_OPEN` → cannot
qualify; and `ship` absent → the ship phase is unreachable from `init`.

Fix (`df_init.py`):
- Forward `candidate_network` and `ship` into `cfg` when present in
  `answers.options` (pass-through; `df_config.load_config` remains the single
  validator — do NOT re-validate shape here, just forward, matching how
  `security_gates`/`twins` are forwarded).
- **Reject unknown `options` keys**: after handling the known set
  (`budget`, `security_gates`, `twins`, `knowledge_base`, `candidate_network`,
  `ship`), any remaining key in `answers.options` → `InitError` naming the
  offending key(s) + the allowed set. (Silent-drop is exactly what hid this;
  fail-closed on typos/unknowns.)
- Keep the existing `answers.options must be an object` guard.

Regression tests (`tests/test_init*.py` / wherever `build_config` is tested):
- `answers.options.candidate_network: "deny"` → `cfg["candidate_network"] ==
  "deny"` and `load_config` accepts it.
- `answers.options.ship: {...}` → `cfg["ship"]` present and `load_config`
  accepts it (a minimal reversible action).
- an unknown `options.bogus` key → `InitError`.
- **End-to-end on-ramp**: `build_config` → `load_config` for (a) standard/H3
  with `candidate_network: deny` seals a config that CAN qualify (i.e. not
  forced-open), and (b) a hardened H4 answers doc with a `ship` block loads
  and exposes `cfg["_ship"]`. (Use the existing init→load test pattern; no
  live build required — assert the config is qualification-capable + ship-
  reachable, closing the "front door works" gap the audit named.)

## DF-R3-07 (High-impact) — stale/contradictory skill docs
The skill's own frontmatter + docs still describe the pre-M36 world, which
can steer an agent/operator to the wrong config. Make code the source of
truth. Confirmed instances (find any others by grep):
- `SKILL.md` FRONTMATTER `description:` ends with "unlocks fully unattended
  **L5/autonomy-5** runs … Per-iteration human checkpoints (pause/resume) at
  **autonomy 4**." → rewrite to the four intervention modes H1–H4 (+ note the
  legacy autonomy/checkpoint fields still map, via `df-migrate-config`).
- `SKILL.md` body: "there are four tiers and **two** [autonomy modes]" (~L18),
  the L4/L5 framing (~L15-18, L269-272), the exit-code "10 = paused … autonomy
  4 / checkpoint: pause" (~L358) → restate in H1–H4 terms (keep a short
  "legacy autonomy/checkpoint compatibility" note pointing at
  `references/modes.md` + `df-migrate-config`; the fields still WORK, so
  document them as compatibility, not as the primary model).
- `references/config-reference.md`: the `assurance` row (~L12) lists only
  cooperative/standard/hardened and omits `enterprise` from that cell (it's
  implemented + covered elsewhere in the file) → add `enterprise` to the
  `assurance` row's value list so the reference isn't self-contradictory.
  Also scan for any "enterprise does not yet exist"/"not yet implemented"
  line and correct it.
- Stale **mount** comments (M46 mounts the adapter FILE now, not its
  directory): grep `scripts/supervisor.py` + `references/*` for comments still
  saying the adapter's *directory* is mounted and correct them to "the
  resolved adapter file" (RA-07/DF-R3-07). Code is already correct; only the
  comments/docs lie.
- The `init` "honest scope" line that says init "does not auto-generate
  scenarios" sits right before the agent-authored (M40) workflow → qualify it
  ("`init` itself never auto-generates; the separate `author-scenarios` step
  can, via a different-model author + critic" — pointer to authoring.md).

No behavior change for DF-R3-07 — docs/comments only. Keep edits faithful to
what the code actually does (verify each claim against the validator/impl
before writing it).

## Out of scope (later milestones, already sequenced)
- DF-R3-02/03/06 ship-phase audit integrity → M49.
- DF-R3-04/05 identity (model-identity relabel+seal; confinement digest bind)
  → M50.
- DF-R3-08 base-image digest + lockfile (code) + LICENSE/CI (owner decision).

## Rules
Fail-closed; real `raise`/`InitError`, never bare `assert`. Additive/back-compat
(an answers doc without `candidate_network`/`ship` behaves identically; the
unknown-key rejection only fires on genuinely unknown keys — confirm no
existing example/answers doc carries a now-"unknown" key by re-running the
full suite). Match house comment style. Full suite green (baseline 1832
passed, 12 skipped in the M44 worktree lineage — re-baseline on current main).
