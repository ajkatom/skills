# M58 — init/run compat validator, init passthrough, image-digest persistence, toolchain PATH fidelity (Codex R5 DF-R5-05/06/09/10)

Branch `dark-factory-m58-init-compat`, worktree `../skills-worktree-m58`. Implemented by hand (subagents stall on deep supervisor tasks).

## DF-R5-05 — shared init/run pre-build compat validator (High, functional contract)
Problem: `validate_scaffold` blesses a root that `run` then rejects `GATE_FAILED` — the
candidate_network:"deny" vs http-scenario rule lives ONLY in supervisor's pre-build gate
(supervisor.py ~4272). SKILL.md promises init reuses the exact same validators.
Fix:
- `run_scenarios.deny_network_incompatible_ids(scenarios)` — THE single shared pure rule
  (when.http scenario, or property scenario with an http step ⇒ needs loopback).
- supervisor's gate consumes it (same journal/manifest behavior, byte-identical outcome).
- `df_init.validate_scaffold` captures cfg from load_config; when candidate_network=="deny",
  runs the SAME function; non-empty ⇒ report["network_incompatible"], scaffold fails
  (tree removed) naming the offending scenario ids.

## DF-R5-06 — init passthrough + legacy default parity (Medium/high)
- Forward `hardened`, `credentials`, `brownfield` options verbatim (df_config stays the ONE
  validator); add to `_allowed_options`.
- Shaped `answers.roles.builder` merges over {"adapter": answers.builder_adapter}: carries
  timeout_s / adapter_sha256 / model_identity / support_files. If shaped names a DIFFERENT
  adapter than answers.builder_adapter ⇒ InitError (no silent ambiguity).
- Legacy parity: `checkpoint` omitted with legacy autonomy ⇒ default exactly as df_config:
  "pause" if autonomy==4 else "auto" (was: always "auto" ⇒ silent H3).
- The live-H4-through-ship exercise stays an OPERATOR step (see audit/09 open question).

## DF-R5-09 — one logical run = one image identity across resume (Medium)
Problem: `_effective_image` caches on in-memory cfg only; resume re-resolves a mutable tag ⇒
iterations under digest A, resume under digest B, only B sealed.
Fix:
- `_pin_effective_image(cfg, run_dir, journal)` at `_run_loop` entry (fresh AND resume path both
  enter here): if journal already has IMAGE_RESOLVED ⇒ pre-seed
  `_effective_image`/`_resolved_image_digest` from it (no re-resolution); else resolve once and
  journal `IMAGE_RESOLVED {effective_image, resolved_image_digest}`.
- Pre-M58 resumed runs lack the event ⇒ resolve-and-journal then (legacy honest).
- Related R5-11 code note: enterprise `policy_digest` hashes the CONFIG image string; switch to
  `_effective_image(cfg)` so the digest fingerprints the image that actually runs.

## DF-R5-10 — toolchain identity mirrors child PATH/cwd resolution (Medium/low)
Problem: bare-command `shutil.which` runs from the SUPERVISOR cwd; the child chdirs to the action
cwd BEFORE execvpe, so a relative PATH entry (PATH=".", "bin") finds a tool the evidence missed
(null hash for a command that ran).
Fix: in `df_ship.toolchain_identity`, absolutize every relative/empty PATH entry against the
ACTION cwd before `shutil.which` — exactly execvpe-after-chdir semantics. Exec argv stays
UNTOUCHED (argv[0] semantics preserved; the mirror-resolution option from the audit's two
alternatives — zero behavior change, evidence now correct).

## Tests (test_m58_init_compat.py)
- shared rule: deny+http scaffold refused by init (tree removed, ids named); the id list function
  flags when.http + property-http-step, not plain scenarios; supervisor gate unchanged (existing
  GATE_FAILED tests keep passing).
- passthrough: hardened/credentials/brownfield/shaped-builder land in config.json and load_config
  accepts; shaped adapter mismatch ⇒ InitError; unknown option still refused.
- legacy parity: answers {autonomy:4} alone ⇒ loaded config resolves H2 (pause), matching runtime.
- image pin: fresh pin journals IMAGE_RESOLVED; a second _pin (resume) with a CHANGED resolver
  reuses the journaled identity, never re-resolves.
- toolchain: PATH="." + tool in action cwd ⇒ resolved_path+sha256 recorded; relative "bin" entry
  under action cwd resolved; supervisor-cwd file NOT falsely matched.

Pipeline: opus adversarial review (security-adjacent evidence paths) → fix → full suite → merge.
