# M47 — RA-08 candidate egress/containment + audit conditions #7/#10 (final remediation milestone)

Closes the last Codex re-audit finding (RA-08, Medium) and the remaining
"conditions for a production-ready judgment" (#7 adapter authentication, #10
H1 init selector + hermetic suite + stale-doc cleanup), then re-states the
QUALIFIED claim now that RA-01…RA-08 are fixed. Baseline main @ M46 (1b64bc4),
1846 tests.

## RA-08 (Medium) — candidate containment residual risk
Three sub-parts:

### (a) Unrestricted candidate egress must be DISQUALIFYING at qualifying tiers
Today `candidate_network` defaults to `"unrestricted"` and unrestricted is
**non-disqualifying** — a standard+ run leaves the built app's egress wide open
and still seals `COMPLETE_QUALIFIED`. Fix: add a `candidate_egress` derived
sub-state to `df_qualify.derive` (the single qualification AND). At a qualifying
tier, `candidate_egress` is True iff `candidate_network in ("deny","loopback")`;
`"unrestricted"` ⇒ False ⇒ the run is NOT qualified, sealing the distinct code
`CANDIDATE_EGRESS_OPEN`. Keep the config default `"unrestricted"` (so no config
ERRORS and back-compat holds for cooperative), but such a run at standard+ now
honestly seals unqualified. Wire it exactly like `host_isolation` was folded in
(M36a): a new sub-state boolean in `derive()` + a distinct non-qualified code,
sealed into `manifest["qualification"].substates`. `df_qualify`'s superset
invariant must hold (this can only NEWLY fail a run, never newly pass one).
Update the interview/authoring to recommend `deny`/`loopback` for a qualifying
run and explain unrestricted is now unqualified.

### (b) Process containment — strengthen where feasible, document honestly
`_reap_process_group` (killpg) cannot fully contain a candidate child that
deliberately `setsid()`s / double-forks into its own session on a HOST backend
(macOS `sandbox-exec`, and the standard-tier host path). Where a real PID
namespace exists (Linux M29c netns/PID-ns, hardened/enterprise container) this
is already closed by construction. Fix: (1) keep + harden the process-group
reap (best-effort on host); (2) record a `process_containment` field in the
manifest `host_isolation` block = `"namespace"` (container/netns backends) vs
`"process_group_besteffort"` (host backends), and add `process_group_escape`
to the documented host-isolation residuals so a host-backend run's residual is
auditable and honest (it does NOT flip qualification — host_isolation already
carries its residuals; this just names this one). Document in
`references/isolation.md`.

## Condition #7 — authenticate the adapter by content, not basename
The manifest already records `adapter_sha256` (actual). Add OPTIONAL
`roles.builder.adapter_sha256` (+ `roles.author`, `roles.critic`) in df_config:
a 64-hex expected content hash. When set, the supervisor computes the adapter
file's sha256 at run start and REFUSES (fail-closed, exit 2, journal
`ADAPTER_DIGEST_MISMATCH`) if it differs — so an operator pins the exact adapter
bytes rather than trusting a path/basename. Default absent ⇒ today's behavior.
Validate the hex shape at config load. Document: pin the adapter digest for a
production run.

## Condition #10 — H1 init selector + hermetic suite + stale-doc cleanup
- **H1 (and H2/H3/H4) selectable at `init`:** `df_init.py` accepts
  `answers.intervention_mode` (H1|H2|H3|H4, or the human aliases) and writes it
  into the scaffolded `config.json`, so H1 no longer requires a hand-edit.
  Reject setting BOTH `intervention_mode` and legacy `autonomy`/`checkpoint`
  (mirror df_config's dual-field rejection). Keep the legacy fields working.
- **Hermetic default suite:** the suite runs a few ambient network-reachability
  probes (e.g. real `1.1.1.1:443` baselines in the candidate-network tests).
  Gate those behind an env flag (`DF_ALLOW_NETWORK_TESTS=1`) so a default
  `pytest` run is HERMETIC (they `skip` without it), and the non-vacuity they
  provide is still available in CI/opt-in. Do NOT weaken the probes themselves —
  only skip-guard the ones that reach outside localhost. Grep for
  `1.1.1.1`/`create_connection`/live external targets in tests.
- **CI workflow:** add `.github/workflows/ci.yml` running the hermetic suite
  (`python -m pytest -q`) on push/PR (stdlib-only, no third-party lock needed —
  document that the runtime is stdlib-only so there is nothing to pin; the CI
  file IS the "CI validation" the auditor asked for). Keep it minimal + honest.
- **Stale-doc cleanup:** grep the references + SKILL.md for mode documentation
  that still describes ONLY the legacy autonomy/checkpoint model as the primary
  interface (superseded by H1–H4 in M36a) and correct it to lead with
  intervention modes (legacy mapping noted). Don't delete the legacy mapping.

## The honest QUALIFIED re-statement (docs)
With RA-01…RA-08 fixed, update `references/audit.md`, README, OVERVIEW to state
plainly: qualification now derives from evidence bound to the exact sealed
object (M44), attestations require an off-box receipt + manifest eligibility
(M44), confinement can't be configured off (M45), the scenario bundle is
sealed (M45), crash recovery is idempotent (M46), the adapter mount is minimal
(M46), and unrestricted candidate egress is disqualifying (M47). Then the
HONEST remaining residuals, unchanged and named: human spec/behaviors fidelity;
perf/load/scale (separate tool); the same-user detection-grade ceiling
(control-plane is same-user-forgeable — documented in
`prevention-grade-roadmap.md`); host-backend process-group escape; enterprise
trusted-time. Do NOT claim prevention-grade or production-authority beyond what
the mechanisms prove.

## Rules / invariants
- Fail CLOSED; real `raise`/return-nonzero, never bare `assert` (`-O`).
- Superset: RA-08(a) can only NEWLY fail a run (never newly pass); df_qualify's
  documented superset invariant test must be extended to cover `candidate_egress`.
  Condition #7 default-absent ⇒ byte-identical. H1 init selector is additive.
  The hermetic skip-guard must not remove coverage that runs in CI (opt-in).
- Regression tests fail-before / pass-after: RA-08(a) a standard unrestricted
  run seals `CANDIDATE_EGRESS_OPEN`/unqualified (and deny/loopback still
  qualifies); #7 a digest-mismatch adapter refuses; #10 an `init` with
  `intervention_mode:"H1"` scaffolds H1.
- Deterministic tests. Full suite green (baseline 1846 passed, 12 skipped) via
  `DOCKER_CONFIG=/tmp/dockercfg …/.venv/bin/python -m pytest -q` from the
  worktree's `dark-factory` — AND confirm the hermetic default (no
  `DF_ALLOW_NETWORK_TESTS`) still passes with the network tests skipped. No
  commits — leave dirty for opus review.

## Out of scope (documented, genuinely owner/infra or permanent)
- Full per-scenario copy-on-run (M29d) and macOS Mach-service full closure —
  documented residuals.
- perf/load/scale oracle — permanently a separate tool.
- The same-user detection-grade ceiling — needs privileged/off-host infra.
