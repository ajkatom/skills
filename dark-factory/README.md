# dark-factory

A Claude Code skill implementing the StrongDM-style "dark factory" (Level-5
vibe-coding) loop: you write a spec, an isolated **builder** agent implements
it without ever seeing the hidden acceptance scenarios, a **verifier** runs
those scenarios against what the builder wrote, and only a behavior-ID +
fixed-taxonomy failure signal crosses back to the builder — never the
scenario content itself — until the build converges or the run is
abandoned. The hidden scenarios can be written by a human or, with the same
barrier, by an independent **author** agent (a different model than the
builder) — and those agent-authored scenarios can be class-typed
(happy/boundary/failure), sharpness-proven (each assertion must reject a battery
of near-miss mutants), and adversarially critiqued by a **second** decorrelated
model. Scenarios can also be **generative** (`when.property`, M43a): assert an
invariant — round-trip, idempotency, determinism, "never crashes / fails
cleanly" — over many seeded, machine-generated (including malformed/fuzz)
inputs, with any counterexample kept control-plane-only. A generative property
may add a `concurrency` block (M43b) that runs the steps IN PARALLEL to catch
lost updates / crashes-under-parallelism / non-idempotent retries (ONE STRIKE =
fail; a PASS is probabilistic detection, not a race-freedom proof). That
narrows the gap to human spec fidelity + perf/load/scale (a separate tool) —
see `references/authoring.md`, `references/scenario-adequacy.md`, and
`references/scenario-format.md`.

Design spec: [`docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md`](../docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md).
Full operational instructions (the doc Claude itself follows when running
this skill): [`SKILL.md`](SKILL.md). A plain-language overview of what this
does and what each reference doc covers, if `SKILL.md` and this README are
too technical: [`OVERVIEW.md`](OVERVIEW.md).

("Level-5" above is the industry-generic term for fully-autonomous coding,
not dark-factory's own config. Inside dark-factory, two separate axes
control a run: four **assurance tiers** (cooperative/standard/hardened/
enterprise — how strongly the barrier is enforced; see "Assurance tiers"
below) and four **intervention modes** (H1–H4 — how much a human is in the
loop; see "Intervention modes" below). The legacy `autonomy` (4/5) +
`checkpoint` (pause/auto) fields still work and map onto the modes;
`supervisor.py df-migrate-config` rewrites an old config to the new
`intervention_mode` field.)

## Why "dark factory"

An AI builder that can see the tests will, given enough iterations, learn to
satisfy the tests rather than the spec — teaching to the test. dark-factory's
answer is an **information barrier**: the builder receives the spec (and
prior-attempt feedback) and nothing else; the scenarios that actually decide
pass/fail live only on the verifier's side of that barrier, and the feedback
that crosses back is deliberately impoverished (a behavior ID plus one of a
small fixed vocabulary of failure kinds — never scenario content, never
expected values). At the strongest tiers the barrier is not a convention the
builder is trusted to respect; it is enforced by OS sandboxing or a Docker
container that never has the holdout scenarios mounted.

## Install / update

The skill is used live via a symlink:

```bash
ln -sfn "$PWD/dark-factory" ~/.claude/skills/dark-factory
```

## Quickstart

```bash
# 1. Scaffold a control root from a spec + behaviors + scenarios (see
#    references/authoring.md for the interview, or copy the worked example):
python3 scripts/supervisor.py init --control-root /path/to/cr \
  --answers examples/kv-service/answers.json

# 2. Run the build/verify loop:
python3 scripts/supervisor.py run --control-root /path/to/cr

# 3. Inspect the signed result:
python3 scripts/supervisor.py verify --control-root /path/to/cr
```

`init` validates structure (oracle discrimination, behavior coverage, no
scenario content leaked into the builder-visible spec) before a run ever
starts, and refuses — removing the invalid tree — rather than leaving
something broken to fail confusingly later. See `references/authoring.md`
for the full interview script and `examples/kv-service/answers.json` for a
complete, copyable example (a small KV JSON HTTP API, 7 behaviors, 12
dev+final scenarios, hand-verified against a real converged build).

## Assurance tiers

Four tiers, each strictly stronger than the last, chosen per run via
`config.json`'s `assurance` field:

| Tier | Isolation mechanism | Qualification |
|---|---|---|
| `cooperative` | Honor-system — the builder is asked not to look, nothing stops it | Every run is explicitly **unqualified** |
| `standard` | OS-level read/write-denial sandbox (macOS `sandbox-exec` / Linux `bwrap`), verified by a fail-closed startup denial probe. The **candidate** (built artifact under test) additionally runs under a **default-deny** profile so it can't read the operator's host (`~/.ssh`, cloud creds, other repos) or reach non-allowlisted loopback ports | A converged run is **qualified** — if every sub-state holds (see "Qualification") |
| `hardened` | Builder runs inside a Docker container that **never has the control root mounted** — denial by construction, not a deny-rule — still probe-verified | Qualified; unlocks the unattended `H4` (lights-off) intervention mode |
| `enterprise` | `hardened` + kernel-locked egress to a host-side credential proxy + seccomp + **split-custody sign-off** (K-of-N ed25519 approver attestation bound to the sealed manifest — no single operator can ship) | Qualified only via the separate custody attestation step |

See `references/isolation.md` (standard + default-deny candidate),
`references/hardened.md` (hardened), and `references/enterprise.md`
(enterprise) for the mechanism and honest scope of each.

## Intervention modes

Orthogonal to the tier, `intervention_mode` sets how much a human is in the
loop. All four are pause-point *sets* over one mechanism (persist a
checkpoint and exit; a human resumes) — no live prompting.

| Mode | Pauses at | For |
|---|---|---|
| `H1` Directed | before each rebuild, after each verify, before ship | tight, step-by-step human direction |
| `H2` Supervised (default) | after each verify, before ship | review progress between attempts |
| `H3` Guarded-autonomous | only at guard conditions (e.g. budget soft-alert) | runs on its own, stops if something needs a decision |
| `H4` Lights-out | never — any human-needed condition is a deterministic fail-closed terminal, never a silent proceed | fully unattended; `hardened`/`enterprise` only |

See `references/modes.md` for the full state-transition table (approval
points, failure handling, timeouts, qualification consequences).

## Qualification

A run's `qualified` flag is one authoritative AND over derived sub-states —
`barrier` (probe-proven isolation) ∧ `host_isolation` (candidate default-deny
held) ∧ `control_plane` (signed manifest + bound artifact) ∧ `app_security`
(mandatory gates passed or every finding waived) ∧ `waiver_validity`. When
one is false the run seals a **distinct** non-qualified code (e.g.
`HOST_ISOLATION_LIMITED`, `SECURITY_GATE_FAILED`), never an ambiguous partial
"qualified." At `standard`+ the security gates are **mandatory** (a converged
artifact with a planted secret is rejected); an accepted-risk finding can be
cleared only by a separate **signed, scoped, expiring waiver** (`df-waiver`),
never by weakening the gate. See `references/audit.md` and
`references/security-gates.md`.

## Cross-model builders

The builder can be any model reachable through a protocol-0.1 adapter
(`scripts/adapters/`): CLI-driven (`claude`, `codex`, `gemini`) or a direct
stdlib HTTP call to a provider API (`api_anthropic`, `api_openai`) — the
latter needs no CLI binary in the image, which is what makes a real model
buildable inside the hardened tier's minimal container. See
`references/role-adapters.md` for the adapter protocol and every shipped
adapter's specifics, and `references/builder-confinement.md` for how each
one is confined (or, for `gemini`/`codex`, honestly marked unsupported where
a live probe couldn't prove confinement holds).

## Repository layout

```
dark-factory/
  SKILL.md              # operational instructions (what Claude follows)
  README.md             # this file
  OVERVIEW.md            # plain-language overview + reference-doc index
  scripts/
    supervisor.py        # the build/verify loop FSM (init/run/resume/verify)
    df_config.py          # config schema validation, all tiers
    df_container.py       # hardened/enterprise Docker argv + probes
    df_sandbox.py          # standard-tier OS sandbox backends
    df_confine.py           # per-adapter builder capability confinement
    df_gates.py, df_security.py, df_depaudit.py  # security/dependency gates
    df_custody.py            # enterprise split-custody attestation
    df_modes.py, df_qualify.py  # intervention modes + single qualification state machine
    df_waiver.py, df_override.py  # signed gate waivers + signed resume overrides
    df_proxy.py               # host-side credential forwarding proxy
    df_twins.py, df_kb.py, df_audit*.py, df_creds.py, df_notify.py, ...
    adapters/               # protocol-0.1 builder adapters (one per model)
    run_scenarios.py, id_feedback.py, snapshot_source.py  # the oracle
  references/              # one topic-focused doc per subsystem (~20 files)
  examples/kv-service/       # a complete, copyable worked example
  tests/                       # ~1490 tests, `pytest dark-factory/tests`
```

## Run lifecycle beyond a single run

- **Resume** a paused run with `supervisor.py resume`; the phase-aware
  checkpoint is hash-chain-validated on every resume (fail-closed on
  corruption). A `BUDGET_PAUSE` can be lifted only with a **signed resume
  override** (`df-override`, approver-allowlisted, replay-protected) — a
  budget-ceiling raise is a policy change, not a silent edit.
- **Fork** a run with `df-fork`: a new run starts from a parent's *sealed
  artifact object* as its input snapshot, records lineage, and marks the
  parent superseded (the parent still verifies, but says so).

## Testing

```bash
.venv/bin/python -m pytest dark-factory/tests -v
```

Most of the suite is deterministic (fixtures, stubs, monkeypatched
subprocess/network calls — no paid API calls, no live CLI required). A
handful of tests are opt-in and need something extra to run: `DF_LIVE_CONFINE=1`
for a live `claude` CLI confinement probe, a running Docker daemon for the
hardened/enterprise container tests (they skip cleanly without one), and
`npm`/network access for `df_depcache.py`'s own tests (see
`references/hardened.md`).

## Honest scope

This skill enforces an information barrier and, at `standard`+, real OS/
container isolation — it does not judge whether your scenarios actually
capture what you meant by the spec (that is still a human call: review
`scenarios/*.json` before trusting them), and it does not evaluate code
quality beyond what your scenarios exercise. `references/orchestrator-lockdown.md`
documents one thing this skill deliberately does **not** self-provide: a
skill cannot sandbox the session that is running it (the *orchestrator*,
as opposed to the *builder*, which dark-factory does confine) — that is a
harness-layer configuration step, with the operator recipe spelled out
there. **The workflow can optionally continue past the sealed
artifact into a governed *ship phase*** (M41): after a run qualifies, operator-
defined ship actions (merge/deploy/migrate — plain argv) run as an audited,
gated, crash-safe, rollback-capable phase, unattended even under H4 lights-out;
**irreversible actions are signature-gated** (a K-of-N `df-release` approval,
fail-closed to `SHIP_APPROVAL_PENDING`). See `references/ship.md`. This is a
governed *runner*, not a deploy engine, and ship actions are protected by
qualification + the signature gate + audit, **not** by sandboxing (they run with
real network + credentials). **Remaining non-goals:** incident response and
real-user validation/cutover *judgment* (the skill runs a cutover COMMAND under
the signed gate but provides no monitoring-driven decisioning), and provisioning
or rotating production **secret values** (broker-name references only) — those
stay on the operator, outside this skill.
