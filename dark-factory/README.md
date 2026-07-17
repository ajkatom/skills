# dark-factory

A Claude Code skill implementing the StrongDM-style "dark factory" (Level-5
vibe-coding) loop: you write a spec, an isolated **builder** agent implements
it without ever seeing the hidden acceptance scenarios, a **verifier** runs
those scenarios against what the builder wrote, and only a behavior-ID +
fixed-taxonomy failure signal crosses back to the builder — never the
scenario content itself — until the build converges or the run is
abandoned.

Design spec: [`docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md`](../docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md).
Full operational instructions (the doc Claude itself follows when running
this skill): [`SKILL.md`](SKILL.md). A plain-language overview of what this
does and what each reference doc covers, if `SKILL.md` and this README are
too technical: [`OVERVIEW.md`](OVERVIEW.md).

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
| `standard` | OS-level read/write-denial sandbox (macOS `sandbox-exec` / Linux `bwrap`), verified by a fail-closed startup denial probe | A converged run is **qualified** |
| `hardened` | Builder runs inside a Docker container that **never has the control root mounted** — denial by construction, not a deny-rule — still probe-verified | Qualified; unlocks fully unattended `autonomy: 5` (lights-off) runs |
| `enterprise` | `hardened` + kernel-locked egress to a host-side credential proxy + seccomp + **split-custody sign-off** (K-of-N ed25519 approver attestation bound to the sealed manifest — no single operator can ship) | Qualified only via the separate custody attestation step |

See `references/isolation.md` (standard), `references/hardened.md`
(hardened), and `references/enterprise.md` (enterprise) for the mechanism
and honest scope of each.

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
    df_proxy.py               # host-side credential forwarding proxy
    df_twins.py, df_kb.py, df_audit*.py, df_creds.py, df_notify.py, ...
    adapters/               # protocol-0.1 builder adapters (one per model)
    run_scenarios.py, id_feedback.py, snapshot_source.py  # the oracle
  references/              # one topic-focused doc per subsystem (~20 files)
  examples/kv-service/       # a complete, copyable worked example
  tests/                       # ~1100+ tests, `pytest dark-factory/tests`
```

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
there.
