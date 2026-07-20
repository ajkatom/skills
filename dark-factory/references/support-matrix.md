# Supported app × host × tier matrix

Codex R6 DF-R6-12 asks for a precise statement of what dark-factory can qualify,
by application shape, host OS, and assurance tier — so the "an app end to end at
every level of hardness" claim is scoped honestly rather than assumed universal.

## Host × tier

| Tier | macOS (arm64/x86) | Linux |
|---|---|---|
| **cooperative** | ✅ (honor-system, always UNQUALIFIED) | ✅ (always UNQUALIFIED) |
| **standard** (OS default-deny sandbox) | ✅ `sandbox-exec`, probe-verified | ✅ `bwrap`, probe-verified |
| **hardened** (Docker builder barrier) | ✅ needs a running Docker daemon | ✅ needs a running Docker daemon |
| **enterprise** (+ kernel egress + seccomp + K-of-N custody) | ✅ Docker + the enterprise entrypoint | ✅ Docker + the enterprise entrypoint |

A tier is usable only when its runtime prerequisites are actually present
(a supported OS sandbox backend, a Docker daemon, etc.); a missing prerequisite
fails closed (exit 2) unless `--allow-downgrade` is passed.

## Application shape × candidate networking

The verifier runs the built app against hidden scenarios. Apps that need a
**loopback test server or a digital twin** (any `when.http` scenario, or a
`when.property` scenario with an `http` step) require the candidate to reach
`127.0.0.1` while still being denied the wider host — the `candidate_network:
"loopback"` profile.

| App shape | Needs | macOS | Linux |
|---|---|---|---|
| CLI / pure-function / file-I/O (no localhost server) | `candidate_network: "deny"` or `"unrestricted"` | ✅ all tiers | ✅ all tiers |
| HTTP service / twin-backed (localhost test server) | `candidate_network: "loopback"` | ✅ all tiers | ⛔ **not supported at standard+** |

### The Linux loopback/twins limitation (DF-R6-12)

On Linux the `bwrap` candidate wrapper does **not** implement the `loopback`
profile (`scripts/df_sandbox.py`; `references/isolation.md`). At standard and
above, `unrestricted` candidate egress is disqualifying and `deny` blocks
`127.0.0.1`, so an HTTP/twin-backed app **cannot qualify at standard, hardened,
or enterprise on Linux** under the current model. Such an app can:

- run at those tiers on **macOS** (loopback is implemented, and DF-R6-05 fixed
  the denied-CWD probe failure), or
- be redesigned on Linux to avoid a localhost server (e.g. exercise the handler
  in-process via a `when.run`/`when.property` scenario rather than over HTTP).

This is a documented product limit, not a hidden bug. Closing it needs a
Linux netns-local verifier/twin bridge (a netns-scoped loopback that keeps the
default-deny host isolation) — deferred; see `references/isolation.md`.

## Intervention modes × tier

`intervention_mode` (H1–H4) is orthogonal to the assurance tier, with one gate:
**H4 `lights_out` requires an effective hardened or enterprise tier** (a
never-pausing run is only safe on a denial-by-construction backend). H1–H3 run
at any tier.
