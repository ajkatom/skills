# dark-factory isolation (hardened tier)

`hardened` is the strongest assurance tier dark-factory ships (M10). It keeps
`standard`'s host OS read-denial sandbox for the **verifier**, and adds a
second, independent isolation layer for the **builder**: the builder no
longer merely runs under a wrapper that denies reads — it runs **inside a
Docker container that never has the control root mounted at all**.

## Denial by construction, not a deny-rule

`standard`'s OS sandbox (macOS `sandbox-exec`, Linux `bwrap`) works by
*permitting* the whole filesystem and then adding an explicit deny-rule over
the control root's subpath. That is a real, probe-verified guarantee, but the
control root's bytes are still reachable in principle — the OS is asked, at
every read, to say no.

`hardened`'s container barrier is categorically different: the control root
is **never bind-mounted into the container in the first place**. There is no
deny-rule to bypass, misconfigure, or race — from inside the builder
container, the control root's path simply does not exist. Only two paths are
ever mounted into the builder container:

- the **workspace**, read-write, at its host realpath;
- the **adapter's directory**, read-only, at its host realpath (so the
  adapter-protocol contract — an absolute executable path — still resolves
  identically inside and outside the container).

Nothing else. `df_container.build_argv` asserts this structurally: the
resulting argv contains exactly `1 + len(ro_mounts)` `-v` flags, so a third
mount (e.g. the control root sneaking in) is a test failure, not a runtime
surprise. `dark-factory/tests/test_e2e_hardened.py`'s barrier test goes
further and proves it empirically: a builder fixture (`fake_builder_snoop`)
that actively tries to walk up from its workspace and glob for scenario files
and a planted canary token finds **nothing** when run inside the hardened
container — while the same fixture, run directly on the host (uncontained),
does find and dump that content. The empty result is proof of denial, not an
artifact of a broken probe. (Scope note: the snoop searches a bounded number
of parent levels around the workspace, so it is an empirical complement — the
**load-bearing** guarantee remains the structural mount-count assertion above,
which catches any extra mount regardless of where it would appear.)

## Fail-closed, twice

`hardened` requires **both** halves to be proven working at run start, or the
run refuses:

1. the OS sandbox backend (for the verifier) — `available()` AND
   `probe_denial()` passing, exactly as `standard` requires;
2. a running Docker daemon AND a passing `probe_container()` — a canary is
   planted in the control root and a probe container must launch (`rc == 0`)
   and prove the canary was unreachable (denial marker in stdout, not the
   canary's content).

Either probe failing raises `SandboxError` (exit 2) unless `--allow-downgrade`
is passed, in which case the run downgrades: hardened → standard if the OS
sandbox is still healthy, else → cooperative — each journaled as a
`DOWNGRADE` entry naming what was requested vs. what's effective, with a
`qualified` manifest field that always reflects the *effective* tier truthfully
(never the configured one). `manifest.tier`, by the same convention as
`standard`'s downgrade tests, always echoes the *configured* assurance
(`"hardened"`); read `qualified` + the journal's `DOWNGRADE` entry for the
effective outcome of a downgraded run.

There is no such thing as "docker missing, ran anyway, looked fine" — a
missing daemon, a missing image, or a failing probe is either a hard refusal
or an explicitly journaled downgrade, never a silent no-op.

## The hardening flags (always applied, per builder call)

Every builder invocation at `hardened` is wrapped in:

| Flag | Effect |
|---|---|
| `--rm -i` | ephemeral container, stdin passed through (adapter protocol) |
| `--network <mode>` | `"none"` (default) or `"bridge"` — see Honesty note below |
| `--cap-drop ALL` | every Linux capability dropped |
| `--security-opt no-new-privileges` | no privilege escalation via setuid/setcap |
| `--pids-limit <pids>` | fork-bomb / resource-exhaustion ceiling (default 256) |
| `--memory <memory>` | hard memory ceiling (default `2g`) |
| `--read-only` | the container's root filesystem is immutable |
| `--tmpfs /tmp` | the one writable scratch path, backed by `HOME=/tmp` |
| `-v <workspace>:<workspace>` | the only read-write bind mount |
| `-v <adapter_dir>:<adapter_dir>:ro` | the only other bind mount, read-only |

Never applied, under any configuration: `--privileged`, the Docker socket
bind-mounted in, or a shared host PID/IPC namespace. `df_container.build_argv`
is pure and unit-tested for the exact flag set and order; nothing in
`hardened.*` config can add a mount, a capability, or a namespace share beyond
this fixed set (M10 ships one flag profile for the builder role — see
Deferred, below).

## L5 (autonomy 5, lights-off)

Spec §2.2 gates fully unattended operation on assurance ≥ hardened. Before
M10, no conforming hardened backend existed, so `autonomy: 5` had no path to
ever be legal. Now that `hardened` is real and probe-verified, `autonomy: 5`
is accepted **only** alongside `assurance: "hardened"` — any other tier with
`autonomy: 5` is a `ConfigError` at load, before any docker/build activity
("autonomy 5 (lights-off) requires assurance: hardened"). At hardened + L5,
`checkpoint` defaults to `"auto"`: the loop runs its full build → verify →
feedback cycle to convergence (or cap/failure) in one unattended CLI
invocation, with no `CHECKPOINT` journal entry and no `state.json` ever
written for a human to review mid-run. A budget cap can still pause even at
L5 (`BUDGET_PAUSE` is a different, financial safety rail — see
`references/budget.md`) — L5 removes the *review* checkpoint, not every
pause condition.

## The TCB now includes the Docker daemon

Spec §2.1's trusted computing base grows at `hardened`: trusting a run's
isolation now means trusting the Docker daemon (and its image layer) in
addition to the host OS sandbox primitive. A compromised or misconfigured
Docker daemon is a bypass path this tier cannot detect — `probe_container`
proves the *configured* barrier holds at *this* run's start, not that Docker
itself is trustworthy software. This is the same honesty discipline as
`standard`'s dependence on `sandbox-exec`/`bwrap`: the probe is real, but it
is a probe of the mechanism you chose to trust, not a proof that the
mechanism is unconditionally safe.

## Image requirements for real builders

M10's own live verification uses a stock `python:3.12-alpine` image running
the repo's fake builder fixtures — no CLI, no credentials, no network needed.
A **real** cross-model builder using the `claude`/`codex`/`gemini` adapters
needs a **user-supplied image** (`hardened.image`) with that model's CLI
installed and its credentials baked in or otherwise available inside the
container — dark-factory does not build or publish such an image. The
`api_anthropic` adapter (M24, below) removes this requirement entirely for
Anthropic models: no image customization needed at all. Two direct
consequences for the CLI adapters:

- **Network egress.** `hardened.network` defaults to `"none"` — the
  strongest posture is the default, not something you opt into. A real
  builder CLI that calls out to its provider's API needs
  `hardened.network: "bridge"`, which is **unrestricted egress**: any host,
  any port, honestly recorded on the manifest (`container.network`) so a
  reader of the audit trail can see the residual channel it represents.
  Provider-only egress enforcement (an allowlist so the container can reach
  *only* the model provider's API, nothing else) is **not built yet** — that
  is M12.
- **Credential hygiene.** The container's environment is always `None` at
  the invoke_adapter call (a clean env, only `HOME=/tmp` set by
  `build_argv`) — this is crude-but-honest hygiene, not a credential broker.
  Whatever the image needs (API keys, session tokens) must already be baked
  into the image or otherwise reachable inside it; dark-factory does not
  inject or scrub secrets into/out of the container. A proper credential
  broker with scoped, rotated, non-baked-in tokens is **not built yet** —
  that is M11.

## `api_anthropic`: real-model-in-container without a custom image (M24)

The "Image requirements for real builders" section above is the gap M24
closes for Anthropic models. `claude`/`codex`/`gemini` all shell out to a
CLI binary that the stock `python:3.12-alpine` image doesn't have — inside
the container they fail closed with "CLI not found on PATH", so a real
in-container build with one of them needed a hand-built image. `scripts/
adapters/api_anthropic` (`references/role-adapters.md`) needs nothing but
`python3` stdlib (`urllib`): it POSTs the Anthropic Messages API directly
instead of invoking a CLI. The stock image already has everything this
adapter needs — **no custom image, no baked-in CLI, no baked-in credentials.**

### The operator step: from proven mechanism to a live paid model

`dark-factory/tests/test_e2e_api_container.py` proves the full mechanism
live — the adapter running inside a real Docker container, reaching an HTTP
endpoint over the network, parsing a response, and writing the result into
the mounted workspace — against a **local stub** Messages endpoint (no paid
calls, deterministic, safe for CI). Going from that proven mechanism to a
**live, paid** model in the container is a configuration change, not new
code:

1. Set `roles.builder.adapter` to `scripts/adapters/api_anthropic`.
2. Set `hardened.network: "bridge"` — like any other real builder CLI that
   calls out to its provider, `api_anthropic` needs egress; hardened's
   default `network: "none"` is correct for a builder with no network need
   at all, but this adapter's entire job is one outbound HTTP call.
3. Provide `ANTHROPIC_API_KEY` (via the M11 credential allowlist —
   `references/credentials.md` — so the raw key is injected as a container
   `-e` flag baked into `df_container.build_argv`'s own invocation, never
   via the docker CLIENT process's env) and, at **enterprise**, add
   `api.anthropic.com` to the credential proxy's allowlist
   (`credential_proxy.allowlist`) instead of `network: bridge` directly, so
   egress stays routed through the governed proxy exactly like any other
   enterprise-tier credential (`references/enterprise.md`).
4. Point `ANTHROPIC_BASE_URL` at the real API (its default,
   `https://api.anthropic.com`, needs no override at all unless routing
   through the enterprise proxy).

That's the whole step. No new adapter code, no new container flags, no new
confinement wiring — `df_confine.PROFILES["api_anthropic"]` (`references/
builder-confinement.md`) already marks this adapter `supported: True` for
the hardened/enterprise confinement gate on structural grounds (a plain HTTP
client has no agentic tool surface to strip).

### Honest scope

`test_e2e_api_container.py` stubs **only the model's brain** — a canned
Messages API response. Every other layer it exercises is the real thing,
running live: the Docker container (`df_container.build_argv`, the same
argv shape `_run_loop` builds for every hardened builder call), the network
hop out of the container to the stub server on the host (via
`host.docker.internal`, the same pattern `test_enterprise_config.py`'s live
egress-proxy probe already proves on this Docker install), the real HTTP
POST and response parse, and the path-safe write into the bind-mounted
workspace. Going from that to a real paid model changes exactly one thing:
what answers the HTTP request — everything downstream (container, network,
parse, write, verify, security gates, signed audit) is unchanged and already
proven.

**A real live run was also performed in development** (not part of the
automated suite, so it costs nothing to run the tests): a real
`claude-sonnet-5`, called through this exact adapter, built a small
key-value-store app **inside** a `python:3.12-alpine` container over the real
Anthropic Messages API, and the built app passed all 12 of that milestone's
hidden acceptance scenarios. That run is the existence proof that the
mechanism works end-to-end with a real model, not only a stub; the suite's
own `test_e2e_api_container.py` deliberately uses the deterministic stub
instead so CI never makes a paid API call.

### `api_openai`: the same mechanism, a different provider

`scripts/adapters/api_openai` (`references/role-adapters.md`) is the same
stdlib-HTTP, no-custom-image adapter shape as `api_anthropic`, targeting
OpenAI's Chat Completions API instead. Steps 1-4 above apply identically
(`roles.builder.adapter` → `scripts/adapters/api_openai`,
`hardened.network: "bridge"`, `OPENAI_API_KEY` via the credential allowlist,
`OPENAI_BASE_URL` at its default unless routed through the enterprise
proxy), and it is `df_confine.PROFILES["api_openai"]`-supported on the same
structural grounds. Unlike `api_anthropic`, it does not yet have its own
in-container e2e test (`test_e2e_api_container.py` covers `api_anthropic`
only) — the container-level mechanism is identical and already proven for
`api_anthropic`, but this adapter's in-container path has not been
separately exercised. See `references/role-adapters.md` for the full honest
scope note.

## Twins at hardened

The **verifier's** digital-twin wiring (`references/digital-twins.md`) is
completely unaffected — twins run on the host, and the verifier still runs
under the OS sandbox exec-prefix exactly as at `standard`.

The **builder's** twin environment (`DF_TWIN_<NAME>` localhost URLs) is
**not forwarded into the container** at hardened: a twin bound to
`127.0.0.1` on the host is not reachable from inside a container's own
network namespace without deliberate port-forwarding or a shared network,
which dark-factory does not set up in M10. When a run has twins enabled and
reaches a hardened builder call, the supervisor journals `TWIN_ENV_SKIPPED`
(tier, reason) instead of silently handing the builder an env var pointing
nowhere — an authenticated builder↔twin topology across the container
boundary is **not built yet** — that is M12.

## Deferred (honest scope)

Explicitly not built in M10, in increasing order of the milestone that ships
them:

- **Per-role capability profiles.** M10 ships exactly one fixed hardened flag
  set, applied to the builder role only. A future milestone could let
  different roles (or different declared risk levels) carry different
  capability/network/resource profiles; M10 does not distinguish.
- **Credential broker (M11).** Scoped, rotated, non-baked-in credentials
  injected into the container per-call, with raw-token scrubbing on the way
  out. M10's container gets whatever the image already has, and nothing is
  scrubbed because nothing is injected.
- **Egress allowlists + authenticated builder↔twin topology (M12).**
  Provider-only network egress (rather than the all-or-nothing
  `none`/`bridge` choice) and a real network path for twins to reach a
  containerized builder.
- **Off-box audit sink (M13).** Signed manifests currently live only on the
  host filesystem next to the run; shipping them to a remote, tamper-evident
  store is a later milestone.
- **Non-Docker runtimes.** The registry's backend name is explicitly
  `container-docker` — podman, containerd, or other OCI runtimes are not
  registered and would need their own conforming backend + probe.

## References

- `references/isolation.md` — the `standard` tier (OS read-denial sandbox)
- `references/config-reference.md` — `hardened.*` config fields, the L5 gate,
  and the hardened ⇒ signed-audit requirement
- `references/audit.md` — signed manifest / `verify-manifest` mechanics
- `dark-factory/scripts/df_container.py` — `build_argv`/`docker_available`/
  `probe_container` implementation
- `dark-factory/tests/test_e2e_hardened.py` — the live convergence + barrier
  proof, L5 lights-off, and docker-less refusal tests
- `dark-factory/tests/test_e2e_api_container.py` — the live `api_anthropic`
  in-container proof (M24): stub-brained, real container + network + parse +
  write
- `references/role-adapters.md` — the `api_anthropic`/`api_openai` adapters
- `references/builder-confinement.md` — their structural (non-live-probe)
  confinement justification
