# dark-factory builder confinement (M14)

`builder_confinement` confines the **BUILDER subprocess** — the agentic CLI
(`claude`/`codex`/`gemini`) dark-factory spawns to write the workspace — to an
explicit build-tool allowlist: no MCP servers, no sub-agents, no web/network
tools beyond what its profile documents as still open. It is opt-in
(`builder_confinement.enabled`), fail-closed once enabled, and **probe-verified**
against the CLI actually installed on this machine, not merely inferred from a
flag name. See `references/config-reference.md` for the config schema.

## The threat

An agentic builder CLI is not a dumb code generator — it is a tool-using agent
that, left unconstrained, can reach far past "write files in the workspace":
call out to configured MCP servers (the user's personal knowledge base, cloud
drive, deploy tooling, arbitrary remote services), spawn sub-agents, browse the
web, or invoke whatever else its host CLI happens to expose. dark-factory's
barrier already keeps the *scenarios* out of the builder's prompt — M14 closes
a different gap: even a builder that never sees the scenarios could, if
compromised or simply overzealous, use its ambient tool access to exfiltrate
the workspace, poison a knowledge base, or reach outside the sandbox tier's
own guarantees. `builder_confinement` narrows what the builder CLI can *do*,
independent of what it can *see*.

## Enforcement point: the adapter boundary

Confinement is enforced where the supervisor constructs the argv/config for
each builder CLI — `dark-factory/scripts/df_confine.py`'s per-CLI `PROFILES`,
applied by each adapter (`scripts/adapters/{claude,codex,gemini}`) when the
protocol request carries `"confine": true`. This is a control-plane decision,
not a builder-visible one: the builder still receives only the prompt (spec +
ID/taxonomy feedback) and the workspace, exactly as the barrier requires — no
confinement detail crosses back into feedback.

A CLI with no conforming profile raises `ConfineError` (`confinement_flags`)
or has `PROFILES[cli]["supported"] is False` (`is_supported`) — callers MUST
treat this as fail-closed: refuse the run rather than fall back to spawning
the CLI unconfined. This is why `gemini` ships **unsupported** (see below):
shipping an unverified profile that *looks* like it constrains the CLI, but
hasn't been proven to, would be worse than shipping nothing.

## Per-CLI profiles (claude verified; codex + gemini unsupported/refused;
## api_anthropic + api_openai supported on structural grounds)

### claude — verified: Bash tool blocked entirely

```
claude -p <prompt> --permission-mode acceptEdits \
  --allowedTools Read,Write,Edit \
  --disallowedTools Task,WebFetch,WebSearch,Bash \
  --strict-mcp-config --mcp-config '{"mcpServers":{}}'
```

`--strict-mcp-config` + an empty `--mcp-config` remove every configured MCP
server; `--disallowedTools` denies `Task` (sub-agents), `WebFetch`/`WebSearch`
(web), and `Bash` (shell) outright; `--allowedTools` narrows the rest to the
build allowlist (`df_confine.BUILD_TOOLS = ["Read", "Write", "Edit"]`).

**Live-verified denied tool: Bash.** The probe's own transcript confirms Bash
isn't merely refused at the permission layer — it is never loaded as a tool
at all: asked directly "is there a Bash/shell tool available to you?", a
confined `claude -p` session answers "there is no Bash/shell tool available in
this environment (no such tool exists to load)" and creates nothing. Across
repeated live runs, the confined session consistently created `ALLOWED_PROOF`
(via `Write`, still available) and never `DENIED_PROOF` (the Bash-only
action) once the probe used a dedicated, single-purpose call for the denied
attempt (see "Why the probe makes two calls, not one" below).

### codex — UNSUPPORTED: the live probe falsified its confinement

`df_confine.PROFILES["codex"] = {"supported": False, "reason": "…"}`. codex
shipped a candidate profile — `codex exec --sandbox danger-full-access
--skip-git-repo-check -c mcp_servers={} <prompt>`, on the theory that
`-c mcp_servers={}` clears codex's MCP surface (the escalation path, since
codex has no individually-nameable Bash/sub-agent tool like claude). **The
M14 live probe falsified that theory, and this is precisely the failure the
airtight probe exists to catch.**

What the probe observed on this install:

- An **unconfined** `codex exec` enumerating its tools lists a large
  `mcp__*` bridge — `mcp__codex_apps__*` (300+ tools: GitHub write, Google
  Drive, site deploys), `mcp__node_repl__*`, `mcp__open_brain__*`,
  `mcp__sites_design_picker__*`.
- The **identical** ask under `-c mcp_servers={}` — **and** under
  `-c mcp_servers={} -c plugins={} -c marketplaces={}`, **and** under
  `--ignore-user-config` — *still* lists those `mcp__*` tools on roughly half
  of runs (a nondeterministic race). They are not cosmetic: the probe's
  denied-tool call **actually created `DENIED_PROOF` via a real, functional
  `mcp__node_repl__js` / `mcp__codex_apps__*` tool**.
- These tools are injected by the ChatGPT **desktop-app / app-server
  runtime**, out-of-band from `$CODEX_HOME/config.toml`. No CLI config
  override reliably removes them, and a clean `CODEX_HOME` that would exclude
  them also loses authentication (401), so there is no flag combination that
  both authenticates and confines on this install.

A confinement that holds only ~half the time is **false assurance — worse
than none**, because it invites a caller to trust a barrier that isn't there.
So codex is marked `supported: False` and the codex adapter fail-closes on a
`confine: true` request **without ever spawning** (identical to gemini,
below) — a confinement-required tier refuses rather than run codex under a
flag that doesn't hold. This is the fail-closed, honest outcome the milestone
mandates: *a passed flag is not proof; where the probe can't produce proof,
the tier refuses.*

**Not a permanent verdict.** This is a property of *this* install (the
desktop-app MCP bridge), not of codex universally. A clean codex install
without that bridge — where `-c mcp_servers={}` genuinely empties the tool
list — can be re-probed with `probe_confinement("codex", …)` and, if it
returns `(True, "verified")`, re-enabled by flipping `PROFILES["codex"]`
back to a supported profile. The probe is the gate; the static profile only
claims what the probe has confirmed.

### gemini — unsupported (refused, not best-effort-trusted)

`df_confine.PROFILES["gemini"] = {"supported": False, "reason": "no
probe-verified confinement profile yet"}`. At a confinement-required tier, the
gemini adapter reports `status:"error", detail:"confinement unsupported for
gemini"` **without ever spawning the gemini CLI**, even if it is installed and
would otherwise run fine (`dark-factory/tests/test_e2e_confinement.py`'s
deterministic refusal test proves exactly this — no workspace artifact ever
appears). A tier that requires confinement then refuses fail-closed rather
than silently running gemini unconfined.

### api_anthropic — structural confinement (no live probe needed)

`df_confine.PROFILES["api_anthropic"] = {"supported": True, "structural":
True, "mcp_disabled": True, "tool_allowlist": []}`. This profile is
`supported: True` too, but for a categorically different reason than
claude's live-verified flags: **there is nothing in-band for a confinement
probe to test in the first place.**

claude/codex/gemini are agentic CLIs — general-purpose tool-using programs
that, unconfined, can reach a shell, an MCP bridge, a sub-agent, or the web.
Confining them means proving a *specific* tool got closed off, which is
exactly what `probe_confinement`'s ALLOWED_PROOF/DENIED_PROOF dance verifies.
`api_anthropic` (M24) is not that kind of program: it is a single stdlib
`urllib` POST to one fixed, supervisor-configured endpoint
(`ANTHROPIC_BASE_URL`), and its only possible output is a `{"files": {...}}`
JSON reply that the adapter itself parses and writes under strict
path-safety (`references/role-adapters.md`). There is no MCP client, no
sub-agent spawner, no shell, no web browser inside this adapter for a model
to reach through — the model's entire capability surface, whatever it might
"want" to do, is bounded by what a plain-text HTTP response can express, and
the adapter never executes anything the model returns as code or a command.

Confinement for `api_anthropic` is therefore not a flag set to verify — it
**is** the env the supervisor hands it: the API key, the base URL (at
enterprise, the credential-proxy endpoint instead of the provider directly,
so egress stays governed), and nothing else. That env is fully constructed
by the supervisor's own `df_container.build_argv`/credential-handling code
(`references/credentials.md`), never chosen or extended by the adapter
itself — the same "argv/env fully controlled by the caller" property that
makes the hardened container barrier itself airtight (`references/
hardened.md`).

Concretely, both `confinement_flags` and `probe_confinement` short-circuit
for a `structural` profile rather than pretending to run the claude-style
dance against a program that has no denied tool to attempt:

- `confinement_flags("api_anthropic", prompt)` returns `[]` — there is no
  CLI argv to build in the first place (the adapter is invoked via
  protocol-0.1 JSON on stdin, not a prompt baked into a command line), so
  "no flags to add" is the honest answer, not an omission.
- `probe_confinement("api_anthropic", workdir)` returns `(True, "structural:
  ...")` **without spawning anything** — there is no denied-tool call to
  make, so a live probe would only be theater around an argument the
  structural analysis above already settles.

This is a deliberately narrower, more conservative bar than "unsupported":
`api_anthropic` isn't marked unsupported the way `gemini` is (no evidence
either way) or the way `codex` is (a live probe *falsified* its candidate
profile) — it is supported because the class of thing a live probe checks
for (an escapable in-band tool) provably does not exist in this adapter's
design. If a future version of this adapter grows any agentic capability
(tool use, code execution, an MCP client), this structural argument stops
holding and the profile must be re-derived, probe-verified like claude's, or
withdrawn — `structural: True` is a claim about *this* adapter's shape, not
a blanket exemption from ever needing a probe.

#### The structural claim is bound to the shipped-adapter IDENTITY (M50, DF-R3-05)

The structural argument above is a claim about **this skill's shipped adapter
code**, not about any executable that merely shares the basename
`api_anthropic`/`api_openai`. Keying `supported: True` off the basename alone
would hand the "no agentic tool/MCP surface" claim to an *unrelated* executable
someone renamed `api_anthropic` — which might be a shell, an agentic CLI, or
anything at all. So `df_confine.profile_for(cli, adapter_path, expected_sha256)`
**binds the structural claim to a trusted adapter identity**, fail-closed: for
the structural profiles, `supported: True` holds only when the resolved
`adapter_path` EITHER

1. realpath-equals this skill's OWN shipped adapter file
   (`<skill_dir>/scripts/adapters/<name>`, where `<skill_dir>` is derived from
   `df_confine.py`'s own on-disk location — the trusted installation path), OR
2. matches a configured `expected_sha256` — the role's `adapter_sha256` content
   pin (see `references/config-reference.md`), so a byte-identical **relocated
   copy** is trusted by content.

Anything else (a renamed impostor, or a relocated copy with no digest pin) gets
an UNSUPPORTED profile (`supported: False`, a reason naming the path) — it is
treated as unconfined/unsupported, never granted the claim by name. The
supervisor threads the resolved builder adapter path + its pinned digest into
this call, so the `builder_confinement` manifest field honestly records
`mcp_disabled: false` / `probe: "unsupported"` for an impostor instead of a
false structural claim. A normally-installed shipped `api_anthropic` (the common
case) resolves to the trusted path and stays supported — byte-identical to
before. (`claude`'s support is a live tool-denial *probe*, not adapter identity,
so it is unaffected by this binding; unknown CLIs remain unsupported.)

### api_openai — same structural argument as api_anthropic

`df_confine.PROFILES["api_openai"]` is the identical `{"supported": True,
"structural": True, "mcp_disabled": True, "tool_allowlist": []}` shape, for
the identical reason: `scripts/adapters/api_openai` is also a single stdlib
`urllib` POST to one fixed, supervisor-configured endpoint
(`OPENAI_BASE_URL`), with the same "only possible output is a parsed
`{"files": {...}}` JSON reply" capability bound as `api_anthropic` — no
shell, no MCP client, no sub-agent spawner inside it either. Everything the
`api_anthropic` subsection above says about why a live probe would be theater
here, and why `confinement_flags`/`probe_confinement` short-circuit without
spawning anything, applies verbatim.

## The airtight-probe rationale

Confinement profiles are **per-CLI and version-sensitive** — a flag name that
worked against today's `claude`/`codex` release can silently stop meaning the
same thing after an upgrade, and a hand-written profile can simply be wrong
from day one (this milestone's own first draft was: the plan explicitly
flagged claude's `--strict-mcp-config`/`--disallowedTools` interaction and
codex's `-c mcp_servers={}` syntax as *unverified* until a live run proved
them). A passed flag is therefore not proof of anything on its own —
`probe_confinement(cli, workdir)` is the airtight anchor: it re-verifies
effectiveness against the **actually-installed** CLI via an **observable side
effect** (a file a denied tool would create), never the model's self-report.

Confinement is verified iff, after the probe's calls, `ALLOWED_PROOF` exists
(the CLI ran and could use an allowed tool — the run wasn't just a crash) AND
`DENIED_PROOF` does **not** exist (the denied tool/capability was genuinely
unreachable). Any spawn failure, timeout, absent CLI, or unsupported profile
is `(False, reason)` — an inconclusive probe is a **failed** probe, never a
pass.

### Why the probe makes two calls, not one

The first working version of this probe asked a single confined CLI call to
do both things in one turn: "create `ALLOWED_PROOF`, then try to create
`DENIED_PROOF` via the denied tool, and if that tool is unavailable, do NOT
create `DENIED_PROOF` any other way." Live runs against both `claude` and
`codex` showed this measurably fails: roughly 30-50% of combined-turn runs
still produced `DENIED_PROOF` — not because the denied tool worked, but
because the model, told "create this file" and finding its preferred tool
missing, **substituted an allowed tool** (`Write` for claude; its own
`exec`/`apply_patch` for codex) to satisfy the letter of the request anyway,
even with explicit "do not substitute" wording in the prompt. That is a
probe-design failure, not a confinement failure — the flags were correctly
removing the tool the whole time; the model was just being "helpful" around
the artificial constraint.

The fix: `probe_confinement` makes **two separate, single-purpose confined
CLI calls** — one whose entire prompt is "create `ALLOWED_PROOF`," and a
second, independent call whose entire prompt is "is a denied tool available?
if yes, use it to create `DENIED_PROOF`; if no, create nothing" with nothing
else competing for the model's attention in that turn. For `claude` this made
the substitution behavior stop recurring across repeated live trials. (For
`codex` the two-call split was not enough on its own — the follow-on trials
that exposed codex's real confinement hole, above, ran under this same
two-call design; the *reason* codex creates `DENIED_PROOF` turned out to be a
genuinely-present MCP tool, not mere substitution.)
`dark-factory/scripts/df_confine.py`'s `_ALLOWED_PROBE_PROMPT` /
`_denied_probe_prompt` carry this history in comments so a future editor
doesn't re-collapse the two calls into one without re-discovering why.

### Non-vacuity: the DENIED_CALL_RAN liveness marker

Splitting into two calls introduced a subtler trap: once `ALLOWED_PROOF` only
proves *call 1* ran, the denied-only *call 2* could silently no-op — a spawn
hiccup, an empty model response, a nonzero exit — and `DENIED_PROOF`'s absence
would then read as "blocked" when in fact **nothing was ever attempted**. That
is a false PASS, and it defeats the whole point of an airtight probe.

So the denied-only call's **final, unconditional** instruction is to write
`DENIED_CALL_RAN` (via the allowed Write tool) as its very last action,
regardless of what happened with the denied tool. `probe_confinement` now
requires **all three** conditions for `(True, "verified")`:

1. `ALLOWED_PROOF` exists — call 1 ran and could use an allowed tool;
2. `DENIED_CALL_RAN` exists — call 2 actually executed to completion (a
   missing marker → `(False, "denied-call did not complete — inconclusive")`,
   never a pass);
3. `DENIED_PROOF` does **not** exist — the denied tool was blocked.

Writing `DENIED_CALL_RAN` with the allowed Write tool is deliberately **not**
a substitution of the denied action: it targets a distinct path and proves
liveness, it does not stand in for creating `DENIED_PROOF` via the denied
tool. The three deterministic non-vacuity branches (call 2 no-ops →
inconclusive; call 2 creates `DENIED_PROOF` → not-blocked; all markers correct
→ verified) are pinned by fake-runner tests in
`dark-factory/tests/test_confine.py`, with no live CLI. On any non-verifying
live run, each call's returncode + stderr tail is surfaced into the failure
`reason` so a failure is diagnosable without a re-run.

## Fail-closed tier gating

`builder_confinement.enabled` (default `false`) + `.required` (default =
`.enabled`) + `.profile` (default/only value `"standard"`) load into
`cfg["_confine"]`. When enabled, the supervisor threads `confine=True` into
the builder's `invoke_adapter` request. If the adapter reports
`status:"error"` with a detail containing "confinement unsupported":

- **`required: true`** (the default once enabled) → fail-closed refusal:
  `CONFINEMENT_UNSUPPORTED` journaled, terminal manifest
  `outcome: "CONFINEMENT_REFUSED"`, `qualified: false`, exit 2. The builder is
  **never** run unconfined — not even once, not even for the rest of a
  cap-bounded loop.
- **`required: false`** → `CONFINEMENT_WARN` journaled and the supervisor
  retries the same builder call unconfined (`confine: false`) for the rest of
  the run, converging normally. This is an explicit, opt-in downgrade — the
  manifest's `builder_confinement.enabled` flips to `false` the moment this
  happens, so a WARN-downgraded run never claims a profile it didn't actually
  apply.

`builder_confinement` is additive on **every** terminal manifest (fresh,
resumed, aborted) — same pattern as `credentials` (M11) and `mode`/
`characterization` (M15): `{"enabled": bool, "profile": str, "mcp_disabled":
bool, "tool_allowlist": [str, ...], "probe": "unverified"|"n/a"}`.
`tool_allowlist` reflects only what the CLI **actually enforces**, so the
field is honest and per-CLI distinguishable. **claude** (the one supported
profile) records `mcp_disabled: true` + `["Read", "Write", "Edit"]` (genuinely
enforced via `--allowedTools`/`--disallowedTools`). An **unsupported** CLI
(codex, gemini) that somehow reaches the manifest with `enabled: true` records
`mcp_disabled: false` + `[]` — never claude's allowlist — because
`profile_for(<unsupported cli>)` carries no enforced properties; an auditor
reading the machine-readable manifest is therefore never misled into thinking
an un-enforced allowlist was applied. (In practice an unsupported CLI at a
confinement-required tier refuses before producing a converged manifest, and
at a not-required tier WARN-downgrades to `enabled: false`; the empty/false
field is the belt-and-suspenders honesty guarantee.) M14 does
not wire `probe_confinement`'s own `(True, "verified")`/`(False, reason)`
result into any manifest — no run yet calls it as a startup gate, so the
manifest field's `probe` value is only ever `"unverified"` (confinement
enabled for this run) or `"n/a"` (not applied). `"verified"` only ever
appears as `probe_confinement`'s own live return value, exercised directly by
`test_e2e_confinement.py`'s opt-in live claude test and by this milestone's
acceptance runs (see below) — wiring that result into the manifest as a
startup gate is M17/enterprise scope.

## Honesty: hardened already confines heavily — M14's biggest win is elsewhere

`hardened` (M10) already confines the builder severely via the **container**
barrier: the default `hardened.network: "none"` means no network egress at
all, and no network means no MCP server can be reached regardless of what
flags the CLI itself is passed — MCP servers that need a local socket or
loopback port are unreachable, and remote ones have no route out. A hardened
builder is *already* substantially confined by construction, independent of
`builder_confinement`.

`builder_confinement`'s marginal value is therefore **largest at
`cooperative`/`standard`** — the tiers with no container network barrier —
where, before M14, an agentic builder CLI's MCP/sub-agent/web reach was
constrained only by whatever the CLI's own default config happened to allow
(i.e. not constrained by dark-factory at all). It remains useful even at
`hardened` as defense-in-depth (e.g. `hardened.network: "bridge"` reopens
egress for a real builder's API calls, at which point `builder_confinement`
is the thing still keeping *this run's* MCP surface closed even though the
network isn't).

The codex finding above sharpens this: the very MCP bridge that no codex
*flag* could close (`mcp__codex_apps__*` reaching `api.openai.com`,
`mcp__node_repl__*` shelling to a local helper) is exactly what
`hardened`'s `network: "none"` container **would** cut off by construction —
no route to the remote bridge, no way for a bundled helper to phone home. So
codex being unsupported here is specifically a `standard`/`cooperative`-tier
gap; a hardened container closes the same hole a different way, reinforcing
that the flag-based confinement is the *supplement*, not the primary barrier,
at the strongest tier.

## Deliberately out of scope (honest, matches the plan)

- **Confining the orchestrator** (this Claude session, or whichever session
  is driving dark-factory). Not a subprocess dark-factory controls — trusted
  by design, same as `references/hardened.md`'s "Composing with other
  skills" note. An enforced, content-hash-pinned orchestrator skill allowlist
  is `enterprise` scope (spec §3B), not built.
- **A startup confinement probe enforced on every run.** M14 ships the probe
  and runs it during milestone acceptance; requiring it at every run start
  (so a silently-broken profile can never even reach `CONFINEMENT_UNSUPPORTED`
  before it's caught) is M17/enterprise scope. Today, `builder_confinement`
  trusts the shipped profile between probe runs — the profile itself doesn't
  re-verify itself automatically on every invocation.
- **Version pinning + probe-on-version-change.** Recording the exact CLI
  version a profile was verified against, and re-probing automatically when
  that version drifts, is a future hardening — not built in M14.
- **A working codex profile.** codex is unsupported on this install (its MCP
  bridge survives every flag — see "codex — UNSUPPORTED" above). Finding a
  codex configuration that the live probe can verify (or a clean install
  without the desktop-app bridge) and re-enabling it is future work; M14 ships
  it fail-closed rather than trusted.

## References

- `dark-factory/scripts/df_confine.py` — `PROFILES`, `confinement_flags`,
  `probe_confinement` implementation
- `dark-factory/tests/test_confine.py` — deterministic profile/adapter-argv
  tests (no live CLI)
- `dark-factory/tests/test_confine_config.py` — config matrix + supervisor
  fail-closed/WARN gating (monkeypatched `invoke_adapter`)
- `dark-factory/tests/test_e2e_confinement.py` — the deterministic fail-closed
  refusal e2e (real supervisor CLI + real gemini adapter, no live CLI needed),
  the deterministic codex-unsupported assertion, and the opt-in live claude
  probe test (`DF_LIVE_CONFINE=1`) that is the airtight evidence for claude
- `references/config-reference.md` — `builder_confinement.*` config schema
- `references/hardened.md` — the container barrier's own MCP-closing effect
  via `hardened.network: "none"`, and the `api_anthropic` in-container e2e
- `references/role-adapters.md` — the `api_anthropic`/`api_openai` adapters
  themselves (protocol, output contract, path-safety, key handling)
