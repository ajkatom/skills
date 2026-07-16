# dark-factory M14 — Airtight Builder Capability Confinement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Confine the **builder subprocess** so an agentic builder CLI (claude / codex / gemini) cannot escalate beyond writing the workspace — no MCP servers, no sub-agents, no web/network tools, no tools outside an explicit allowlist. Enforcement lives at the **adapter boundary** (the argv/config the supervisor's adapter constructs for the CLI), is **fail-closed** (a tier that requires confinement refuses any builder CLI that can't be constrained), **airtight** (a live probe proves a denied tool is actually blocked, not just that a flag was passed), and **recorded** on the manifest. The orchestrator (the human's own planning session) is trusted and out of scope — this constrains only the subprocess dark-factory spawns.

**Architecture:** A new `df_confine.py` holds per-CLI **confinement profiles** (the exact flags/config each CLI needs to disable MCP + sub-agents + web + restrict tools to a build allowlist) and `probe_confinement(adapter_path, cli, workdir)` — a live, observable-side-effect probe that instructs the CLI under its confinement profile to use a DENIED tool and confirms the side effect never happens. The adapter protocol request gains `confine: bool`; each adapter applies its profile when set, or returns `status:"error", detail:"confinement unsupported"` (fail-closed) if its CLI has no conforming profile. The supervisor sets `confine` from `cfg["_confine"]`, refuses at confinement-required tiers when the adapter reports unsupported, and records `builder_confinement` on every manifest. Hardened already confines heavily via the container (no network ⇒ no MCP, no host mounts, cap-drop) — M14 extends an explicit, probe-verified confinement to standard/cooperative and hardens the claim at every tier.

**Honest scope (stated in docs):** confinement profiles are **per-CLI and version-sensitive** — a CLI that changes its flag surface can silently weaken; that is why the **live probe** is the airtight anchor (it re-verifies effectiveness against the installed CLI, not a hardcoded assumption). Profiles are provided and probe-verified for `claude` and `codex` (both installed here); `gemini` ships a best-effort profile that is **refused at confinement-required tiers until its probe passes** (fail-closed, not best-effort-trusted). The probe calls the real model (slow, costs tokens), so it is opt-in for the normal suite and run live during milestone acceptance; enterprise (M17) can require it at startup.

**Tech Stack:** Python stdlib. Live probes need the real `claude`/`codex` CLIs (present here). pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Fail-closed:** at a tier where `cfg["_confine"]["required"]` is true, a builder whose adapter returns `confinement unsupported`, or whose startup confinement check fails, → the run refuses (SandboxError-style, exit 2), never runs unconfined.
- **Airtight:** "confined" is only claimed when a live probe has observably shown a denied tool cannot act (a passed flag alone is NOT sufficient evidence). The probe uses an observable side effect (a file the denied tool would create), not the model's self-report.
- **Barrier untouched:** confinement is control-plane; the builder still receives only the prompt (spec + ID/taxonomy feedback) + workspace. No confinement detail crosses back into feedback.
- **Back-compat:** absent `builder_confinement` config → `confine=False`, adapters behave exactly as today (633 tests green). The `confine` protocol field defaults false; existing adapters/tests unaffected until opted in.
- **Additive manifest:** `builder_confinement = {"enabled":bool,"profile":str,"mcp_disabled":bool,"tool_allowlist":[...],"probe":"verified"|"unverified"|"n/a"} | None` on every terminal (fresh + resume).
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_confine.py            # Task 1 — per-CLI profiles + probe_confinement
    adapters/{claude,codex,gemini}  # Task 1 — honor req["confine"]
    df_config.py             # Task 2 — builder_confinement → cfg["_confine"]
    supervisor.py            # Task 2 — confine signal, tier gating, manifest field
  references/
    builder-confinement.md   # Task 3
    config-reference.md
  SKILL.md                   # Task 3
  tests/
    test_confine.py              # Task 1 (profiles + adapter argv, deterministic)
    test_confine_config.py       # Task 2
    test_e2e_confinement.py      # Task 3 (fail-closed refusal deterministic; live probe opt-in)
```

---

### Task 1: df_confine profiles + adapters honor `confine`

**Files:** create `dark-factory/scripts/df_confine.py`, `dark-factory/tests/test_confine.py`; modify `dark-factory/scripts/adapters/{claude,codex,gemini}`.

**Interfaces (Produces):**
```python
class ConfineError(RuntimeError): ...

# The build tool allowlist — exactly what a builder needs to write a project:
BUILD_TOOLS = ["Read", "Write", "Edit"]   # NO Bash by default; profiles may extend

PROFILES = {                # cli -> profile dict
  "claude": {"supported": True,  "mcp_disabled": True, "tool_allowlist": [...],
             "flags_fn": <callable(prompt)->list[str]>},
  "codex":  {"supported": True,  ...},
  "gemini": {"supported": False, "reason": "no probe-verified confinement profile yet"},
}

def confinement_flags(cli: str, prompt: str) -> list[str]
    # Return the FULL confined argv (minus cwd) for the CLI, or raise
    # ConfineError if PROFILES[cli]["supported"] is False. Exact flags:
    #  claude: ["claude","-p",prompt,"--permission-mode","acceptEdits",
    #           "--allowedTools", ",".join(tool_allowlist),
    #           "--disallowedTools","Task,WebFetch,WebSearch,Bash",
    #           "--strict-mcp-config","--mcp-config","{\"mcpServers\":{}}"]
    #  codex: ["codex","exec","--sandbox","danger-full-access",
    #          "--skip-git-repo-check","-c","mcp_servers={}",prompt]
    #  (dark-factory still provides the OS/container sandbox; codex confinement
    #   here = no MCP servers loaded. Document that codex's own tool surface is
    #   narrower and MCP is the escalation path we close.)
    # The exact flag names are validated by the live probe (Task 3); if a flag
    # is wrong the probe fails and the CLI is refused — fail-closed by design.

def profile_for(cli: str) -> dict            # PROFILES[cli] or a {"supported":False} default
def is_supported(cli: str) -> bool

def probe_confinement(cli: str, workdir: str, *, timeout_s: int = 120,
                      runner=subprocess.run) -> tuple[bool, str]
    # LIVE, observable proof. Under confinement_flags(cli, PROMPT) with cwd=workdir,
    # where PROMPT instructs the model to create ./DENIED_PROOF using a DENIED
    # tool (Bash `touch DENIED_PROOF` for claude; an MCP/web action for others),
    # AND to create ./ALLOWED_PROOF using an ALLOWED tool (Write). Confinement is
    # verified iff after the run ALLOWED_PROOF exists (the CLI ran and could use
    # an allowed tool) AND DENIED_PROOF does NOT exist (the denied tool was
    # blocked). Returns (True,"verified") or (False, reason). Any spawn failure /
    # CLI absent / timeout → (False, ...). Fail-closed.
```
- Adapters: read `req.get("confine")`. When true and `df_confine.is_supported(<this_cli>)` → build argv via `df_confine.confinement_flags(<cli>, prompt)`; when true and NOT supported → `respond("error","confinement unsupported for <cli>")` and return (fail-closed, no unconfined run). When false → today's argv unchanged. (Adapters import df_confine — they already run with scripts/ on the path via the supervisor's invocation; confirm the import works in the adapter's exec context, else inline the profile.)

- [ ] **Step 1 (TDD, deterministic — no live CLI):** `test_confine.py` — `confinement_flags("claude", "P")` contains `--strict-mcp-config`, an empty `mcpServers` mcp-config, `--disallowedTools` including Task/Bash/WebFetch, `--allowedTools` = the build set; `confinement_flags("codex","P")` disables mcp_servers; `confinement_flags("gemini",...)` raises ConfineError; is_supported matrix. Adapter behavior via a fake `df_confine`/monkeypatched `subprocess.run` capturing argv: with `confine:true` the claude adapter's argv carries the confinement flags; with `confine:true` for gemini the adapter responds `error confinement unsupported` and never spawns; with `confine:false` argv == today's. (Probe is Task 3 / opt-in — do NOT call it in the deterministic suite.)
- [ ] **Step 2:** Implement → green. Full suite (633 + new; existing adapter tests must stay green — they use `confine` absent/false).
- [ ] **Step 3:** Commit `feat(dark-factory): builder confinement profiles + adapters honor confine (fail-closed on unsupported)`.

---

### Task 2: config + supervisor gating + manifest

**Files:** modify `dark-factory/scripts/df_config.py`, `dark-factory/scripts/supervisor.py`, `references/config-reference.md`; create `dark-factory/tests/test_confine_config.py`.

**Interfaces:**
- `cfg["_confine"]` from optional `builder_confinement` block: `{"enabled":bool(default False),"required":bool(default = enabled),"profile":"standard"(default)}`. Validation: bools; unknown profile → ConfigError. Absent → `{"enabled":False,"required":False}`.
- Supervisor: when `cfg["_confine"]["enabled"]`, pass `confine=True` in the builder `invoke_adapter` request (extend the request dict + `invoke_adapter` to thread a `confine` kwarg into the JSON). If the adapter returns `status:"error"` with a detail containing "confinement unsupported" AND `cfg["_confine"]["required"]` → treat as a fail-closed refusal: journal `CONFINEMENT_UNSUPPORTED`, finalize a terminal manifest `outcome:"CONFINEMENT_REFUSED"`, qualified False, exit 2 (do not retry unconfined). If `required` False → journal `CONFINEMENT_WARN` and fall back to an unconfined call (record `probe:"n/a"`, enabled False on the manifest).
- Manifest additive `builder_confinement` (per Global Constraints) on every terminal, fresh + resume (M11/M12/M13 threading pattern). `mcp_disabled`/`tool_allowlist`/`profile` read from `df_confine.profile_for(cli)`; `probe` is `"unverified"` unless a startup probe ran (M17 wires the startup probe; M14 records `"unverified"` when enabled-without-probe, `"n/a"` when disabled).

- [ ] **Step 1 (TDD):** `test_confine_config.py` — config matrix (defaults; enabled→required defaults true; bad types; unknown profile → ConfigError). Supervisor (monkeypatched invoke_adapter): enabled → the builder request JSON carries `confine:true`; adapter returning "confinement unsupported" + required → run exits 2, manifest outcome CONFINEMENT_REFUSED, no build proceeds; + not required → unconfined fallback + CONFINEMENT_WARN + converges; manifest `builder_confinement` present on converged + abort + resume; disabled → confine:false + field enabled False.
- [ ] **Step 2:** Implement → green. Full suite.
- [ ] **Step 3:** config-reference rows. Commit `feat(dark-factory): builder_confinement config + fail-closed tier gating + manifest field`.

---

### Task 3: live probe proof + e2e + docs

**Files:** create `dark-factory/tests/test_e2e_confinement.py`; `references/builder-confinement.md`; modify `SKILL.md`.

- [ ] **Step 1:** `test_e2e_confinement.py`:
  - **Deterministic (always runs):** fail-closed refusal end-to-end — a control with `builder_confinement:{enabled:true,required:true}` and `roles.builder.adapter` = the gemini adapter (unsupported) → supervisor CLI exits 2, journal `CONFINEMENT_UNSUPPORTED`, manifest `outcome:CONFINEMENT_REFUSED`; the builder CLI is never spawned (no workspace artifact).
  - **Live probe (opt-in via `DF_LIVE_CONFINE=1`, skipif unset OR CLI absent):** `df_confine.probe_confinement("claude", tmp_workdir)` → (True,"verified"): ALLOWED_PROOF written, DENIED_PROOF (Bash) absent — proving `--disallowedTools Bash` actually blocked the tool, not just that a flag was passed. Same for `codex` if present. These are the airtight evidence; run them live during acceptance and record the result in the report.
- [ ] **Step 2:** `builder-confinement.md`: the threat (an agentic builder reaching MCP/sub-agents/web/arbitrary tools), the enforcement point (adapter argv), the per-CLI profiles (claude/codex verified; gemini refused-until-probed), the airtight-probe rationale (flags are version-sensitive; the probe re-verifies against the installed CLI via an observable side effect), fail-closed tier gating, and the honest note that hardened's container ALREADY confines heavily (no network⇒no MCP) so M14's largest marginal value is at standard/cooperative. SKILL.md: builder_confinement sub-step + that confinement is probe-verified and fail-closed. config-reference cross-check.
- [ ] **Step 3:** Docs-vs-code verify; full suite green; run the live probe for claude + codex and record real results in the task report; commit `feat(dark-factory): live confinement probe (observable denied-tool block) + e2e + docs`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M14):** the security-substantive core of the spec's "enforced skill/capability allowlist" — the BUILDER subprocess cannot reach MCP servers, sub-agents, web, or non-allowlisted tools; enforced at the adapter boundary; **fail-closed** (unconstrainable CLI refused at required tiers); **airtight** (a live observable probe proves a denied tool is actually blocked, closing the "flag passed but ineffective" gap); recorded on every manifest.

**Deliberately deferred (honest, in builder-confinement.md):** confining the **orchestrator** (the human's own Claude session) — not a subprocess dark-factory controls, so not enforceable from skill code (the original mis-scoped reading; documented as trusted-by-design); a gemini confinement profile (shipped unsupported → refused until a probe is written); a startup confinement probe enforced on every run (M14 makes the probe available + runs it in acceptance; M17/enterprise can require it at startup); signing/pinning the exact CLI version a profile was verified against (a version pin + probe-on-version-change is a future hardening).

**Honesty note:** a passed flag is not proof; M14 treats a profile as trustworthy only after the live probe observably blocks a denied tool against the actually-installed CLI. Where that proof can't be produced (gemini today), the tier that requires confinement refuses rather than trusting the flag.
