# dark-factory M11 — Credential Broker (allowlist, scrubbing, gitignore) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Give real builders a safe way to receive provider credentials without ever letting raw tokens touch run artifacts, git, or roles that don't need them. Three enforced properties: (1) **allowlist-only injection** — the builder's env receives exactly the credential variables the config allowlists, sourced from an env-file, the macOS keychain, or the launcher env (never from git-tracked files); (2) **scrubbing** — every credential VALUE is redacted from journals, manifests, reports, and captured adapter/scenario stderr before it is written; (3) **gitignore verification** — an env-file living inside a git repo must be `git check-ignore`-clean or the run refuses (fail-closed; the user's standing guardrail). At `hardened`, this is the ONLY way any env reaches the container (M10 ships a clean env; M11 adds the brokered allowlist). At `standard`/`cooperative`, the builder inherits the host env today — M11 additionally strips credential-shaped vars (`*_API_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`) that are NOT allowlisted.

**Architecture:** New module `df_creds.py` (stdlib only): `load_credentials(spec, runner=...)` resolves the allowlisted names from the configured source and returns `{name: value}` plus a `Redactor` built from the values. The supervisor holds credentials ONLY in memory, passes them to `invoke_adapter` (at hardened: via `build_argv(env=...)` `-e` flags; at other tiers: merged into the builder env after the strip), and wraps its journal/manifest/report writers with the Redactor so no value can be persisted. `verify-manifest` and all M9 security gates are unaffected (they scan the artifact, which never legitimately contains the token — if the builder echoes it into a file, M9's secret_scan is the backstop and the M11 e2e proves the finding stays rule-name-only).

**Honest scope (stated in docs):** the broker cannot make a static API key "short-lived" — provider keys have provider lifetimes; what M11 guarantees is *containment* (allowlist-only, artifact-scrubbed, git-ignored), not rotation. A determined malicious builder that receives a credential can still exfiltrate it over an open network (`hardened.network: "bridge"`) — query-level egress control is the enterprise credential proxy (deferred, M12+/enterprise). Keychain support is macOS `security` CLI (Linux `secret-tool` noted as a config value but implemented only if trivially testable — otherwise documented as future); the keychain path is unit-tested via an injected runner, not by touching the user's real keychain.

**Tech Stack:** Python stdlib. pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Raw token values NEVER appear in:** the journal, any manifest, checkpoint reports, `security_report.json`, saved state, stderr tails captured into feedback/manifests, or any file under `run_dir`. Values live only in supervisor memory and the builder process env.
- **Fail-closed:** a configured credential that cannot be resolved (missing env-file, missing key in it, keychain item absent, `security` CLI failure) → ConfigError-style refusal at run start (exit 2), never a silent empty value. An env-file inside a git work tree that is NOT git-ignored → refusal with the exact remedy in the message.
- **Allowlist-only:** nothing outside `credentials.allowlist` is ever brokered; at hardened nothing outside it enters the container env (HOME=/tmp from build_argv is the only exception, already fixed).
- **env-file permissions:** refuse a group/world-readable env-file (mode & 0o077 must be 0) with a chmod remedy in the message.
- **Back-compat:** absent `credentials` block → exactly today's behavior at every tier (374 tests stay green; hardened keeps its clean env).
- **Barrier untouched:** credentials are control-plane; nothing about scenarios/holdout changes.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_creds.py        # Task 1 — sources, allowlist resolution, Redactor, gitignore check
    df_config.py       # Task 2 — credentials block → cfg["_credentials"]
    supervisor.py      # Task 2 — brokered builder env + redacted writers
  references/
    credentials.md     # Task 3 — the containment model + honest limits
    config-reference.md
  SKILL.md             # Task 3 — credentials sub-step
  tests/
    test_creds.py          # Task 1
    test_creds_config.py   # Task 2
    test_e2e_credentials.py # Task 3
```

---

### Task 1: df_creds — sources, resolution, Redactor, gitignore check

**Files:** create `dark-factory/scripts/df_creds.py`, `dark-factory/tests/test_creds.py`.

**Interfaces (Produces):**
```python
class CredsError(RuntimeError): ...

def parse_env_file(path: str) -> dict
    # KEY=VALUE lines; ignores blank lines and #-comments; strips optional
    # surrounding single/double quotes on the value; `export KEY=VALUE` accepted.
    # Malformed line (no '=', empty key) → CredsError with the line number.
    # Refuses (CredsError) if os.stat(path).st_mode & 0o077 != 0 (too permissive)
    # or the file is missing.

def check_gitignored(path: str, runner=subprocess.run) -> None
    # If `git -C <dir> rev-parse --is-inside-work-tree` says the env-file's
    # directory is inside a git work tree:
    #   `git -C <dir> check-ignore -q <path>` must exit 0 → OK.
    #   exit 1 (NOT ignored) → CredsError("env-file ... is inside a git repository
    #     but not git-ignored; add it to .gitignore before running").
    #   ALSO `git -C <dir> ls-files --error-unmatch <path>` exiting 0 (already
    #   TRACKED — ignoring it now wouldn't untrack it) → CredsError("... is
    #   git-TRACKED; remove it from the index (git rm --cached) and gitignore it").
    # Not a work tree / git absent → OK (no repo to leak through). Spec 7.3.

def keychain_lookup(service: str, runner=subprocess.run) -> str
    # macOS: ["security", "find-generic-password", "-s", service, "-w"]
    # rc 0 → stripped stdout (empty → CredsError). rc != 0 / OSError / timeout 10s
    # → CredsError naming the service. Non-darwin platform → CredsError
    # ("keychain source requires macOS in M11").

def load_credentials(spec: dict, runner=subprocess.run) -> dict
    # spec = cfg["_credentials"] (Task 2 shape). Resolves every name in
    # spec["allowlist"] from spec["source"]:
    #   "env-file": check_gitignored(env_file) then parse_env_file(env_file);
    #               every allowlisted name must be present → else CredsError.
    #   "keychain": value = keychain_lookup(f"{spec['service_prefix']}{name}").
    #   "env":      value = os.environ[name] → KeyError → CredsError.
    # Returns {name: value}; every value non-empty (empty → CredsError).

class Redactor:
    def __init__(self, values: Iterable[str]):  # keeps values len >= 6 only
        # (shorter would redact common substrings); stores sorted longest-first.
    def redact(self, text: str) -> str
        # replaces every occurrence of every value with "***REDACTED***".
        # Non-str input returned unchanged.
    def redact_obj(self, obj):
        # recursively redacts str leaves of dict/list/tuple (returns same shape).
```

- [ ] **Step 1 (TDD):** `test_creds.py` —
  - parse_env_file: happy path (plain, quoted, `export`), comments/blanks skipped; malformed line → CredsError with line number; missing file → CredsError; **permissions: chmod 0644 file → CredsError mentioning permissions; 0600 → OK**.
  - check_gitignored (real git in tmp_path — git is available): env-file in a git repo + .gitignore covering it → OK; same repo without the ignore → CredsError "not git-ignored"; file git-ADDED then ignored → CredsError "git-TRACKED"; file outside any repo → OK; injected runner raising OSError (git absent) → OK (documented: no repo to leak through — verify via monkeypatched runner).
  - keychain_lookup with injected runner: rc0+stdout → value stripped; rc0+empty → CredsError; rc1 → CredsError naming service; OSError/timeout → CredsError; non-darwin (monkeypatch sys.platform) → CredsError.
  - load_credentials: env-file source resolves exactly the allowlist (extra vars in the file are NOT returned); allowlisted name missing from file → CredsError; env source (monkeypatch os.environ); keychain source with injected runner (service_prefix + name); empty resolved value → CredsError.
  - Redactor: single + multiple values; longest-first (value A substring of value B — B fully redacted, no partial leftovers); short values (<6 chars) skipped; redact_obj on a nested dict/list keeps shape; non-str leaves untouched.
- [ ] **Step 2:** Verify fail → implement → green.
- [ ] **Step 3:** Full suite green (374 + new). Commit `feat(dark-factory): df_creds — allowlist credential sources, redactor, gitignore verification`.

---

### Task 2: credentials config + brokered builder env + redacted writers

**Files:** modify `dark-factory/scripts/df_config.py`, `dark-factory/scripts/supervisor.py`, `references/config-reference.md`; create `dark-factory/tests/test_creds_config.py`.

**Interfaces:**
- Consumes Task 1 (`df_creds.load_credentials`, `df_creds.Redactor`, `CredsError`).
- Produces:
  - `cfg["_credentials"]` from an optional `credentials` block:
    ```
    {"source": "env-file"|"keychain"|"env",   # required when block present
     "env_file": str,          # required iff source=="env-file"; ~ expanded;
                               # must be DISJOINT from control root AND workspace
     "service_prefix": str,    # keychain only; default "dark-factory/"
     "allowlist": [str, ...]}  # required, non-empty, each ^[A-Z][A-Z0-9_]*$
    ```
    Absent block → `cfg["_credentials"] = None`. Validation ConfigErrors: unknown source; missing/relative `env_file` for env-file source (absolute after expanduser required); env_file inside control root or workspace; empty allowlist; malformed var name; allowlist entries duplicated.
  - Supervisor (`_run_locked` + `resume`, before the loop): if `cfg["_credentials"]`:
    ```python
    try:
        creds = df_creds.load_credentials(cfg["_credentials"])
    except df_creds.CredsError as e:
        sys.stderr.write(f"dark-factory: credentials: {e}\n"); return 2
    redactor = df_creds.Redactor(creds.values())
    ```
    else `creds, redactor = None, None`.
  - **Journal redaction:** the Journal writer gains an optional `redactor`; `journal.write(...)` passes its data dict through `redactor.redact_obj` before serialization (None → no-op). Same for `finalize_manifest` / checkpoint report writer / `save_state` payloads — one shared choke point where each dict is serialized (find the existing `atomic_write(canonical_json(...))` seams; apply redact_obj immediately before serialization).
  - **Builder env brokering** at the single builder `invoke_adapter` call site:
    - hardened: `builder_env = None` becomes `builder_env = creds` — and the container argv gets `env=creds` via `build_argv(..., env=creds)` (values enter ONLY as `-e` container env, not the docker client env; note: `-e K=V` argv IS visible to local `ps` — document this residual in credentials.md honestly; mitigating via `--env-file` piped tmpfile is a noted alternative — implement `-e` now, it matches build_argv's existing contract).
    - standard/cooperative: builder env = `dict(os.environ)` with every var matching `(_API_KEY|_TOKEN|_SECRET|_PASSWORD)$` AND not in the allowlist REMOVED, then `creds` merged in. Implemented as `df_creds.launcher_scoped_env(base_env, allowlist, creds)` — add this small pure helper + tests to df_creds in THIS task (allowed: Task-2 commit touches df_creds for it).
    - `TWIN_ENV_SKIPPED` semantics unchanged (twin env still not forwarded at hardened).
  - Manifest: additive `credentials = {"source":..., "allowlist": [...]} if configured else None` — names only, NEVER values — on every terminal manifest (fresh + resume; the M9/M10 threading pattern).
- [ ] **Step 1 (TDD):** `test_creds_config.py` —
  - config matrix: absent block → None; valid env-file/keychain/env shapes; each ConfigError case above (incl. env_file inside control root / workspace).
  - launcher_scoped_env: strips `FOO_API_KEY`/`X_TOKEN`/`A_SECRET`/`B_PASSWORD` not allowlisted; keeps `PATH`/`HOME`; keeps allowlisted `ANTHROPIC_API_KEY`; merges creds last.
  - supervisor (monkeypatched load_credentials + captured invoke_adapter): at hardened, builder container argv contains `-e NAME=value` for exactly the allowlist and `builder_env is creds`; at standard, the captured env_extra has the stripped+merged shape; unresolvable creds → run exits 2 BEFORE any builder call; journal entries containing a cred value are redacted on disk (write a journal event with the value smuggled into a field via a stub, read journal.ndjson back, assert `***REDACTED***`); manifest has names-only `credentials` field on converged AND on an abort path; resume path re-resolves creds (state.json never stores values — assert).
- [ ] **Step 2:** Verify fail → implement → green (existing suite intact).
- [ ] **Step 3:** config-reference rows. Full suite green. Commit `feat(dark-factory): brokered builder credentials — allowlist env, redacted artifacts, fail-closed resolution`.

---

### Task 3: e2e + docs

**Files:** create `dark-factory/tests/test_e2e_credentials.py`, `dark-factory/references/credentials.md`; modify `SKILL.md`.

- [ ] **Step 1:** `test_e2e_credentials.py` (CLI subprocess; new fixture `fake_builder_envdump` — a fake_builder copy that also writes `sorted(os.environ)` KEYS (names only) to `env_seen.txt` in the workspace AND actively tries to smuggle the VALUE of `DF_TEST_CRED` into supervisor-captured output. **Smuggle channel:** read the real adapter protocol / supervisor capture points first (adapter stderr tails on failure, journaled BUILD data, checkpoint report fields) and pick one that verifiably lands in a run_dir artifact — e.g. fail iteration 1 with the value in the adapter's stderr/error message (STUBBORN-style), converge on iteration 2. The e2e must then assert BOTH: the value string appears NOWHERE under run_dir or in CLI stdout/stderr, AND `***REDACTED***` appears somewhere in the run artifacts — the second assertion proves the smuggle reached a written artifact and the redactor fired, i.e. the absence check is non-vacuous):
  - **(a) hardened brokered env (live docker, skipif):** credentials env-file source (0600 file in a 3rd tmp dir, `DF_TEST_CRED=supersecret-...uuid`), allowlist `["DF_TEST_CRED"]`, hardened defaults → exit 0; `env_seen.txt` contains `DF_TEST_CRED` and `HOME` but NOT a control var planted in the supervisor's env before the run (e.g. `DF_LEAKME_API_KEY`) — allowlist-only proven; the smuggle assertions above; manifest `credentials` field is names-only.
  - **(b) standard launcher-scoping (no docker needed):** same env-file, assurance standard, supervisor launched with `DF_LEAKME_API_KEY=evil` in its env → builder's `env_seen.txt` has `DF_TEST_CRED`, has `PATH`, does NOT have `DF_LEAKME_API_KEY`.
  - **(c) gitignore refusal:** env-file inside a fresh `git init` tmp repo, not ignored → exit 2, stderr mentions gitignore; add the ignore → run proceeds past credential resolution (any later outcome fine — assert the credentials error is gone).
  - **(d) unresolvable → refusal:** allowlist names a var missing from the env-file → exit 2 before any builder call (no runs/*/iterations artifacts beyond the pre-build gates).
- [ ] **Step 2:** `credentials.md`: the containment model (allowlist-only, scrubbed artifacts, gitignore/permission gates, launcher-scoped standard-tier env); the honest limits (static keys stay static — no rotation; `-e` argv visible to local `ps` at hardened — noted with the --env-file alternative; bridge-network exfiltration by a malicious builder is out of scope until the enterprise credential proxy; keychain = macOS `security` in M11). SKILL.md: credentials sub-step (point at env-file/keychain per the user guardrail: never commit credentials; gitignore enforced). config-reference cross-check.
- [ ] **Step 3:** Docs-vs-code verify; full suite green; commit `feat(dark-factory): credential broker e2e (allowlist, scrubbing, gitignore) + docs`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M11):** spec §7.3 standard — "provider credentials launcher-scoped and excluded from the builder's env allowlist" (launcher_scoped_env strip + allowlist), `.gitignore` **plus** `git check-ignore` + `git ls-files` verification (check_gitignored does exactly these two), log redaction (Redactor at every serialization choke point), secret-scan backstop already mandatory from M9; §7.3 hardened — role-scoped credentials with raw tokens scrubbed from role artifacts (allowlist into the container only, redacted everywhere else). The user's standing guardrail (env-file/keychain, never shared publicly, gitignore enforced) is now machine-enforced, fail-closed.

**Deliberately deferred (honest, in credentials.md):** true short-lived/rotating credentials (provider-dependent); the enterprise **host-side credential proxy** (tokens never entering any sandbox + query-level egress control) — that is the enterprise tier's core and needs a real authenticating proxy; the read-only pinned dependency proxy/cache; Linux keychain (`secret-tool`); `--env-file`-based injection to hide values from local `ps` (documented alternative).

**Honesty note:** M11 is containment, not rotation — credentials.md says so in the first paragraph; and the `-e` argv `ps`-visibility residual at hardened is disclosed rather than hidden.
