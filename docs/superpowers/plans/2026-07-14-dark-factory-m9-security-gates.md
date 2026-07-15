# dark-factory M9 — Mandatory Security Gates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Because no human reviews the built code, run **mandatory security gates on the converged artifact, independent of scenario pass-rate** (§7.6/§15.10): a **secret scan**, a **dangerous-pattern / negative-security-invariant scan**, and an **SBOM** of declared dependencies — all stdlib-only and genuinely working — plus a **pluggable external-command gate** interface (run `bandit`/`semgrep`/`trufflehog`/etc. when installed, else honestly record `unavailable`). A finding on a **mandatory** gate makes the run terminal `SECURITY_GATE_FAILED` (exit 3, never qualified) even when every scenario passed. Fail-closed: a mandatory gate whose tool is unavailable does not silently "pass."

**Architecture:** `df_security.py` holds pure scanners over a directory. `run_gates(workspace, cfg_gates) -> report` runs the built-ins + configured external gates (probing each command's presence), returns per-gate `{status: pass|fail|unavailable, findings|detail}`. The supervisor runs the gates AFTER dev converges + the final exam passes, on the workspace artifact; if any gate in `fail_on` returns `fail` (or `unavailable` at `hardened`+ / when configured strict) → journal `SECURITY_GATE_FAILED`, finalize a manifest (qualified=False, security=report), return 3. On pass → CONVERGED as today, with the `security` report in the manifest.

**Honest scope (stated in docs):** the built-in scanners are **heuristic and pattern-based**, not a full SAST/secret-detection engine — they catch the common, high-value cases (private-key blocks, cloud keys, `eval/exec/os.system/shell=True/pickle.loads`, unpinned deps) and are explicitly a floor, not a ceiling; the external-gate interface is how you add a real SAST. Secret/dangerous scans can have false positives (that's the safe direction for a mandatory gate — a human adjudicates a `SECURITY_GATE_FAILED`). SBOM is a **declared-dependency inventory** (from requirements/package manifests), not a resolved transitive graph. Findings are heuristic — a passing gate is not a security guarantee.

**Tech Stack:** Python stdlib only (`re`, `os`, `ast`, `json`, `shutil`, `subprocess`). pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Runtime stdlib only.** Back-compatible: absent `security_gates` block (or `enabled:false`) → gates skipped, manifest `security.checked=false`; existing tests stay green.
- **Gates run on the CONVERGED artifact, independent of scenario pass** — a clean scenario run with a planted secret still fails the security gate.
- **Fail-closed:** a gate listed in `fail_on` that returns `fail` → `SECURITY_GATE_FAILED` (exit 3, qualified False). A `fail_on` gate that is `unavailable` (external tool missing) is treated as a failure when `strict_unavailable` is set (default true) — a mandatory gate you can't run is not a pass.
- **Barrier untouched:** gates scan the workspace artifact (shared plane) + declared deps; findings recorded control-plane. No holdout scenario content is involved. Findings must not include holdout content (they're about the artifact — inherently safe).
- **Deterministic** built-in scanners (regex/AST over sorted file walk); no network.
- **Exit codes unchanged (0/2/3/10):** `SECURITY_GATE_FAILED` is a non-converged terminal → exit 3 (human evaluates), distinguished by outcome.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_security.py    # Task 1 — secret_scan, dangerous_scan, sbom (pure); Task 2 run_gates
    df_config.py      # Task 2 — validate security_gates; inject cfg["_security"]
    supervisor.py     # Task 3 — run gates after converge; SECURITY_GATE_FAILED; manifest security
  references/
    security-gates.md # Task 3 — the gates, external interface, honest heuristic caveat
    config-reference.md
  SKILL.md            # Task 3
  tests/
    test_security_scanners.py  # Task 1
    test_security_gates.py     # Task 2
    test_e2e_security.py        # Task 3
```

Control plane: `security_gates` config block (Task 2).

---

### Task 1: Built-in security scanners (`df_security.py`)

**Files:** create `dark-factory/scripts/df_security.py` + `dark-factory/tests/test_security_scanners.py`.

**Interfaces (pure, over a directory; skip `.git`, follow no symlinks):**
- `df_security.secret_scan(root: str) -> list[dict]` — scan text files for secret patterns; each finding `{"file": relpath, "line": int, "rule": str}` (rule name only — do NOT include the matched secret value in the finding). Rules (compiled regex): `private_key` (`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`), `aws_access_key` (`AKIA[0-9A-Z]{16}`), `slack_token` (`xox[baprs]-[0-9A-Za-z-]{10,}`), `generic_secret_assignment` (`(?i)(?:api[_-]?key|secret|token|password)\s*[=:]\s*['\"][^'\"\n]{16,}['\"]`). Skip binary files (a NUL byte in the first chunk). Sorted by (file, line).
- `df_security.dangerous_scan(root: str) -> list[dict]` — scan `*.py` files for negative-security-invariant patterns; findings `{"file","line","rule"}`. Rules (regex, line-based): `eval_exec` (`\b(?:eval|exec)\s*\(`), `os_system` (`\bos\.system\s*\(`), `shell_true` (`shell\s*=\s*True`), `pickle_loads` (`\bpickle\.loads\s*\(`), `yaml_unsafe` (`\byaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)`). Sorted.
- `df_security.sbom(root: str) -> dict` — declared-dependency inventory: parse `requirements.txt` (one dep per non-comment line), `package.json` (`dependencies`+`devDependencies` keys), `pyproject.toml` (best-effort: `[project] dependencies` array via a simple line scan — stdlib has no tomllib pre-3.11, so do a tolerant regex/line parse and mark `parser: "best-effort"`). Return `{"declared": {"<ecosystem>": [<name==ver or name>...]}, "count": N, "unpinned": [deps without a version]}`. Missing manifest files → empty inventory (not an error).

- [ ] **Step 1: Write failing tests** `test_security_scanners.py`:
  - secret_scan: a file containing a fake `AKIA................` (16 caps), a `-----BEGIN PRIVATE KEY-----` block, an `api_key = "0123456789abcdef0123"` → 3 findings with correct rules; the finding does NOT contain the secret value (assert the matched literal isn't in `json.dumps(findings)`); a clean file → []; a binary file (NUL byte) skipped.
  - dangerous_scan: a py file with `eval(x)`, `os.system(cmd)`, `subprocess.run(c, shell=True)`, `pickle.loads(d)` → 4 findings; a clean py file → [].
  - sbom: a dir with `requirements.txt` (`flask==2.0`, `requests` [unpinned], `# comment`) → declared.pip has flask==2.0 + requests, unpinned includes requests; a `package.json` with dependencies → declared.npm listed; no manifests → empty.
- [ ] **Step 2-4:** implement; verify; full suite green (255 + new). **Step 5:** commit `feat(dark-factory): stdlib security scanners (secret, dangerous-pattern, sbom)`.

---

### Task 2: `security_gates` config + gate runner

**Files:** modify `df_security.py` (add `run_gates`) + `df_config.py`; create `test_security_gates.py`.

**Interfaces:**
- df_config injects `cfg["_security"]`:
  ```
  {"enabled": bool,                 # default False
   "secret_scan": bool,             # default True when enabled
   "dangerous_scan": bool,          # default True when enabled
   "sbom": bool,                    # default True when enabled
   "external": [{"name": str, "cmd": [str,...]}],   # optional external gates
   "fail_on": [str],                # gate names that are MANDATORY (finding→fail run). default ["secret_scan","dangerous_scan"] when enabled
   "strict_unavailable": bool}      # default True: a fail_on external gate that's unavailable => fail
  ```
  Validation: booleans are bool; `external` a list of `{name:str, cmd:[str,...] non-empty}`; `fail_on` a list of known gate names (`secret_scan`,`dangerous_scan`,`sbom`, or an external gate `name`); `enabled` absent → `{"enabled": False}` and gates skipped. Malformed → ConfigError.
- `df_security.run_gates(workspace: str, sec: dict) -> dict` — runs the enabled built-ins + external gates:
  - built-ins: `secret_scan`→ status `fail` if findings else `pass`, with `findings`; same for `dangerous_scan`; `sbom` → always `pass` with the inventory (informational; only `fail_on`-listed gates can fail the run — sbom typically informational).
  - external gate `{name, cmd}`: if `shutil.which(cmd[0])` is None → status `unavailable`; else run `subprocess.run(cmd, cwd=workspace, capture_output=True, text=True, timeout=300)` → status `pass` if returncode 0 else `fail` (with a tail of output in `detail`, truncated). No network assumptions.
  - Return `{"checked": True, "gates": {name: {status, findings?/detail?}}, "failed": [names in fail_on that are fail, or unavailable when strict_unavailable]}`. The RUN fails iff `failed` is non-empty (supervisor enforces).

- [ ] **Step 1:** `test_security_gates.py`: config validation (defaults, bad external shape, unknown fail_on name → ConfigError); run_gates over a workspace with a planted secret + `fail_on:["secret_scan"]` → `failed==["secret_scan"]`; clean workspace → `failed==[]`; an external gate with a bogus command (`cmd:["definitely-not-a-real-tool-xyz"]`) in fail_on + strict_unavailable → `unavailable` and in `failed`; an external gate = `["true"]` (present) → pass; `["false"]` in fail_on → fail. (Use `/bin/true`/`/bin/false` via `["true"]`/`["false"]` — on PATH on macOS/Linux.)
- [ ] **Step 2-4:** implement; verify; full suite green. **Step 5:** commit `feat(dark-factory): security-gate config + runner (built-in + external, fail-closed)`.

---

### Task 3: Supervisor wiring + e2e + docs

**Files:** modify `supervisor.py`; create `references/security-gates.md`, `test_e2e_security.py`; modify `SKILL.md`, `config-reference.md`.

**Interfaces:** Read `_run_loop`'s converged path (post-dev-converge, post-final-exam, from M6/M7). Add, when `cfg["_security"]["enabled"]`, AFTER the final exam passes and BEFORE declaring CONVERGED:
1. `sec_report = df_security.run_gates(workspace, cfg["_security"])`; write `security_report.json` to run_dir; journal `SECURITY_GATES(checked=True, failed=sec_report["failed"])`.
2. If `sec_report["failed"]`: journal `SECURITY_GATE_FAILED(failed=...)`, finalize manifest outcome `SECURITY_GATE_FAILED` + qualified=False + `security=sec_report`, `_clear_state`, `_kb_writeback`, print "security gate failed (artifact rejected): <failed>", return 3.
3. Else: CONVERGED as today, with `security=sec_report` in the manifest.
- When disabled: `security={"checked": False}` in all manifests (thread via manifest_base like M7's coverage/oracle).
- Gates run on the artifact (workspace) — barrier-safe (no holdout). This runs on the FINAL converged artifact only (not every iteration) — cheap + correct.

- [ ] **Step 1:** `test_e2e_security.py` (CLI subprocess): (a) a control whose builder writes a clean artifact + `security_gates.enabled` → converges exit 0, manifest `security.checked==True`, `security.failed==[]`; (b) a builder whose artifact contains a planted secret (e.g. a `config.py` with `AKIA` + a real-looking key) with `fail_on:["secret_scan"]` → the scenarios still pass (the greet behavior works) BUT the run ends `SECURITY_GATE_FAILED` exit 3 (proves gates are independent of scenario pass); (c) no security block → converges, `security.checked==False`. Build a fixture builder `fake_builder_secret` that writes a working greet.py PLUS a file with a planted fake secret.
- [ ] **Step 2:** `security-gates.md` (the three built-ins + external interface + fail_on/strict_unavailable + the honest heuristic/floor caveat + SECURITY_GATE_FAILED semantics). SKILL.md: security_gates config sub-step + note gates run on the converged artifact independent of scenario pass, and a finding rejects the artifact. config-reference rows.
- [ ] **Step 3:** verify docs vs code; full suite green; commit `feat(dark-factory): mandatory security gates on the converged artifact; e2e + docs`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M9):** mandatory security gates run on the converged artifact **independent of scenario pass** (§7.6/§15.10) — secret scanning, negative-security-invariant (dangerous-pattern) scanning, and an SBOM, all stdlib and genuinely working; a pluggable **external-command gate** interface for real SAST tools; **fail-closed** (a mandatory gate that fails, or a mandatory external gate that's unavailable under `strict_unavailable`, rejects the artifact via `SECURITY_GATE_FAILED`); the security report recorded on every terminal manifest (signed under audit.signing).

**Deliberately deferred (honest, in security-gates.md):** a bundled real SAST/secret engine (M9 ships heuristic built-ins + the interface to plug in `bandit`/`semgrep`/`trufflehog`); resolved **transitive** dependency graphs + CVE lookup (SBOM here is declared-deps only, no network); license-policy enforcement beyond recording; resource-limit *enforcement* on the built artifact at runtime (sandbox-tier concern). M9 makes "nobody reviewed the code" less scary by giving the machine a mandatory, fail-closed, pluggable security floor.

**Honesty note:** the built-in scanners are heuristic (pattern/AST), so they have false positives (safe direction for a mandatory gate — a human adjudicates the rejection) and false negatives (they are a floor, not a proof). security-gates.md states this and points to the external interface for stronger tools.
```
