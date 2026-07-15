# Mandatory security gates (M9) — a floor, not a proof

Because **no human reviews the built code** in a dark-factory run, the
supervisor runs a mandatory security check on the **converged artifact**
before it will ever declare `CONVERGED` — **independent of scenario
pass-rate**. A clean, fully-passing build with a planted secret in it still
gets rejected. This is opt-in (`security_gates.enabled`, default `false`,
back-compatible) but, once enabled, fail-closed: a finding on a gate listed
in `fail_on` makes the run terminal `SECURITY_GATE_FAILED` (exit 3, never
qualified), the same way `FINAL_EXAM_FAILED` does.

## When it runs

**After** dev converges and the sealed final exam (if any) passes, **before**
`CONVERGED` is declared. Gates run exactly **once**, on the final converged
workspace artifact — not on every iteration. This is deliberate: it's cheap
(one scan, not N), and it's correct (only the artifact you'd actually ship
needs to pass a security floor; intermediate buggy drafts don't).

Gates scan the **workspace artifact** (shared/control plane) — the same
tree the builder wrote, no holdout scenario content is ever involved. A
`security_report.json` is written into the run directory when gates ran;
`security: {"checked": false}` is recorded on every terminal manifest when
they didn't (gates disabled, or the run died before reaching the converged
gate — pre-build gate failure, build error, final-exam failure, a paused
run that was aborted/accepted, etc.).

## The three built-ins

All stdlib-only (`re`, `os`, `ast` not needed — line-based regex is
sufficient here — `json`, `shutil`, `subprocess`), deterministic (sorted
file walk, no randomness), no network I/O. Binary files (a NUL byte in the
first read chunk) and `.git`/symlinks are skipped.

### `secret_scan`

Scans every text file for four patterns: `private_key` (a PEM `-----BEGIN
... PRIVATE KEY-----` block), `aws_access_key` (`AKIA[0-9A-Z]{16}`),
`slack_token` (`xox[baprs]-...`), and `generic_secret_assignment` (an
`api_key`/`secret`/`token`/`password` variable assigned a quoted string
≥16 chars). Findings are `{"file", "line", "rule"}` — **the rule name
only, never the matched secret value**. This is load-bearing: the security
report, the manifest, and the journal are all run artifacts that may be
shared, logged, or committed, so the actual credential must never appear
in any of them.

### `dangerous_scan`

Scans `*.py` files for five negative-security-invariant patterns:
`eval_exec` (`eval(`/`exec(`), `os_system` (`os.system(`), `shell_true`
(`shell=True`, e.g. on `subprocess.run`), `pickle_loads`
(`pickle.loads(`), `yaml_unsafe` (**every** `yaml.load(` call — the rule
deliberately does not special-case `Loader=yaml.SafeLoader`, because a
line-scoped regex can't see a `Loader=` on another line; flagging safe
loads too is the accepted false-positive direction for a mandatory gate).
These are patterns that are *usually* a red
flag (arbitrary code execution, shell injection, insecure deserialization)
even though each has legitimate uses — see Honest scope below.

### `sbom`

A **declared-dependency inventory**, not a resolved dependency graph:
parses `requirements.txt` (one dep per line), `package.json`
(`dependencies` + `devDependencies`), and — best-effort, since the
stdlib has no `tomllib` before Python 3.11 — a tolerant line scan of
`pyproject.toml`'s `[project] dependencies` array (marked
`"parser": "best-effort"` in the report when used). Returns
`{"declared": {"<ecosystem>": [...]}, "count": N, "unpinned": [...]}`.
Missing manifest files are simply omitted, not an error. `sbom` is
**always `status: "pass"`** — it's informational unless you explicitly put
it in `fail_on`, and even then it has no failure condition of its own (no
declared-dependency shape currently constitutes a "finding").

## Honest scope — heuristic and a floor, not a full SAST engine

**These built-ins are pattern-based, not a real static-analysis or
secret-detection engine.** They catch the common, high-value cases and
nothing more:

- **False positives are the safe direction.** A mandatory gate that's
  too eager (e.g. a generic `secret = "..."` in a test fixture, a
  legitimate `subprocess.run(..., shell=True)` for a trusted, fully
  quoted command) fails closed and a human adjudicates the rejection.
  That's an acceptable cost for a mandatory gate — better a false alarm
  a human dismisses than a real leak that ships.
- **False negatives mean this is a floor, not a proof.** A regex-based
  secret scanner will miss secrets that don't match one of the four
  patterns (a custom internal token format, a secret split across
  concatenated strings, one base64-encoded inline). A pattern-based
  dangerous-scan will miss anything expressed differently (e.g.
  `getattr(os, "sys" + "tem")(cmd)`) or, symmetrically, will not
  understand that a particular `eval()` call is provably safe. **A
  passing gate is not a security guarantee** — it means the floor-level
  checks found nothing, not that the code was reviewed.
- **`sbom` is declared dependencies, not resolved ones.** No transitive
  dependency graph, no CVE lookup, no network calls of any kind (M9 is
  deliberately network-free — determinism and no data exfiltration
  concerns). "Nothing declared is obviously outdated" is not the same
  claim as "nothing in the dependency tree has a known CVE."

For anything stronger than this floor, use the **external gate**
interface below to plug in a real tool.

## The external-gate interface

`security_gates.external` is a list of `{"name": str, "cmd": [str, ...]}`
— pluggable commands run via `subprocess.run(cmd, cwd=workspace,
capture_output=True, text=True, timeout=300)`:

```json
"security_gates": {
  "enabled": true,
  "external": [
    {"name": "bandit", "cmd": ["bandit", "-r", "."]},
    {"name": "semgrep", "cmd": ["semgrep", "--config=auto", "--error"]}
  ],
  "fail_on": ["secret_scan", "dangerous_scan", "bandit"]
}
```

- `name` must be unique and must not collide with a built-in name
  (`secret_scan`, `dangerous_scan`, `sbom` are reserved).
- **Probed, not assumed.** Before running, `shutil.which(cmd[0])` checks
  the command is actually on `PATH`. Missing → `status: "unavailable"`
  (never a silent pass). A spawn error or a 300s timeout is also
  `unavailable`, with the error in `detail`.
- **Exit-code convention.** Return code `0` → `status: "pass"`. Any
  non-zero → `status: "fail"`, with a truncated tail (last ~2000 chars)
  of stderr (or stdout if stderr is empty) in `detail`. This matches how
  `bandit`, `semgrep`, `trufflehog`, etc. already signal findings via
  exit code — no custom output parsing needed.
- Runs with `cwd=workspace` — the same converged artifact the built-ins
  scan. No holdout scenario content is reachable from there, so an
  external tool has the same barrier guarantee as the built-ins.

## `fail_on` and `strict_unavailable` — fail-closed semantics

`fail_on` (default `["secret_scan", "dangerous_scan"]` when
`security_gates.enabled`) is the list of gate names that are **mandatory**
— `secret_scan`/`dangerous_scan`/`sbom` or a declared `external[].name`.
A gate not listed in `fail_on` can still run and appear in the report, but
a finding on it never rejects the run (it's recorded, not enforced —
useful for `sbom` or an external gate you want visibility into before
making it mandatory).

**`strict_unavailable` (default `true`)** governs what happens when a
`fail_on` gate comes back `unavailable` — either an external tool missing
from `PATH`, or (regression-hardened) a built-in `fail_on` gate whose flag
was turned off (e.g. `dangerous_scan: false` but `dangerous_scan` still
listed in `fail_on` — it never ran, so it's reported `unavailable`, not
silently absent from `failed`). Under `strict_unavailable: true`, an
unavailable mandatory gate **counts as a failure**: *"a mandatory gate you
can't run is not a pass."* This is deliberate fail-closed design — without
it, uninstalling `bandit` from CI would silently downgrade a "must pass
bandit" policy into "bandit's absence is fine." Set `strict_unavailable:
false` only if you genuinely want an optional-when-installed posture for
mandatory-named gates (uncommon; prefer just not listing the gate in
`fail_on` instead).

The **run fails iff `run_gates()`'s `failed` list is non-empty** — i.e.
at least one `fail_on` gate is `fail`, or (under `strict_unavailable`)
`unavailable`.

## `SECURITY_GATE_FAILED` — artifact rejected

When gates run and `failed` is non-empty:

1. Journal `SECURITY_GATE_FAILED(failed=[...])` (gate **names** only —
   never finding detail, never secret values).
2. Finalize the manifest: `outcome: "SECURITY_GATE_FAILED"`,
   `qualified: false` (unconditionally — a security-rejected artifact is
   never a qualified ship-candidate regardless of tier), `security:
   <full report>`.
3. Clear `state.json` (terminal, not resumable via `continue` — same as
   `FINAL_EXAM_FAILED`; a human must decide, then re-run or fix the spec
   and start fresh).
4. Opt-in KB write-back, if configured (outcome-level only, same
   barrier-safe fields as any other terminal).
5. Print `"dark-factory: security gate failed (artifact rejected):
   <gate names>. Run: <run_dir>"` and return exit **3** — the same code
   as `CAP_REACHED`/`FINAL_EXAM_FAILED`: a non-converged terminal that a
   human evaluates, distinguished by `outcome`.

**This is independent of scenario pass.** Every dev scenario (and the
sealed final exam, if present) can pass, and the run still ends
`SECURITY_GATE_FAILED` if a mandatory gate finds something — that's the
whole point: nobody reviewed the code, and passing behavioral tests says
nothing about whether the code also planted a secret or called
`eval()` on untrusted input.

## Manifest `security` field

Every terminal manifest from every code path — pre-build gate failures,
build errors, `CAP_REACHED`, `FINAL_EXAM_FAILED`, `CONVERGED`
(`COMPLETE_QUALIFIED`/`COMPLETE_UNQUALIFIED`), `SECURITY_GATE_FAILED`, and
(via `resume`) `ABORTED_BY_HUMAN`/`ACCEPTED_WAIVED`/a resumed
`CONVERGED` — carries a `security` field, threaded through `manifest_base`
the same way M7 threads `coverage`/`oracle`:

```json
"security": {"checked": false}
```

when gates are disabled, or the run terminated before the gates ever ran
(any outcome before `CONVERGED`/`SECURITY_GATE_FAILED`); or the full
report:

```json
"security": {
  "checked": true,
  "gates": {
    "secret_scan": {"status": "pass", "findings": []},
    "dangerous_scan": {"status": "pass", "findings": []},
    "sbom": {"status": "pass", "sbom": {"declared": {...}, "count": 3, "unpinned": []}}
  },
  "failed": []
}
```

on `CONVERGED`/`SECURITY_GATE_FAILED` when gates ran. `security_report.json`
in the run directory is the same object, written whenever gates ran
(regardless of pass/fail) — a copy on disk independent of `manifest.json`,
for tooling that wants to inspect the raw report.

**Resume threads it identically.** Gates run inside `_run_loop`'s
`CONVERGED` branch, which is the **same function** both a fresh `run` and
a `resume --decision continue` funnel through — a paused-then-resumed run
that converges gets the exact same gate treatment as a fresh converge,
with no separate wiring. `resume --decision abort`/`accept` never reach
that branch (gates never run for them), so their manifests carry
`security: {"checked": false}`, honestly reflecting that the artifact was
never gate-checked.

## Deferred (honest, not shipped in M9)

- **A bundled real SAST/secret-detection engine.** M9 ships heuristic
  built-ins plus the external-gate interface to plug in `bandit`,
  `semgrep`, `trufflehog`, or similar — it does not vendor one of those
  tools itself.
- **Resolved transitive dependency graphs + CVE lookup.** `sbom` is a
  declared-dependency inventory (from manifest files), not a resolved
  graph, and does no network calls (no CVE database lookup).
- **License-policy enforcement.** Nothing in `sbom` inspects or enforces
  package licenses beyond recording the declared dependency names.
- **Resource-limit enforcement on the built artifact at runtime.** That's
  a sandbox-tier concern (see `references/isolation.md`), not a
  build-time security gate.

## See also

- `references/config-reference.md` — `security_gates.*` schema +
  validation rules
- `references/coverage-gates.md` — the M7 pre-build gate (mutation +
  coverage); `security_gates` is the analogous **post**-build,
  **post**-final-exam mandatory gate on the converged artifact
- `references/budget.md` — another mandatory-by-config control that
  threads a field through every terminal manifest the same way
