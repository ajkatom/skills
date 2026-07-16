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

## The built-ins

All stdlib-only (`re`, `os`, `ast` not needed — line-based regex is
sufficient here — `json`, `shutil`, `subprocess`, `tomllib` when available),
deterministic (sorted file walk, no randomness), no network I/O. Binary
files (a NUL byte in the first read chunk) and `.git`/symlinks are skipped.

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

### `license` (M18)

Spec §7.6 lists license policy among the mandatory security gates; this is
its offline implementation. An **offline license-policy gate** against an
operator-supplied allowlist,
opt-in via `security_gates.license.enabled` (default `false`, absent block
→ no license gate at all, byte-identical to pre-M18). Runs
`df_security.license_scan(workspace, allowlist, require_license=...)`
and produces findings `{"file", "package", "license", "rule"}` where
`rule` is `"disallowed-license"` (a declared license not in the allowlist)
or `"missing-license"` (a discovered package with no declared license at
all, only reported when `require_license: true`). Matching is
case-insensitive; an **empty allowlist disallows every declared license**
(the operator must list them explicitly — there is no implicit "anything
goes" state).

**Sources — declared/vendored metadata physically present in the
workspace only, no network:**

- `pyproject.toml`: `[project].license` (a string, or `{text = "..."}` —
  `{file = "..."}` alone contributes no checkable text, since reading an
  arbitrarily-named referenced file for its contents is out of scope) and
  any `License ::` trove classifier in `[project].classifiers` (e.g.
  `"License :: OSI Approved :: MIT License"` → declared value `"MIT
  License"`).
- `package.json`: the modern `"license"` field (an SPDX string, or a
  `{"type": ...}` object) and the legacy `"licenses"` array
  (`[{"type": "MIT"}, ...]` or a bare string list).
- Vendored `node_modules/<pkg>/package.json` (including scoped packages,
  `node_modules/@scope/pkg/package.json`, and nested vendoring) — the
  same `"license"`/`"licenses"` parse, findings named by the vendored
  package's directory path (e.g. `"foo"`, `"@scope/foo"`), not the root
  project.
- Vendored `*.dist-info/METADATA` — `License:` and `Classifier: License
  :: ...` header lines (scan stops at the first blank line, i.e. the end
  of the RFC822-style header block, so the free-text description can
  never spuriously match). Package name comes from the `Name:` header,
  falling back to parsing the `<name>-<version>.dist-info` directory name
  if absent.

**Parser note:** pyproject.toml is parsed with stdlib `tomllib` when
available (Python 3.11+), falling back to the same tolerant best-effort
line/regex scan style `sbom()` already uses for its `[project]
dependencies` array, for interpreters where `tomllib` doesn't exist.

### `dependency_audit` (M23)

Spec residue #6 (network dependency/CVE analysis), added as a **tier-aware**
gate: `df_depaudit.parse_installed(workspace)` extracts the artifact's
PINNED dependencies (`requirements.txt` `name==version`, `package.json`
exact versions, best-effort `pyproject.toml`, vendored `*.dist-info` /
`node_modules/<pkg>` installs), then each `{name, version, ecosystem}` is
checked against the **OSV vulnerability database** for known CVEs. Opt-in
via `security_gates.dependency_audit.enabled` (default `false`, absent
block → no gate at all, byte-identical to pre-M23 — zero network calls,
ever). A finding is `{"name", "version", "ecosystem", "vuln_ids", "source"}`
— package identity + OSV vuln IDs only, never artifact source or secrets.

**Two backends, selected by `security_gates.dependency_audit.source`, and
a TIER POLICY that keeps every tier's egress promise intact:**

| `source` | What it does | Network egress | Allowed tiers |
|---|---|---|---|
| `osv-api` | POSTs each `{name, version, ecosystem}` **live** to `api.osv.dev` | **Yes** — sends dependency names+versions to `api.osv.dev` over the network, every run | `cooperative`, `standard` only. **`ConfigError` at `hardened`/`enterprise`** at config load: *"`<tier>` forbids uncontrolled network egress; use source: osv-snapshot"* |
| `osv-snapshot` | Matches pinned versions against a **pre-provisioned local OSV export**, fully offline | **None, ever** — no fetcher parameter exists on this code path; it cannot reach the network by construction | **Every tier**, including `hardened`/`enterprise` |

Net effect: every tier can get a CVE check, and no tier's egress guarantee
is ever broken by turning this gate on.

**PROMINENT EGRESS CAVEAT (`osv-api`):** this is the **one** place in the
built-in security gates where turning on a config flag makes an outbound
network call during a run. It is opt-in, off by default, and sends ONLY
dependency **names and versions** (never source code, secrets, or any
other artifact content) to Google's `api.osv.dev`. If you need a CVE
check with zero run-time egress — including at `cooperative`/`standard`,
not just where it's mandatory — use `osv-snapshot` instead.

**Offline snapshot provisioning (`osv-snapshot`):** the snapshot is never
fetched during a sealed run. An operator runs
`df_depaudit.fetch_snapshot(ecosystem, dest_dir)` **out-of-band**, ahead of
time (the same posture as building the hardened Docker image — a
provisioning step outside any run), which downloads OSV's published
per-ecosystem export (`https://osv-vulnerabilities.storage.googleapis.com/
<ecosystem>/all.zip`) and unzips its `*.json` records into
`dest_dir/<ecosystem>/`. **Freshness of the snapshot is the operator's
documented responsibility** — `dependency_audit` never re-fetches it, and
an unrefreshed snapshot will not know about CVEs published after it was
taken. Re-run `fetch_snapshot` on whatever cadence your risk posture
requires.

**Honest matching scope (`osv-snapshot`), reliably matches:**

- A package version **enumerated** in an OSV record's
  `affected[].versions` list — an exact match.
- A version falling inside a **simple** `introduced`/`fixed` range (one
  `introduced` event, one `fixed` event, cleanly-parsed dotted-numeric
  versions — packaging-style release-tuple compare for PyPI, semver-ish
  tuple compare for npm).

**Under-matches, relative to the live API, on:**

- Complex range expressions (multiple `introduced`/`fixed` pairs, a
  `limit`/`last_affected` event, or an unparseable version string in a
  range) on a package whose **name** still matches a snapshot record.

The matcher deliberately **errs toward flagging**: any of the above
ambiguous cases is reported as a finding with a `"range-uncertain"` note
rather than silently dropped — a false negative (missing a real vuln) is
the dangerous direction, and a false positive here just costs a human a
look at an over-cautious finding, exactly the same trade-off the other
built-in gates make. If your snapshot data trips this often, cross-check
suspicious packages with `osv-api` at a lower tier, or keep the snapshot
current.

**Fail-closed unavailable, both backends:** any backend error — `osv-api`
network failure/timeout/non-200/bad JSON on any package, or a missing/
empty/corrupt `osv-snapshot` directory — makes the gate `status:
"unavailable"`, never a silent pass. Under `fail_on` + `strict_unavailable`
(the default), an unavailable `dependency_audit` gate counts as a run
failure, same as every other mandatory gate.

**Not covered (honest, deferred):**

- Routing the live `osv-api` query through the enterprise
  credential-proxy allowlist, which would let `hardened`/`enterprise` use
  the live API under governed egress instead of the offline snapshot —
  real plumbing (the gate runs host-side, not inside the builder
  container) that the offline snapshot covers the need for today.
- A full, ecosystem-correct version-range solver — the offline matcher is
  intentionally best-effort (see above), not a reimplementation of each
  ecosystem's real version-comparison semantics (PEP 440, semver, etc. in
  full).
- Non-OSV vulnerability sources / commercial SCA tooling — plug one in
  via the external-gate interface below if you need it.
- Snapshot auto-refresh/caching policy — `fetch_snapshot` is
  operator-run, on whatever schedule the operator chooses; there is no
  built-in staleness check or auto-refresh.
- Audits **declared/pinned** dependencies (+ pinned transitives shipped
  in a lockfile/vendored tree) — like `sbom`/`license`, not a from-scratch
  dependency solve of everything that would be installed from an
  unpinned manifest.

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
- **`license` covers declared/vendored metadata physically present in the
  tree — not the full transitive dependency graph.** A dependency that is
  merely NAMED in a manifest's `dependencies` list but never vendored
  anywhere in the workspace (a normal state for an un-vendored pip/npm
  install) is simply invisible to `license_scan` — it produces no
  finding either way, and is **not silently treated as license-compliant**
  under `require_license`. Resolving such a dependency's real license
  would require a network lookup (PyPI/npm registry) or a bundled SPDX/
  license database, both out of scope for an offline, stdlib-only tool.
  If you need full transitive coverage, resolve the dependency tree and
  vendor it (or its metadata) into the artifact before the gate runs, or
  plug in a real tool via the external-gate interface below.

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
  (`secret_scan`, `dangerous_scan`, `sbom`, `license`, `dependency_audit`
  are reserved).
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
— `secret_scan`/`dangerous_scan`/`sbom`/`license`/`dependency_audit` or a
declared `external[].name`.
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
    "sbom": {"status": "pass", "sbom": {"declared": {...}, "count": 3, "unpinned": []}},
    "license": {"status": "pass", "findings": []},
    "dependency_audit": {"status": "pass", "findings": []}
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
- **Resolved transitive dependency graphs.** `sbom` is a declared-dependency
  inventory (from manifest files), not a resolved graph, and still does no
  network calls itself. **CVE lookup against PINNED dependencies** is now
  covered by the opt-in `dependency_audit` gate (M23, see above) — but it
  audits pinned/vendored deps only, not a from-scratch resolve of an
  unpinned manifest's full transitive tree.
- **License resolution for un-vendored transitive dependencies.** `license`
  (M18) enforces an allowlist against licenses declared in manifests and
  vendored metadata physically present in the artifact; it does not (and,
  offline/stdlib-only, cannot) resolve the license of a dependency that's
  merely named in a manifest but never vendored into the tree — see the
  `license` honest-scope note above.
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
