# dark-factory M23 — Network Dependency/CVE Audit Gate (opt-in) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add an **opt-in** `dependency_audit` security gate that resolves the artifact's declared dependencies (name+version from `requirements.txt`/`package.json`/`pyproject.toml`) and queries the **OSV vulnerability database** (api.osv.dev) for known CVEs — a finding on a vulnerable dependency rejects the artifact fail-closed. This is a **deliberate, documented departure from dark-factory's offline/no-exfiltration model**: it makes outbound network calls and sends declared **dependency names + versions** (not artifact content, not secrets) to OSV. Default OFF; when enabled a network failure reports the gate **unavailable** (fail-closed under `strict_unavailable`), never a silent pass.

**Architecture:** New module `df_depaudit.py` (stdlib `urllib` — no new dependency): `parse_installed(root)` extracts `[{ecosystem, name, version}]` from the artifact's manifests (only entries with a pinned version — OSV needs a version); `query_osv(pkgs, fetcher=...)` POSTs each to `https://api.osv.dev/v1/query` and returns `[{name, version, ecosystem, vulns:[{id, summary}]}]`; the HTTP fetch is via an **injectable `fetcher`** so unit tests use a fake (canned OSV responses) and one live test (skipif no network) hits the real API. `run_gates` (M9) gains a `dependency_audit` gate: enabled via `security_gates.dependency_audit`; a dependency with ≥1 OSV vuln → `status:"fail"` (finding: name/version/vuln-ids — no secret); a network/parse error → `status:"unavailable"` (so under `fail_on`+`strict_unavailable` it rejects, like an external gate). Nothing about the audit reaches the builder (barrier unchanged).

**Honest scope (stated in docs):** this gate **makes network calls and egresses dependency names+versions to OSV** — that is the whole point and it is opt-in + documented, NOT the offline default. It audits **declared/pinned** dependencies present in the manifests (an unpinned dep is skipped — OSV needs a version; reported as `audited:false`), not a fully-resolved transitive lockfile graph (if the artifact ships a lockfile with pinned transitives those ARE audited; otherwise only direct pinned deps). It is not a replacement for a dedicated SCA tool — it is a real CVE check against a real database, with OSV's coverage/latency caveats. A network failure is **unavailable, not pass** (fail-closed).

**Tech Stack:** Python stdlib (urllib). pytest. Network for the ONE live OSV test (skipif). `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Opt-in + off by default:** absent `security_gates.dependency_audit` → the gate never runs, no network call ever happens (the offline default is preserved). All 997 existing tests stay green + make zero network calls.
- **Fail-closed on unavailable:** a network error / OSV non-200 / timeout → the gate is `unavailable`; when `dependency_audit` ∈ `fail_on` and `strict_unavailable` → it rejects the artifact (SECURITY_GATE_FAILED), never a silent pass. (Consistent with M9 external-gate semantics.)
- **Barrier + no secret egress:** only dependency NAMES+VERSIONS (from the artifact's manifests) are sent to OSV — never artifact source, never any credential/secret; the redactor is applied to the gate's findings before they hit run artifacts (defense in depth). Nothing about the audit reaches the builder.
- **Deterministic tests, one live probe:** all logic tests use an injected fake fetcher (canned OSV JSON); exactly ONE live test hits the real api.osv.dev (skipif no network) for a known-vulnerable pinned package to prove the real integration; a bounded timeout on every call.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_depaudit.py     # Task 1 — parse_installed + query_osv (injectable fetcher)
    df_security.py     # Task 2 — dependency_audit gate in run_gates
    df_config.py       # Task 2 — security_gates.dependency_audit config
    supervisor.py      # (already calls run_gates; ensure redactor applies)
  references/
    security-gates.md  # Task 2 — the network gate + the honest egress caveat
    config-reference.md
  tests/
    test_depaudit.py         # Task 1
    test_depaudit_gate.py     # Task 2
```

---

### Task 1: df_depaudit — parse_installed + OSV client

**Files:** create `dark-factory/scripts/df_depaudit.py`, `dark-factory/tests/test_depaudit.py`.

**Interfaces (Produces):**
```python
class DepAuditError(RuntimeError): ...

def parse_installed(root: str) -> list[dict]
    # scan the artifact tree (skip .git/binary/symlinks like df_security):
    #   requirements.txt lines "name==version" -> {ecosystem:"PyPI", name, version};
    #   package.json dependencies/devDependencies with an EXACT version (no ^/~/*
    #   ranges) -> {ecosystem:"npm", name, version};
    #   pyproject.toml [project] dependencies "name==version" (best-effort) -> PyPI;
    #   vendored *.dist-info -> {PyPI, name, version} from the dir name;
    #   node_modules/<pkg>/package.json exact "version" -> npm.
    # Only PINNED entries (a concrete version). Deduped, sorted. Never raises on a
    # malformed manifest (skip it, errors="ignore").

def query_osv(pkgs: list[dict], *, fetcher=_urlopen_fetch, timeout_s: int = 20) -> dict
    # POST each pkg to https://api.osv.dev/v1/query with body
    #   {"version": v, "package": {"name": n, "ecosystem": e}}.
    # fetcher(url, data_bytes, timeout) -> (status:int, body:bytes); default uses
    # urllib. Returns {"checked": True, "results": [{name,version,ecosystem,
    #   vulns:[{id, summary}]}], "unavailable": bool, "reason": str}.
    # ANY fetch error / non-200 / JSON error on ANY package -> unavailable:True
    # (fail-closed: a partial audit is not a clean audit) with a reason; never
    # raises. A package with no vulns -> vulns:[]. dependency names only in the
    # request; NEVER any secret.
```

- [ ] **Step 1 (TDD):** `test_depaudit.py` — parse_installed over a tmp tree: requirements.txt pinned/unpinned (unpinned skipped), package.json exact vs `^1.0.0` range (range skipped), a vendored dist-info, node_modules exact — deduped/sorted; malformed manifest → skipped not raised; non-UTF8 manifest → no crash. query_osv with an INJECTED fake fetcher: a canned OSV response with a vuln → results include the vuln id; no-vuln response → vulns:[]; the fetcher raising / returning 500 / bad JSON → unavailable:True (never raises), reason set; assert the request body sent to the fetcher contains ONLY name/version/ecosystem (no extra fields, no secrets). **Live (skipif no network):** query_osv against the real api.osv.dev for a KNOWN-vulnerable pinned package (e.g. PyPI `jinja2==2.4.1` or a documented old CVE'd version) → unavailable:False AND at least one vuln id returned (proves the real integration); a clearly-safe/nonexistent package → vulns:[].
- [ ] **Step 2:** Implement → green. Full suite (997 + new; the non-live tests make ZERO network calls — verify by using only the fake fetcher).
- [ ] **Step 3:** Commit `feat(dark-factory): df_depaudit — OSV vulnerability query over declared deps (injectable fetcher)`.

---

### Task 2: dependency_audit gate + config + e2e + docs

**Files:** modify `df_security.py`, `df_config.py`, `references/security-gates.md`, `config-reference.md`; create `dark-factory/tests/test_depaudit_gate.py`.

- `df_config`: `security_gates.dependency_audit` block `{enabled:bool(False), ecosystems:[...] optional, timeout_s:int}`; validate; inject into `cfg["_security"]["dependency_audit"]`; `dependency_audit` becomes a valid `fail_on` name (extend the M9 cross-reference validation).
- `df_security.run_gates`: when `sec["dependency_audit"]["enabled"]`, run `df_depaudit.parse_installed(workspace)` → `df_depaudit.query_osv(pkgs)`; gate `dependency_audit` = `{"status": "unavailable"}` if the OSV result is unavailable, else `{"status": "fail" if any pkg has vulns else "pass", "findings": [{name,version,ecosystem,vuln_ids}]}`. Participates in `fail_on` + `strict_unavailable` exactly like an external gate. (Inject the fetcher path so tests can stub it — e.g. `query_osv` default fetcher, and run_gates passes none; test_depaudit_gate monkeypatches df_depaudit.query_osv.)
- [ ] **Step 1 (TDD):** `test_depaudit_gate.py` — run_gates with dependency_audit enabled + monkeypatched df_depaudit (vulnerable dep → gate fail + in `failed` when in fail_on; clean → pass; OSV unavailable → gate unavailable + in `failed` under strict_unavailable, NOT under strict_unavailable False); absent dependency_audit → gate never runs, df_depaudit never called (assert), offline default preserved; config matrix + fail_on:["dependency_audit"] accepted; a vuln finding carries no secret + is redacted in the security_report.
- [ ] **Step 2:** Implement → green. Full suite.
- [ ] **Step 3:** security-gates.md: the `dependency_audit` gate — **prominently** the network/egress caveat (opt-in; sends dependency names+versions to api.osv.dev; NOT the offline default; a network failure is unavailable→fail-closed, not pass), the pinned-deps-only scope, OSV coverage caveat. config-reference rows. Commit `feat(dark-factory): dependency_audit security gate (OSV CVE check, opt-in, network, fail-closed)`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M23 / residue #6):** the flagged network dependency/CVE analysis — an opt-in `dependency_audit` gate that queries the real OSV database for known vulns in the artifact's declared+pinned dependencies, wired into the M9 gate runner (fail_on/strict_unavailable/manifest recording), fail-closed on network failure, with the network-egress departure from the offline model made explicit and opt-in.

**Deliberately deferred (honest, in security-gates.md):** full transitive dependency-graph resolution for artifacts that don't ship a lockfile (M23 audits declared+pinned + any pinned transitives present in a shipped lockfile/vendored tree — it does not itself resolve a dependency solver); non-OSV vuln sources / commercial SCA; license-policy via network (M18's license gate stays offline/declared); caching/rate-limit handling beyond a bounded timeout (OSV is queried per-run; a heavy monorepo may want caching — noted).

**Honesty note:** this is the ONE gate that leaves the box — opt-in, off by default, documented as sending dependency names+versions to api.osv.dev; a network failure is `unavailable` (fail-closed under fail_on+strict_unavailable), never a silent pass; no artifact source or secret is ever sent.
