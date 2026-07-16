# dark-factory M23 — Dependency/CVE Audit Gate (tier-aware: live OSV + offline snapshot) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add an **opt-in `dependency_audit` security gate** that checks the artifact's declared+pinned dependencies against the **OSV vulnerability database** for known CVEs, with **two backends selected by a tier-coherent policy**: (1) **`osv-api`** — queries `api.osv.dev` live (makes network calls, egresses dependency names+versions); allowed at **cooperative/standard** (tiers that make no egress promise), **forbidden by ConfigError at hardened/enterprise** (whose whole guarantee is no/controlled egress); (2) **`osv-snapshot`** — queries a **pre-provisioned local OSV data snapshot** with **zero run-time network egress**; allowed at **every** tier including hardened/enterprise. Net effect: every tier can get a CVE check, and no tier breaks its egress promise. A finding on a vulnerable dependency rejects the artifact fail-closed; a backend failure reports **unavailable** (never a silent pass).

**Architecture:** New module `df_depaudit.py` (stdlib `urllib`/`zipfile`/`json` — no new dependency): `parse_installed(root)` extracts `[{ecosystem,name,version}]` from the artifact's manifests (pinned versions only); `query_osv_api(pkgs, fetcher=...)` POSTs each to OSV live (injectable fetcher for tests); `load_snapshot(dir)` + `query_osv_snapshot(pkgs, snapshot)` match pinned versions against a local OSV snapshot **offline**; `fetch_snapshot(ecosystem, dest, fetcher=...)` is the ONE deliberate network op — an **operator-run provisioning step** (outside any sealed run, like provisioning the hardened image) that downloads OSV's published per-ecosystem export. `run_gates` (M9) gains a `dependency_audit` gate driven by `sec["dependency_audit"]["source"]`. `df_config` enforces the tier policy: `source:"osv-api"` + assurance ∈ {hardened,enterprise} → ConfigError; `source:"osv-snapshot"` requires a `snapshot_path` and is allowed at any tier.

**Honest scope (stated in docs):** `osv-api` **makes network calls and egresses dependency names+versions to api.osv.dev** — opt-in, off by default, and refused at the tiers whose promise it would break. `osv-snapshot` makes **zero** run-time network calls (the snapshot is provisioned once, out-of-band, by the operator; its freshness is the operator's documented responsibility). The offline matcher reliably matches OSV records that **enumerate affected versions** plus simple `introduced`/`fixed` ranges; complex range expressions may be under-matched vs the live API (documented) — the operator should keep the snapshot fresh and can cross-check with `osv-api` at a lower tier. Both audit **declared/pinned** deps (+ any pinned transitives shipped in a lockfile/vendored tree), not a from-scratch dependency solve. A backend failure/timeout is **unavailable → fail-closed** under `fail_on`+`strict_unavailable`, never pass.

**Tech Stack:** Python stdlib (urllib, zipfile, json). pytest. Network only for the ONE live `osv-api` test + the `fetch_snapshot` live test (both skipif no network). `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Opt-in + off by default:** absent `security_gates.dependency_audit` → the gate never runs, ZERO network calls ever (offline default preserved). All 997 existing tests stay green + make no network calls.
- **Tier policy fail-closed:** `source:"osv-api"` at hardened/enterprise → ConfigError at load ("this tier guarantees no/controlled egress; use source: osv-snapshot"). `source:"osv-snapshot"` without a valid `snapshot_path` → ConfigError. The offline gate at hardened/enterprise makes NO run-time network call — a test asserts it (the query path uses only the local snapshot; the injected fetcher is never called).
- **Fail-closed on unavailable:** a network error / OSV non-200 / timeout (api), or a missing/corrupt snapshot (snapshot) → the gate is `unavailable`; under `fail_on`+`strict_unavailable` it rejects (SECURITY_GATE_FAILED), never silent pass. False-negative direction (missing a vuln) is the dangerous one — the offline matcher errs toward flagging on an ambiguous match and documents it.
- **Barrier + no secret egress:** only dependency NAMES+VERSIONS are ever sent (api) — never artifact source/secrets; findings redacted before hitting run artifacts; nothing about the audit reaches the builder.
- **Deterministic tests, guarded live probes:** logic tests use an injected fake fetcher / a tiny fixture snapshot dir; exactly one live api test + one live fetch_snapshot test (skipif no network); bounded timeouts.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_depaudit.py     # Task 1 — parse_installed + api + snapshot + fetch_snapshot
    df_security.py     # Task 2 — dependency_audit gate in run_gates
    df_config.py       # Task 2 — dependency_audit config + tier policy
  references/
    security-gates.md  # Task 2 — the gate, the tier policy, egress + offline caveats
    config-reference.md
  tests/
    test_depaudit.py         # Task 1
    test_depaudit_gate.py     # Task 2
    fixtures/osv_snapshot/    # Task 1 — a tiny fixture OSV snapshot
```

---

### Task 1: df_depaudit — parse_installed + api + snapshot + fetch

**Files:** create `dark-factory/scripts/df_depaudit.py`, `dark-factory/tests/test_depaudit.py`, `dark-factory/tests/fixtures/osv_snapshot/` (a couple of hand-written OSV JSON records).

**Interfaces (Produces):**
```python
class DepAuditError(RuntimeError): ...

def parse_installed(root) -> list[dict]
    # requirements.txt "name==version" -> {ecosystem:"PyPI",name,version};
    # package.json deps/devDeps with an EXACT version (no ^/~/*/range) -> npm;
    # pyproject.toml [project] deps "name==version" (best-effort) -> PyPI;
    # *.dist-info dirs -> PyPI name/version; node_modules/<pkg>/package.json exact
    # version -> npm. PINNED only. Deduped, sorted. Never raises on a bad manifest
    # (skip, errors="ignore", non-UTF8 safe).

def query_osv_api(pkgs, *, fetcher=_urlopen_fetch, timeout_s=20) -> dict
    # POST each pkg to https://api.osv.dev/v1/query body {"version":v,
    # "package":{"name":n,"ecosystem":e}}. fetcher(url,data,timeout)->(status,body).
    # -> {"source":"osv-api","checked":True,"results":[{name,version,ecosystem,
    #     vulns:[{id,summary}]}],"unavailable":bool,"reason":str}. ANY error/non-200/
    #     bad-JSON on ANY pkg -> unavailable:True (fail-closed). Request carries name/
    #     version/ecosystem ONLY. Never raises.

def load_snapshot(snapshot_dir) -> dict
    # load OSV records from a local snapshot dir (per-ecosystem subdirs of *.json,
    # OR the flat layout fetch_snapshot writes). Index by (ecosystem, lower(name))
    # -> list of records. Missing/empty/corrupt -> DepAuditError (caller maps to
    # unavailable). errors="ignore" per-record (skip a bad record, don't crash).

def query_osv_snapshot(pkgs, snapshot) -> dict
    # same return shape (source:"osv-snapshot"), matching each pkg's version against
    # the indexed records OFFLINE: a record matches if the pkg version is in the
    # record's affected[].versions list, OR falls in an introduced/fixed range
    # (simple comparator; PyPI = packaging-style tuple compare on release segments,
    # npm = semver-ish tuple compare — stdlib, best-effort). Ambiguous/unparseable
    # range on a matching package name -> FLAG it (err toward a finding, not a miss)
    # with the vuln id + a "range-uncertain" note. NEVER makes a network call.

def fetch_snapshot(ecosystem, dest_dir, *, fetcher=_urlopen_fetch, timeout_s=120) -> int
    # operator provisioning: download OSV's published export for `ecosystem`
    # (https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip),
    # unzip the *.json records into dest_dir/<ecosystem>/. Returns record count.
    # This is the ONE deliberate network op; NOT called during a run.
```

- [ ] **Step 1 (TDD):** `test_depaudit.py` — parse_installed matrix (pinned vs unpinned/range skipped; dist-info; node_modules; malformed/non-UTF8 → skipped not raised). query_osv_api with fake fetcher (vuln → id returned; none → []; fetch raises / 500 / bad JSON → unavailable:True never raises; request body has ONLY name/version/ecosystem). load_snapshot + query_osv_snapshot against `fixtures/osv_snapshot/` (a record enumerating an affected version → flagged; a safe version → []; a range-only record on a matching name with an unparseable range → flagged with range-uncertain; snapshot query makes NO network call — pass a fetcher that raises if called and confirm it never is; missing snapshot dir → DepAuditError). **Live (skipif no network):** query_osv_api against real OSV for a known-vulnerable pinned pkg (e.g. `jinja2==2.4.1`) → unavailable:False + ≥1 vuln id; fetch_snapshot("PyPI", tmp) → >0 records + a subsequent offline query_osv_snapshot on the SAME vulnerable pkg also flags it (proves fetch→offline round-trip).
- [ ] **Step 2:** Implement → green. Full suite (997 + new; non-live tests make ZERO network calls — enforce via a fetcher that raises).
- [ ] **Step 3:** Commit `feat(dark-factory): df_depaudit — OSV CVE check (live api + offline snapshot + fetch)`.

---

### Task 2: dependency_audit gate + tier policy + e2e + docs

**Files:** modify `df_security.py`, `df_config.py`, `references/security-gates.md`, `config-reference.md`; create `dark-factory/tests/test_depaudit_gate.py`.

- `df_config`: `security_gates.dependency_audit` block `{enabled:bool(False), source:"osv-api"|"osv-snapshot", snapshot_path:str(req for snapshot), ecosystems:[...] optional, timeout_s:int}`; validate. **Tier policy:** `enabled` + `source=="osv-api"` + `assurance ∈ {hardened,enterprise}` → ConfigError ("hardened/enterprise forbid uncontrolled egress; use source: osv-snapshot"); `source=="osv-snapshot"` + no/invalid snapshot_path → ConfigError. `dependency_audit` is a valid `fail_on` name (extend M9 cross-reference). Inject `cfg["_security"]["dependency_audit"]`.
- `df_security.run_gates`: when enabled, `parse_installed(workspace)` → `query_osv_api` OR `query_osv_snapshot` per source; gate `dependency_audit` = `{"status":"unavailable"}` if the result is unavailable, else `{"status":"fail" if any vulns else "pass","findings":[{name,version,ecosystem,vuln_ids,source}]}`. Participates in `fail_on`+`strict_unavailable` like an external gate. (Tests monkeypatch df_depaudit.query_*; run_gates never calls the network in a test.)
- [ ] **Step 1 (TDD):** `test_depaudit_gate.py` — config: osv-api at standard OK; osv-api at hardened/enterprise → ConfigError; osv-snapshot at hardened/enterprise + valid snapshot → OK; osv-snapshot without snapshot_path → ConfigError; fail_on:["dependency_audit"] accepted; absent block → gate never runs, df_depaudit never called (offline default). run_gates (monkeypatched df_depaudit): vulnerable dep → gate fail + in `failed` when in fail_on; clean → pass; unavailable → gate unavailable + in `failed` under strict_unavailable, NOT under strict_unavailable False; a finding carries no secret + is redacted in security_report. Assert the snapshot path makes NO network call (fetcher-that-raises).
- [ ] **Step 2:** Implement → green. Full suite.
- [ ] **Step 3:** security-gates.md: the `dependency_audit` gate — the TIER POLICY table (osv-api: cooperative/standard only; osv-snapshot: every tier, zero run-time egress), the **prominent** egress caveat for osv-api (opt-in; sends dep names+versions to api.osv.dev), the offline-snapshot provisioning (`fetch_snapshot`, operator-run, freshness is the operator's job) + its honest matching scope (enumerated versions + simple ranges; complex ranges may be under-matched vs the live api; errs toward flagging), fail-closed unavailable. config-reference rows. Commit `feat(dark-factory): dependency_audit gate — tier-gated live OSV + offline snapshot (fail-closed)`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M23 / residue #6, tiered):** the network dependency/CVE analysis, designed so it is coherent with every tier's promise — live OSV where egress is unrestricted (cooperative/standard), an offline pre-provisioned snapshot where it isn't (hardened/enterprise), the live backend refused fail-closed at the locked tiers, wired into the M9 gate runner (fail_on/strict_unavailable/manifest/redaction), fail-closed on any backend failure. This is the option-2 design agreed with the user: every tier gets a CVE check; no tier breaks its egress guarantee; the DoD's "production-ready at any tier" is strengthened, not weakened.

**Deliberately deferred (honest, in security-gates.md):** routing the live osv-api query through the enterprise credential-proxy allowlist (would let hardened/enterprise use the live API under governed egress — real plumbing since the gate runs host-side; the offline snapshot covers the need for now); a full ecosystem-correct version-range solver (offline matcher is best-effort: enumerated versions + simple ranges, errs toward flagging); non-OSV vuln sources / commercial SCA; snapshot auto-refresh/caching policy (operator-run `fetch_snapshot`, freshness documented as their responsibility).

**Honesty note:** exactly one backend leaves the box, only at the tiers that permit egress, opt-in and documented; the locked tiers use a zero-egress local snapshot instead; every backend failure is `unavailable` (fail-closed), never a silent pass; the offline matcher's precision limits vs the live API are stated plainly.
