# dark-factory M13 — Hash-Chained Audit + Off-Box WORM Sink Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make the audit trail tamper-EVIDENT beyond a single run: (1) a per-control-root **hash chain** links every run's manifest to the previous one, so any silent deletion or mid-history edit breaks the chain and is detectable by a `verify-chain` command; (2) a pluggable **append-only remote sink** ships each signed chain entry off the run's box, where an append-only receiver (or a WORM object store) prevents rewrite even by someone holding the local key. The honest anchor is off-box: a local process that can rewrite the local chain AND holds the signing key can still forge the local history — but it cannot rewrite what an append-only receiver in a different trust domain already recorded.

**Architecture:** `df_audit_chain.py` appends one signed entry per finalized manifest to `<control_root>/audit-chain.jsonl` — `{invocation, manifest_sha256, prev_chain_hash, chain_hash, ts}` where `chain_hash = sha256(canonical(entry_without_chain_hash) + prev_chain_hash)`, optionally HMAC-signed with the existing M5a audit key (rewriting a link then needs the key). `df_audit_sink.py` pushes each entry to a configured sink: `http-append` (PUT to a stdlib reference receiver that rejects overwrite/delete) or `s3-objectlock` (stdlib SigV4 PUT to an object-lock/WORM bucket). The supervisor calls both after `finalize_manifest`, records `audit_chain`/`audit_sink` on the manifest, and fails closed when `audit.sink.required` and the push fails. `df_audit_receiver.py` is the deployable reference receiver (also the test double).

**Honest scope (stated in docs):** the hash chain makes tampering *evident*, not *impossible* — its guarantee is "silent partial edits break a verifiable link," and full tamper-resistance requires the off-box sink to live in a **different trust domain** than the runner (a WORM bucket you own, or a receiver on a separate host/account). Running the reference receiver on the same box is a *demonstration* of the protocol, not the production guarantee — documented explicitly. The S3 adapter is stdlib SigV4 (no boto3); its WORM property comes from the bucket's server-side object-lock config, which the operator sets. `http-append` is the always-green tested baseline; the S3 path is tested against a local MinIO object-lock container.

**Tech Stack:** Python stdlib only (SigV4 = hashlib+hmac; no boto3). Docker for the MinIO object-lock test (skipif unavailable). pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Chain integrity:** `chain_hash` binds the entry's content AND the previous `chain_hash`; `verify_chain` recomputes every link and the referenced `manifest_sha256`, reporting the first break. A signed chain (audit key present) additionally requires the key to forge any link.
- **Fail-closed sink:** `audit.sink.required: true` → a sink push failure aborts the run at finalize with a nonzero exit and a journaled `AUDIT_SINK_FAILED`; `required: false` → journal `AUDIT_SINK_WARN` and continue (local chain still written). The sink NEVER receives credential values (push the chain entry + manifest digest, or the already-redacted manifest text — never raw env).
- **Append-only receiver:** the reference receiver accepts PUT to a NEW key (201) and rejects PUT to an existing key (409) with no DELETE/overwrite route; a stored entry is immutable. Tests prove a second PUT to the same invocation is refused.
- **Barrier untouched:** audit is control-plane; nothing new reaches the builder. The chain file lives in the control root (denied to builder/candidate at standard+).
- **Back-compat:** absent `audit.sink` and absent chain config → today's behavior plus the chain file is still written (chain is always-on, additive, cheap); existing 581 tests stay green (manifest gains additive `audit_chain`/`audit_sink` fields; verify-manifest unaffected).
- **Stdlib only** (SigV4 included). **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_audit_chain.py     # Task 1 — chain entry, append, verify_chain
    df_audit_sink.py      # Task 2 — http-append + s3-objectlock clients
    df_audit_receiver.py  # Task 2 — reference append-only WORM receiver (stdlib http.server)
    df_config.py          # Task 2 — audit.sink validation → cfg["_audit"]["sink"]
    supervisor.py         # Task 3 — chain+sink wiring, verify-chain CLI, manifest fields
  references/
    audit.md              # Task 3 — chain + off-box model + trust-domain honesty
    config-reference.md
  SKILL.md                # Task 3
  tests/
    test_audit_chain.py       # Task 1
    test_audit_sink.py        # Task 2 (http-append always; MinIO s3 skipif)
    test_e2e_offbox_audit.py  # Task 3
```

---

### Task 1: df_audit_chain — chain entry, append, verify

**Files:** create `dark-factory/scripts/df_audit_chain.py`, `dark-factory/tests/test_audit_chain.py`.

**Interfaces (Produces):**
```python
class ChainError(RuntimeError): ...

GENESIS = "0" * 64   # prev_chain_hash for the first entry

def compute_chain_hash(entry_core: dict, prev_chain_hash: str) -> str
    # sha256( canonical_json(entry_core) + prev_chain_hash ), hexdigest.
    # entry_core = {"invocation","manifest_sha256","ts"} (NO chain_hash/sig).
    # Uses df_common.canonical_json + df_common.sha256_str.

def read_chain(chain_path: str) -> list[dict]
    # Parse the ndjson chain (missing file → []). Malformed line → ChainError
    # (line number). Each entry must have the core keys + chain_hash.

def append_entry(chain_path: str, invocation: str, manifest_sha256: str,
                 ts: str, audit_key: bytes | None = None) -> dict
    # prev = last entry's chain_hash (or GENESIS if empty). Build entry_core,
    # compute chain_hash, and if audit_key given add
    # "sig": df_audit.sign(audit_key, chain_hash.encode()). Atomically append
    # one ndjson line (df_common.atomic_write can't append — read+rewrite the
    # whole file atomically via a temp file + os.replace to stay crash-safe).
    # Return the full entry dict.

def verify_chain(chain_path: str, audit_key: bytes | None = None) -> tuple[bool, str]
    # Walk entries: entry[0].prev must be GENESIS; each chain_hash must equal
    # compute_chain_hash(core, prev); each entry links to the previous
    # chain_hash. If audit_key given, every entry MUST carry a valid "sig"
    # over its chain_hash (a missing/invalid sig on a signed chain → fail).
    # Returns (True, "OK: <n> entries") or (False, "<first-break description>").
```

- [ ] **Step 1 (TDD):** `test_audit_chain.py` — append 3 entries → read_chain returns 3, each links to the prior chain_hash, first prev == GENESIS; verify_chain OK. Tamper: flip a `manifest_sha256` in the middle → verify_chain False naming that invocation. Tamper: delete the middle entry (rewrite file without it) → verify_chain False (broken link). Signed chain: append with audit_key → each entry has `sig`; verify_chain(key) OK; strip a sig → False; wrong key → False. Malformed ndjson line → ChainError. Concurrent-append crash-safety: partial temp file never corrupts the chain (simulate by asserting os.replace atomicity — write via the same code path twice, file always parseable).
- [ ] **Step 2:** Implement → green. Full suite (581 + new).
- [ ] **Step 3:** Commit `feat(dark-factory): hash-chained audit log with verify_chain (signed links)`.

---

### Task 2: df_audit_sink + reference receiver + config

**Files:** create `dark-factory/scripts/df_audit_sink.py`, `dark-factory/scripts/df_audit_receiver.py`, `dark-factory/tests/test_audit_sink.py`; modify `df_config.py` + `config-reference.md`.

**Interfaces:**
- `df_audit_receiver.py`: a stdlib `http.server` app — `PUT /audit/<key>` with a JSON body: if `<key>` unknown → store (under a `--store-dir`), return 201 + `{"receipt": sha256(body)}`; if known → 409 (append-only, no overwrite); `GET /audit/<key>` → the stored body or 404; no DELETE handler (405). Runnable as `python df_audit_receiver.py --port N --store-dir DIR`. A `serve(store_dir, port=0) -> (httpd, port)` helper for tests (ephemeral port, background thread).
- `df_audit_sink.py`:
  ```python
  class SinkError(RuntimeError): ...
  def push(sink_cfg: dict, key: str, body: bytes, *, timeout_s: int = 20) -> dict
      # sink_cfg["kind"]: "http-append" | "s3-objectlock".
      # http-append: PUT {url}/audit/{key} (urllib), body as-is. 201/200 → return
      #   {"kind","status","receipt": <server receipt or sha256(body)>}. 409 →
      #   SinkError("sink already has an entry for {key} (append-only)"). Any
      #   other status / URLError / timeout → SinkError.
      # s3-objectlock: PUT https://{endpoint}/{bucket}/{prefix}{key} with a
      #   stdlib SigV4 header (access/secret from sink_cfg or env
      #   DF_AUDIT_S3_ACCESS_KEY/SECRET_KEY; region, endpoint from cfg). 200 →
      #   return {"kind","status","etag"}. Non-2xx → SinkError. WORM is enforced
      #   server-side by the bucket's object-lock config (not the client).
  def _sigv4_headers(...) -> dict   # stdlib AWS SigV4 (hashlib+hmac); unit-tested
                                    # against a KNOWN AWS test vector.
  ```
- `df_config.py` → `cfg["_audit"]["sink"]`: optional `audit.sink` block:
  ```
  {"kind": "none"|"http-append"|"s3-objectlock",   # default "none"
   "required": bool,                                # default False
   "url": str,             # http-append: required, http(s)://...
   "endpoint","bucket","region","prefix": str,      # s3-objectlock
   "access_key_env","secret_key_env": str}          # s3: names of env vars (never inline secrets)
  ```
  Validation (ConfigError): unknown kind; http-append without a valid url; s3-objectlock missing endpoint/bucket/region; `required` non-bool; NO raw secret keys inline (only env-var NAMES) — an inline `secret_key` field → ConfigError pointing at the env-var-name pattern. Absent block → `{"kind":"none","required":False}`.

- [ ] **Step 1 (TDD):** `test_audit_sink.py`:
  - receiver: `serve()` on ephemeral port; PUT new key → 201 + receipt; PUT same key again → 409; GET → body; DELETE → 405. (in-process, fast.)
  - push http-append against the live receiver: success returns receipt; second push same key → SinkError "append-only"; unreachable url (closed port) → SinkError; the body bytes stored == pushed.
  - SigV4: `_sigv4_headers` reproduces a published AWS SigV4 test-vector Authorization header exactly (pin the canonical example from AWS docs).
  - s3-objectlock **(skipif no docker)**: start MinIO with object-lock in a container (`minio server` with a versioned, object-locked bucket created via the MinIO client or a stdlib PUT with the lock header); push an object → 200; a second push to the SAME key is refused/creates a locked version (assert the object cannot be deleted within retention — GET the retention or attempt delete → denied). Session fixture pulls `minio/minio`.
  - config matrix: each ConfigError case; inline-secret rejection; defaults.
- [ ] **Step 2:** Implement → green. Full suite.
- [ ] **Step 3:** Commit `feat(dark-factory): audit sink clients (append-only http + s3 object-lock) + reference receiver`.

---

### Task 3: supervisor wiring + verify-chain CLI + e2e + docs

**Files:** modify `dark-factory/scripts/supervisor.py`, `references/audit.md`, `SKILL.md`, `config-reference.md`; create `dark-factory/tests/test_e2e_offbox_audit.py`.

**Interfaces:**
- After every `finalize_manifest` returns the digest, in a shared helper `_anchor_audit(cfg, control_root, run_dir, invocation, digest, audit_key, journal) -> int` (returns 0 normally, or 3 to force a fail-closed exit):
  1. `entry = df_audit_chain.append_entry(<control_root>/audit-chain.jsonl, invocation, digest, _now(), audit_key)`; write `<run_dir>/audit_chain.json = entry`; journal `AUDIT_CHAINED(chain_hash=..., prev=...)`.
  2. If `cfg["_audit"]["sink"]["kind"] != "none"`: `receipt = df_audit_sink.push(sink, invocation, json.dumps(entry).encode())`; write `<run_dir>/audit_sink_receipt.json`; journal `AUDIT_SINK_OK(kind, receipt)`. On SinkError: if `sink["required"]` → journal `AUDIT_SINK_FAILED(error=...)` and return 3; else journal `AUDIT_SINK_WARN(error=...)` and return 0.
  - **Design (avoids binding-circularity):** the chain binds the manifest's finalized digest, so the chain results CANNOT live inside that same manifest (embedding them would change the digest that was chained). Therefore `audit_chain`/`audit_sink` are recorded as **run_dir sidecars** (`audit_chain.json`, `audit_sink_receipt.json`) + **journal events**, NOT as manifest fields — the manifest stays the immutable thing the chain anchors. State this explicitly in audit.md as the reason (it's the correct design, not an omission). The manifest is never re-finalized. `_anchor_audit` is called once per terminal, immediately after each `finalize_manifest` call site (fresh + resume paths); a required-sink failure makes the caller return `_anchor_audit`'s 3 instead of its normal exit code (the terminal manifest is already on disk and correctly describes the run outcome — only the process exit reflects the sink failure, and the `AUDIT_SINK_FAILED` journal entry records it).
- New CLI subcommand `verify-chain <control_root> [--key-path PATH]`: loads the chain, calls `df_audit_chain.verify_chain` (with the key if signing configured/among audit cfg), prints `OK: <n> entries` / the break, exit 0/1. Mirror the existing `verify-manifest` CLI arg handling.

- [ ] **Step 1:** `test_e2e_offbox_audit.py` (CLI subprocess):
  - (a) two sequential runs in one control root → `audit-chain.jsonl` has 2 linked entries; `verify-chain` exits 0 "OK: 2 entries"; then corrupt one manifest_sha256 in the chain file → `verify-chain` exits 1 naming the break.
  - (b) signed chain (audit.signing on, hardened or standard+signing) → chain entries carry `sig`; verify-chain --key-path OK; verify-chain WITHOUT the key on a signed chain → still verifies structure but reports signatures unchecked (or requires the key — match verify-manifest's semantics).
  - (c) http-append sink (start the reference receiver in-process on an ephemeral port; point `audit.sink.url` at it): a run pushes its entry; `audit_sink_receipt.json` exists in run_dir; journal has `AUDIT_SINK_OK`; the receiver holds the entry body (GET returns it). (409-on-duplicate is covered at the df_audit_sink unit level in Task 2, since live-run invocations are unique.)
  - (d) required-sink fail-closed: `audit.sink={kind:http-append, url:<closed port>, required:true}` → run exits nonzero, journal `AUDIT_SINK_FAILED`, and NO `audit_sink_receipt.json`; same with `required:false` → run still converges (exit 0/normal), journal `AUDIT_SINK_WARN`. In both, `audit_chain.json` still exists (the local chain is written before the sink push).
- [ ] **Step 2:** `audit.md`: the chain model (linked hashes, signed links, verify-chain), the off-box sink (http-append + s3 object-lock), and the **trust-domain honesty** (chain = tamper-evident not tamper-proof; the sink's guarantee needs a different trust domain; same-box reference receiver is a demo; WORM bucket / separate-account receiver is production). `SKILL.md`: audit-sink sub-step + verify-chain mention. config-reference rows.
- [ ] **Step 3:** Docs-vs-code verify; full suite green; commit `feat(dark-factory): off-box audit wiring — chain + sink on every manifest, verify-chain, fail-closed required sink; e2e + docs`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M13):** spec §7.5 hardened "signed, chained append-only records" (the hash chain with signed links + verify-chain) and §7.5 enterprise "off-box append-only / remote sink as the tamper-evidence anchor" (the http-append receiver + s3 object-lock WORM adapter, fail-closed when required). The honest gap the spec itself names — "a local process that can rewrite the manifest can also recompute an unsigned chain" — is exactly why the chain is *signed* and the anchor is *off-box*; both are now implemented, with the residual (same-trust-domain sink = demo only) disclosed.

**Deliberately deferred (honest, in audit.md):** a managed transparency-log / Merkle-inclusion-proof service (the chain here is linear, not a Merkle tree with inclusion proofs); automatic periodic chain-head anchoring to an external immutable timestamp; boto3-based full S3 feature coverage (M13 uses minimal stdlib SigV4 PUT — enough for object-lock WORM, not the whole S3 API); non-AWS WORM stores beyond the S3-compatible API (MinIO/GCS-S3-mode work; native GCS/Azure are future adapters behind the same `push` interface).

**Honesty note:** the always-green tested baseline is the stdlib `http-append` receiver; the S3 object-lock path is tested against a real MinIO object-lock container when Docker is present and skipped (not faked) otherwise — so "off-box WORM works" is proven against real object-lock semantics, not asserted.
