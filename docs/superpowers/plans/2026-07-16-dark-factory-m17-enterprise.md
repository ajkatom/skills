# dark-factory M17 — Enterprise Tier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Register a real `enterprise` assurance tier that ADDS, on top of `hardened`, the three enterprise-only guarantees the spec names (§2.2, §7.2–7.5): (1) **split-custody sign-off** — a run is `qualified` only after **K-of-N distinct approvers** each ed25519-sign the manifest (no single operator can ship); (2) a **host-side credential proxy** — raw provider tokens **never enter the sandbox**; the builder reaches providers only through a proxy that injects the token host-side and **allowlists destination hosts** (query/host-level egress control); (3) **kernel-enforced egress lock + per-role seccomp** — the enterprise container can reach *only* the proxy (iptables default-deny egress, the NET_ADMIN cap dropped for the child so it can't undo the rules — the same CAP lesson M16 taught) under a restrictive seccomp profile. Everything `hardened` requires (container barrier, `audit.sink.required`, `builder_confinement.required`, signed audit) is **mandatory** at enterprise; enterprise is **fail-closed** — it refuses unless every piece is present and probe-verified.

**Architecture:** `df_custody.py` (ed25519 via the `cryptography` dep — the one non-stdlib module, scoped here) manages approver keypairs, threshold signing, and `verify_custody(manifest_bytes, sigs, approvers, k)`. `df_proxy.py` is a stdlib host-side forward proxy: it accepts the container's requests, matches the destination host against an allowlist, injects the provider credential (read host-side from the M11 broker), forwards, and refuses non-allowlisted hosts. The enterprise container (built on M10's `df_container`) adds `--cap-add NET_ADMIN` + a startup entrypoint that installs `iptables` default-deny-egress-except-proxy, then drops NET_ADMIN before exec'ing the builder, plus a `--security-opt seccomp=<profile>`. The supervisor's enterprise path composes: resolve hardened container + confinement + sink, THEN require the custody threshold before emitting `qualified: true`, and live-verify the egress lock via the M16 Linux-harness primitives. `enterprise` is registered fail-closed in `supported_tiers.json` (needs Linux kernel egress/seccomp — on macOS Docker Desktop that is the container's Linux VM, so it is live-testable here).

**Honest scope (stated in docs):** split-custody is real cryptographic K-of-N (approvers hold private keys; the verifier needs only public keys — chosen over HMAC precisely so a verifier can't forge). The credential proxy is a **reference** host-side broker proving the pattern (token never in-sandbox, host-allowlisted egress); a production deployment points it at a hardened proxy appliance. The egress lock is kernel-enforced **inside the container's Linux kernel** and live-tested; seccomp ships a conservative default profile (deny `mount`, `ptrace`, `bpf`, kernel-module + a few more) — a per-role hand-tuned profile is a documented refinement. Enterprise requires Linux-container primitives; the tier registration is **fail-closed** where they're unavailable.

**Tech Stack:** Python stdlib + `cryptography` (ed25519, enterprise-only — added to a scoped `requirements-enterprise.txt`, imported only by `df_custody.py`). Docker (Linux container for egress/seccomp — live here). pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Dependency isolation:** `cryptography` is imported ONLY by `df_custody.py`. Every other module stays stdlib. A `requirements-enterprise.txt` documents it; the rest of dark-factory runs without it (guard the import so a non-enterprise run never needs it — the 682 existing tests must pass whether or not cryptography is importable... but it IS installed here, so they pass regardless; the guard is for honesty/portability).
- **Split-custody fail-closed:** at enterprise, `qualified: true` is emitted ONLY if `verify_custody` confirms ≥K valid, DISTINCT approver signatures over the exact finalized manifest bytes. Fewer than K, a duplicate approver, an unknown pubkey, or a bad signature → not qualified (a distinct terminal `CUSTODY_PENDING`/`CUSTODY_FAILED`, exit 3). No single key can satisfy K>1.
- **Credential never in-sandbox:** the enterprise builder container env carries NO provider token (M14 confinement already gives a clean env; enterprise additionally routes provider calls through the proxy). The proxy reads the token host-side (M11 broker) and injects it; the token never appears in container argv/env/mounts. Grep-proof in tests.
- **Egress kernel-locked + un-undoable:** the container can reach ONLY the proxy endpoint; all other egress is dropped by iptables in the container's kernel; NET_ADMIN is dropped for the builder child so it cannot remove the rules (the M16 CAP_SYS_ADMIN/remount lesson applied to NET_ADMIN). Live-verified: an allowlisted host via the proxy succeeds; a direct connect to any other host fails.
- **Enterprise ⊇ hardened:** enterprise mandates container barrier, `audit.signing`, `audit.sink.required:true`, `builder_confinement.required:true`; a config that weakens any of these at enterprise → ConfigError.
- **Fail-closed registration:** if the Linux egress/seccomp primitives can't be applied (probe fails) → the enterprise run refuses (SandboxError, exit 2), never runs as a lesser tier silently (—allow-downgrade may drop to hardened with a journaled DOWNGRADE).
- **Additive manifest:** `custody = {"required_k":K,"approvers":N,"signatures":m,"satisfied":bool} | None`, `proxy = {"enabled":bool,"allowlist":[...]} | None`, `enterprise_egress = {"locked":bool,"probe":"verified"} | None` on every terminal. Never any private key or token value.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_custody.py          # Task 1 — ed25519 K-of-N (cryptography-scoped)
    df_proxy.py            # Task 2 — host-side allowlist credential proxy
    df_container.py        # Task 3 — enterprise container: NET_ADMIN entrypoint + seccomp
    df_config.py           # Tasks 1-3 — custody/proxy/enterprise validation
    supervisor.py          # Tasks 1,3 — custody gate, enterprise compose, manifest, verify-custody CLI
    supported_tiers.json   # Task 3 — enterprise entry
    seccomp/enterprise.json # Task 3 — conservative seccomp profile
  references/
    enterprise.md          # Task 4
    config-reference.md
  requirements-enterprise.txt  # Task 1
  SKILL.md                 # Task 4
  tests/
    test_custody.py            # Task 1
    test_proxy.py              # Task 2
    test_enterprise_config.py  # Task 3
    test_e2e_enterprise.py     # Task 4 (live container egress/seccomp)
```

---

### Task 1: df_custody — ed25519 K-of-N split-custody

**Files:** create `dark-factory/scripts/df_custody.py`, `dark-factory/tests/test_custody.py`, `requirements-enterprise.txt`; modify `df_config.py` + `config-reference.md`.

**Interfaces (Produces):**
```python
class CustodyError(RuntimeError): ...

def generate_keypair() -> tuple[str, str]
    # returns (private_hex, public_hex) — raw 32-byte ed25519 each, hex.
    # For approver key setup (a CLI helper `df-custody keygen` wraps this).

def sign_manifest(private_hex: str, manifest_bytes: bytes) -> str
    # ed25519 signature over manifest_bytes, hex (64 bytes). Raises CustodyError
    # on a malformed key.

def verify_one(public_hex: str, manifest_bytes: bytes, sig_hex: str) -> bool
    # single-signature verify (constant-time; any error → False).

def verify_custody(manifest_bytes: bytes, signatures: list[dict],
                   approvers: list[str], k: int) -> tuple[bool, str]
    # signatures = [{"approver": <public_hex>, "sig": <hex>}, ...].
    # Rules: each sig's approver MUST be in `approvers`; each must verify over
    # manifest_bytes; count DISTINCT approvers with a valid sig; satisfied iff
    # that count >= k. Duplicate approver entries count once. Unknown approver
    # or bad sig are ignored (not counted), never crash. Returns
    # (satisfied, "m/k distinct approver signatures" | reason).
```
- `df_config.py` → `cfg["_custody"]` from optional `custody` block: `{"approvers":[<public_hex>,...], "threshold":int}`. Validation: approvers a non-empty list of 64-hex strings, unique; threshold int 1..len(approvers); at enterprise `custody` is REQUIRED (absent → ConfigError). Absent block at non-enterprise → `None`.
- `requirements-enterprise.txt`: `cryptography>=42`. `df_custody` imports cryptography at module top; wrap in a try/except that raises a clear CustodyError("enterprise custody requires `pip install -r requirements-enterprise.txt`") on use if missing.

- [ ] **Step 1 (TDD):** `test_custody.py` — keygen round-trips; sign/verify_one happy + wrong-key + tampered-bytes → False; verify_custody: 3 approvers k=2 with 2 valid distinct sigs → satisfied; 1 valid → not; 2 sigs from the SAME approver → counts once → not satisfied; a sig from an unknown pubkey → ignored; a valid-looking but bad sig → ignored; k=N all-must-sign; malformed sig entry → ignored not crash. Config matrix (approvers hex/uniqueness/threshold range; enterprise-requires-custody deferred to Task 3 but validate the block shape here).
- [ ] **Step 2:** Implement → green. Full suite (682 + new).
- [ ] **Step 3:** config-reference rows. Commit `feat(dark-factory): ed25519 K-of-N split-custody (verify_custody, keygen, sign)`.

---

### Task 2: df_proxy — host-side allowlist credential proxy

**Files:** create `dark-factory/scripts/df_proxy.py`, `dark-factory/tests/test_proxy.py`; modify `df_config.py` + `config-reference.md`.

**Interfaces:**
- `df_proxy.py`: a stdlib forwarding proxy (http.server-based `http.server.BaseHTTPRequestHandler` handling both plain HTTP forward and `CONNECT`). `serve(allowlist, token_env, upstream_scheme="https", port=0) -> (httpd, port)` for tests + a `__main__` runner. Behavior: a request whose destination host ∈ `allowlist` → forward it, injecting `Authorization: Bearer <os.environ[token_env]>` (or an `x-api-key` header — configurable header name) if not already present; host ∉ allowlist → `403` + a JSON body `{"error":"host not in egress allowlist"}` and NOTHING forwarded. The token value is read host-side from the env and never logged / never returned to the client. `AllowlistError` for config issues.
- `df_config.py` → `cfg["_proxy"]` from optional `credential_proxy` block: `{"enabled":bool,"allowlist":[host,...],"token_env":str,"header":"authorization"|"x-api-key"(default authorization)}`. Validation: allowlist non-empty list of hostnames when enabled; token_env a valid env-var NAME (never an inline token → ConfigError on an inline `token` field, mirroring M11/M13). Absent → `{"enabled":False}`.

- [ ] **Step 1 (TDD):** `test_proxy.py` — start `serve(allowlist=["api.example.test"], token_env="DF_PROXY_TOKEN")` + a local stub upstream (another ephemeral http.server acting as "api.example.test" via a Host header / a monkeypatched resolver, OR test the allow/deny + injection logic at the handler level without real DNS): an allowlisted request is forwarded with the injected auth header (assert the upstream stub SAW the header, and the header value came from the env, and the CLIENT never sent it); a non-allowlisted host → 403, upstream never contacted; the token value appears in NO proxy log line / NO client-visible response (grep). Config matrix incl. inline-token rejection.
- [ ] **Step 2:** Implement → green. Full suite.
- [ ] **Step 3:** config-reference rows. Commit `feat(dark-factory): host-side credential proxy — egress allowlist + host-side token injection`.

---

### Task 3: enterprise tier — container egress lock + seccomp + config + supervisor compose

**Files:** modify `df_container.py`, `df_config.py`, `supervisor.py`, `supported_tiers.json`; create `dark-factory/scripts/seccomp/enterprise.json`, `dark-factory/tests/test_enterprise_config.py`.

**Interfaces:**
- `supported_tiers.json`: add `enterprise` (qualified true, backend `container-enterprise`, note: builder in a container with kernel-locked egress-to-proxy + seccomp; requires split-custody sign-off, required sink, required confinement, signed audit; Linux-container primitives probe-verified; fail-closed).
- `df_container.py`: `build_enterprise_argv(image, workspace, ro_mounts, *, proxy_endpoint, seccomp_profile_path, memory, pids, ...)` — like `build_argv` PLUS `--cap-drop ALL --cap-add NET_ADMIN --security-opt seccomp=<profile>`, `--network` a user-defined bridge (or default) where the proxy is reachable, and an ENTRYPOINT wrapper that: (1) with NET_ADMIN installs `iptables -P OUTPUT DROP` + allow-established + allow-only `<proxy_ip>:<port>` + allow loopback/DNS-to-proxy; (2) drops NET_ADMIN for the child (`capsh --drop=cap_net_admin --` or `setpriv`); (3) execs the builder with `HTTP_PROXY/HTTPS_PROXY` = the proxy. Provide the entrypoint as a small shell script mounted read-only. A `probe_enterprise_egress(...)` (reuse M16 harness style) proves: allowlisted-via-proxy reachable, direct-to-other-host denied, child cannot re-add iptables rules (NET_ADMIN dropped).
- `df_config.py` → enterprise composition: at `assurance:"enterprise"` require `custody` present (Task 1), `credential_proxy.enabled:true` (Task 2), `audit.sink.required:true` (M13), `builder_confinement.required:true` (M14), `audit.signing` on (hardened default). Any missing/weakened → ConfigError naming the missing guarantee. Inject `cfg["_enterprise"]={"seccomp":<profile path>}`.
- `supervisor.py`: enterprise resolve = hardened container path + enterprise egress/seccomp + the proxy started host-side (lifecycle: start proxy before the build, reap after — process-group like twins). The custody gate runs at the CONVERGED point (after final exam passes, like M9 security gates): load `<control_root>/custody-signatures.json` (approver sigs over this run's manifest), `verify_custody(...)`; satisfied → `qualified:true` CONVERGED; not → terminal `CUSTODY_PENDING` (exit 3, qualified False) with a clear "awaiting K-of-N approver signatures" message + the manifest bytes to sign. New CLI `verify-custody <control_root> --run-dir ...`. (Because approvers sign AFTER a run produces the manifest, enterprise convergence is a TWO-PHASE ship: the run produces a signed manifest + a CUSTODY_PENDING terminal; approvers sign; a `df-custody attach` + re-verify flips it to qualified. Document this workflow — it is the point of split custody.) Manifest additive `custody`/`proxy`/`enterprise_egress` on every terminal.
- `seccomp/enterprise.json`: a conservative Docker seccomp profile (default action allow, deny `mount`,`umount2`,`ptrace`,`bpf`,`init_module`,`finit_module`,`delete_module`,`kexec_load`,`reboot`,`swapon`,`setns`,`unshare`(user-ns escalation)) — documented.

- [ ] **Step 1 (TDD):** `test_enterprise_config.py` (mostly deterministic + one live egress test guarded by docker): enterprise requires custody/proxy/sink.required/confinement.required/signing — each missing → ConfigError; a well-formed enterprise config validates + injects _enterprise/_custody/_proxy. Supervisor (monkeypatched): custody not satisfied → CUSTODY_PENDING exit 3 qualified False; satisfied (2-of-3 real sigs over the manifest) → qualified True CONVERGED; manifest carries custody/proxy/enterprise_egress. Live (skipif no docker): `probe_enterprise_egress` — allowlisted host via proxy reachable, direct other-host denied, child can't re-add iptables (run under the enterprise container with NET_ADMIN-then-dropped).
- [ ] **Step 2:** Implement → green (existing hardened/M10 tests unaffected; enterprise is additive). Full suite.
- [ ] **Step 3:** Commit `feat(dark-factory): enterprise tier — kernel-locked egress-to-proxy + seccomp + split-custody gate + fail-closed composition`.

---

### Task 4: e2e + docs

**Files:** create `dark-factory/tests/test_e2e_enterprise.py`; `references/enterprise.md`; modify `SKILL.md`, `config-reference.md`.

- [ ] **Step 1:** `test_e2e_enterprise.py` (CLI subprocess):
  - **(a) split-custody two-phase (deterministic, no docker needed for the custody logic — run the custody gate at cooperative-container-stub or mock the container so the custody path is what's exercised; OR run live if fast):** an enterprise run converges the build+scenarios but ends `CUSTODY_PENDING` exit 3 (qualified False) with the manifest to sign; then generate 2-of-3 approver sigs via `df-custody sign`, attach, `verify-custody` → satisfied, and the run flips to qualified. Prove ONE signature (k=2) does NOT qualify.
  - **(b) live enterprise container egress lock (skipif no docker):** a real enterprise container run reaches an allowlisted host through the proxy, and a direct connect to a non-allowlisted host FAILS (egress kernel-locked); the token never appears in the container env/argv (grep the docker inspect + the run artifacts).
  - **(c) fail-closed registration:** enterprise config missing custody → exit 2 ConfigError; enterprise with sink.required:false → ConfigError; enterprise where the egress probe fails (simulate) → refuse (exit 2) or journaled DOWNGRADE to hardened under --allow-downgrade.
- [ ] **Step 2:** `enterprise.md`: the tier's TCB (spec §2.1 enterprise — only supervisor + signing key + broker trusted), the three added guarantees (split-custody two-phase ship workflow; host-side credential proxy = token never in-sandbox + host-allowlisted egress; kernel-locked egress + seccomp), the honest scope (reference proxy; conservative seccomp; the `cryptography` dependency; Linux-container primitive requirement), and how to run an enterprise build end to end (keygen → config → run → approvers sign → verify → qualified). SKILL.md: enterprise tier row + the split-custody workflow. config-reference cross-check.
- [ ] **Step 3:** Docs-vs-code verify; full suite green; run the live enterprise egress e2e for real and record results; commit `feat(dark-factory): enterprise e2e (split-custody two-phase, kernel-locked egress, fail-closed) + docs`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M17):** spec §2.2 enterprise split-custody (K-of-N ed25519 sign-off gates `qualified`, two-phase ship); §7.3 enterprise host-side credential proxy (raw token never in sandbox, host-allowlisted egress); §7.2/§7.4 enterprise per-role container hardening (kernel-locked egress-to-proxy, NET_ADMIN dropped for the child so rules can't be undone — the M16 CAP lesson, seccomp profile); §7.5 enterprise off-box sink (composed from M13, required); enterprise ⊇ hardened, fail-closed registration + composition.

**Deliberately deferred (honest, in enterprise.md):** a hand-tuned per-ROLE seccomp profile (ships one conservative default; per-role is a refinement); a production credential-proxy appliance (M17 ships a reference proxy proving the token-never-in-sandbox + host-allowlist pattern); mutual-TLS/authenticated identities on the proxy channel (the egress lock + host allowlist is the M17 guarantee; cryptographic peer auth is a refinement); HSM-backed approver keys (M17 uses file/CLI ed25519 keys — an HSM/KMS is a drop-in for `sign_manifest`); a native-Linux host (M17 live-tests the Linux primitives inside Docker Desktop's Linux VM — a native Linux run remains the gold standard, per M16).

**Honesty note:** split-custody is genuinely single-operator-proof (K>1 distinct private keys required, verifier holds only public keys); the credential proxy genuinely keeps the token out of the sandbox (host-side injection, grep-proven); the egress lock is kernel-enforced and un-undoable by the child (NET_ADMIN dropped) and live-verified — each claim is proven, not asserted, or it isn't claimed.
