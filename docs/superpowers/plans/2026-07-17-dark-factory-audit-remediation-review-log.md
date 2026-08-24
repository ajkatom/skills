# Plan Review Log: Remediate the Dark Factory audit (DF-01 … DF-10 + four intervention modes)
Started session (2026-07-17). MAX_ROUNDS=5. Reviewer: Codex `gpt-5.6-sol` (xhigh), read-only.

## Round 1 — Codex (gpt-5.6-sol, medium, read-only)

The plan does not close DF-01 and has a fatal DF-03 transport assumption. Concrete flaws:

1. **DF-01 attests a different moment than was tested.** Final scenarios and gates run against the mutable workspace, then the artifact is hashed later; an attacker can replace a passing tree with malicious content between [final verification](/Users/alonadelson/Projects/ai_projects/skills/dark-factory/scripts/supervisor.py:2322), [security gates](/Users/alonadelson/Projects/ai_projects/skills/dark-factory/scripts/supervisor.py:2356), and manifest finalization.  
Fix: Create an immutable snapshot/package before final verification, and run the final exam, gates, hashing, signing, and custody exclusively against that same snapshot.

2. **Rehash-before-attest still has a custody TOCTOU.** `attach_custody` can recompute the workspace hash, then the workspace can change before or after `custody_attestation.json` is written; the attestation never makes a mutable directory immutable.  
Fix: Attest a content-addressed immutable artifact object, not a live workspace path, and publish it atomically only after verification.

3. **The proposed tree walker is itself racy.** Existing `lstat(path)` followed by `sha256_file(path)` can be swapped to a symlink or different inode between operations, and `os.walk` is vulnerable to directory replacement ([snapshot_source.py](/Users/alonadelson/Projects/ai_projects/skills/dark-factory/scripts/snapshot_source.py:23)).  
Fix: Traverse with directory FDs, open files using `O_NOFOLLOW`, and compare `fstat` identity/metadata before and after reading—or snapshot inside an isolated filesystem transaction.

4. **“Mirrors `build_manifest`” does not bind the whole tree.** It excludes every `.git` directory, ignores empty directories, and therefore cannot detect all structural changes despite the plan claiming structure mismatch detection.  
Fix: Define an artifact-specific canonical format that includes all relevant paths and empty directories with no source-snapshot exclusions.

5. **The metadata policy ignores security-relevant mode changes.** Only executable bits are bound; setuid/setgid, world-writable changes, ownership, ACLs, xattrs, and Linux file capabilities remain invisible.  
Fix: Normalize artifact metadata during packaging or bind every security-relevant metadata field supported by the target platform.

6. **The artifact contains supervisor scratch files, not a defined deliverable.** The workspace includes `spec.md`, `DARK_FACTORY_PROMPT.md`, and `feedback.json`, so “artifact” currently means an incidental working directory rather than the files intended for shipment.  
Fix: Define an explicit output root or allowlisted packaging manifest and verify/package only that deliverable.

7. **Workspace resolution is unspecified and unsafe.** Current `verify_manifest` accepts only `run_dir` ([supervisor.py](/Users/alonadelson/Projects/ai_projects/skills/dark-factory/scripts/supervisor.py:872)); deriving a mutable absolute workspace path from journal/state is not portable and permits path substitution.  
Fix: Record an artifact object identifier and require verification against an explicitly supplied artifact whose digest—not pathname—establishes identity.

8. **Custody operations are not serialized with workspace mutation or audit-chain appends.** `attach_custody` does not take the supervisor’s control-root lock, so concurrent attach/run operations can race both artifact checks and the known read-modify-write audit chain.  
Fix: Lock custody attachment and chain publication, while still relying on an immutable artifact rather than the lock for content integrity.

9. **DF-03’s `urllib` assumption is only half true.** `urllib.request.urlopen` does honor proxy environment settings, but an HTTPS URL uses HTTP `CONNECT`; `df_proxy` explicitly rejects `CONNECT` and only injects credentials into absolute-URI forwarding requests.  
Fix: Use an explicit adapter-to-proxy protocol, such as a plaintext local HTTP connection carrying the absolute HTTPS target, or redesign the proxy with authenticated TLS termination.

10. **The enterprise egress probe has the same transport defect.** Its `ProxyHandler({"https": proxy_url})` will use `CONNECT`, so a realistic HTTPS allowlisted probe cannot exercise the implemented injection path.  
Fix: Make the probe use the exact explicit transport used by the adapters and assert both credential injection and direct-egress denial.

11. **Ambient proxy bypass variables remain active.** The entrypoint exports proxy variables but does not clear `NO_PROXY`/`no_proxy` ([df_container.py](/Users/alonadelson/Projects/ai_projects/skills/dark-factory/scripts/df_container.py:240)); image-supplied bypass rules can skip the proxy, causing inconsistent behavior or reliance solely on iptables failure.  
Fix: Ignore ambient proxy discovery entirely and pass a validated dedicated proxy endpoint directly to the adapter.

12. **The sentinel is not sufficient configuration authentication.** `DF_CREDENTIAL_PROXY=1` says nothing about which proxy, target host, provider, or injection header is expected, and accidental use outside enterprise can send prompts through an attacker-controlled ambient proxy.  
Fix: Require a supervisor-generated proxy descriptor containing endpoint, provider, allowed origin, and header mode, and reject sentinel mode outside the enterprise launch contract.

13. **Provider/proxy compatibility is not validated.** Anthropic requires `x-api-key`, OpenAI requires `Authorization`, while the proxy configuration permits either independently; the wrong pairing fails only at runtime.  
Fix: Validate adapter type, base URL host, allowlist entry, and injection header as one coherent provider configuration at config load.

14. **DF-06 lands before the policy is sealed.** M33 makes gates qualification-critical, but M34 later seals gate policy; today resume reloads live config, adapter, spec, and scenarios ([supervisor.py](/Users/alonadelson/Projects/ai_projects/skills/dark-factory/scripts/supervisor.py:2519)), allowing a paused run’s gate policy to change before qualification.  
Fix: Seal qualification policy before—or atomically with—making gates mandatory.

15. **“Mandatory gates” has no defined mandatory baseline.** Current configurations can disable the entire block or individual gates, and `fail_on` can omit them; the plan does not say which scanners must run at each tier.  
Fix: Define an immutable per-tier minimum gate set that configuration may strengthen but never disable.

16. **Signed waivers have no usable trust model at standard/hardened.** Custody is optional there, and the existing signature flow signs whole enterprise manifests rather than scoped waiver events.  
Fix: Specify a tier-independent waiver signer allowlist/threshold and a canonical signed waiver schema before implementing qualification logic.

17. **Waiver scope is underspecified and replayable.** A finding ID/path is insufficient for external gates and line-shifting findings, and expiry based only on the local clock is rollback-prone.  
Fix: Bind each waiver to run ID, artifact digest, gate-policy digest, gate-report digest, normalized finding fingerprint, signer policy, and an anchored issuance/expiry time.

18. **External gates can mutate the artifact they inspect.** They execute arbitrary commands with `cwd=workspace` and no read-only confinement ([df_security.py](/Users/alonadelson/Projects/ai_projects/skills/dark-factory/scripts/df_security.py:520)), so a gate can change the tree before later hashing.  
Fix: Run every gate in a read-only sandbox against the immutable candidate artifact and write outputs only to a separate report directory.

19. **DF-07 directly breaks checkpoint “adjust spec.”** Existing workflow explicitly permits editing `spec.md` and resuming; forcing every edit to a new run discards the current run’s continuation semantics and lineage.  
Fix: Define adjustment as an explicit forked run that snapshots the prior workspace/state, gets a new bundle/run ID, and records parent lineage without exposing final scenarios.

20. **DF-07 also breaks budget raise-and-resume.** Budget pauses intentionally require editing `config.json`, but “resume references that exact bundle” would preserve the old cap and immediately pause again.  
Fix: Separate immutable verification/security policy from signed, journaled resume overrides such as budget ceilings.

21. **Credential resume semantics conflict with sealing.** Credentials are intentionally re-resolved on every resume, while sealing “config” wholesale implies freezing credential references and potentially their policy.  
Fix: Explicitly classify sealed policy fields versus refreshable runtime inputs and bind every refresh to a journaled resume event.

22. **The proposed bundle omits material control inputs.** `behaviors.json`, twin definitions/implementations, generated brownfield scenarios, seccomp profiles, dependency snapshots, external gate executables, sandbox wrappers, and provider/base-URL policy all affect qualification but are not listed.  
Fix: Build the bundle from a complete dependency graph of every byte or executable that can influence generation, verification, gates, or qualification.

23. **A copied “read-only” bundle is not immutable against the same OS user.** `chmod` and read-only mounts do not stop the owning supervisor account from replacing the source object, and digest verification can itself race.  
Fix: Store bundles in an append-only/content-addressed object store and open verified objects by stable file descriptor or immutable mount.

24. **Bundling holdouts increases disclosure risk.** A single bundle containing final scenarios, adapters, and builder-visible material becomes catastrophic if mounted wholesale into the builder or future verifier container.  
Fix: Create separate content-addressed builder and verifier projections, with holdouts present only in the verifier projection.

25. **Four intervention modes are not actually designed.** Names and vague “approval points” are insufficient to implement distinct behavior, failure handling, timeouts, noninteractive operation, or qualification consequences.  
Fix: Specify a complete state-transition table for all four modes before scheduling implementation.

26. **Current checkpoint state cannot support additional approval phases.** `state.json` mainly stores `next_iter` and a reason; approvals after final exam, gates, or artifact sealing would either rerun work or resume at the wrong phase.  
Fix: Replace it with a versioned phase-aware FSM checkpoint that persists completed phase outputs and their bound artifact/bundle digests.

27. **The legacy mapping is ambiguous.** Existing `autonomy:4` permits both `checkpoint:"pause"` and `"auto"`, while `df_init` defaults checkpoint to auto even though config loading defaults autonomy 4 to pause; mapping only `4|5` loses real behavior.  
Fix: Map the full `(autonomy, explicit checkpoint, tier)` tuple, reject dual old/new fields, and provide a deterministic migration command.

28. **The four-mode blast radius is understated.** It affects init answers, config schema, state files, exit codes, budget pauses, custody, manifests, every checkpoint test, examples, and user-facing workflow—not merely validation and the supervisor loop.  
Fix: Treat M36 as a schema/FSM migration with compatibility fixtures for every legacy combination and update docs in the same milestone, not M38.

29. **Qualification fields risk contradictory authorities.** Adding three qualification booleans while retaining `qualified`, enterprise `CUSTODY_PENDING`, and a separate custody attestation creates multiple sources of truth.  
Fix: Define one computed qualification state machine and make all booleans derived presentation fields with schema invariants.

30. **Manual artifact threading across terminal branches is error-prone.** `finalize_manifest` is called from many abort, resume, gate, final-exam, cap, and custody paths; the plan’s “every terminal manifest” promise is likely to miss branches.  
Fix: Centralize terminalization in one function that freezes the artifact when applicable, validates schema invariants, signs, anchors, and clears state exactly once.

VERDICT: REVISE
### Claude's response (Round 1 → revision for Round 2)

Verified the three most load-bearing findings directly against the tree and all confirmed: `df_proxy.do_CONNECT` is a 501 stub with injection only on plaintext absolute-URI forwarding (#9/#10); the enterprise entrypoint exports HTTP(S)_PROXY but never clears NO_PROXY (#11); `_run_external_gate` runs `subprocess.run(cwd=workspace)` unconfined (#18). Codex is right that the plan as written does NOT close DF-01 (moment-mismatch/TOCTOU) and that DF-03's transport is broken. Accepting the large majority:

- **ACCEPTED — core redesign (#1,#2,#3,#6,#7,#18,#23,#30):** M28 becomes SEAL-FIRST. Freeze the build into a content-addressed immutable artifact object BEFORE the final exam + gates; run final exam, gates (read-only, against the frozen object, reports to a separate dir), hashing, signing, and custody against THAT SAME object; verify/attest by digest identity, not a live path. Centralize terminalization in one function that freezes-when-applicable, validates schema invariants, signs, anchors, clears state once.
- **ACCEPTED — DF-03 transport (#9,#10,#11,#12,#13):** proxy-mode adapter speaks PLAINTEXT HTTP to the local proxy carrying the absolute https:// target (df_proxy's real forwarding+injection path), NOT urllib HTTPS+proxy (CONNECT). Supervisor passes a validated proxy DESCRIPTOR (endpoint, provider, allowed origin, header mode), clears NO_PROXY, and config-load validates the adapter/host/allowlist/header as one coherent provider config. The egress probe uses the same explicit transport and asserts injection + direct-egress denial.
- **ACCEPTED — sealing (#14,#19,#20,#21,#22,#24):** DF-07 folds into the M28 seal-first foundation. The sealed bundle covers the COMPLETE qualification-influencing input set (config policy fields, spec, scenarios+schemas, cohort assignment, behaviors.json, twins, brownfield scenarios, seccomp profiles, dep snapshots, external-gate executables, sandbox wrappers, provider/base-URL policy, gate policy). Separate content-addressed BUILDER vs VERIFIER projections so holdouts never enter a builder mount. Classify sealed-policy vs refreshable-runtime fields (budget ceilings, credential refs) so budget raise-and-resume and credential re-resolution still work via signed, journaled resume overrides; spec adjustment becomes an explicit FORKED run with parent lineage, not a silent re-hash. Mandatory gates (DF-06) ride on the sealed policy — reordered accordingly.
- **ACCEPTED — waivers/gates (#15,#16,#17):** define a per-tier immutable MINIMUM gate set (config may strengthen, never disable); a canonical signed waiver schema binding run id + artifact digest + gate-policy digest + gate-report digest + normalized finding fingerprint + signer allowlist/threshold + anchored issuance/expiry; a tier-independent waiver signer trust model.
- **ACCEPTED — four modes (#25,#26,#27,#28,#29):** M36 gets a full state-transition table before implementation; a versioned phase-aware FSM checkpoint (persists completed-phase outputs + their bound artifact/bundle digests) replacing the `next_iter`+reason state.json; full `(autonomy, explicit checkpoint, tier)` tuple legacy mapping with a deterministic migration command + compat fixtures; docs updated in-milestone (not deferred to M38). ONE computed qualification state machine; the qualification booleans become derived presentation fields with schema invariants.
- **SCOPED (not rejected) — #3, #23:** I adopt freeze-then-hash-the-frozen-copy (copy with O_NOFOLLOW + symlink/special/multi-link rejection into an object dir we write once and thereafter only read), plus verify-by-digest. This neutralizes the material race without a full append-only object-store DB or fd-stable immutable mounts — which exceed dark-factory's threat model (same-OS-user deletion is the same trust boundary finalize_manifest already documents for cooperative/standard; enterprise adds custody + off-box sink). Documented as an explicit residual, not silently dropped.
- **SCOPED — #5:** rather than binding every platform metadata field (uid/gid/ACL/xattr/caps), the freeze NORMALIZES metadata for a defined deliverable and additionally rejects setuid/setgid/world-writable regular files at freeze time (fail-closed) — closing the security-relevant cases without a cross-platform metadata zoo.

Revised PLAN.md accordingly (seal-first foundation, reordered, DF-03 transport-correct, waiver/mode specs deepened). Re-submitting for Round 2.

## Round 2 — Codex (gpt-5.6-sol, medium, read-only)

The architecture is materially better, but several security and sequencing gaps remain.

1. **M29c breaches the holdout barrier.** It mounts the “sealed verifier object” containing scenarios into the same container as generated candidate code; unless there is another enforced boundary inside that container, the candidate can read the holdouts.  
Fix: Keep the verifier projection outside the candidate sandbox and mount only the frozen artifact into a separately isolated candidate container.

2. **DF-02 remains open at `standard`.** M29c containerizes only `hardened`/`enterprise`; standard-tier generated code still runs under a deny-control-root host sandbox and can read home, SSH, cloud, and other host files.  
Fix: Containerize candidates at every qualifying tier or make `standard` unqualified until equivalent host-read isolation exists.

3. **Linux egress fallback contradicts mandatory isolation.** M29b permits unrestricted candidate networking with a warning whenever Linux runs twins or HTTP scenarios, yet the result can apparently remain qualified.  
Fix: Treat unrestricted candidate egress as unqualified, or implement a network namespace/proxy topology that supports loopback scenarios without external egress.

4. **The “immutable object” is not immutable under the stated implementation.** A same-user process can rewrite/delete the object between final exam, gate execution, manifest signing, custody attachment, verification, or handoff; off-box manifest storage only proves what bytes once existed.  
Fix: Use an actually immutable/read-only snapshot or require digest verification immediately at every consumption/handoff and stop claiming downstream TOCTOU is eliminated.

5. **Scoping out immutable storage conflicts with the security claim.** The plan simultaneously says ordinary object directories exceed the threat model and that the design closes “every downstream TOCTOU”; both cannot be true.  
Fix: Narrow the guarantee explicitly to content identity under a trusted object store, or strengthen storage to enforce that trust assumption.

6. **Source traversal safety is still underspecified.** `O_NOFOLLOW` protects only the final opened component unless traversal uses trusted directory FDs; parent-directory replacement can still escape or produce an attacker-selected copy.  
Fix: Require `openat`-style FD-relative traversal with `O_DIRECTORY|O_NOFOLLOW`, inode checks, and before/after `fstat` validation.

7. **Content-addressed publication has no collision/concurrency protocol.** The object ID is unknown until copying finishes, and two runs may publish the same ID or encounter an existing corrupt/incomplete directory.  
Fix: Build in a private temporary directory, fsync it, validate any existing object byte-for-byte, and atomically rename without overwrite under an object-store lock.

8. **Object layout risks a hash self-reference ambiguity.** The plan does not say whether the canonical manifest is inside the object it describes or a sidecar.  
Fix: Specify a fixed layout where the manifest is an external sidecar keyed by the tree digest, or define an explicit excluded metadata namespace.

9. **The artifact output contract is still permissive and collision-prone.** “Whole workspace minus scratch filenames” silently excludes legitimate deliverables named `spec.md` or `feedback.json` and relies on reserved-name conventions.  
Fix: Require a dedicated output directory and reject builder writes to reserved supervisor paths.

10. **Directory metadata handling is incomplete.** The plan rejects world-writable regular files but says nothing about world-writable/setgid directories, while also hashing directory modes.  
Fix: Normalize all destination file and directory modes during copying and reject unsupported security metadata before publication.

11. **`terminalize()` can accidentally refreeze the wrong bytes.** It is described as freezing “when applicable,” including after final-exam/gate failure; once verification starts, refreezing the live workspace would recreate the original moment mismatch.  
Fix: Make terminalization accept an already-sealed object ID and forbid any second freeze after final verification begins.

12. **Waiver collection has no executable lifecycle in M33.** Waivers can only be signed after the artifact and gate-report digests exist, but current gate failure is terminal and the phase-aware resumable FSM does not land until M36.  
Fix: Move the phase-aware FSM before M33 or implement a dedicated `WAIVER_PENDING` phase that resumes against the same frozen object without rebuilding.

13. **Waiver expiry makes baked qualification fields stale.** A manifest or custody attestation created before expiry may continue saying qualified afterward unless every verification reevaluates the waiver.  
Fix: Make current waiver validity a mandatory runtime verification result and never treat the manifest’s historical qualification boolean as sufficient.

14. **Trusted expiry evaluation remains vague.** “Anchored issuance/expiry” authenticates timestamps but does not define the authoritative current time used to decide that expiry has passed.  
Fix: Define the trusted-time source and fail closed when it cannot be consulted.

15. **Refreshable “credential references” weaken the sealed policy.** Changing environment-variable names, secret sources, or allowlists changes what authority the builder receives and therefore is policy, not merely runtime refresh.  
Fix: Seal credential source/reference/allowlist policy and refresh only the referenced secret values.

16. **Signed resume overrides lack a signer policy.** Standard-tier audit signing is not necessarily configured, and a journal entry signed by the same process applying the override does not prove human authorization.  
Fix: Define an override approver allowlist, threshold, canonical payload, and replay protection independently of supervisor audit HMAC.

17. **Spec-fork semantics are incomplete.** Continuing from a parent workspace means the new run begins with code generated under the old spec; starting fresh loses the claimed continuation behavior.  
Fix: Define the parent’s sealed artifact as the new run’s explicit input snapshot, or require a clean rebuild and document that adjustment does not continue in place.

18. **Forking creates ambiguous paused-run selection.** Current resume selects the newest directory containing `state.json` ([supervisor.py](/Users/alonadelson/Projects/ai_projects/skills/dark-factory/scripts/supervisor.py:221)); a paused parent plus forked child can resume the wrong run.  
Fix: Add mandatory run-ID selection for resume/fork and mark superseded parent states explicitly.

19. **The “complete bundle” cannot be complete merely by copying executables.** External gates depend on interpreters, shared libraries, PATH tools, plugins, configuration, and databases not captured by the executable file alone.  
Fix: Run gates in digest-pinned images/environments and bind that environment digest plus all mounted rule/data objects.

20. **Image mutability remains until M37.** M28 claims to seal every qualification-influencing input, but mutable container tags are not digest-pinned until nine milestones later.  
Fix: Resolve and seal container image digests in M28, leaving broader dependency-lock work for M37.

21. **Derived control inputs need a defined sealing boundary.** Brownfield scenarios do not exist at run start, so the plan cannot create the stated complete verifier bundle at initial bundle creation without a staged bundle transition.  
Fix: Define an initial builder-policy bundle and an append-only derived verifier bundle created after characterization, with both IDs and derivation recorded.

22. **Proxy access is unauthenticated.** Any local process able to reach the transient proxy can use its injected credential against the allowed provider while it is running, even if it cannot read the credential itself.  
Fix: Require an unguessable per-run proxy capability token validated in `Proxy-Authorization` before forwarding.

23. **Origin enforcement must include scheme and port.** The current proxy allowlist matches hostname only and permits any port; “allowed origin” in the descriptor does not help unless the proxy itself enforces it.  
Fix: Enforce exact `(scheme, hostname, port)` matching in `df_proxy`, not only in adapter validation.

24. **The proxy descriptor has no integrity model.** If it is a mutable environment value or workspace file, generated code or a compromised launcher can redirect the adapter to another local endpoint.  
Fix: Mount a supervisor-created descriptor read-only, bind its digest into the sealed policy, and cross-check the endpoint against the network-lock destination.

25. **M32’s live probe target is undefined.** Proving real provider credential injection may incur paid requests, while a local stub does not prove the configured provider route and TLS behavior.  
Fix: Specify a provider-safe authenticated probe endpoint or distinguish a mandatory transport/lock probe from an optional paid provider probe without overstating either.

26. **The enterprise scaffold may only be syntactically valid, not usable.** Custody requires real public keys and a required audit sink requires a reachable destination; dummy placeholders can pass parts of validation while producing a dead scaffold.  
Fix: Require these answers explicitly or generate a real keypair and clearly marked local development sink, then run an operational preflight.

27. **Object retention is absent.** Qualification by object ID is useless if cleanup, collision handling, or manual deletion removes the only artifact bytes while manifests and attestations remain.  
Fix: Define referenced-object retention, deletion refusal, and explicit “artifact unavailable” verification semantics.

28. **Acceptance tests still miss adversarial timing.** Mutation-after-final-exam tests do not cover concurrent replacement during freeze, gate execution, custody checking, object publication, or final handoff.  
Fix: Add deterministic race-injection tests at every seal/read/publish boundary, including concurrent publishers and malicious background candidate processes.

VERDICT: REVISE
### Claude's response (Round 2 → pause loop for owner decision)

Round 2 is high-value again. The findings split cleanly into two buckets.

**Bucket A — accepted in full (correct, mostly cheap, independent of threat-model grade). Folding all into the plan:**
- #1 **(correctness bug, must fix)** M29c must NOT mount the verifier/holdout object into the candidate container — candidate gets ONLY the frozen artifact; scenarios run from a separately-isolated verifier context. The barrier is preserved.
- #6 FD-relative (`openat`, `O_DIRECTORY|O_NOFOLLOW`) traversal + before/after `fstat` during the freeze.
- #7 atomic content-addressed publish: build in a private temp dir, fsync, byte-validate any existing object, atomic rename-no-overwrite under an object-store lock.
- #8 manifest is an external sidecar keyed by the tree digest.
- #9 dedicated builder OUTPUT directory; reject builder writes to reserved supervisor paths (replaces "workspace minus scratch names").
- #10 normalize destination file+dir modes; reject world-writable/setgid dirs at freeze.
- #11 `terminalize()` accepts an already-sealed object id and forbids any second freeze once final verification has begun.
- #12 move the phase-aware FSM (from M36) EARLIER so waivers have a `WAIVER_PENDING` resumable phase against the same frozen object.
- #13/#14 waiver validity is a mandatory RUNTIME verification result (never a frozen boolean); trusted time = the audit-chain/off-box-sink anchor, fail closed when unavailable.
- #15 seal credential source/reference/allowlist as POLICY; refresh only the referenced secret VALUE.
- #16 signed resume overrides get an approver allowlist/threshold + canonical payload + replay protection, independent of the supervisor HMAC.
- #17/#18 spec-fork = parent's sealed artifact becomes the child's input snapshot with recorded lineage; mandatory run-ID selection for resume/fork; superseded parents marked.
- #19/#20 run gates in a digest-pinned environment and bind that env digest; **resolve+seal the container image digest in M28** (not deferred to M37).
- #21 staged bundle: an initial builder-policy bundle at run start + an append-only derived verifier bundle created after brownfield characterization, both ids recorded.
- #22/#23/#24 per-run proxy capability token in `Proxy-Authorization`; `df_proxy` enforces exact `(scheme,host,port)`; the proxy descriptor is mounted read-only with its digest bound into sealed policy and cross-checked against the network lock.
- #25 M32 splits a mandatory local transport/lock probe from an optional paid provider probe.
- #26 enterprise scaffold generates a real keypair + a clearly-marked local dev sink + an operational preflight (usable, not just syntactically valid).
- #27 referenced-object retention: deletion refusal while referenced + explicit "artifact unavailable" verification semantics.

**Bucket B — one genuine fork that is the OWNER's call, not Codex's or mine (#2, #3, #4/#5, #28):** these all reduce to *what adversary the artifact/isolation defends against*:
- **Detection-grade** (my recommendation): the adversary is the *confined builder/candidate* + accidental/gate mutation; the supervisor account is trusted. Guarantee = fail-closed DETECTION via verify-by-digest at every consumption/handoff (freeze, gate, sign, attest, verify, hand-off), read-only gates, hostile-metadata rejection, barrier never breached. This closes the ORIGINAL audit's DF-01 honestly. Standard tier is documented as qualifying the *barrier*, not host-isolation of generated code (that's hardened+). I will **narrow the over-claim** (#5 correctly caught): the plan will say "content identity verified at every consumption; fail-closed on mismatch" — NOT "every downstream TOCTOU eliminated."
- **Prevention-grade** (where Codex is pushing): defend against a hostile *local same-user process* — needs an append-only/content-addressed object store with fd-stable immutable mounts, capability tokens, a Linux netns/proxy egress topology, candidate containerization at EVERY qualifying tier, and race-injection tests at every seal/read/publish boundary. Roughly 2–3× the program.

I'm pausing the Codex loop after Round 2 (not deadlocked — converged on everything except this one grade decision, which no amount of further Codex rounds can settle because it's a product/threat-model choice). Taking the accepted-Bucket-A plan + this grade fork to the human for the sign-off gate.

### Owner decision + Round 2→3 revision
Owner chose **prevention-grade** (Codex's bar). Revised PLAN.md to prevention-grade: content-addressed immutable object store (fd-relative traversal, atomic publish, read-only mounts, verify-by-digest at every consumption, race-injection tests); host-read isolation at EVERY qualifying tier (default-deny OS sandbox at `standard` — no Docker needed — containers at hardened+); Linux netns/proxy egress topology so loopback-without-egress is achievable (no unrestricted-but-qualified escape); proxy capability token + `(scheme,host,port)` + read-only digest-bound descriptor + NO_PROXY cleared; phase-aware FSM pulled before gates so waivers have a resumable phase; all Bucket-A hardening folded in. Guarantee wording narrowed per #5 (read-only access + verify-by-digest at each use, not "no bytes can change vs root"). Re-submitting for Round 3.

## Round 3 — Codex (gpt-5.6-sol, medium, read-only)

The revision closes several design gaps, but the prevention-grade threat model is still inconsistent with same-user storage and key handling.

1. **Read-only permissions do not protect against a hostile same-user process.** That process can `chmod`, rewrite, unlink, or hold a writable FD to object files; a read-only bind mount still reflects host-side inode modifications.  
Fix: Put the CAS behind a different OS identity/privileged service or use enforced immutability such as fs-verity plus immutable snapshots, not owner-controlled permissions.

2. **Stable FDs protect names, not file contents.** An attacker can modify an inode after the pre-use digest while final examination executes it, then restore the original bytes before a post-use check—an undetectable ABA attack.  
Fix: Execute from fs-verity-protected files or a private immutable materialization inaccessible to the adversarial user for the entire consumption interval.

3. **The claimed same-user threat model also defeats object retention.** “Refuse deletion” is merely application policy when the adversary can directly remove `objects/<digest>`.  
Fix: Enforce retention in the privileged CAS boundary and make clients incapable of direct filesystem writes or deletion.

4. **The signing-key residual is internally inconsistent.** A hostile same-user process can read key files, inspect process memory, or ptrace a signing process and thereby become the excluded “supervisor holding the signing key.”  
Fix: Place signing and waiver keys in a separate-user/off-host signing service with non-exportable keys, or explicitly remove hostile same-user processes from the threat model.

5. **Generating an approver private key locally undermines split custody.** A same-host generated key controlled by the supervisor user is neither an independent approver nor prevention-grade custody.  
Fix: Generate only a signing request/public-key template and require approvers to supply public keys from independently controlled off-host keypairs.

6. **The local development audit sink cannot support enterprise qualification.** The existing reference receiver explicitly has no authentication, trusted timestamp, or same-user protection ([df_audit_receiver.py](/Users/alonadelson/Projects/ai_projects/skills/dark-factory/scripts/df_audit_receiver.py:1)).  
Fix: Mark local-sink scaffolds development/unqualified and require a separately administered authenticated WORM sink for enterprise qualification.

7. **The proposed trusted time source does not currently exist.** The audit receiver returns only a body digest, while chain timestamps originate locally; neither provides an independently authenticated current time for waiver expiry.  
Fix: Define a signed remote timestamp receipt protocol and require it whenever a waiver participates in qualification.

8. **Pause/resume state remains same-user mutable before terminal signing.** A hostile process can rewrite `state.json`, journal entries, phase outputs, or bound IDs during `WAIVER_PENDING`; M35’s durable lease lands later and a removable lock is not integrity protection.  
Fix: Sign and remotely anchor every durable FSM transition, and verify the transition chain before resume.

9. **The object-store lock is not adversary-resistant.** A same-user process can remove, replace, or impersonate the lock and race publication despite the supervisor obeying it.  
Fix: Have the privileged CAS service serialize publication internally instead of trusting a user-writable lock file.

10. **Portable atomic no-overwrite publication is unspecified.** Linux `renameat2(RENAME_NOREPLACE)` and macOS `renamex_np(RENAME_EXCL)` differ, and ordinary `rename` overwrites.  
Fix: Specify platform primitives and fail closed on filesystems where atomic no-overwrite publication cannot be proven.

11. **Final scenarios cannot universally run against a read-only artifact.** Applications commonly create databases, caches, sockets, uploads, or other runtime files under their working directory; mounting the artifact strictly read-only will break valid scenarios.  
Fix: Give each scenario a disposable writable overlay with the verified object as immutable lower layer, then discard the overlay.

12. **Default-deny isolation must sanitize inherited environment and IPC.** Current scenario execution inherits `os.environ` ([run_scenarios.py](/Users/alonadelson/Projects/ai_projects/skills/dark-factory/scripts/run_scenarios.py:633)); secrets, `SSH_AUTH_SOCK`, proxy variables, language paths, and agent sockets can leak without any filesystem read.  
Fix: Launch candidates with a minimal allowlisted environment and explicitly deny inherited Unix sockets, Mach services, agents, and credential brokers.

13. **Linux “minimal system paths” cannot retain the current `--ro-bind / /` design.** That exposes the whole host filesystem read-only, including many secrets, `/proc`, runtime sockets, and user-installed libraries ([df_sandbox.py](/Users/alonadelson/Projects/ai_projects/skills/dark-factory/scripts/df_sandbox.py:135)).  
Fix: Construct a fresh mount and PID namespace with explicit runtime binds, private `/proc`, private `/tmp`, and no host-root bind.

14. **macOS keychain and DNS exfiltration need explicit closure.** File denial alone does not stop keychain/securityd or `mDNSResponder` Mach IPC; the current implementation already documents DNS as an egress channel ([df_sandbox.py](/Users/alonadelson/Projects/ai_projects/skills/dark-factory/scripts/df_sandbox.py:21)).  
Fix: Deny the relevant Mach services and prove keychain/DNS denial, or make standard-tier macOS unqualified.

15. **The macOS default-deny allowlist is not yet a design.** “Minimal-but-workable” can easily permit user-controlled Python packages, dynamic libraries, plugins, or shell startup files that reintroduce host reads or code injection.  
Fix: Define per-runtime immutable allowlists, sanitize loader/language variables, and probe representative interpreters before claiming qualification.

16. **The Linux netns topology does not explain verifier-to-service reachability.** A service bound to loopback inside the candidate namespace is not reachable at host `127.0.0.1`, which is how HTTP scenarios currently poll candidates.  
Fix: Specify a namespace-local verifier client or narrowly scoped veth/port-forward design with source/destination firewall rules and live probes.

17. **The proxy capability token is not secret from a hostile same-user process.** That process can read the mounted descriptor’s host source, inspect the launching process, or observe the token before using the proxy itself.  
Fix: Authenticate the isolated workload by an unexposed channel such as a namespace-private Unix socket or privileged proxy broker, not a same-user-readable bearer token.

18. **Exact-origin comparison still needs canonicalization rules.** Userinfo, IPv6 forms, trailing dots, IDNA, percent-encoding, default ports, and DNS rebinding can defeat naïve `(scheme, host, port)` comparisons.  
Fix: Define one strict canonical-origin parser, reject ambiguous forms, and pin/validate resolved addresses against forbidden IP ranges.

19. **“Digest-pinned gate environment image” conflicts with Docker-free standard.** If mandatory standard-tier gates run in that image, Docker is required; if they run on the host, the sealed environment claim is false.  
Fix: State the standard gate runtime explicitly and provide a reproducible non-Docker sandboxed environment or accept Docker as a standard-tier prerequisite.

20. **Race tests do not explicitly cover mid-consumption ABA mutation.** Boundary replacement tests can all pass while an attacker changes and restores an already-open executable during final examination.  
Fix: Inject mutations during file execution/read—not only before and after each boundary—and require kernel-enforced rejection.

21. **M36 still unnecessarily delays Critical DF-02.** The FSM must precede M33 waivers, but it does not need to precede M29 candidate isolation; landing the broad migration first prolongs the critical exposure and increases supervisor conflicts.  
Fix: Sequence M28 → M29 → FSM core → M30–M33.

22. **Skip-cleanly language is unsafe for qualifying-platform tests.** If netns, sandbox, proxy, or immutable-store integration tests skip in the only CI environment meant to prove a tier, the security property is untested.  
Fix: Require at least one mandatory non-skipped CI job per claimed platform/tier and permit skips only in non-qualifying developer jobs.

VERDICT: REVISE

### Claude's response (Round 3 → escalate to owner: prevention-grade is architecturally infeasible here)

Codex Round 3 is correct on the merits, and the through-line is decisive: **prevention-grade against a hostile SAME-USER process cannot be achieved in dark-factory's current architecture** (single OS user, stdlib-only, no privileged daemon, local signing keys, user-writable object store/locks/state). Specifically and unarguably:
- The signing/waiver key is a file or in-memory in a process owned by the same user — a hostile same-user process can read it, `ptrace` the signer, or just re-sign (#4). So excluding "compromised supervisor" from the model while including "hostile same-user process" is INCOHERENT on a single-user box: they are the same trust boundary.
- Read-only permissions/mounts, "refuse deletion," and the object-store lock are all owner-controlled and thus bypassable by that same user (#1,#3,#9); stable FDs don't stop ABA content mutation during consumption (#2,#20).
- Local approver-key generation isn't independent custody (#5); a local dev sink + local timestamps can't provide authenticated WORM or trusted time for enterprise qualification (#6,#7); pre-terminal FSM state is same-user mutable (#8).

Genuine prevention-grade would require a real privilege boundary this architecture doesn't have: a privileged CAS/signing service under a SEPARATE OS user or OFF-HOST, off-host approver keypairs, an authenticated remote WORM sink + signed remote timestamp service, fs-verity/kernel-enforced immutability, and namespaced execution. That is a multi-component deployed system with external infra — a different product from "a skill Alon runs on his workstation," and it contradicts dark-factory's stated non-goals (HSM keys, mTLS, off-box services already documented as out of scope).

**Therefore: pausing the loop and returning to the owner.** The achievable, coherent ceiling for the current architecture is DETECTION-grade (fail-closed detection at every consumption; honestly closes the ORIGINAL audit's DF-01). Prevention-grade needs an explicit re-architecture the owner must green-light as its own infra project.

**Round-3 findings I keep REGARDLESS of grade (fold into whatever plan proceeds):** #10 portable atomic no-overwrite (renameat2 RENAME_NOREPLACE / renamex_np RENAME_EXCL, fail closed where unavailable); #11 disposable writable overlay per scenario (verified object as immutable lower layer) — real correctness, read-only artifact breaks writing apps; #12 sanitize inherited env/IPC (SSH_AUTH_SOCK, sockets, Mach services, loader/lang vars); #13 fresh Linux mount+PID namespace, private /proc + /tmp, NO host-root ro-bind; #14/#15 macOS keychain/DNS/allowlist honesty (or mark standard-macOS host-isolation limited); #16 netns verifier-reachability design; #18 strict canonical-origin parser + resolved-IP pinning; #21 resequence M28→M29→FSM→M30-33; #22 mandatory non-skipped CI job per claimed platform/tier.

Loop status: not deadlocked — CONVERGED on the finding that the owner's chosen grade is infeasible without re-architecture. Escalating that decision to the human.

### Owner decision (Round 3) + Round 3→4 revision
Owner chose **detection-grade + all grade-independent hardening**. Finalized PLAN.md to detection-grade: precise threat model (in-model = confined candidate + accidents + hostile gate; out-of-model residual = same-user/compromised-supervisor, documented, prevention-grade deferred to a future infra spec). Folded in ALL grade-independent Round-3 fixes: portable atomic no-overwrite (renameat2/renamex_np, fail-closed), disposable writable scenario overlay, env/IPC sanitization, fresh Linux namespace (no host-root bind, private /proc+/tmp), macOS keychain/DNS honesty, netns verifier-reachability, strict canonical-origin parser + resolved-IP pinning, operator-supplied off-host approver keys + real WORM sink for enterprise (dev sink unqualified), explicit standard gate runtime, mandatory non-skipped CI per tier, resequenced M28→M29→FSM→M30-33. Read-only/atomic/token kept as defense-in-depth, not overclaimed. Re-submitting for Round 4 (confirmation).

## Round 4 — Codex (gpt-5.6-sol, medium, read-only)

Within the detection-grade threat model, several material gaps remain.

1. **A hostile gate can falsify its own result.** Read-only artifact access prevents mutation, but a malicious external gate can simply exit 0 or emit fabricated findings, contradicting the inclusion of “hostile security gate” as an in-model adversary.  
Fix: Scope hostile gates to mutation attempts only, or require independently trusted/redundant gate implementations before treating their verdicts as security evidence.

2. **Gate confinement is incomplete.** “Read-only in the digest-pinned env” does not explicitly deny access to the control root, signing keys, network, agents, report files, or persistent subprocesses.  
Fix: Give gates a dedicated sandbox with artifact-read-only, isolated report output, sanitized environment, no control-plane mounts, default-deny network, and complete process teardown.

3. **`killpg` does not guarantee full process-tree teardown.** A malicious candidate can call `setsid()`, double-fork, and escape the original process group, especially at standard-macOS.  
Fix: Use a PID namespace/cgroup/container on Linux and a proven macOS process-containment mechanism, or mark macOS standard limited/unqualified when descendants cannot be reaped reliably.

4. **“Limited” macOS standard is incompatible with qualification.** If keychain or DNS Mach IPC remains reachable, generated code is neither fully host-read-isolated nor egress-denied, yet the plan does not explicitly remove qualification.  
Fix: Require both Mach-service denials to pass live probes or make standard-macOS unqualified.

5. **Waiver trusted time is still not designed.** The current audit sink returns only a digest receipt, and chain timestamps are supplied locally; neither is an authenticated timestamp authority.  
Fix: Add a signed remote timestamp receipt protocol and require it for every waiver-bearing qualification at every tier.

6. **Enterprise WORM status is asserted, not verified.** Reachability preflight cannot prove S3 Object Lock/retention or equivalent authenticated append-only enforcement; the existing client explicitly delegates that to operator provisioning.  
Fix: Require and verify a sink capability/retention attestation, including readback of the anchored object and active retention policy.

7. **The proxy grants excessive credential authority.** Exact origin enforcement still lets a confined client use arbitrary methods and paths—`DELETE`, uploads, fine-tuning, files, administration, or other provider APIs—with the injected credential.  
Fix: Enforce provider-specific method/path/header/body-size/request-count policy, not merely origin.

8. **Resolved-IP pinning needs connection-level enforcement.** Checking DNS and then letting `http.client` resolve the hostname again leaves a DNS rebinding interval.  
Fix: Connect directly to the validated pinned IP while preserving the canonical Host header and TLS SNI/certificate validation for the provider hostname.

9. **The mandatory local egress probe cannot obviously exercise the exact production origin.** A local stub changes DNS, TLS, origin, or CA state; a real origin may require a paid request.  
Fix: Define separate non-vacuous tests for the exact network policy and proxy transport, and state precisely which provider-specific property remains unverified without the optional live probe.

10. **The standard gate runtime remains an unresolved fork.** “Either non-Docker runtime or Docker prerequisite” conflicts with the declared no-Docker standard-tier architecture and postpones a security-critical product decision.  
Fix: Choose and specify one standard-tier gate runtime before implementation.

11. **Disposable per-scenario overlays can change existing scenario semantics.** Current scenarios share one workspace during `run_all`; a scenario that creates state for a later scenario would now fail or behave differently.  
Fix: Define scenario independence as a validated contract or use one disposable overlay per cohort while resetting only where explicitly requested.

12. **Overlay implementation is unspecified cross-platform.** Linux OverlayFS commonly requires privileges, while macOS has no equivalent native overlay matching the design.  
Fix: Specify a proven backend per platform, with a verified copy/clone fallback that preserves the immutable base invariant.

13. **Object directory and external sidecar cannot be atomically published together.** A crash after publishing one but before the other leaves a committed-looking partial object that may block later reuse.  
Fix: Define the sidecar as the final atomic commit record and quarantine/recover directories lacking a valid commit record.

14. **The enterprise init behavior is contradictory.** It may emit only an approver-key template and a deliberately unqualified development sink, yet M31 is supposed to produce a usable enterprise scaffold.  
Fix: Require operator public keys and a conforming remote sink in enterprise answers, or emit an explicitly non-enterprise development configuration that cannot claim enterprise assurance.

15. **Pre-M28 verification can still be misused by automation.** Printing “artifact not bound” is insufficient if `verify_manifest` returns success and callers treat exit 0 as shipment approval.  
Fix: Return a distinct non-success/unbound status for pre-M28 manifests and prohibit custody or handoff from accepting it.

16. **FSM integrity before terminal signing is underspecified.** Although same-user forgery is out of scope, accidental corruption of phase checkpoints or journals must still be detected before resume.  
Fix: Hash-chain and atomically persist FSM transitions, validating the chain and bound object/bundle IDs on every resume.

17. **Security documentation is deferred too long.** M28–M33 materially change artifact, isolation, proxy, gate, and qualification semantics, but M38 remains responsible for broad claim correction.  
Fix: Update operational and assurance documentation in each security milestone, leaving M38 only for residual cleanup.

18. **Mandatory CI can still prove only a simulation.** A local fake WORM sink or stub provider does not constitute a non-skipped enterprise qualification test despite exercising the wire protocol.  
Fix: Separate mandatory primitive CI from a required scheduled integration job against a genuinely provisioned authenticated WORM environment, and label their evidence distinctly.

VERDICT: REVISE

### Claude's response (Round 4 → fold in + resolve punted forks; final round next)
No new fundamental problem this round (unlike R1 TOCTOU / R3 feasibility) — all 18 are "tighten further" or "resolve a punted fork." Accepting and folding into PLAN.md:
- #2 gates get a DEDICATED sandbox: artifact-read-only, isolated report dir, sanitized env, NO control-plane/key mounts, default-deny network, full process teardown.
- #3/#4 process-tree teardown + macOS honesty: Linux uses PID-namespace/cgroup reaping; **macOS-standard is BARRIER-qualified but explicitly NOT host-isolation-qualified** when keychain/DNS Mach-IPC or descendant reaping can't be closed — separate the two qualification properties, never overclaim.
- #5 waiver time: **enterprise requires a signed remote timestamp receipt**; standard/hardened use local-time expiry with the same-user-forgeable residual documented (waiver is digest-bound to artifact+report so not replayable across artifacts).
- #6 WORM verified not asserted: enterprise preflight must READ BACK the anchored object + confirm active retention/Object-Lock, not just reachability.
- #7 proxy authority: df_proxy enforces provider-specific method/path (+ body-size/request-count), not just origin — restrict to the exact chat/messages endpoint + POST.
- #8 connection-level IP pinning: df_proxy connects to the validated pinned IP with preserved Host/SNI + cert validation (closes DNS-rebinding).
- #9 probe honesty: separate non-vacuous tests for network policy vs proxy transport; state exactly what stays unverified without the optional paid probe.
- #10 DECIDED: **standard-tier gates run on the HOST in the default-deny sandbox (no Docker, no "digest-pinned env" claim at standard)**; hardened+ gates run in the digest-pinned container. No unresolved fork.
- #11/#12 DECIDED: scenario isolation contract = **each scenario gets a fresh copy-on-run writable scratch** (copy the immutable artifact → run → discard; portable, no OverlayFS privilege); cross-scenario state handoff must use an explicit twin/fixture, not shared-workspace mutation — documented + validated.
- #13 sidecar = the atomic commit record; quarantine/recover object dirs lacking a valid sidecar.
- #14 DECIDED enterprise init: **require operator-supplied approver PUBLIC keys + a conforming remote WORM sink in the answers**; absent those, init emits an explicitly NON-enterprise dev config that cannot claim enterprise assurance.
- #15 pre-M28 verify returns a distinct UNBOUND non-success status; custody/handoff refuse it.
- #16 hash-chain + atomically persist FSM transitions; validate chain + bound ids on resume (detects accidental corruption — in-model).
- #17 update assurance docs in EACH security milestone; M38 = residual only.
- #18 CI: mandatory primitive jobs (no skip) distinct from a required SCHEDULED integration job against a genuinely provisioned WORM env; label evidence distinctly.
- #1 SCOPED: a gate that lies about its own findings (exit 0 / fabricated) is operator-trust (you chose to run it) — no harness prevents garbage-in; "hostile gate" in-model = MUTATION/escape attempts, now confined by #2. Documented.
Running the final Codex round (5/5) to confirm; if it still REVISEs, remaining items will be the inherent scope/infra limits (gate-verdict trust, real WORM infra, macOS Mach-IPC) — I'll surface those to the owner at sign-off rather than pretend convergence.

## Round 5 — Codex (gpt-5.6-sol, medium, read-only) — FINAL ROUND (MAX_ROUNDS)

Three in-scope gaps remain:

1. **macOS loopback is still overbroad.** Allowing all `localhost:*` lets a candidate reach unrelated Redis instances, browser-debug ports, credential proxies, databases, and other host services.  
Fix: Dynamically allowlist only the exact twin/verifier ports assigned to the run and probe that other loopback ports are denied.

2. **Linux verifier reachability remains an unresolved security fork.** “Namespace-local verifier client or scoped veth/port-forward” describes materially different trust boundaries and firewall policies.  
Fix: Select one topology and specify namespace ownership, routes, allowed source/destination tuples, teardown, and non-vacuous probes before implementation.

3. **Partial qualification lacks an authoritative overall outcome.** The delta introduces `barrier-qualified` and `host-isolation-qualified`, while the main schema still describes a single derived `qualified`; macOS-standard could therefore be interpreted inconsistently by automation.  
Fix: Define `qualified = barrier && host_isolation && app_security && control_plane && current_waiver_validity`, with distinct nonqualified outcome codes for limited tiers.

4. **The primary milestones still contradict their later deltas.** M29d still specifies overlays, M33 still leaves the standard runtime as “either,” M28 requires remote time universally, and M31 permits templates/dev sinks; relying on a trailing override section invites implementation of obsolete requirements.  
Fix: Edit the milestone text to incorporate the final decisions directly, then remove the superseded delta entries.

VERDICT: REVISE
### Claude's final resolution (MAX_ROUNDS reached — converged, not deadlocked)
Round 5's items were narrow and I resolved them as final arbiter, then consolidated PLAN.md so the milestone bodies carry the decisions directly (deltas section removed — R5 #4):
- **R5 #1 (macOS loopback overbroad):** M29e now restricts `loopback` to a run-specific EXACT-port allowlist (only this run's twin/verifier ports; all other loopback ports denied + probed).
- **R5 #2 (Linux verifier reachability fork):** DECIDED — namespace-local verifier (the HTTP poll client runs inside the candidate netns; no route out; probed).
- **R5 #3 (authoritative outcome):** `qualified = barrier ∧ host_isolation ∧ control_plane ∧ app_security ∧ waiver_validity`, sub-states derived, distinct non-qualified codes (e.g. `HOST_ISOLATION_LIMITED`).
- **R5 #4 (body/deltas contradiction):** folded all deltas into milestone bodies; removed the standalone section; verified no contradictions remain.

Findings trajectory: R1=30 → R2=28 → R3=22 → R4=18 → R5=3+editorial → resolved. This is convergence.

**Documented residuals (inherent limits, NOT plan flaws — Codex would flag these forever because they're architecture/infra boundaries, not fixable in-plan):**
1. A security gate that fabricates its OWN verdict (exits 0 / fake findings) — operator-trust/garbage-in; no harness prevents running a tool you chose to trust. In-model "hostile gate" = mutation/escape, which the gate sandbox confines.
2. Genuine authenticated WORM + trusted-timestamp for enterprise qualification needs operator-provisioned infra (S3 Object-Lock etc.) — dark-factory verifies it (readback/retention) but cannot BE it.
3. macOS-standard keychain/DNS Mach-IPC can't be closed by file-sandboxing → macOS-standard is barrier-qualified, host-isolation-LIMITED (honestly coded, not overclaimed).
4. Same-user/compromised-supervisor forgery — the detection-grade residual, out of model by owner decision; prevention-grade deferred to references/prevention-grade-roadmap.md.

Loop CLOSED at MAX_ROUNDS. Handing the final plan to the human for the build sign-off (gate #2).

## Round 6 — Codex (owner-requested extra round)

One substantive in-scope gap remains:

- **The decided Linux topology breaks digital twins.** A candidate netns with no veth or host route can reach its namespace-local verifier, but it cannot reach the existing host-bound twin processes; twin-backed scenarios will fail regardless of artifact behavior.  
Fix: Launch each required twin inside the same per-scenario network namespace—with its definitions, observer storage, and verifier controls remaining outside the candidate mount/PID views—or provide a narrowly port-scoped twin proxy with equivalent probes and teardown.

VERDICT: REVISE
### Claude's response (Round 6)
Down to ONE substantive in-scope finding — and it's correct: my R5 namespace-local-verifier decision breaks twins (host-bound twin processes are unreachable from an isolated candidate netns). ACCEPTED. Fix folded into M29e: each required twin's LISTENING SOCKET runs inside the same per-scenario netns (candidate reaches it on loopback), while the twin's definition, observation log, and verifier controls stay OUTSIDE the candidate's mount/PID namespaces — so twin-backed scenarios work AND the barrier + twin-evidence integrity (M12) hold (the candidate can't reach or tamper with the observation log). Verifier poll client also runs in-netns. Running the additional (Round 7) round the owner requested to confirm.

## Round 7 — Codex (owner-requested) — APPROVED

No remaining in-scope, detection-grade flaw found. The Linux twin/netns design now preserves reachability, holdout isolation, observation integrity, teardown, and non-vacuous verification. Remaining issues are documented residuals or minor wording cleanup.

VERDICT: APPROVED
### Outcome: CONVERGED + APPROVED after 7 rounds. Findings: R1=30 R2=28 R3=22 R4=18 R5=3 R6=1 R7=0. Remaining = documented inherent residuals only. Plan ready for human build sign-off (gate #2).
