# dark-factory M10 — Hardened Tier (Container Builder Isolation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Register a real `hardened` assurance tier: the **builder runs inside a Docker container** where the control root is unreachable **by construction** (never mounted), with dropped capabilities, no host PID/docker socket, read-only rootfs, resource limits, and default `--network none`; the verifier keeps the host OS read-denial wrapper (standard-tier mechanics). With a conforming hardened backend present, **L5 (autonomy 5, lights-off) becomes available** — spec §2.2 gates L5 on assurance ≥ hardened. Fail-closed everywhere: no Docker daemon, no image, or a failing probe → the run refuses (or journals an explicit downgrade under `--allow-downgrade`).

**Architecture:** New module `df_container.py` (stdlib + the `docker` CLI as the runtime substrate) produces a per-call `docker run` argv: workspace bind-mounted rw at its host path, the adapter's directory mounted ro at its host path (so adapter-protocol paths stay valid), control root **not mounted**. `resolve_isolation` grows a hardened branch returning both a verifier exec-prefix (host OS sandbox, probe-verified as in M2b) and a container spec the supervisor uses to build the builder argv per call. The fail-closed probe runs a reader inside the container against a canary planted in the control root and accepts only a proven denial (launch succeeded AND the denial marker came back — the M2b probe discipline). Hardened requires signed audit (spec §7: at hardened+ the manifest is signed).

**Honest scope (stated in docs):** the TCB now includes the container runtime (Docker daemon — spec §2.1 row for hardened). Real cross-model builders (claude/codex/gemini CLIs) need an image with the CLI installed + credentials, supplied by the user via `hardened.image`; M10's live verification uses the fake builder on a stock `python:3.12-alpine`. Builder-side twin env is NOT forwarded into the container (localhost URLs don't cross the container boundary; authenticated builder→twin topology is M12) — journaled when skipped; verifier-side twins are unaffected. `--network none` is the default; setting `network: "bridge"` (needed by real builder CLIs for API egress) is unrestricted egress and is recorded on the manifest — provider-only egress enforcement is M12. Credential brokering is M11.

**Tech Stack:** Python stdlib. Docker CLI (daemon must be running for live tests; every docker-dependent test is `skipif`-guarded so the suite passes on docker-less machines, while fail-closed *refusal* paths are tested without docker via injected fakes). pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Fail-closed:** hardened is usable only when `docker_available()` AND `probe_container(...)` returns True at run start; otherwise refuse with a clear message (exit 2 path via SandboxError, same as standard), or journal `DOWNGRADE` under `--allow-downgrade` (hardened → standard if the OS-sandbox probe passes, else cooperative).
- **Barrier by construction:** the control root is never mounted into the builder container; the probe proves it (canary read must fail from inside). Nothing new crosses to the builder.
- **L5 gate:** `autonomy: 5` requires `assurance: "hardened"` — ConfigError otherwise. autonomy must be 4 or 5 (int). autonomy 5 ⇒ checkpoint defaults to `auto` (existing line already does this — keep).
- **Hardened ⇒ signed audit:** at `assurance: "hardened"`, `audit.signing` defaults to **true**; explicitly `false` → ConfigError (`"hardened requires signed audit manifests (audit.signing: true)"`).
- **Container hardening flags (always):** `--rm -i --network <mode> --cap-drop ALL --security-opt no-new-privileges --pids-limit <pids> --memory <memory> --read-only --tmpfs /tmp -e HOME=/tmp`. Never mount the docker socket; never `--privileged`; never host PID/IPC namespaces.
- **Back-compat:** cooperative/standard behavior unchanged; existing 302 tests stay green. Manifest fields additive (`container` block; `sandbox_backend: "container-docker"` at hardened).
- **Suite must pass without docker:** live-docker tests use `pytest.mark.skipif(not docker_live(), ...)`; refusal/argv/config tests run everywhere.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_container.py        # Task 1 — docker availability, argv builder, fail-closed probe
    supported_tiers.json   # Task 2 — hardened tier entry
    df_config.py           # Task 2 — hardened block, L5 gate, hardened⇒signing
    supervisor.py          # Task 2 — resolve_isolation hardened branch + builder wiring + manifest
  references/
    hardened.md            # Task 3 — TCB, image requirements, honest scope
    config-reference.md    # Task 2/3 rows
  SKILL.md                 # Task 3 — hardened tier + L5 workflow
  tests/
    test_container.py      # Task 1
    test_hardened_config.py # Task 2
    test_e2e_hardened.py   # Task 3
```

---

### Task 1: df_container — availability, argv builder, fail-closed probe

**Files:** create `dark-factory/scripts/df_container.py`, `dark-factory/tests/test_container.py`.

**Interfaces (Produces):**
```python
class ContainerError(RuntimeError): ...

BACKEND_NAME = "container-docker"
DEFAULT_IMAGE = "python:3.12-alpine"

def docker_available(runner=subprocess.run) -> bool
    # shutil.which("docker") is not None AND `docker info` exits 0 within 10s.
    # Any exception → False (fail-closed). `runner` injectable for tests.

def build_argv(image: str, workspace: str, ro_mounts: list[str], *,
               network: str = "none", memory: str = "2g", pids: int = 256,
               env: dict | None = None) -> list[str]
    # Pure. Returns:
    # ["docker","run","--rm","-i","--network",network,
    #  "--cap-drop","ALL","--security-opt","no-new-privileges",
    #  "--pids-limit",str(pids),"--memory",memory,
    #  "--read-only","--tmpfs","/tmp","-e","HOME=/tmp",
    #  "-v", f"{ws}:{ws}"] + [x for p in sorted(set(realpath(ro_mounts))) for x in ("-v", f"{p}:{p}:ro")]
    # + ["-w", ws] + [x for k in sorted(env or {}) for x in ("-e", f"{k}={env[k]}")]
    # + [image]
    # ws = os.path.realpath(workspace). Raises ContainerError if workspace or any
    # ro_mount does not exist, is not absolute after realpath, or contains ":"
    # (would corrupt the -v spec). df_container does not know the control root —
    # the CALLER guarantees the control root is never passed as a mount; the probe
    # (below) and the Task-1 argv test ("exactly 1 + len(ro_mounts) -v flags")
    # enforce that nothing else can appear.

def probe_container(image: str, deny_root: str, workspace: str, *,
                    timeout_s: int = 180, runner=subprocess.run) -> bool
    # Fail-closed. Plants a canary (uuid token) in deny_root, runs
    #   build_argv(image, workspace, ro_mounts=[]) + ["python3","-c",CODE,canary]
    # where CODE reads argv[1] and prints its content, or "DF-READ-DENIED" on any
    # exception (reuse df_sandbox's marker discipline: import the marker or redefine
    # the same literal "DF-READ-DENIED").
    # True ONLY if returncode == 0 AND stdout.strip() == "DF-READ-DENIED".
    # (rc==0 proves the container launched and python3 ran; the marker proves the
    # canary was unreachable — deny_root is not mounted, so open() must fail.)
    # OSError/TimeoutExpired/non-zero rc/token-in-stdout → False. Canary unlinked in finally.
```

- [ ] **Step 1 (TDD):** `test_container.py` —
  - `build_argv` pure tests (no docker): exact flag set present in order (`--cap-drop ALL`, `--security-opt no-new-privileges`, `--read-only`, `--tmpfs /tmp`, `--pids-limit`, `--memory`, `-e HOME=/tmp`); workspace mounted rw at its realpath; each ro_mount mounted `:ro`; env dict → sorted `-e K=V` pairs; image is the LAST element; network value honored; missing workspace / relative path / path containing `":"` → ContainerError; **no `-v` for any path not passed in** (assert the argv contains exactly 1 + len(ro_mounts) `-v` flags — the control root can never sneak in).
  - `docker_available` with injected fake runners: which() present + rc 0 → True (monkeypatch `shutil.which`); rc 1 → False; runner raising OSError/TimeoutExpired → False; which() → None → False.
  - `probe_container` fail-closed with injected fake runner: fake rc 0 + stdout `DF-READ-DENIED` → True; rc 0 + stdout = the canary token (leak!) → False; rc 1 + `DF-READ-DENIED` (launch failure) → False; runner raises TimeoutExpired → False; canary file always removed (assert not exists after).
  - **Live (skipif):** module-level `DOCKER_LIVE = docker_available()`; `@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")` — `test_live_probe_denies_unmounted_root`: real `probe_container(DEFAULT_IMAGE, tmp control dir, tmp ws)` → True; `test_live_workspace_writable`: run build_argv + `python3 -c "open('probe.txt','w').write('ok')"` in a tmp workspace → file appears on host (bind-mount rw works); `test_live_network_none_blocks_egress`: run `python3 -c` socket connect to 1.1.1.1:443 with 3s timeout under `network="none"` → must FAIL (prints marker). Pre-pull in a session fixture: `docker pull python:3.12-alpine` (idempotent).
- [ ] **Step 2:** Verify new tests fail (module absent), implement `df_container.py`, tests green.
- [ ] **Step 3:** Full suite: `.venv/bin/python -m pytest dark-factory/tests -q` → 302 existing + new, 0 failures (docker-less machines: live tests skip). Commit `feat(dark-factory): df_container — hardened docker argv + fail-closed probe`.

---

### Task 2: hardened tier registration, config gates, supervisor wiring

**Files:** modify `dark-factory/scripts/supported_tiers.json`, `df_config.py`, `supervisor.py`, `references/config-reference.md`; create `dark-factory/tests/test_hardened_config.py`.

**Interfaces:**
- Consumes Task 1: `df_container.docker_available/build_argv/probe_container/BACKEND_NAME/DEFAULT_IMAGE/ContainerError`.
- Produces:
  - `supported_tiers.json` gains: `"hardened": {"qualified": true, "backend": "container-docker", "note": "Builder in a Docker container; control root never mounted (denial by construction, probe-verified); verifier under host OS read-denial. Requires running Docker daemon + signed audit. Spec 7.2/2.2."}`.
  - `df_config.py` injects `cfg["_container"] = {"image": str, "network": "none"|"bridge", "memory": str, "pids": int}` from an optional `hardened` block (defaults: DEFAULT_IMAGE, "none", "2g", 256). Validation: block must be a dict; image non-empty str; network in {"none","bridge"}; memory a non-empty str matching `^[0-9]+[bkmg]$` (lowercase ok, e.g. "2g", "512m"); pids int ≥ 16. A `hardened` block with `assurance != "hardened"` → ConfigError (`"hardened block requires assurance: hardened"`).
  - **L5 gate in df_config:** `autonomy` must be int 4 or 5 (absent → 4). `autonomy == 5 and assurance != "hardened"` → ConfigError (`"autonomy 5 (lights-off) requires assurance: hardened (spec 2.2)"`).
  - **hardened ⇒ signing:** if `assurance == "hardened"`: `audit.signing` absent → treated as `true` (key_path default applies); explicitly `false` → ConfigError.
  - `supervisor.resolve_isolation` hardened branch — returns the existing 4-tuple `(effective, exec_prefix, backend_name, probe_passed)`:
    ```python
    if cfg["assurance"] == "hardened":
        os_backend = df_sandbox.current_backend()
        os_ok = os_backend is not None and os_backend.available() and \
                df_sandbox.probe_denial(os_backend, control_root, workspace)
        c = cfg["_container"]
        dk_ok = df_container.docker_available() and \
                df_container.probe_container(c["image"], control_root, workspace)
        if os_ok and dk_ok:
            return "hardened", os_backend.wrap_prefix(control_root, workspace), \
                   df_container.BACKEND_NAME, True
        # fail-closed: journal PROBE_FAILED with which half failed; --allow-downgrade
        # → journal DOWNGRADE to "standard" if os_ok (recurse into the standard path
        # semantics: effective "standard" with os prefix) else to "cooperative";
        # otherwise raise df_sandbox.SandboxError("hardened tier requires a running
        # Docker daemon + passing container probe (and a working OS sandbox for the
        # verifier); ...").
    ```
    (`exec_prefix` — the returned one — stays the **verifier** wrapper, exactly as standard uses it for `run_all`.)
  - **Builder call wiring** in `_run_loop`: where `invoke_adapter(adapter, "builder", ...)` is called, at effective tier `"hardened"` replace the builder's `exec_prefix` with a per-call container argv:
    ```python
    if effective == "hardened":
        c = cfg["_container"]
        builder_prefix = df_container.build_argv(
            c["image"], workspace, ro_mounts=[os.path.dirname(os.path.realpath(adapter))],
            network=c["network"], memory=c["memory"], pids=c["pids"])
        if build_env_extra:  # twin env cannot cross the container boundary in M10
            journal.write("TWIN_ENV_SKIPPED", tier="hardened",
                          reason="builder-side twin env not forwarded into container (M12)")
        builder_env = None  # clean container env, always (credential hygiene until M11)
    else:
        builder_prefix, builder_env = exec_prefix, build_env_extra
    resp, err = invoke_adapter(adapter, "builder", workspace, prompt_file, timeout_s,
                               exec_prefix=builder_prefix, env_extra=builder_env)
    ```
    Verifier (`run_all`) keeps `exec_prefix` + `verify_env_extra` unchanged.
  - **Manifest:** at hardened, `manifest_base` records `sandbox_backend: "container-docker"`, `denial_probe_passed: True`, and a new additive `container = {"image":..., "network":..., "memory":..., "pids":...}`; other tiers get `container = None`. Thread through resume() the same way (`supervisor.py:936` region), like M9's `security`.

- [ ] **Step 1 (TDD):** `test_hardened_config.py` —
  - config: hardened accepted (registry has it) with defaults injected into `_container`; each bad field (empty image, network "host", memory "lots", pids 2, non-dict block) → ConfigError; `hardened` block under assurance standard → ConfigError; autonomy 5 + standard → ConfigError; autonomy 5 + hardened → OK and checkpoint defaults to auto; autonomy 3 / "5" (string) → ConfigError; hardened + audit.signing explicitly false → ConfigError; hardened + audit absent → `_audit["signing"] is True`.
  - resolve_isolation (monkeypatch `df_container.docker_available/probe_container` and `df_sandbox.probe_denial`): both ok → ("hardened", os-prefix, "container-docker", True); docker down + no downgrade → SandboxError; docker down + allow_downgrade + os ok → journaled DOWNGRADE to standard; both down + allow_downgrade → cooperative.
  - builder wiring (unit, monkeypatched invoke_adapter capture): at effective hardened, the builder argv prefix starts with "docker" and contains NO mount of the control root; the verifier wrapper passed to run_all is the OS prefix (not docker). Twin-env case journals TWIN_ENV_SKIPPED and passes env_extra=None.
- [ ] **Step 2:** Verify fail → implement (registry row, config, resolve_isolation, wiring, manifest threading incl. resume) → green.
- [ ] **Step 3:** config-reference.md: `assurance: hardened` row + `hardened.{image,network,memory,pids}` rows + autonomy 4/5 row (L5 gate) + hardened⇒signing note. Full suite green. Commit `feat(dark-factory): hardened tier — container builder isolation, L5 gate, signed-audit requirement`.

---

### Task 3: e2e hardened + L5 + refusal, docs

**Files:** create `dark-factory/tests/test_e2e_hardened.py`, `dark-factory/references/hardened.md`; modify `SKILL.md`.

- [ ] **Step 1:** `test_e2e_hardened.py` (CLI subprocess, reuse the setup_control/FAKE-builder helpers from existing e2e tests; `DOCKER_LIVE` skipif guard on the live ones):
  - **(a) live hardened convergence + barrier invariant:** hardened config (defaults, fake builder from `tests/fixtures/`, autonomy 4 checkpoint auto for a clean single run) → exit 0; manifest: `tier == "hardened"`, `qualified is True`, `sandbox_backend == "container-docker"`, `container.image == "python:3.12-alpine"`, `container.network == "none"`, `audit_signing` on and manifest verifies (M5a `verify_manifest` path). **Barrier proof:** plant a canary token in the control root before the run; use a fake-builder variant `fake_builder_snoop` (new fixture, copy of fake_builder that ALSO tries to read the canary path — passed via the prompt? NO, the builder can't be told the path… instead: snoop walks up from workdir and globs for `*/scenarios/*.json` and `.probe-canary*`, writing whatever it finds into `snoop.txt` in the workspace) → after the run assert `snoop.txt` exists and contains NO scenario content / canary token (the container simply cannot see those paths).
  - **(b) live L5 lights-off:** same control but `autonomy: 5` (hardened) → run completes exit 0 with NO checkpoint pause (journal has no PAUSED/state.json), manifest records `tier: hardened`; and the config-level assertion that the same config with `assurance: standard` is REJECTED at load (exit 2, stderr mentions "autonomy 5").
  - **(c) refusal without docker (no skipif — runs everywhere):** hardened config, run the supervisor CLI with `PATH` stripped of docker (env PATH=/usr/bin:/bin minus docker dir, or monkeypatched `docker_available` via an env-var test hook — simplest: subprocess env `PATH` pointing at an empty dir plus system python; assert exit != 0 and stderr mentions hardened/docker) → refusal, and with `--allow-downgrade` → journal DOWNGRADE and the manifest says effective standard-or-cooperative with `qualified` matching.
- [ ] **Step 2:** `hardened.md`: what hardened adds over standard (denial **by construction** vs deny-rule; hardening flags table; L5 availability); the TCB now includes the Docker daemon (spec §2.1); image requirements for real builders (CLI + creds baked into a user-supplied image; `network: "bridge"` needed for API egress and what that honestly means pre-M12); twins: verifier-side unaffected, builder-side env skipped (journaled) until M12; deferred: per-role capability profiles beyond the fixed flag set, credential broker (M11), egress allowlists + authenticated twin topology (M12), off-box audit (M13). SKILL.md: hardened row in the tier table + L5 note + `hardened` config sub-step. config-reference cross-check.
- [ ] **Step 3:** Verify docs vs code; full suite green (live tests skip cleanly without docker — run once with docker up, and once with `PATH` masked to prove skips); commit `feat(dark-factory): hardened e2e (container barrier, L5, fail-closed refusal) + docs`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M10):** spec §7.2 hardened row — enforced container with dropped caps, no docker socket/host PID, read-only rootfs, resource limits (`--pids-limit`, `--memory`); control-root unreachability **by construction** plus a fail-closed probe (§2.3 "probe-verified" applies to every qualified tier); §2.2 L5 ⇒ assurance ≥ hardened, now actually available because a conforming backend ships (registry + runtime probe); §7 hardened+ ⇒ signed manifest (config-enforced); honest downgrade/refusal semantics identical to M2b's discipline.

**Deliberately deferred (honest, in hardened.md):** per-role capability *profiles* (M10 ships one fixed hardened flag set for the builder role only); credential broker + raw-token scrubbing (M11 — at M10 the container gets a clean env, which is crude-but-honest hygiene); authenticated network graph, provider-only egress, builder-visible twins (M12); off-box audit sink (M13); non-Docker runtimes (podman/containerd — registry note, the backend name is explicit `container-docker`).

**Honesty note:** `network: "bridge"` (required for real builder CLIs) is unrestricted egress — a hardened run records it on the manifest so a reader can see the residual channel; `none` is the default so the *strongest* posture is opt-out, not opt-in. The suite's live container tests skip without a daemon; the fail-closed refusal path is what runs everywhere, so "docker missing" can never silently look like "hardened worked."
