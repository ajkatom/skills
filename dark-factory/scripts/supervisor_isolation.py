"""Run-time isolation resolution: enterprise egress verification, tier probes + downgrade, candidate network/host confinement prefixes, twin port pinning.

Extracted verbatim from supervisor.py (see supervisor.py for the CLI entry point and
the run/resume core). Every top-level name here is re-exported by supervisor.py, so
`supervisor.<name>` keeps working for tests and df_evidence_bundle.
"""
import http.server
import json
import os
import secrets
import socket
import sys
import threading
import uuid

import df_container
import df_proxy
import df_sandbox
from df_common import canonical_json, sha256_str
from supervisor_core import (
    _ENTERPRISE_PROXY_HOST,
    _QUALIFYING_TIERS,
    _effective_image,
)


def _seccomp_profile_ok(path):
    """Fast, deterministic, offline sanity check that the enterprise seccomp
    profile at `path` exists and parses as a plausible Docker seccomp JSON
    document (has "defaultAction" + "syscalls"). This is NOT the live proof
    that the egress lock actually holds on a real kernel — that is
    df_container.probe_enterprise_egress, which needs a running proxy and
    specific allowed/denied hosts. (DF-05/M32: the live probe now DOES run
    once per enterprise run, via `_verify_enterprise_egress` below — against
    a throwaway stub target, not the real provider/allowlist — see that
    function's docstring for the honest scope split.) Any error (missing
    file, invalid JSON, wrong shape) → False, never a silent pass."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(data, dict) and "defaultAction" in data and "syscalls" in data


# ---------------------------------------------------------------------------
# DF-05/M32: mandatory per-run egress verification.
#
# resolve_isolation's enterprise probe deliberately skips
# df_container.probe_enterprise_egress (needs a running proxy, which isn't up
# yet at resolve time — see _seccomp_profile_ok's docstring). Once the real
# credential proxy for THIS run is started (_run_loop, effective=="enterprise"),
# _verify_enterprise_egress runs the deferred probe exactly once, before the
# first builder call, and the run refuses (fail-closed) if it doesn't verify.
# ---------------------------------------------------------------------------

_EGRESS_PROBE_DENIED_HOST = "1.1.1.1"


def _egress_probe_stub_handler():
    class _StubHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            body = b"df-egress-probe-ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def log_message(self, format, *args):
            pass

    return _StubHandler


def _start_egress_probe_stub():
    """Start a throwaway loopback HTTP stub (always 200 OK) — the mandatory
    per-run egress probe's "allowed" leg (see _verify_enterprise_egress).
    Never a real provider. Caller owns shutdown: httpd.shutdown();
    httpd.server_close()."""
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _egress_probe_stub_handler())
    httpd.daemon_threads = True
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, httpd.server_address[1]


def _verify_enterprise_egress(cfg, pcfg, proxy_endpoint):
    """DF-05/M32 mandatory per-run egress verification. Called ONCE per
    enterprise `_run_loop` invocation (fresh run or resume — both restart the
    proxy), before the first builder call, from inside the same try/finally
    that already owns proxy_httpd/twin cleanup.

    HONEST SCOPE — what this DOES prove: using the SAME container image and
    seccomp profile this run will use for the builder, wired through a real
    (Docker) instance of the SAME enterprise entrypoint/iptables lockdown
    machinery (df_container.build_enterprise_argv +
    df_container.probe_enterprise_egress), it proves live that (a) an
    allowlisted-via-proxy origin is reachable and (b) a direct connection to
    a denied host is blocked and the probed child cannot re-add an iptables
    ACCEPT rule (NET_ADMIN was dropped).

    What this does NOT prove: it deliberately does NOT exercise the run's
    REAL credential_proxy process/allowlist/provider (the one started in
    _run_loop for the actual builder call) — the "allowed" leg here is a
    local, always-200 stub server this function starts and tears down
    itself, fronted by a distinct, throwaway proxy + capability token. This
    is a deliberate choice, not an oversight: when the builder is an API
    adapter, the run's REAL proxy has the M30 provider method/path
    injection lock ARMED (see df_proxy._PROVIDER_METHOD_PATH / Part 1's
    `provider=` wiring below) — a generic probe request against it would
    either be refused (method/path mismatch) or, worse, if it happened to
    match the locked method+path with no client auth header, actually
    trigger a REAL credential injection and a real (paid) provider call.
    Neither is acceptable for a MANDATORY, every-run, no-cost probe. Proving
    the run's real proxy+allowlist+injection+provider-lock end to end needs
    a real provider round trip — that is a SEPARATE, OPTIONAL, operator-
    invoked, paid check (see test_enterprise_config.py's
    test_probe_enterprise_egress_live and references/enterprise.md), not run
    automatically here.

    Returns (ok: bool, detail: dict [diagnostic only, never a secret/token],
    policy_digest: str [a STABLE sha256 over the allowlist/header/image/seccomp
    that define this run's egress policy — excludes the ephemeral proxy port
    so it is comparable across runs to detect policy drift]). Never raises: any failure to even set
    up the probe (stub server, throwaway proxy, docker) resolves to
    ok=False with a diagnostic detail — fail-closed, like
    df_container.probe_enterprise_egress's own contract.
    """
    # A STABLE, cross-run-comparable fingerprint of the egress-relevant
    # policy: the allowlist + injection header + the container image + the
    # seccomp profile that together define what egress is permitted. It
    # deliberately EXCLUDES the ephemeral proxy_endpoint (its port is
    # OS-assigned and random every run, which would make the digest differ
    # run-to-run even under an identical policy and defeat drift detection).
    # An operator can diff this digest across two runs to see whether the
    # egress policy actually changed.
    # DF-R5-09/R5-11: fingerprint the EFFECTIVE (digest-pinned) image — the one
    # probes and dispatch actually use — not the configured string, so a moved
    # mutable tag shows up as policy drift instead of hiding behind a stable
    # config value.
    policy_digest = sha256_str(canonical_json({
        "allowlist": sorted(pcfg["allowlist"]),
        "header": pcfg["header"],
        "image": _effective_image(cfg),
        "seccomp_profile": cfg["_enterprise"]["seccomp"],
    }))
    stub_httpd = None
    probe_proxy_httpd = None
    # A per-call, randomly-named env var carries the probe's OWN throwaway
    # "provider" token for its OWN throwaway stub -- never a real credential,
    # never a name that could collide with an operator-configured env var,
    # and always removed in the finally below regardless of outcome.
    token_env_name = f"_DF_EGRESS_PROBE_TOKEN_{uuid.uuid4().hex}"
    try:
        stub_httpd, stub_port = _start_egress_probe_stub()
        os.environ[token_env_name] = secrets.token_urlsafe(16)
        probe_cap_token = secrets.token_urlsafe(32)
        probe_proxy_httpd, probe_proxy_port = df_proxy.serve(
            [f"127.0.0.1:{stub_port}"], token_env_name,
            capability_token=probe_cap_token)
        probe_proxy_endpoint = f"{_ENTERPRISE_PROXY_HOST}:{probe_proxy_port}"
        ok, detail = df_container.probe_enterprise_egress(
            _effective_image(cfg), probe_proxy_endpoint,
            f"http://127.0.0.1:{stub_port}/", _EGRESS_PROBE_DENIED_HOST,
            seccomp_profile_path=cfg["_enterprise"]["seccomp"],
            capability_token=probe_cap_token)
        return bool(ok), detail, policy_digest
    except Exception as e:
        return (False, {"error": f"egress probe setup failed: {e.__class__.__name__}: {e}"},
                policy_digest)
    finally:
        os.environ.pop(token_env_name, None)
        if probe_proxy_httpd is not None:
            probe_proxy_httpd.shutdown()
            probe_proxy_httpd.server_close()
        if stub_httpd is not None:
            stub_httpd.shutdown()
            stub_httpd.server_close()


def resolve_isolation(cfg, control_root, workspace, journal, allow_downgrade):
    if cfg["assurance"] == "enterprise":
        os_backend = df_sandbox.current_backend()
        os_name = os_backend.name if os_backend is not None else None
        os_ok = os_backend is not None and os_backend.available() and df_sandbox.probe_denial(
            os_backend, control_root, workspace)
        # DF-R4-10: pin the digest ONCE, before the first container op, and use
        # the pinned reference for every probe + the real builder dispatch.
        eff_image = _effective_image(cfg)
        dk_ok = df_container.docker_available() and df_container.probe_container(
            eff_image, control_root, workspace)
        seccomp_path = cfg["_enterprise"]["seccomp"]
        # M22 Task 1: the offline shape-check (_seccomp_profile_ok) is a
        # fast, no-docker-needed rejection of a missing/malformed profile
        # (mirrors df_config's own load-time validation); the LIVE probe
        # (df_container.probe_seccomp) is the actual proof the profile
        # DENIES what it claims to on a real kernel -- run it only once the
        # offline check and the container probe both already passed (no
        # point spending a docker run on a profile path that's already known
        # bad, or when docker itself isn't even up). Same fail-closed
        # discipline as the egress probe: any doubt -> seccomp_ok False.
        seccomp_ok = (
            _seccomp_profile_ok(seccomp_path)
            and dk_ok
            and df_container.probe_seccomp(eff_image, seccomp_path)
        )
        if os_ok and dk_ok and seccomp_ok:
            return ("enterprise", os_backend.wrap_prefix(control_root, workspace),
                    df_container.ENTERPRISE_BACKEND_NAME, True)
        failed = []
        if not dk_ok:
            failed.append("docker")
        if not os_ok:
            failed.append("os_sandbox")
        if not seccomp_ok:
            failed.append("seccomp_profile")
        reason = f"enterprise probe failed: {', '.join(failed)}"
        if allow_downgrade:
            # Enterprise ⊇ hardened: a failed enterprise probe with a
            # WORKING hardened path (os+docker both ok, only the seccomp
            # profile is the problem) downgrades one step to hardened —
            # still container-barrier-qualified, just without the egress
            # lock/seccomp — before falling further to standard/cooperative.
            if os_ok and dk_ok:
                journal.write("DOWNGRADE", requested="enterprise", effective="hardened",
                              reason=reason)
                sys.stderr.write("dark-factory: enterprise tier UNavailable — DOWNGRADED to "
                                 "hardened (qualified, no egress lock/split-custody) by "
                                 "--allow-downgrade.\n")
                return ("hardened", os_backend.wrap_prefix(control_root, workspace),
                        df_container.BACKEND_NAME, True)
            if os_ok:
                journal.write("DOWNGRADE", requested="enterprise", effective="standard",
                              reason=reason)
                sys.stderr.write("dark-factory: enterprise tier UNavailable — DOWNGRADED to "
                                 "standard (qualified) by --allow-downgrade.\n")
                return ("standard", os_backend.wrap_prefix(control_root, workspace), os_name, True)
            journal.write("DOWNGRADE", requested="enterprise", effective="cooperative",
                          reason=reason)
            sys.stderr.write("dark-factory: enterprise tier UNavailable — DOWNGRADED to "
                             "cooperative (unqualified) by --allow-downgrade.\n")
            return ("cooperative", [], os_name, False)
        journal.write("PROBE_FAILED", requested="enterprise", reason=reason)
        raise df_sandbox.SandboxError(
            "enterprise tier requires a running Docker daemon + passing container probe "
            "+ a valid seccomp profile (and a working OS sandbox for the verifier); "
            f"none available ({reason}). Fix docker/the sandbox/seccomp profile, or set "
            "assurance=hardened/standard/cooperative (or pass --allow-downgrade).")
    if cfg["assurance"] == "hardened":
        os_backend = df_sandbox.current_backend()
        os_name = os_backend.name if os_backend is not None else None
        os_ok = os_backend is not None and os_backend.available() and df_sandbox.probe_denial(
            os_backend, control_root, workspace)
        # DF-R4-10: pin the digest ONCE and probe the pinned reference.
        dk_ok = df_container.docker_available() and df_container.probe_container(
            _effective_image(cfg), control_root, workspace)
        if os_ok and dk_ok:
            return ("hardened", os_backend.wrap_prefix(control_root, workspace),
                    df_container.BACKEND_NAME, True)
        failed = []
        if not dk_ok:
            failed.append("docker")
        if not os_ok:
            failed.append("os_sandbox")
        reason = f"hardened probe failed: {', '.join(failed)}"
        if allow_downgrade:
            if os_ok:
                journal.write("DOWNGRADE", requested="hardened", effective="standard",
                              reason=reason)
                sys.stderr.write("dark-factory: hardened tier UNavailable — DOWNGRADED to "
                                 "standard (qualified) by --allow-downgrade.\n")
                return ("standard", os_backend.wrap_prefix(control_root, workspace), os_name, True)
            journal.write("DOWNGRADE", requested="hardened", effective="cooperative",
                          reason=reason)
            sys.stderr.write("dark-factory: hardened tier UNavailable — DOWNGRADED to "
                             "cooperative (unqualified) by --allow-downgrade.\n")
            # Intentionally (os_name, False), NOT (None, None) like a
            # configured-cooperative run: here the backend was probed and
            # FAILED, vs never probed at all — manifests keep that distinction.
            return ("cooperative", [], os_name, False)
        journal.write("PROBE_FAILED", requested="hardened", reason=reason)
        raise df_sandbox.SandboxError(
            "hardened tier requires a running Docker daemon + passing container probe "
            "(and a working OS sandbox for the verifier); none available "
            f"({reason}). Fix the sandbox/docker or set assurance=standard/cooperative "
            "(or pass --allow-downgrade).")
    if cfg["assurance"] != "standard":
        return "cooperative", [], None, None
    backend = df_sandbox.current_backend()
    name = backend.name if backend is not None else None
    ok = backend is not None and backend.available() and df_sandbox.probe_denial(
        backend, control_root, workspace)
    if ok:
        return "standard", backend.wrap_prefix(control_root, workspace), name, True
    if allow_downgrade:
        journal.write("DOWNGRADE", requested="standard", effective="cooperative",
                      reason="sandbox unavailable or denial probe failed")
        sys.stderr.write("dark-factory: standard tier UNavailable/probe failed — "
                         "DOWNGRADED to cooperative (unqualified) by --allow-downgrade.\n")
        return "cooperative", [], name, False
    journal.write("PROBE_FAILED", requested="standard",
                  reason="sandbox unavailable or denial probe failed")
    raise df_sandbox.SandboxError(
        "standard tier requires a working OS sandbox + passing denial probe; "
        "none available. Fix the sandbox or set assurance=cooperative "
        "(or pass --allow-downgrade).")


def _resolve_candidate_network_prefix(cfg, control_root, workspace, exec_prefix, eff_tier, journal):
    """M27 Task 2 (spec §7.4): builds the CANDIDATE/verifier-only exec wrapper
    used by every run_all(...) call (and brownfield characterize()), kept
    strictly separate from `exec_prefix` -- which stays exactly what
    resolve_isolation returned and is what the BUILDER uses at every tier
    (see _run_loop's builder_prefix handling, unchanged by this function). A
    network restriction on the candidate must never reach the builder.

    cfg["candidate_network"] == "unrestricted" (the default, and the ONLY
    legal value df_config accepts at a configured cooperative tier) is a
    total no-op: returns `exec_prefix` unchanged, byte-identical to pre-M27
    behavior -- nothing new is ever built or probed.

    Otherwise the EFFECTIVE tier must actually carry an OS sandbox backend
    (standard/hardened/enterprise -- the same tiers resolve_isolation ever
    calls `os_backend.wrap_prefix()` for; see _QUALIFYING_TIERS). A
    --allow-downgrade run can still resolve to "cooperative" at RUNTIME even
    though df_config only ever accepted candidate_network != "unrestricted"
    for a CONFIGURED standard-or-above tier -- in that case there is no
    sandbox left to enforce the restriction, so this fails closed exactly
    like a failed isolation probe: journals PROBE_FAILED and raises
    SandboxError, which every existing call site already catches and turns
    into a clean exit 2 (never a traceback).

    When a backend IS available, `wrap_prefix(..., network=mode)` builds the
    candidate-only wrapper and `probe_network_denial` LIVE-proves it before
    anything relies on it -- the same fail-closed discipline as the base
    denial probe. A SandboxError raised by wrap_prefix itself (e.g. Linux +
    "loopback", which bwrap cannot support) surfaces the same clean way.
    """
    mode = cfg["candidate_network"]
    if mode == "unrestricted":
        return exec_prefix
    if eff_tier not in _QUALIFYING_TIERS:
        reason = (f"effective isolation tier is {eff_tier!r} -- no OS sandbox "
                  "backend is available to enforce it")
        journal.write("PROBE_FAILED", requested=f"candidate_network:{mode}", reason=reason)
        raise df_sandbox.SandboxError(
            f"candidate_network {mode!r} requires a working OS sandbox backend, but "
            f"{reason}. Fix the sandbox or set candidate_network=unrestricted.")
    os_backend = df_sandbox.current_backend()
    try:
        candidate_prefix = os_backend.wrap_prefix(control_root, workspace, network=mode)
    except df_sandbox.SandboxError as e:
        journal.write("PROBE_FAILED", requested=f"candidate_network:{mode}", reason=str(e))
        raise
    ok, reason = df_sandbox.probe_network_denial(os_backend, control_root, workspace, mode)
    if not ok:
        journal.write("PROBE_FAILED", requested=f"candidate_network:{mode}", reason=reason)
        raise df_sandbox.SandboxError(
            f"candidate_network {mode!r} live network-denial probe failed -- refusing "
            f"to run the candidate with an unproven network restriction: {reason}")
    return candidate_prefix


# host_isolation residuals that DISQUALIFY (manifest host_isolation.qualified
# False when any is present). RESIDUAL_METADATA (stat/existence visibility
# outside $HOME, structural to the profile's measured-required broad
# file-read-metadata allow) and RESIDUAL_NET_UNRESTRICTED (egress open because
# candidate_network was CONFIGURED unrestricted -- that axis' own choice, not
# a host-read defect) are the two non-disqualifying ones; everything else --
# host reads open, keychain reachable, resolver reachable at a denying network
# mode -- defeats the point of host isolation. M36's qualification FSM folds
# this field into the overall `qualified` boolean; M29b only computes and
# seals it honestly.
_HOST_ISOLATION_SOFT_RESIDUALS = frozenset({
    df_sandbox.RESIDUAL_METADATA,
    df_sandbox.RESIDUAL_NET_UNRESTRICTED,
    # M47 RA-08(b): a host backend's process-group escape is NAMED honestly as a
    # residual but does NOT disqualify -- host_isolation already gates on host
    # READ containment; the process-group best-effort is a separately-documented
    # residual (references/isolation.md) that a namespace backend closes.
    df_sandbox.RESIDUAL_PROCESS_GROUP_ESCAPE,
    # M93: the service-port reservation race is SOFT for the same reason
    # process_group_escape is -- its adversary is a hostile SAME-USER local
    # process acting live during the run, which the documented
    # detection-grade threat model already excludes for stronger claims
    # than this (it can rewrite the audit chain). Named + sealed, never
    # silently absent.
    df_sandbox.RESIDUAL_SERVICE_PORT_RACE,
    # M93 note: RESIDUAL_LOOPBACK_OUTBOUND_OPEN is deliberately NOT in this
    # set -- loopback_outbound="any" opens a confused-deputy egress channel
    # to services ALREADY listening (no live racing adversary needed --
    # materially weaker than the reservation race above), so a run under it
    # is HONESTLY unqualified. The qualifying path for self-serving
    # candidates is candidate_service_ports (pinned-only outbound).
})


def _host_isolation_qualified(mode, passed, residuals):
    return bool(
        mode == "default_deny"
        and passed
        and not [r for r in residuals if r not in _HOST_ISOLATION_SOFT_RESIDUALS]
    )


def _annotate_process_containment(hi, backend=None):
    """M47 RA-08(b): stamp the honest `process_containment` label onto a
    host_isolation dict, and for a best-effort (host) backend append the (soft)
    process_group_escape residual so the residual is auditable.

    A candidate that ACTUALLY ran default-deny on a PID-namespace backend (Linux
    --unshare-pid netns; a hardened/enterprise container's own PID namespace)
    has every descendant -- setsid()/double-fork included -- reaped by
    construction: "namespace". Every other case (macOS sandbox-exec, the
    standard-tier host path, an allow-host-read opt-out, cooperative's unwrapped
    candidate) can only best-effort killpg the process group, which a deliberate
    setsid()/double-fork escapes: "process_group_besteffort" (+ the residual).
    "none" only when there is no OS sandbox backend at all. Conservative by
    design -- it never OVER-claims "namespace" (the fail-closed direction).
    Idempotent (dedups the residual). Returns the same dict for convenience."""
    if backend is None:
        backend = df_sandbox.current_backend()
    if backend is None:
        hi["process_containment"] = "none"
        return hi
    namespace = (getattr(backend, "provides_pid_namespace", False)
                 and hi.get("mode") == "default_deny")
    if namespace:
        hi["process_containment"] = "namespace"
        return hi
    hi["process_containment"] = "process_group_besteffort"
    residuals = hi.setdefault("residuals", [])
    if df_sandbox.RESIDUAL_PROCESS_GROUP_ESCAPE not in residuals:
        residuals.append(df_sandbox.RESIDUAL_PROCESS_GROUP_ESCAPE)
    return hi


def _host_isolation_preliminary(cfg):
    """Config-time-known seed for the manifest `host_isolation` field, so
    EVERY terminal manifest carries it (including pre-probe abort branches,
    same additive pattern as `candidate_network`). probed=False /
    qualified=False until resolve_candidate_prefix replaces it with the
    live-probed truth."""
    if cfg.get("candidate_host_read") == "default_deny":
        mode = "default_deny"
    elif cfg.get("assurance") in ("standard", "hardened", "enterprise"):
        mode = "allow_host_read_optout"
    else:
        mode = "none"
    residuals = [] if mode == "default_deny" else [df_sandbox.RESIDUAL_HOST_READ_OPEN]
    hi = _annotate_process_containment(
        {"mode": mode, "probed": False, "passed": None,
         "residuals": residuals, "qualified": False})
    # M93: pre-probe manifests seal the REQUESTED loopback-outbound scoping
    # + service-port authority too, so no terminal (GATE_FAILED, coverage,
    # invalid-scenario, ...) ever omits the field on a loopback-mode config.
    return _stamp_loopback_outbound(
        hi, cfg, cfg.get("candidate_loopback_outbound", "pinned"))


def _stamp_loopback_outbound(hi, cfg, actual):
    """M93 (audit finding 2): EVERY host_isolation dict for a loopback-mode
    run seals which outbound scoping ACTUALLY applied -- "pinned"/"any" on
    the default-deny profile, "any_legacy_m27" on every legacy/opt-out/
    downgrade path (the M27 wrapper never pinned loopback outbound), or the
    REQUESTED value on pre-probe preliminary manifests. Also seals the
    service-port authority (audit finding 3): the configured count plus the
    SOFT reservation-race residual whenever N > 0, so an auditor reads the
    widened-authority scope off the manifest, never only off config_sha256.
    No-op for non-loopback candidate_network."""
    if cfg.get("candidate_network") == "loopback":
        hi["loopback_outbound"] = actual
        n = cfg.get("candidate_service_ports", 0)
        hi["candidate_service_ports"] = n
        if n:
            residuals = hi.setdefault("residuals", [])
            if df_sandbox.RESIDUAL_SERVICE_PORT_RACE not in residuals:
                residuals.append(df_sandbox.RESIDUAL_SERVICE_PORT_RACE)
    return hi


def resolve_candidate_prefix(cfg, control_root, workspace, exec_prefix, eff_tier,
                             journal, allow_downgrade=False):
    """M29b (DF-02 host-read half): resolves the CANDIDATE/verifier-only exec
    wrapper AND the manifest `host_isolation` field -- returns
    (candidate_prefix, host_isolation). The builder's `exec_prefix` is never
    touched (CLI builders legitimately need HOME/keychain/DNS; their
    isolation story is the hardened/enterprise container).

    Paths, in order:
    - cfg["candidate_host_read"] != "default_deny" (explicit opt-out at
      standard+, or the cooperative-tier default): the prefix is EXACTLY the
      M27 `_resolve_candidate_network_prefix` result -- byte-identical
      behavior -- and host_isolation says so honestly
      (mode="allow_host_read_optout"/"none", RESIDUAL_HOST_READ_OPEN,
      qualified False).
    - default_deny + effective tier downgraded to cooperative (only
      reachable via --allow-downgrade, which already sanctioned running
      unqualified): no backend is left to enforce anything; journal the
      DOWNGRADE and return the (empty) exec_prefix with mode="none". A
      restricted candidate_network still fails closed here exactly as M27
      (delegated below).
    - default_deny + backend WITHOUT `supports_default_deny` (Linux bwrap
      until M29c, plus any test double): the legacy candidate wrapper +
      legacy probes, reported as mode="legacy_allow_host_read" -- flagged,
      never a fake default-deny claim.
    - default_deny + macOS: `probe_candidate_confinement` live-proves the
      profile fail-closed BEFORE any build. Probe failure refuses the run
      (journal CANDIDATE_CONFINEMENT_PROBE_FAILED, SandboxError -> the
      existing clean exit 2), unless --allow-downgrade, which falls back to
      the legacy wrapper as mode="allow_host_read_downgrade" (journaled,
      unqualified) -- mirroring the isolation-probe downgrade UX. On
      success the returned prefix pins NO loopback ports yet (twins are not
      started); _run_loop rebuilds the same proven profile shape per verify
      pass with that pass's twin ports via _candidate_prefix_for_twins.
    """
    host_read = cfg.get("candidate_host_read", "allow_host_read")
    net_mode = cfg["candidate_network"]

    if host_read != "default_deny" or eff_tier not in _QUALIFYING_TIERS:
        # Both the explicit opt-out and the sanctioned runtime downgrade land
        # on the M27 resolver, which itself fails closed on a restricted
        # candidate_network with no backend to enforce it.
        prefix = _resolve_candidate_network_prefix(
            cfg, control_root, workspace, exec_prefix, eff_tier, journal)
        if eff_tier not in _QUALIFYING_TIERS:
            if host_read == "default_deny":
                # Configured default_deny but the run was explicitly
                # downgraded to cooperative -- record that the host-read
                # protection went with the sandbox it rides on.
                journal.write("DOWNGRADE", requested="candidate_host_read:default_deny",
                              effective="none",
                              reason="effective tier is cooperative -- no OS sandbox backend")
                sys.stderr.write(
                    "dark-factory: candidate_host_read default_deny DOWNGRADED to none "
                    "(cooperative tier has no sandbox) -- host_isolation unqualified.\n")
            hi = {"mode": "none", "probed": False, "passed": None,
                  "residuals": [df_sandbox.RESIDUAL_HOST_READ_OPEN], "qualified": False}
            _stamp_loopback_outbound(hi, cfg, "any_legacy_m27")
        else:
            hi = {"mode": "allow_host_read_optout", "probed": False, "passed": None,
                  "residuals": [df_sandbox.RESIDUAL_HOST_READ_OPEN], "qualified": False}
            _stamp_loopback_outbound(hi, cfg, "any_legacy_m27")
        # M47 RA-08(b): neither branch runs the candidate in a PID namespace
        # (opt-out / cooperative-downgrade), so process containment is
        # best-effort -- labelled honestly with the process_group_escape residual.
        return prefix, _annotate_process_containment(hi)

    os_backend = df_sandbox.current_backend()
    if os_backend is None:
        # eff_tier is qualifying, so resolve_isolation just used a live
        # backend; it vanishing between the two calls is a broken
        # environment, not a policy choice -- fail closed.
        reason = "no OS sandbox backend available for the candidate wrapper"
        journal.write("CANDIDATE_CONFINEMENT_PROBE_FAILED",
                      requested="candidate_host_read:default_deny", reason=reason)
        raise df_sandbox.SandboxError(
            f"candidate_host_read 'default_deny': {reason}")

    if not getattr(os_backend, "supports_default_deny", False):
        # Backend without a default-deny profile (since M29c both shipped
        # backends have one, so in practice a test double): take the EXACT
        # M27 path -- same wrapper,
        # same probes, same journal events (a network-probe failure still
        # surfaces as PROBE_FAILED, not as a confinement failure it isn't)
        # -- and label the result honestly: host reads are OPEN here.
        # probed/passed refer to the legacy guarantees that were actually
        # proven for this run (resolve_isolation's control-root denial
        # probe at every qualifying tier, plus the M27 network probe when
        # candidate_network is restricted), never to a default-deny claim.
        prefix = _resolve_candidate_network_prefix(
            cfg, control_root, workspace, exec_prefix, eff_tier, journal)
        hi = {"mode": "legacy_allow_host_read", "probed": True, "passed": True,
              "residuals": [df_sandbox.RESIDUAL_HOST_READ_OPEN], "qualified": False}
        _stamp_loopback_outbound(hi, cfg, "any_legacy_m27")
        return prefix, _annotate_process_containment(hi, os_backend)

    ok, report = df_sandbox.probe_candidate_confinement(
        os_backend, control_root, workspace, net_mode,
        loopback_outbound=cfg.get("candidate_loopback_outbound", "pinned"))
    if not ok:
        reason = report.get("detail", "confinement probe failed")
        journal.write("CANDIDATE_CONFINEMENT_PROBE_FAILED",
                      requested="candidate_host_read:default_deny", reason=reason)
        if allow_downgrade:
            journal.write("DOWNGRADE", requested="candidate_host_read:default_deny",
                          effective="allow_host_read", reason=reason)
            sys.stderr.write(
                "dark-factory: candidate default-deny confinement probe FAILED; "
                "DOWNGRADED to allow_host_read (unqualified host_isolation) by "
                "--allow-downgrade.\n")
            prefix = _resolve_candidate_network_prefix(
                cfg, control_root, workspace, exec_prefix, eff_tier, journal)
            hi = {"mode": "allow_host_read_downgrade", "probed": True, "passed": False,
                  "residuals": [df_sandbox.RESIDUAL_HOST_READ_OPEN], "qualified": False}
            _stamp_loopback_outbound(hi, cfg, "any_legacy_m27")
            return prefix, _annotate_process_containment(hi, os_backend)
        raise df_sandbox.SandboxError(
            "candidate_host_read 'default_deny' live confinement probe failed -- "
            f"refusing to run the candidate with unproven host isolation: {reason} "
            "(fix the sandbox, set candidate_host_read=allow_host_read, or pass "
            "--allow-downgrade)")

    # M93 compat: kwarg only when non-default ("pinned" == legacy bytes; a
    # pre-M93 backend then fails loudly only when "any" is truly requested).
    _lo = cfg.get("candidate_loopback_outbound", "pinned")
    _lo_extra = {} if _lo == "pinned" else {"loopback_outbound": _lo}
    try:
        prefix = os_backend.wrap_candidate_prefix(
            control_root, workspace, network=net_mode, **_lo_extra)
    except df_sandbox.SandboxError as e:
        journal.write("CANDIDATE_CONFINEMENT_PROBE_FAILED",
                      requested="candidate_host_read:default_deny", reason=str(e))
        raise
    mode = report.get("mode", "default_deny")
    residuals = list(report.get("residuals", []))
    hi = {"mode": mode, "probed": True, "passed": True, "residuals": residuals,
          "qualified": _host_isolation_qualified(mode, True, residuals)}
    _stamp_loopback_outbound(
        hi, cfg, cfg.get("candidate_loopback_outbound", "pinned"))
    # M47 RA-08(b): on a namespace backend (Linux --unshare-pid) this stamps
    # "namespace"; on macOS sandbox-exec (a host backend) "process_group_
    # besteffort" + the soft process_group_escape residual. qualified was
    # computed above and the residual is SOFT, so labelling never flips it.
    return prefix, _annotate_process_containment(hi, os_backend)


def _reserve_service_ports(n):
    """M93: reserve n fresh loopback ports for the candidate's OWN listeners
    this verify pass -- bind :0, record, close. The tiny bind-race window
    (another process grabbing a port between close and the scenario's bind)
    fails a scenario visibly and re-verifies next pass: fail-closed, never
    widened. Returns a sorted list of ints."""
    socks, ports = [], []
    try:
        for _ in range(n):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", 0))
            ports.append(s.getsockname()[1])
            socks.append(s)
    finally:
        for s in socks:
            s.close()
    return sorted(ports)


def _service_ports_env(cfg, env_extra):
    """When candidate_service_ports > 0, reserve a fresh set and merge
    DF_SERVICE_PORTS into (a copy of) env_extra; else return env_extra
    untouched. The env var is the scenario-facing half of the contract; the
    profile-pinning half is _candidate_prefix_for_twins parsing it back."""
    n = cfg.get("candidate_service_ports", 0)
    if not n:
        return env_extra
    ports = _reserve_service_ports(n)
    merged = dict(env_extra or {})
    merged["DF_SERVICE_PORTS"] = ",".join(str(p) for p in ports)
    return merged


def _candidate_prefix_for_twins(cfg, host_isolation, workspace, base_prefix, twin_env):
    """Per-verify-pass candidate wrapper (M29b): when the run is in
    default-deny mode, rebuild the SAME probe-proven profile shape with THIS
    pass's twin ports pinned (twins bind fresh ephemeral ports on every
    reset, so a run-start wrapper cannot know them). Ports are data flowing
    into an already-live-proven profile shape -- no re-probe per pass. Any
    other mode (opt-out, downgrade, legacy, cooperative) returns the
    resolved base prefix untouched, so this can never silently re-tighten a
    sanctioned downgrade or loosen anything.

    A twin endpoint whose port cannot be parsed is SKIPPED, never widened:
    the candidate then simply cannot reach that twin and the scenario fails
    visibly -- fail closed, not open."""
    if not host_isolation or host_isolation.get("mode") != "default_deny":
        return base_prefix
    backend = df_sandbox.current_backend()
    if backend is None or not getattr(backend, "supports_default_deny", False):
        # resolve_candidate_prefix proved a default-deny-capable backend at
        # run start; it disappearing mid-run is a broken environment.
        raise df_sandbox.SandboxError(
            "candidate default-deny wrapper: sandbox backend disappeared mid-run")
    ports = set()
    for key, value in (twin_env or {}).items():
        if key == "DF_SERVICE_PORTS":
            # M93: the pass's reserved candidate-service ports -- pinned
            # exactly like twin ports (comma-separated ints; a garbled
            # entry is SKIPPED, never widened -- the scenario then fails
            # visibly, fail closed).
            for part in str(value).split(","):
                try:
                    ports.add(int(part))
                except ValueError:
                    continue
            continue
        try:
            ports.add(int(str(value).rsplit(":", 1)[1]))
        except (IndexError, ValueError):
            continue
    _lo = cfg.get("candidate_loopback_outbound", "pinned")
    _lo_extra = {} if _lo == "pinned" else {"loopback_outbound": _lo}
    return backend.wrap_candidate_prefix(
        cfg["_control_root"], workspace, network=cfg["candidate_network"],
        allowed_loopback_ports=sorted(ports), **_lo_extra)
