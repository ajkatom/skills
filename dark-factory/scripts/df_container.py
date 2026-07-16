"""Docker-backed builder isolation for dark-factory hardened tier. Stdlib only.

The builder runs inside a Docker container where the control root is unreachable
BY CONSTRUCTION (never mounted) — dropped capabilities, no host PID/docker socket,
read-only rootfs, resource limits, and (by default) no network. No backend is
trusted without a passing `probe_container` (the fail-closed safety net, same
discipline as `df_sandbox.probe_denial`).

M17 Task 3 (enterprise tier) adds `build_enterprise_argv` + `probe_enterprise_egress`:
the enterprise container reaches ONLY a host-side credential proxy (df_proxy.py) —
everything else is dropped by an in-container iptables default-deny-egress rule,
installed by a small entrypoint wrapper script while it still holds NET_ADMIN, which
then drops NET_ADMIN from the process's (and every descendant's) capability
BOUNDING set before ever exec'ing the builder — the same CAP_SYS_ADMIN-remount
lesson M16 proved for the standard-tier sandbox (a capability granted only to
install a lockdown must be removed, irreversibly, before untrusted code runs, or
the "lockdown" is undone-able by construction), applied here to NET_ADMIN/iptables.
"""
import json
import os
import shutil
import subprocess
import tempfile
import uuid


class ContainerError(RuntimeError):
    pass


BACKEND_NAME = "container-docker"
DEFAULT_IMAGE = "python:3.12-alpine"

# Reuse df_sandbox's marker discipline: a wrapped read that raises must report this
# literal, never propagate the read content. See df_sandbox._READ_DENIAL_MARKER.
_DENIAL_MARKER = "DF-READ-DENIED"


def docker_available(runner=subprocess.run) -> bool:
    """Fail-closed: True only if the `docker` binary exists AND `docker info`
    exits 0 within 10s. Any exception (missing binary, daemon down, timeout,
    permission error) → False."""
    if shutil.which("docker") is None:
        return False
    try:
        proc = runner(
            ["docker", "info"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:
        return False
    return proc.returncode == 0


def _resolve_mount_path(path, label):
    # Require an absolute input path outright: realpath() would silently resolve a
    # relative path against the process cwd (ambiguous/dangerous for a security-
    # sensitive mount list), so relative input is rejected before resolution.
    if not os.path.isabs(path):
        raise ContainerError(f"{label} must be an absolute path: {path}")
    if not os.path.exists(path):
        raise ContainerError(f"{label} does not exist: {path}")
    real = os.path.realpath(path)
    if not os.path.isabs(real):
        raise ContainerError(f"{label} is not absolute after realpath: {real}")
    if ":" in real:
        raise ContainerError(f"{label} contains ':' (would corrupt -v spec): {real}")
    return real


def build_argv(image, workspace, ro_mounts, *, network="none", memory="2g",
               pids=256, env=None) -> list:
    """Pure. Build the `docker run` argv for the hardened builder container.

    Raises ContainerError if workspace or any ro_mount does not exist, is not
    absolute after realpath, or contains ':'. df_container does not know the
    control root — the CALLER guarantees the control root is never passed as a
    mount; nothing else can appear in the resulting -v flags."""
    if not isinstance(image, str) or not image or image.startswith("-"):
        raise ContainerError(
            f"image must be a non-empty string not starting with '-' "
            f"(got {image!r}); a leading '-' could be parsed as a docker flag"
        )
    ws = _resolve_mount_path(workspace, "workspace")
    real_ro_mounts = sorted({
        _resolve_mount_path(p, "ro_mount") for p in (ro_mounts or [])
    })

    argv = [
        "docker", "run", "--rm", "-i",
        "--network", network,
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(pids),
        "--memory", memory,
        "--read-only",
        "--tmpfs", "/tmp",
        "-e", "HOME=/tmp",
        "-v", f"{ws}:{ws}",
    ]
    for p in real_ro_mounts:
        argv += ["-v", f"{p}:{p}:ro"]
    argv += ["-w", ws]
    for k in sorted((env or {}).keys()):
        argv += ["-e", f"{k}={env[k]}"]
    argv += [image]
    return argv


def probe_container(image, deny_root, workspace, *, timeout_s=180, runner=subprocess.run) -> bool:
    """Fail-closed: True ONLY IF the container provably launched (rc == 0) AND the
    canary planted in deny_root was provably unreachable (stdout is exactly the
    denial marker). Any error/timeout/nonzero rc/leaked token → False. Canary is
    always unlinked."""
    token = "DF-CANARY-" + uuid.uuid4().hex
    canary = os.path.join(deny_root, ".probe-canary-" + uuid.uuid4().hex)
    try:
        try:
            with open(canary, "w", encoding="utf-8") as f:
                f.write(token)
        except OSError:
            return False
        try:
            argv = build_argv(image, workspace, [])
        except ContainerError:
            return False
        code = (
            "import sys\n"
            "try:\n"
            "    sys.stdout.write(open(sys.argv[1]).read())\n"
            "except Exception:\n"
            f"    sys.stdout.write({_DENIAL_MARKER!r})\n"
        )
        try:
            proc = runner(
                argv + ["python3", "-c", code, canary],
                capture_output=True, text=True, timeout=timeout_s,
            )
        except Exception:
            return False
        # Fail-closed: True only if the container provably ran AND hit the denial
        # branch. Vacuous stdout from a launch failure (nonzero exit) must NOT be
        # mistaken for a proven denial.
        return proc.returncode == 0 and proc.stdout.strip() == _DENIAL_MARKER
    finally:
        try:
            os.unlink(canary)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# M17 Task 3: enterprise tier -- kernel-locked egress-to-proxy + seccomp.
# ---------------------------------------------------------------------------

ENTERPRISE_BACKEND_NAME = "container-enterprise"

# Mount point INSIDE the container for the host-written entrypoint wrapper
# (see enterprise_entrypoint_script). Fixed, not configurable -- it never
# collides with a caller-supplied ro_mount because df_container never lets
# a ro_mount resolve under this path (it isn't a real host path).
_ENTERPRISE_ENTRYPOINT_CONTAINER_PATH = "/df-entrypoint.sh"

DEFAULT_SECCOMP_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "seccomp", "enterprise.json"
)


def _parse_proxy_endpoint(proxy_endpoint):
    """Pure. 'host:port' -> (host, port). Raises ContainerError on anything
    else -- a malformed endpoint must fail closed at build time, not produce
    an entrypoint script that silently locks the container out of its own
    proxy."""
    if not isinstance(proxy_endpoint, str) or ":" not in proxy_endpoint:
        raise ContainerError(
            f"proxy_endpoint must be a 'host:port' string, got {proxy_endpoint!r}"
        )
    host, _, port_s = proxy_endpoint.rpartition(":")
    if not host:
        raise ContainerError(
            f"proxy_endpoint must be a 'host:port' string, got {proxy_endpoint!r}"
        )
    try:
        port = int(port_s)
    except ValueError:
        raise ContainerError(
            f"proxy_endpoint port must be an integer, got {port_s!r} in {proxy_endpoint!r}"
        )
    if not (1 <= port <= 65535):
        raise ContainerError(f"proxy_endpoint port out of range 1..65535: {port}")
    return host, port


# The entrypoint wrapper, mounted read-only into every enterprise container and
# invoked via `--entrypoint /bin/sh` (see build_enterprise_argv). It runs with
# NET_ADMIN + SETPCAP (granted only for this purpose) and does exactly three
# things, in this order, before ever handing control to the builder:
#
#   1. Resolves the proxy HOSTNAME to an IP address while DNS still works
#      (the lockdown below has not been installed yet) -- so the builder
#      NEVER needs to do its own DNS resolution after lockdown: HTTP(S)_PROXY
#      is exported pointing at the already-resolved IP, not the hostname.
#   2. Installs a default-deny OUTPUT policy that allows ONLY loopback,
#      established/related return traffic, and the resolved proxy IP:port --
#      then IRREVOCABLY drops NET_ADMIN (and SETPCAP, which is what would let
#      a process re-drop/re-raise capability sets at all) from this process's
#      capability BOUNDING set via `setpriv --bounding-set=...`. Per
#      capabilities(7), a bounding-set drop cannot be undone by ANY later
#      operation for this process or any of its descendants, even one still
#      running as root with CAP_SETPCAP at the moment of the drop -- this is
#      the same fail-closed, irrevocable-ratchet property M16 proved for
#      CAP_SYS_ADMIN in the standard-tier bwrap backend, applied here to
#      NET_ADMIN so the iptables lockdown just installed can never be undone
#      by the untrusted builder child.
#   3. execs the builder (the entrypoint's own "$@", i.e. whatever argv
#      docker was given after the entrypoint path) with HTTP_PROXY/
#      HTTPS_PROXY set -- the builder speaks plaintext to the LOCAL proxy
#      port it's been given; df_proxy.py is the one that opens the real
#      (TLS, for https targets) leg to the actual provider.
_ENTERPRISE_ENTRYPOINT_TEMPLATE = """#!/bin/sh
# dark-factory enterprise entrypoint (M17 Task 3) -- DO NOT EDIT BY HAND,
# generated by df_container.enterprise_entrypoint_script(). See
# dark-factory/references/enterprise.md.
set -e

PROXY_HOST="__PROXY_HOST__"
PROXY_PORT="__PROXY_PORT__"

PROXY_IP="$(python3 -c 'import socket,sys; print(socket.gethostbyname(sys.argv[1]))' "$PROXY_HOST")"
if [ -z "$PROXY_IP" ]; then
    echo "df-entrypoint: could not resolve proxy host $PROXY_HOST" >&2
    exit 97
fi

iptables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -d "$PROXY_IP" -p tcp --dport "$PROXY_PORT" -j ACCEPT

export HTTP_PROXY="http://$PROXY_IP:$PROXY_PORT"
export HTTPS_PROXY="http://$PROXY_IP:$PROXY_PORT"
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTPS_PROXY"

exec setpriv --bounding-set=-net_admin,-setpcap -- "$@"
"""


def enterprise_entrypoint_script(proxy_endpoint) -> str:
    """Pure. Render the entrypoint wrapper script text for `proxy_endpoint`
    ('host:port'). Raises ContainerError on a malformed endpoint (via
    _parse_proxy_endpoint) -- never emits a script that would silently fail
    to reach the proxy it's supposed to lock the container down to."""
    host, port = _parse_proxy_endpoint(proxy_endpoint)
    return (
        _ENTERPRISE_ENTRYPOINT_TEMPLATE
        .replace("__PROXY_HOST__", host)
        .replace("__PROXY_PORT__", str(port))
    )


def write_enterprise_entrypoint(path: str, proxy_endpoint) -> None:
    """Render enterprise_entrypoint_script(proxy_endpoint) to `path` and mark
    it read+execute-only (0o555, no write bit for anyone, including the
    owner): the script's integrity matters -- it's what installs the egress
    lock -- so it's written once and never touched again for the life of the
    container invocation that mounts it read-only."""
    script = enterprise_entrypoint_script(proxy_endpoint)
    with open(path, "w", encoding="utf-8") as f:
        f.write(script)
    os.chmod(path, 0o555)


def build_enterprise_argv(image, workspace, ro_mounts, *, proxy_endpoint,
                          seccomp_profile_path, entrypoint_path, network="bridge",
                          memory="2g", pids=256, env=None) -> list:
    """Pure (given entrypoint_path/seccomp_profile_path already exist on disk).
    Build the `docker run` argv for the enterprise builder container: every
    hardened guarantee from `build_argv` (all capabilities dropped, no-new-
    privileges, read-only rootfs, resource limits, control root never
    mounted -- df_container still doesn't know the control root; the CALLER
    still guarantees that) PLUS:

      - NET_ADMIN + SETPCAP added back ONLY so the entrypoint wrapper (see
        enterprise_entrypoint_script) can install the iptables egress lock
        and then irrevocably drop both before the builder ever runs;
      - a restrictive seccomp profile (--security-opt seccomp=<path>);
      - `network` defaults to "bridge" (NOT "none" like hardened's default)
        -- the container must be able to reach the proxy at all; the actual
        confinement is the in-container iptables default-deny-egress rule,
        not the docker network mode;
      - the entrypoint script mounted read-only at a fixed container path
        and invoked via `--entrypoint /bin/sh <image> <entrypoint-path>`, so
        the docker "command" (appended by the caller, e.g. the adapter
        binary path) becomes the entrypoint script's own "$@".

    Raises ContainerError under the same conditions as build_argv (bad
    image/workspace/ro_mounts), PLUS a missing/relative entrypoint_path,
    seccomp_profile_path, or malformed proxy_endpoint.
    """
    if not isinstance(image, str) or not image or image.startswith("-"):
        raise ContainerError(
            f"image must be a non-empty string not starting with '-' "
            f"(got {image!r}); a leading '-' could be parsed as a docker flag"
        )
    ws = _resolve_mount_path(workspace, "workspace")
    real_ro_mounts = sorted({
        _resolve_mount_path(p, "ro_mount") for p in (ro_mounts or [])
    })
    entrypoint_real = _resolve_mount_path(entrypoint_path, "entrypoint_path")
    seccomp_real = _resolve_mount_path(seccomp_profile_path, "seccomp_profile_path")
    # Validated here purely to fail closed at build time on a malformed
    # value -- the resolved host/port are never baked into argv; only the
    # (already-rendered, by write_enterprise_entrypoint) entrypoint script
    # uses them, at container start.
    _parse_proxy_endpoint(proxy_endpoint)

    argv = [
        "docker", "run", "--rm", "-i",
        "--network", network,
        "--cap-drop", "ALL",
        "--cap-add", "NET_ADMIN",
        "--cap-add", "SETPCAP",
        "--security-opt", "no-new-privileges",
        "--security-opt", f"seccomp={seccomp_real}",
        "--pids-limit", str(pids),
        "--memory", memory,
        "--read-only",
        "--tmpfs", "/tmp",
        "--tmpfs", "/run",
        "-e", "HOME=/tmp",
        "-v", f"{ws}:{ws}",
        "-v", f"{entrypoint_real}:{_ENTERPRISE_ENTRYPOINT_CONTAINER_PATH}:ro",
    ]
    for p in real_ro_mounts:
        argv += ["-v", f"{p}:{p}:ro"]
    argv += ["-w", ws]
    for k in sorted((env or {}).keys()):
        argv += ["-e", f"{k}={env[k]}"]
    argv += ["--entrypoint", "/bin/sh", image, _ENTERPRISE_ENTRYPOINT_CONTAINER_PATH]
    return argv


# The probe's in-container payload: proves live (a) the allowlisted host is
# reachable THROUGH the proxy, (b) a DIRECT connection to a non-allowlisted
# host is denied, (c) the child cannot re-add an iptables ACCEPT rule
# (NET_ADMIN was dropped by the entrypoint before this ever ran). Never
# raises -- every check is independently try/excepted into the result dict,
# read back by the host-side probe_enterprise_egress via a single marker line.
_ENTERPRISE_PROBE_TEMPLATE = """
import json, os, socket, subprocess, urllib.request

allowed_url = "__ALLOWED_URL__"
denied_host = "__DENIED_HOST__"
denied_port = __DENIED_PORT__

result = {}

proxy_url = os.environ.get("HTTP_PROXY", "")
result["proxy_url_seen"] = bool(proxy_url)
try:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    resp = opener.open(allowed_url, timeout=5)
    resp.read()
    result["allowed_reachable"] = True
except Exception as e:
    result["allowed_reachable"] = False
    result["allowed_error"] = repr(e)

try:
    s = socket.create_connection((denied_host, denied_port), timeout=5)
    s.close()
    result["denied_blocked"] = False
except Exception:
    result["denied_blocked"] = True

try:
    proc = subprocess.run(
        ["iptables", "-A", "OUTPUT", "-d", "8.8.8.8", "-j", "ACCEPT"],
        capture_output=True, text=True, timeout=10)
    result["iptables_blocked"] = (proc.returncode != 0)
    result["iptables_stderr"] = proc.stderr.strip()[:200]
except Exception as e:
    result["iptables_blocked"] = True
    result["iptables_error"] = repr(e)

print("DF-ENTERPRISE-PROBE " + json.dumps(result))
"""

_ENTERPRISE_PROBE_MARKER = "DF-ENTERPRISE-PROBE "


def probe_enterprise_egress(image, proxy_endpoint, allowed_url, denied_host, *,
                            denied_port=443, seccomp_profile_path=None,
                            memory="512m", pids=64, timeout_s=90,
                            runner=subprocess.run):
    """Fail-closed live probe (M16 harness style) proving, on a REAL Docker
    container, that the enterprise egress lock holds:

      (a) BASELINE (non-vacuity): this same image, plain bridge networking,
          NO lockdown, can reach `denied_host` -- proven FIRST, exactly like
          df_linux_probes.probe_egress_denial's before/after discipline, so a
          later "denied" result can never be mistaken for a dead network.
      (b) LOCKED DOWN, via build_enterprise_argv's entrypoint: `allowed_url`
          is reachable THROUGH the proxy; a DIRECT connect to `denied_host`
          is denied; the child cannot re-add an iptables ACCEPT rule (NET_ADMIN
          was dropped).

    Returns (ok: bool, detail: dict). ok is True only if ALL of baseline
    connectivity, allowed_reachable, denied_blocked, and iptables_blocked
    hold. ANY uncertainty (launch failure, timeout, unparseable probe output,
    a malformed argument) resolves to False -- never a vacuous/partial PASS.
    `detail` never contains proxy_endpoint's resolved IP or any credential;
    it is diagnostic only (stdout/stderr/parsed probe result).
    """
    seccomp_profile_path = seccomp_profile_path or DEFAULT_SECCOMP_PATH
    tmpdir = tempfile.mkdtemp(prefix="df-enterprise-probe-")
    try:
        workspace = os.path.join(tmpdir, "ws")
        os.makedirs(workspace, exist_ok=True)
        entrypoint_path = os.path.join(tmpdir, "df-entrypoint.sh")
        try:
            write_enterprise_entrypoint(entrypoint_path, proxy_endpoint)
        except ContainerError as e:
            return False, {"error": f"entrypoint script: {e}"}

        # --- (a) baseline: plain hardened-style container, real bridge
        # network, NO enterprise lockdown -- proves denial below isn't vacuous.
        try:
            baseline_argv = build_argv(image, workspace, [], network="bridge",
                                       memory=memory, pids=pids)
        except ContainerError as e:
            return False, {"error": f"baseline build_argv: {e}"}
        baseline_code = (
            "import socket\n"
            "try:\n"
            f"    socket.create_connection(({denied_host!r}, {denied_port}), timeout=5).close()\n"
            "    print('DF-BASELINE-OK')\n"
            "except Exception as e:\n"
            "    print('DF-BASELINE-FAIL', repr(e))\n"
        )
        try:
            proc = runner(baseline_argv + ["python3", "-c", baseline_code],
                          capture_output=True, text=True, timeout=timeout_s)
        except Exception as e:
            return False, {"error": f"baseline probe launch failed: {e!r}"}
        if proc.returncode != 0 or "DF-BASELINE-OK" not in proc.stdout:
            return False, {
                "error": "no baseline connectivity to denied_host -- a later "
                         "denial would be vacuous",
                "stdout": proc.stdout, "stderr": proc.stderr,
            }

        # --- (b) the locked-down enterprise container ---
        try:
            argv = build_enterprise_argv(
                image, workspace, [], proxy_endpoint=proxy_endpoint,
                seccomp_profile_path=seccomp_profile_path,
                entrypoint_path=entrypoint_path, memory=memory, pids=pids)
        except ContainerError as e:
            return False, {"error": f"build_enterprise_argv: {e}"}
        probe_code = (
            _ENTERPRISE_PROBE_TEMPLATE
            .replace("__ALLOWED_URL__", allowed_url)
            .replace("__DENIED_HOST__", denied_host)
            .replace("__DENIED_PORT__", str(denied_port))
        )
        try:
            proc = runner(argv + ["python3", "-c", probe_code],
                          capture_output=True, text=True, timeout=timeout_s)
        except Exception as e:
            return False, {"error": f"enterprise probe launch failed: {e!r}"}
        if proc.returncode != 0:
            return False, {
                "error": f"enterprise container exited {proc.returncode}",
                "stdout": proc.stdout, "stderr": proc.stderr,
            }
        line = next(
            (l for l in proc.stdout.splitlines() if l.startswith(_ENTERPRISE_PROBE_MARKER)),
            None,
        )
        if line is None:
            return False, {
                "error": "no DF-ENTERPRISE-PROBE marker line in stdout",
                "stdout": proc.stdout, "stderr": proc.stderr,
            }
        try:
            result = json.loads(line[len(_ENTERPRISE_PROBE_MARKER):])
        except json.JSONDecodeError:
            return False, {"error": "unparseable probe result JSON", "raw": line}

        ok = bool(
            result.get("allowed_reachable") is True
            and result.get("denied_blocked") is True
            and result.get("iptables_blocked") is True
        )
        result["baseline_connectivity"] = True
        return ok, result
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# M22 Task 1: configurable + LIVE-PROBED enterprise seccomp.
#
# M17 shipped one FIXED seccomp profile, sanity-checked only offline (parses
# as JSON, has the right shape -- see supervisor._seccomp_profile_ok). That
# proves nothing about what the profile actually DOES on a real kernel: a
# profile with `defaultAction: SCMP_ACT_ALLOW` and an empty (or wrong) deny
# list parses fine and denies nothing. `probe_seccomp` closes that gap the
# same way M16/M17's other probes do: run a REAL container under the
# profile and observe, not assume.
# ---------------------------------------------------------------------------

_SECCOMP_PROBE_MARKER = "DF-SECCOMP-PROBE "

# In-container payload (M16-harness style): every check is independently
# try/excepted into `result` so the script itself never raises/crashes the
# probe -- ambiguity is resolved on the HOST side (probe_seccomp), which
# treats a missing/unparseable marker line, or any check that didn't
# unambiguously report denied/allowed, as False. Three denied-syscall
# canaries (mount, unshare, ptrace) are attempted WITH SYS_ADMIN granted
# (via --cap-add SYS_ADMIN in the docker invocation below) -- so a profile
# that fails to deny one of them would otherwise SUCCEED (the capability is
# present), proving it is the SECCOMP FILTER, not a missing capability, that
# denies it. One allowed op (a plain file write under /tmp) must still
# succeed, proving the profile isn't so broad it breaks ordinary builder
# operation.
_SECCOMP_PROBE_SCRIPT = """
import ctypes, ctypes.util, json, os, subprocess

result = {}

# FAIL-CLOSED POLARITY: on an EXCEPTION (a missing mount/unshare binary on a
# minimal/distroless image, an unloadable libc, etc.) we CANNOT distinguish
# "the kernel/seccomp denied it" from "we couldn't even attempt the syscall"
# -- so we record AMBIGUITY (None), NOT denial (True). The host-side
# probe_seccomp requires each `*_denied is True` (not merely truthy), so a
# None resolves the whole probe to False: an inconclusive probe refuses the
# tier rather than "verifying" a profile it could not actually test on this
# image. (Contrast the allow-check below, whose fail-closed direction is the
# opposite: an error there means the allowed op did NOT succeed -> False.)
try:
    os.makedirs("/tmp/df-seccomp-mnt", exist_ok=True)
    proc = subprocess.run(
        ["mount", "-t", "tmpfs", "tmpfs", "/tmp/df-seccomp-mnt"],
        capture_output=True, timeout=10)
    result["mount_denied"] = (proc.returncode != 0)
except Exception as e:
    result["mount_denied"] = None
    result["mount_error"] = repr(e)

try:
    proc = subprocess.run(["unshare", "-m", "true"], capture_output=True, timeout=10)
    result["unshare_denied"] = (proc.returncode != 0)
except Exception as e:
    result["unshare_denied"] = None
    result["unshare_error"] = repr(e)

try:
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    rc = libc.ptrace(0, 0, 0, 0)
    result["ptrace_denied"] = (rc != 0)
except Exception as e:
    result["ptrace_denied"] = None
    result["ptrace_error"] = repr(e)

try:
    with open("/tmp/df-seccomp-ok", "w", encoding="utf-8") as f:
        f.write("ok")
    result["write_ok"] = True
except Exception as e:
    result["write_ok"] = False
    result["write_error"] = repr(e)

print("DF-SECCOMP-PROBE " + json.dumps(result))
"""


def probe_seccomp(image, profile_path, *, timeout_s=120, runner=subprocess.run) -> bool:
    """Fail-closed live probe (M22 Task 1): proves, on a REAL Docker
    container, that the seccomp profile at `profile_path` actually DENIES
    mount/unshare/ptrace -- not merely that the JSON parses -- while still
    ALLOWING an ordinary file write.

    Runs `docker run --rm --security-opt seccomp=<profile_path> --cap-add
    SYS_ADMIN <image> sh -c 'python3 -c "$1"' _ <probe script>` (SYS_ADMIN is
    added back so a profile that FAILS to deny mount/unshare would otherwise
    SUCCEED -- proving the seccomp filter, not a missing capability, is what
    denies it).

    Returns True ONLY IF the container provably ran (rc == 0), a single
    well-formed DF-SECCOMP-PROBE marker line was found, AND that line's
    parsed result shows mount_denied, unshare_denied, and ptrace_denied all
    True AND write_ok True. Any error, timeout, missing/duplicate marker,
    unparseable JSON, or a check that didn't unambiguously report denied
    (e.g. a missing key) resolves to False -- never a vacuous/partial PASS.
    This is scoped, honest coverage of the canary syscalls it checks, NOT a
    full profile audit (see references/enterprise.md).
    """
    if not isinstance(profile_path, str) or not profile_path:
        return False
    if not os.path.isfile(profile_path):
        return False
    if not isinstance(image, str) or not image or image.startswith("-"):
        return False
    argv = [
        "docker", "run", "--rm",
        "--security-opt", f"seccomp={profile_path}",
        "--cap-add", "SYS_ADMIN",
        image, "sh", "-c", 'exec python3 -c "$1"', "_", _SECCOMP_PROBE_SCRIPT,
    ]
    try:
        proc = runner(argv, capture_output=True, text=True, timeout=timeout_s)
    except Exception:
        return False
    if proc.returncode != 0:
        return False
    lines = [l for l in proc.stdout.splitlines() if l.startswith(_SECCOMP_PROBE_MARKER)]
    if len(lines) != 1:
        return False
    try:
        result = json.loads(lines[0][len(_SECCOMP_PROBE_MARKER):])
    except json.JSONDecodeError:
        return False
    if not isinstance(result, dict):
        return False
    return bool(
        result.get("mount_denied") is True
        and result.get("unshare_denied") is True
        and result.get("ptrace_denied") is True
        and result.get("write_ok") is True
    )
