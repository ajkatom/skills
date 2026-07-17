"""OS-pluggable read+write-denial sandbox for dark-factory standard tier. Stdlib only.

A backend denies a wrapped process from READING and WRITING `deny_root` (the
holdout control root — scenarios, journal, observation logs) while leaving
`workspace` and the system usable. `current_backend()` returns the backend for
this OS or None (unsupported). No backend is trusted without a passing
`probe_denial` — the probe is the fail-closed safety net, and it proves BOTH
read denial (a planted canary is unreadable) and write denial (a fresh file
cannot be created, and the canary cannot be truncated) before anything relies
on the sandbox.

`wrap_prefix`'s `network` parameter (default `"unrestricted"`, byte-identical
to the pre-M27 profile) additionally restricts a wrapped process's NETWORK
access — `"deny"` blocks all network I/O including loopback; `"loopback"`
blocks everything except localhost (so host-bound twin servers stay
reachable while real network egress is cut off). `probe_network_denial`
mirrors `probe_denial`'s fail-closed, non-vacuous discipline for this new
axis.
"""
import os
import shutil
import socket
import subprocess
import sys
import uuid


class SandboxError(RuntimeError):
    pass


_READ_DENIAL_MARKER = "DF-READ-DENIED"
_WRITE_DENIAL_MARKER = "DF-WRITE-DENIED"
_NET_EXTERNAL_DENIAL_MARKER = "DF-NET-EXTERNAL-DENIED"
_NET_LOOPBACK_DENIAL_MARKER = "DF-NET-LOOPBACK-DENIED"

_NETWORK_MODES = ("unrestricted", "deny", "loopback")

# Real, stable external TCP target used to prove genuine egress denial (not
# just "an address that happens to be this host"). Same convention already
# used by df_linux_probes.probe_egress_denial for the M17 iptables primitive.
# On macOS this choice is load-bearing, not cosmetic: a listener bound to
# this host's OWN non-loopback address (e.g. its LAN IP, discovered via the
# classic "UDP connect to a black-hole address" trick) is USELESS as a
# "must be denied" probe target, because macOS routes traffic to any of the
# host's own addresses via lo0 (confirmed with `route get <own-lan-ip>` →
# `interface: lo0`) — the kernel treats it as intra-host before sandbox
# policy is even consulted, and sandbox-exec's `(remote ip "localhost:*")`
# filter matches it exactly like literal 127.0.0.1. So "connect to my own
# LAN IP" and "connect to 127.0.0.1" are indistinguishable to both the
# kernel and the sandbox on macOS; only a connection to a genuinely
# different host proves real-egress denial. A real external target requires
# actual internet reachability, which is exactly what the baseline
# non-vacuity check below is for: no reachability → fail closed, never a
# false pass.
_NET_PROBE_EXTERNAL_HOST = "1.1.1.1"
_NET_PROBE_EXTERNAL_PORT = 443


class _MacOSBackend:
    name = "macos-sandbox-exec"

    def available(self):
        return shutil.which("sandbox-exec") is not None

    def wrap_prefix(self, deny_root, workspace, network="unrestricted"):
        if network not in _NETWORK_MODES:
            raise SandboxError(
                f"unknown candidate_network mode {network!r} "
                f"(expected one of {_NETWORK_MODES!r})"
            )
        real = os.path.realpath(deny_root)
        profile = (
            "(version 1)"
            "(allow default)"
            f'(deny file-read* (subpath "{real}"))'
            f'(deny file-write* (subpath "{real}"))'
        )
        if network == "deny":
            profile += "(deny network*)"
        elif network == "loopback":
            # Hand-verified against a real external host (1.1.1.1:443) and a
            # real loopback listener (see module docstring / task report for
            # the experiment transcript): `(remote ip "localhost:*")` alone
            # denies genuine external egress while allowing 127.0.0.1.
            #
            # NOTE: the seemingly-more-thorough form that ALSO adds
            # `(allow network* (local ip "localhost:*"))` was tried and
            # measured to be a SECURITY REGRESSION on this macOS version —
            # it allowed the wrapped process to reach a real external host
            # (1.1.1.1:443), defeating the deny entirely. Do not add it back
            # without re-verifying live against a real external target.
            profile += '(deny network*)(allow network* (remote ip "localhost:*"))'
        return ["sandbox-exec", "-p", profile]


class _LinuxBackend:
    name = "linux-bwrap"

    def available(self):
        return shutil.which("bwrap") is not None

    def wrap_prefix(self, deny_root, workspace, network="unrestricted"):
        if network not in _NETWORK_MODES:
            raise SandboxError(
                f"unknown candidate_network mode {network!r} "
                f"(expected one of {_NETWORK_MODES!r})"
            )
        if network == "loopback":
            raise SandboxError(
                "candidate_network 'loopback' is not supported by the bwrap "
                "backend: --unshare-net's namespace has its own loopback, so "
                "host-bound twins would be unreachable; use 'deny' (no "
                "twins/http) or run on macOS"
            )
        real_deny = os.path.realpath(deny_root)
        real_ws = os.path.realpath(workspace)
        argv = [
            "bwrap",
            "--ro-bind", "/", "/",       # whole fs read-only baseline
            "--dev", "/dev",
            "--proc", "/proc",
            "--tmpfs", real_deny,        # mask the control root → real contents unreadable
            "--remount-ro", real_deny,   # SEAL the mask read-only (MS_RDONLY): the fresh
                                         # tmpfs is otherwise owner-writable, and a root
                                         # process has CAP_DAC_OVERRIDE so permission BITS
                                         # (chmod) would not stop it — only a read-only
                                         # MOUNT is kernel-enforced regardless of DAC.
                                         # bwrap applies args in order, so tmpfs-then-
                                         # remount-ro yields an empty, read-only mount:
                                         # reads denied (empty, shadows real content),
                                         # writes denied (MS_RDONLY).
            "--cap-drop", "ALL",         # MS_RDONLY alone is NOT enough: a child holding
                                         # ambient CAP_SYS_ADMIN (setuid-root bwrap, as
                                         # Debian/Ubuntu package it, or a root supervisor)
                                         # can `mount -o remount,rw` the mask and then
                                         # write. bwrap running privileged does not strip
                                         # caps from the child unless told, so drop them
                                         # ALL here — this makes the remount fail
                                         # ("permission denied, are you root?") while the
                                         # --bind workspace stays writable. Together
                                         # --remount-ro (defeats DAC_OVERRIDE) + --cap-drop
                                         # ALL (defeats the CAP_SYS_ADMIN remount) make
                                         # M12's write-denial hold on a real kernel.
            "--bind", real_ws, real_ws,  # workspace read-write
            "--chdir", real_ws,
            "--die-with-parent",
        ]
        if network == "deny":
            argv.append("--unshare-net")  # new net namespace, no interfaces
                                           # configured (not even a usable
                                           # loopback) → all network I/O
                                           # denied, including to the host's
                                           # own loopback.
        argv.append("--")
        return argv


BACKENDS = {"darwin": _MacOSBackend(), "linux": _LinuxBackend()}


def current_backend():
    return BACKENDS.get(sys.platform)


def probe_denial(backend, deny_root, workspace):
    """Fail-closed: True only if a wrapped process provably cannot READ a canary
    planted in deny_root AND cannot WRITE there either (a fresh file, and a
    truncation of the read canary). Any error/uncertainty → False.

    Any write-probe file that somehow ends up existing in deny_root (i.e. a write
    leaked through despite everything else looking fine) is treated as proof of a
    leak (→ False) and is unconditionally unlinked, same as the canary.
    """
    if backend is None or not backend.available():
        return False
    # On Linux the write-denial proof must also cover the CAP_SYS_ADMIN remount
    # escape: a naive open() being denied is not enough if a privileged child can
    # `mount -o remount,rw` the masked control root and then write. So on Linux
    # the wrapped child performs a FOURTH check — attempt to remount deny_root
    # read-write and treat a successful remount as a leak.
    is_linux = sys.platform.startswith("linux")
    read_token = "DF-CANARY-" + uuid.uuid4().hex
    canary = os.path.join(deny_root, ".probe-canary-" + uuid.uuid4().hex)
    write_probe = os.path.join(deny_root, ".probe-write-" + uuid.uuid4().hex)
    remount_probe = os.path.join(deny_root, ".probe-remount-" + uuid.uuid4().hex)
    try:
        try:
            with open(canary, "w", encoding="utf-8") as f:
                f.write(read_token)
        except OSError:
            return False
        try:
            prefix = backend.wrap_prefix(deny_root, workspace)
        except SandboxError:
            return False
        # Wrapped process performs three (macOS) or four (Linux) checks and prints
        # one marker line per check. If the sandbox does NOT deny an operation, the
        # corresponding line will be the real content / a success marker instead of
        # the denial marker → treated as a leak, fail closed.
        code = (
            "import sys\n"
            "canary_path, write_probe_path = sys.argv[1], sys.argv[2]\n"
            "try:\n"
            "    sys.stdout.write(open(canary_path).read())\n"
            "except Exception:\n"
            f"    sys.stdout.write({_READ_DENIAL_MARKER!r})\n"
            "sys.stdout.write(chr(10))\n"
            "try:\n"
            "    open(write_probe_path, 'w').write('leak')\n"
            "    sys.stdout.write('DF-WRITE-LEAKED')\n"
            "except Exception:\n"
            f"    sys.stdout.write({_WRITE_DENIAL_MARKER!r})\n"
            "sys.stdout.write(chr(10))\n"
            "try:\n"
            "    open(canary_path, 'w').write('leak')\n"
            "    sys.stdout.write('DF-WRITE-LEAKED')\n"
            "except Exception:\n"
            f"    sys.stdout.write({_WRITE_DENIAL_MARKER!r})\n"
        )
        # Linux-only 4th check: try to defeat the read-only mount with a rw
        # remount (needs CAP_SYS_ADMIN). rc==0 means the seal was broken — a
        # successful rw remount IS the escape, whether or not the follow-up write
        # open then happens to succeed → treat it as a leak.
        if is_linux:
            code += (
                "sys.stdout.write(chr(10))\n"
                "import ctypes, os\n"
                "remount_probe_path = sys.argv[3]\n"
                "deny_dir = os.path.dirname(remount_probe_path)\n"
                "try:\n"
                "    libc = ctypes.CDLL(None, use_errno=True)\n"
                "    MS_REMOUNT = 32\n"
                "    rc = libc.mount(b'none', deny_dir.encode(), b'', MS_REMOUNT, None)\n"
                "    if rc == 0:\n"
                "        try:\n"
                "            open(remount_probe_path, 'w').write('leak')\n"
                "        except Exception:\n"
                "            pass\n"
                "        sys.stdout.write('DF-WRITE-LEAKED')\n"
                "    else:\n"
                f"        sys.stdout.write({_WRITE_DENIAL_MARKER!r})\n"
                "except Exception:\n"
                f"    sys.stdout.write({_WRITE_DENIAL_MARKER!r})\n"
            )
        argv = prefix + [sys.executable, "-c", code, canary, write_probe]
        if is_linux:
            argv.append(remount_probe)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True, text=True, errors="replace", timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        # Fail-closed: True only if the wrapped process provably ran AND every
        # check hit its denial branch. Vacuous/short/garbage stdout from a
        # launch failure must NOT be mistaken for a proven denial. A write-probe
        # file that exists on disk (even if the sandbox reported an exception on
        # some other line) is independent, physical proof of a leak.
        if os.path.exists(write_probe) or os.path.exists(remount_probe):
            return False
        lines = proc.stdout.split("\n")
        min_lines = 4 if is_linux else 3
        if len(lines) < min_lines:
            return False
        read_denied = lines[0].strip() == _READ_DENIAL_MARKER
        write_open_denied = lines[1].strip() == _WRITE_DENIAL_MARKER
        truncate_denied = lines[2].strip() == _WRITE_DENIAL_MARKER
        remount_denied = (not is_linux) or lines[3].strip() == _WRITE_DENIAL_MARKER
        return (
            proc.returncode == 0
            and read_denied
            and write_open_denied
            and truncate_denied
            and remount_denied
        )
    finally:
        for path in (canary, write_probe, remount_probe):
            try:
                os.unlink(path)
            except OSError:
                pass


def probe_network_denial(backend, deny_root, workspace, network):
    """Fail-closed live proof that `network` mode is actually enforced.

    `"unrestricted"` short-circuits to (True, ...) without spawning anything
    (no restriction is asked for, so there is nothing to prove). For `"deny"`
    and `"loopback"` the wrapped process must provably fail to reach a real
    external host; `"loopback"` must ALSO provably succeed reaching a real
    127.0.0.1 listener (proving the mode isn't just a broken profile that
    denies everything, which would silently break host-bound twins).

    Non-vacuity: a BASELINE unwrapped connect to the external target must
    succeed first, else the environment itself has no egress and any later
    "denial" would be meaningless — fails closed rather than reporting a
    false pass. See the module-level comment on `_NET_PROBE_EXTERNAL_HOST`
    for why a real external host is used here rather than a locally-bound
    "non-loopback" address (the latter is indistinguishable from loopback on
    macOS, at the kernel routing level, before the sandbox ever sees it).

    Any spawn failure, timeout, unknown mode, or ambiguous/short output —
    (False, reason), never a guess.
    """
    if network == "unrestricted":
        return True, "unrestricted: no network probe applies"
    if network not in _NETWORK_MODES:
        return False, f"unknown candidate_network mode {network!r}"
    if backend is None or not backend.available():
        return False, "no sandbox backend available"

    try:
        baseline = socket.create_connection(
            (_NET_PROBE_EXTERNAL_HOST, _NET_PROBE_EXTERNAL_PORT), timeout=3
        )
        baseline.close()
    except OSError as exc:
        return False, (
            f"baseline connect to {_NET_PROBE_EXTERNAL_HOST}:"
            f"{_NET_PROBE_EXTERNAL_PORT} failed — probe environment "
            f"unusable ({exc})"
        )

    # A real loopback listener to prove twins stay reachable in "loopback"
    # mode. listen(1) with no accept() is sufficient — the wrapped child
    # makes at most one connection attempt here, and a pending connection
    # completes at the TCP level without the listener ever calling accept().
    loop_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        loop_sock.bind(("127.0.0.1", 0))
        loop_sock.listen(1)
        loop_port = loop_sock.getsockname()[1]

        try:
            prefix = backend.wrap_prefix(deny_root, workspace, network=network)
        except SandboxError as exc:
            return False, f"wrap_prefix raised for network={network!r}: {exc}"

        code = (
            "import socket, sys\n"
            f"host, port, loop_port = {_NET_PROBE_EXTERNAL_HOST!r}, "
            f"{_NET_PROBE_EXTERNAL_PORT}, {loop_port}\n"
            "try:\n"
            "    socket.create_connection((host, port), timeout=3).close()\n"
            "    sys.stdout.write('DF-NET-EXTERNAL-LEAKED')\n"
            "except OSError:\n"
            f"    sys.stdout.write({_NET_EXTERNAL_DENIAL_MARKER!r})\n"
            "sys.stdout.write(chr(10))\n"
            "try:\n"
            "    socket.create_connection(('127.0.0.1', loop_port), timeout=3).close()\n"
            "    sys.stdout.write('DF-NET-LOOPBACK-ALLOWED')\n"
            "except OSError:\n"
            f"    sys.stdout.write({_NET_LOOPBACK_DENIAL_MARKER!r})\n"
        )
        argv = prefix + [sys.executable, "-c", code]
        try:
            proc = subprocess.run(
                argv,
                capture_output=True, text=True, errors="replace", timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False, "wrapped network-probe process failed to launch or timed out"
    finally:
        loop_sock.close()

    # Fail-closed: only trust a full, well-formed two-line transcript. Any
    # missing/extra marker, nonzero exit, or unexpected value → ambiguous →
    # False.
    lines = proc.stdout.split("\n")
    if len(lines) < 2:
        return False, (
            f"network probe produced too few output lines "
            f"(rc={proc.returncode}): stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )
    external_denied = lines[0].strip() == _NET_EXTERNAL_DENIAL_MARKER
    loopback_line = lines[1].strip()
    if network == "deny":
        loopback_ok = loopback_line == _NET_LOOPBACK_DENIAL_MARKER
    else:  # loopback
        loopback_ok = loopback_line == "DF-NET-LOOPBACK-ALLOWED"

    if proc.returncode != 0 or not external_denied or not loopback_ok:
        return False, (
            f"network probe did not prove {network!r}: "
            f"external_denied={external_denied} loopback_line={loopback_line!r} "
            f"rc={proc.returncode} stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )

    detail = "external egress denied"
    detail += ", loopback allowed" if network == "loopback" else ", loopback denied too"
    return True, f"{network}: {detail} (proven via wrapped subprocess, baseline non-vacuous)"
