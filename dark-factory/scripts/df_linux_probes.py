"""Linux-container live probe drivers for dark-factory M16 (Linux live-coverage
harness). Stdlib only. Each probe is small, self-contained, and runnable inside
a Linux container:

- `probe_bwrap` drives the REAL production `df_sandbox` Linux backend
  (`df_sandbox.BACKENDS["linux"]` + `df_sandbox.probe_denial`) — not a
  reimplementation, so this proves the same code path the standard tier runs
  on Linux.
- `probe_egress_denial` drives `iptables -A OUTPUT ... -j DROP` (one of the two
  kernel primitives M17's enterprise tier needs), with a mandatory
  before/after connectivity check so the denial can never be vacuous (a dead
  network mistaken for enforcement).
- `probe_no_new_privs` drives `prctl(PR_SET_NO_NEW_PRIVS)` via ctypes (the
  other M17 primitive), confirmed by re-reading the flag.

Each probe returns `(bool, str)`. The `__main__` CLI dispatch prints exactly
one line `DF-PROBE <name> PASS|FAIL <reason>` and exits 0 (PASS) / 1 (FAIL),
so a caller (e.g. a docker-driven test) can assert on stdout + returncode
without parsing anything more elaborate.

Fail-closed throughout: any uncertainty (wrong platform, missing binary,
launch failure, ambiguous result) resolves to FAIL, never PASS.
"""
import ctypes
import ctypes.util
import socket
import subprocess
import sys

import df_sandbox

PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39


def probe_bwrap(deny_root, workspace):
    """Fail-closed live coverage for the standard tier's Linux backend. Drives
    df_sandbox's own BACKENDS["linux"] + probe_denial — the production code
    path, not a copy — so a PASS here is proof the real bwrap wrap_prefix
    denies both read and write in deny_root on a real Linux kernel."""
    if sys.platform != "linux":
        return False, f"platform is {sys.platform!r}, not linux — bwrap backend requires a real Linux kernel"
    backend = df_sandbox.BACKENDS.get("linux")
    if backend is None or not backend.available():
        return False, "bwrap missing (not found on PATH)"
    if df_sandbox.probe_denial(backend, deny_root, workspace):
        return True, "df_sandbox.probe_denial proved read+write denial via the production bwrap backend"
    return False, "df_sandbox.probe_denial did not prove denial (leak, launch failure, or vacuous result)"


def probe_egress_denial(target_ip="1.1.1.1", port=443, timeout=3):
    """Fail-closed live coverage for the M17 iptables-egress-denial primitive.
    A connect BEFORE the DROP rule must succeed (else the network itself is
    dead and any later "denial" would be vacuous); the DROP rule must apply
    cleanly; a connect AFTER the rule must then fail."""
    try:
        sock = socket.create_connection((target_ip, port), timeout=timeout)
        sock.close()
    except OSError as exc:
        return False, f"no baseline connectivity to {target_ip}:{port} — egress denial would be vacuous ({exc})"

    try:
        proc = subprocess.run(
            ["iptables", "-A", "OUTPUT", "-d", target_ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=timeout + 10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"iptables invocation failed: {exc}"
    if proc.returncode != 0:
        return False, f"iptables -A OUTPUT -d {target_ip} -j DROP failed (rc={proc.returncode}): {proc.stderr.strip()}"

    try:
        sock = socket.create_connection((target_ip, port), timeout=timeout)
        sock.close()
    except OSError:
        return True, f"egress to {target_ip}:{port} denied after iptables DROP rule (baseline connectivity was confirmed first)"
    return False, f"connect to {target_ip}:{port} still succeeded after the DROP rule — egress not denied"


def probe_no_new_privs():
    """Fail-closed live coverage for the M17 no-new-privs primitive. Sets
    PR_SET_NO_NEW_PRIVS via ctypes/prctl, then re-reads PR_GET_NO_NEW_PRIVS to
    confirm the kernel actually applied it — never trusts the setter's return
    code alone."""
    lib_name = ctypes.util.find_library("c") or "libc.so.6"
    try:
        libc = ctypes.CDLL(lib_name, use_errno=True)
    except OSError as exc:
        return False, f"could not load libc ({lib_name}): {exc}"

    set_rc = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if set_rc != 0:
        return False, f"prctl(PR_SET_NO_NEW_PRIVS) returned {set_rc}, expected 0"

    get_rc = libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
    if get_rc != 1:
        return False, f"prctl(PR_GET_NO_NEW_PRIVS) re-read {get_rc}, expected 1"

    return True, "no_new_privs set via prctl and confirmed by re-read"


def _dispatch(argv):
    if not argv:
        return "unknown", False, "no subcommand given (expected bwrap|egress|nnp)"

    cmd = argv[0]
    if cmd == "bwrap":
        if len(argv) != 3:
            return cmd, False, "usage: bwrap <deny_root> <workspace>"
        ok, reason = probe_bwrap(argv[1], argv[2])
        return cmd, ok, reason
    if cmd == "egress":
        if len(argv) != 3:
            return cmd, False, "usage: egress <target_ip> <port>"
        try:
            port = int(argv[2])
        except ValueError:
            return cmd, False, f"port must be an integer, got {argv[2]!r}"
        ok, reason = probe_egress_denial(argv[1], port)
        return cmd, ok, reason
    if cmd == "nnp":
        ok, reason = probe_no_new_privs()
        return cmd, ok, reason
    return cmd, False, f"unknown subcommand {cmd!r} (expected bwrap|egress|nnp)"


def main(argv):
    name, ok, reason = _dispatch(argv)
    status = "PASS" if ok else "FAIL"
    print(f"DF-PROBE {name} {status} {reason}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
