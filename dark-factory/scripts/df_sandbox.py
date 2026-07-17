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

Honest residual scope (macOS): `(deny network*)` denies the wrapped
process's OWN socket-level network operations, and the probe proves that
for TCP connects. Two channels are outside what this profile (built on
`(allow default)`) restricts or the probe measures: (a) UDP/other socket
types are denied by the same `network*` primitive by construction but are
not separately probed; (b) DNS RESOLUTION — `getaddrinfo()` is serviced by
`mDNSResponder`, a separate, unconfined system daemon reached over Mach
IPC (not a `network*` operation by the wrapped process), so the daemon may
issue real DNS queries on the candidate's behalf even under `deny`. A
hostile candidate could therefore exfiltrate bits via DNS query names
despite the socket-level denial. Closing that requires denying Mach IPC
to the resolver (a much broader, app-breaking profile) — documented limit,
not silently ignored. Linux `--unshare-net` has neither gap (the namespace
has no route to the resolver or anything else).

M29b (DF-02 host-read half): `wrap_candidate_prefix` is a SEPARATE,
CANDIDATE-only wrapper built on `(deny default)` instead of `wrap_prefix`'s
`(allow default)`. The candidate — the built artifact under test, the least
trusted code in the system — gets: system runtime reads, the workspace
(read+write+exec), the verifier interpreter's own runtime prefixes, and
nothing else; loopback (when enabled) is pinned to an exact run-specific
port allowlist instead of `localhost:*`. Because `(deny default)` also
default-denies Mach IPC, the two channels the paragraph above documents as
open for the builder wrapper are MEASURED CLOSED here on this backend:
`bootstrap_look_up("com.apple.SecurityServer")` (keychain) and
`bootstrap_look_up("com.apple.dnssd.service")` (DNS resolution) both fail
inside the wrapper, and `getaddrinfo()` errors immediately instead of
reaching mDNSResponder. `probe_candidate_confinement` live-proves all of it
per run, fail-closed, before any scenario relies on it. The Linux bwrap
backend keeps its LEGACY candidate behavior (ro-bind / + tmpfs mask: the
whole host stays readable) until M29c and says so honestly via
`mode="legacy_allow_host_read"` — never a fake default-deny claim.
"""
import ctypes
import os
import shutil
import socket
import subprocess
import sys
import tempfile
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

# Mach bootstrap services that back the two side channels M27 documented as
# open under the (allow default) builder wrapper. Under the candidate's
# (deny default) profile a bootstrap_look_up of either name is DENIED
# (measured kr=1100 BOOTSTRAP_NOT_PRIVILEGED vs kr=0 unwrapped on macOS
# 26.5), which is the crisp, non-vacuous discriminator the confinement probe
# uses — `security find-generic-password` exit codes are NOT usable for this
# (measured: rc 44 "item not found" both wrapped and unwrapped, because the
# CLI normalizes a denied SecurityServer lookup into the same "not found").
_MACH_KEYCHAIN_SERVICE = "com.apple.SecurityServer"
_MACH_DNS_SERVICE = "com.apple.dnssd.service"

# Residual names surfaced in probe reports / the manifest host_isolation
# field. HARD residuals disqualify; the metadata one is structural to the
# profile (see wrap_candidate_prefix) and does not.
RESIDUAL_HOST_READ_OPEN = "host_read_open"
RESIDUAL_KEYCHAIN_OPEN = "keychain_mach_ipc_open"
RESIDUAL_DNS_OPEN = "dns_mach_ipc_open"
RESIDUAL_METADATA = "file_metadata_outside_home"
RESIDUAL_NET_UNRESTRICTED = "network_unrestricted_open"
RESIDUAL_SYSTEM_DATA_OPEN = "system_data_file_open"

# Real sensitive files/dirs that live INSIDE the profile's broad system-read
# allows but are operator secrets, not runtime code — the leaves the
# system_read_carveouts deny clauses close. The confinement probe reads back
# whichever of these EXIST and are readable UNWRAPPED (non-vacuity) and
# asserts the wrapped candidate is DENIED each — so the carve-outs can never
# silently regress. A keychain FILE read is treated exactly like the Mach
# keychain channel: a hard leak (ok=False), not a soft residual.
_SYSTEM_DATA_PROBE_TARGETS = (
    "/Library/Keychains/System.keychain",
    "/Library/Keychains/apsd.keychain",
    "/opt/homebrew/etc",
    "/usr/local/etc",
)


_XCODE_DEV_DIR = None       # cached (never changes mid-process); "" = none


def _xcode_developer_dir():
    """realpath of the ACTIVE Xcode/CLT developer dir, or "" when there is
    none. Needed because macOS's /usr/bin/python3 (and git/cc/...) are xcrun
    SHIMS that dlopen libxcrun out of the developer dir at runtime — under
    (deny default) a candidate argv of plain `python3` died with "xcrun:
    unable to load libxcrun ... file system sandbox blocked open()"
    (measured through the real run path). The developer dir is system
    toolchain, world-readable, no user data. Resolved via `xcode-select -p`
    once and cached (the /var/db/xcode_select_link shortcut is not
    user-readable on macOS 26)."""
    global _XCODE_DEV_DIR
    if _XCODE_DEV_DIR is None:
        dev = ""
        try:
            proc = subprocess.run(["/usr/bin/xcode-select", "-p"],
                                  capture_output=True, text=True, timeout=10)
            if proc.returncode == 0:
                cand = proc.stdout.strip()
                if os.path.isabs(cand) and os.path.isdir(cand):
                    dev = os.path.realpath(cand)
        except (OSError, subprocess.TimeoutExpired):
            dev = ""
        # A full Xcode's dev dir is <bundle>/Contents/Developer, but its
        # tools load @rpath frameworks from sibling dirs
        # (<bundle>/Contents/SharedFrameworks — measured: xcodebuild died
        # there with "file system sandbox blocked open()"), so the allowance
        # root is the whole .app bundle. CLT installs
        # (/Library/Developer/CommandLineTools) have no bundle and are
        # already covered by the /Library read allow.
        suffix = "/Contents/Developer"
        if dev.endswith(suffix):
            dev = dev[:-len(suffix)]
        _XCODE_DEV_DIR = dev
    return _XCODE_DEV_DIR


def _darwin_user_temp_dir():
    """realpath of this user's DARWIN_USER_TEMP_DIR, or "" when unavailable.
    Only the `xcrun_db*` cache paths inside it are ever allowed (see
    wrap_candidate_prefix) — never the whole per-user temp dir, which holds
    other processes' scratch files (a real host-read channel). Resolved via
    ctypes confstr(_CS_DARWIN_USER_TEMP_DIR=65537) because Python's
    os.confstr does not expose the Darwin-specific names (measured:
    'unrecognized configuration name')."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        buf = ctypes.create_string_buffer(1024)
        # _CS_DARWIN_USER_TEMP_DIR from <unistd.h>
        n = libc.confstr(65537, buf, len(buf))
        if not (0 < n <= len(buf)):
            return ""
        d = buf.value.decode("utf-8", "replace")
    except (OSError, ValueError, AttributeError):
        return ""
    if not d or not os.path.isabs(d):
        return ""
    return os.path.realpath(d)


def _candidate_runtime_prefixes():
    """Directories the CANDIDATE must be able to read+exec so that the
    interpreter ecosystem the verifier itself runs scenarios with keeps
    working under (deny default): the realpath'd binary dir, sys.prefix
    (a venv root — pyvenv.cfg + bin/ + lib/ live there and MAY be under
    $HOME, which is why these allows are emitted AFTER the $HOME deny), and
    sys.base_prefix (the framework/base install the venv symlinks into).
    sandbox-exec checks the RESOLVED path of an exec'd binary (measured:
    allowing only the .venv symlink dir still denies process-exec* on the
    Cellar target), so everything is realpath'd. Candidates using a runtime
    outside these prefixes + the system paths need the explicit
    `allow_host_read` opt-out — that is the honest tradeoff, not a silent
    widening."""
    exe = os.path.realpath(sys.executable)
    return sorted({
        os.path.dirname(exe),
        os.path.realpath(sys.prefix),
        os.path.realpath(sys.base_prefix),
    })


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

    # M29b: capability flag the supervisor gates on. Only this backend can
    # build a true default-deny candidate profile today; the Linux backend
    # (and any test double that doesn't set this) falls back to the legacy
    # candidate wrapper and reports mode="legacy_allow_host_read" honestly.
    supports_default_deny = True

    def wrap_candidate_prefix(self, deny_root, workspace, network="unrestricted",
                              allowed_loopback_ports=None, scratch_dirs=()):
        """CANDIDATE-only default-deny profile (M29b). Every allow below was
        developed EMPIRICALLY on macOS 26.5 (sandbox-exec) by iterating a
        live `sandbox-exec -f profile python3 ...` until the Python runtime,
        a subprocess, workspace I/O and a loopback client/server all worked
        — each clause carries its measured reason. SBPL is LAST-MATCH-WINS
        (verified live: a `(deny file-read* (subpath $HOME))` placed after
        the venv allow broke `pyvenv.cfg` reads; moving the venv/workspace
        allows after the deny restored them while the rest of $HOME stayed
        denied), so clause ORDER below is load-bearing: broad system allows
        first, the $HOME belt-and-suspenders deny next, the workspace/
        runtime/scratch allows that must survive under $HOME after it, and
        the deny_root denies DEAD LAST so nothing can override them.
        """
        if network not in _NETWORK_MODES:
            raise SandboxError(
                f"unknown candidate_network mode {network!r} "
                f"(expected one of {_NETWORK_MODES!r})"
            )
        ports = set()
        for p in (allowed_loopback_ports or ()):
            # bool is an int subclass; reject it explicitly (True would
            # silently become port 1).
            if isinstance(p, bool) or not isinstance(p, int) or not (1 <= p <= 65535):
                raise SandboxError(
                    f"allowed_loopback_ports entries must be ints in 1..65535, got {p!r}")
            ports.add(p)
        real_deny = os.path.realpath(deny_root)
        real_ws = os.path.realpath(workspace)
        real_scratch = sorted({os.path.realpath(s) for s in scratch_dirs})
        runtime = _candidate_runtime_prefixes()
        home = os.path.expanduser("~")
        real_home = os.path.realpath(home) if os.path.isabs(home) else None

        def subpaths(paths):
            return " ".join(f'(subpath "{p}")' for p in paths)

        # System paths a runtime needs to START (measured by removal: each of
        # these was individually verified either required or deliberately
        # retained with the reason given):
        #   /usr /bin /sbin      — system binaries + libs (PATH search, /usr/lib)
        #   /usr/local /opt/homebrew — Intel/ARM Homebrew runtimes. NOTE these
        #                          roots ALSO contain operator DATA, not just
        #                          code: /opt/homebrew/etc holds service
        #                          configs (redis.conf requirepass, postgres/
        #                          mysql confs) and /opt/homebrew/var holds
        #                          live DB data — proven readable by a planted
        #                          canary. They are carved back out below.
        #   /System              — dyld shared cache cryptex, frameworks
        #   /Library             — system-WIDE frameworks (python.org installs
        #                          live in /Library/Frameworks); per-user data
        #                          is ~/Library which stays DENIED via $HOME.
        #                          BUT /Library/Keychains (System.keychain,
        #                          apsd.keychain) is world-readable root-owned
        #                          system data, NOT under $HOME — proven read
        #                          back in full — so it is carved out below.
        #   /private/etc         — hosts/ssl/localtime and friends
        #   /private/var/db/timezone — /etc/localtime resolves here; without it
        #                          time.localtime() silently falls back to UTC
        #                          (measured); the REST of /private/var/db is
        #                          NOT needed (measured) and stays denied
        #   /dev                 — tty/null/urandom
        system_read = ["/usr", "/bin", "/sbin", "/usr/local", "/opt/homebrew",
                       "/System", "/Library", "/private/etc",
                       "/private/var/db/timezone", "/dev"]
        system_exec = ["/usr", "/bin", "/sbin", "/usr/local", "/opt/homebrew"]
        # Sensitive DATA subtrees that fall INSIDE the broad system-read
        # allows above but are not $HOME (so the $HOME deny misses them) and
        # not code the runtime needs. Denied AFTER the system allows and
        # BEFORE the deny_root block; each is disjoint from workspace/runtime/
        # scratch (all under $HOME or the control root here) so nothing
        # re-opens them. Keeping them as explicit last-match-wins carve-outs
        # rather than narrowing the roots avoids guessing which sibling code
        # dirs the runtime needs (measured: the roots ARE needed for startup;
        # only these leaves are the leak).
        system_read_carveouts = [
            "/Library/Keychains",     # System.keychain / apsd.keychain (Finding 1)
            "/opt/homebrew/etc", "/opt/homebrew/var",   # brew service confs + DB data (Finding 2)
            "/usr/local/etc", "/usr/local/var",         # Intel-brew equivalents
        ]
        # Active Xcode/CLT developer dir (see _xcode_developer_dir): without
        # it, every /usr/bin xcrun shim (python3, git, cc...) a candidate
        # invokes dies loading libxcrun. CLT installs live under
        # /Library/Developer (already covered); a full Xcode.app does not.
        dev_dir = _xcode_developer_dir()
        if dev_dir:
            system_read.append(dev_dir)
            system_exec.append(dev_dir)

        parts = [
            "(version 1)",
            "(deny default)",
            # Candidates legitimately spawn subprocesses (python3 helpers).
            "(allow process-fork)",
            # One combined exec allow: system runtimes + the verifier
            # interpreter's prefixes + the workspace (candidates run their
            # own built artifacts) + scratch. exec also requires file-read on
            # the binary — granted below, AFTER the $HOME deny where needed.
            "(allow process-exec "
            + subpaths(system_exec + runtime + [real_ws] + real_scratch) + ")",
            # Broad metadata: PATH search and exec-time realpath() stat every
            # ancestor/candidate dir; removing this breaks the interpreter
            # launch outright ("realpath: .venv/bin/: Operation not
            # permitted", measured). Metadata is existence/stat only — file
            # CONTENTS stay denied — and $HOME + deny_root metadata is still
            # denied because their later file-read* denies cover
            # file-read-metadata too (last match wins). The honest leftover
            # is stat/existence visibility of paths outside $HOME, surfaced
            # as the RESIDUAL_METADATA entry in every probe report.
            "(allow file-read-metadata)",
            # dyld reads the root DIRECTORY itself at startup; without this
            # every binary dies in dyld4::CacheFinder with SIGABRT (measured
            # via crash report + `deny(1) file-read-data /` in the kernel
            # sandbox log).
            '(allow file-read-data (literal "/"))',
            "(allow file-read* " + subpaths(system_read) + ")",
            # Carve the sensitive DATA leaves back out (last match wins).
            # These sit inside /Library and /opt/homebrew|/usr/local above but
            # are operator secrets/DB data, not runtime code — see
            # system_read_carveouts. Disjoint from workspace/runtime/scratch,
            # so the allows below can't re-open them.
            "(deny file-read* " + subpaths(system_read_carveouts) + ")",
            # dyld must map libraries executable; a path filter here adds
            # nothing (mapping requires read access, which is already
            # path-restricted above).
            "(allow file-map-executable)",
            # Runtime startup introspection (hw.ncpu etc.).
            "(allow sysctl-read)",
            # same-sandbox, not self: a candidate killing its own timed-out
            # child (subprocess.run(timeout=...)) needs signal on the CHILD;
            # (target self) broke that with EPERM (measured).
            "(allow process-info* (target same-sandbox))",
            "(allow signal (target same-sandbox))",
            # /dev/null sinks + the dtrace helper handshake every process
            # attempts at startup (harmless; keeps stderr free of noise).
            '(allow file-write-data (literal "/dev/null") (literal "/dev/dtracehelper"))',
            # Per-user-dir resolution service: confstr(DARWIN_USER_TEMP_DIR)
            # fails EIO without it, which sends every /usr/bin xcrun shim
            # (python3/git/cc) down a broken /tmp cache path (measured). The
            # service only mints/returns the caller's own per-user dirs.
            '(allow mach-lookup (global-name "com.apple.bsd.dirhelper"))',
        ]
        user_tmp = _darwin_user_temp_dir()
        if user_tmp:
            # ONLY the xcrun toolchain-resolution cache (tool-name -> path
            # map, no user data), NOT the whole per-user temp dir: with the
            # cache readable an xcrun shim resolves instantly; without it,
            # it re-runs `xcodebuild -find` on every launch (measured, works
            # but slow and noisy). Prefix, because the cache is written via
            # a temp name (xcrun_db-XXXX) then renamed.
            xcrun_db = os.path.join(user_tmp, "xcrun_db")
            parts.append(f'(allow file-read* (prefix "{xcrun_db}"))')
            parts.append(f'(allow file-write* (prefix "{xcrun_db}"))')
        if real_home is not None:
            # Belt-and-suspenders: nothing under the operator's $HOME is
            # readable/writable even if a system allow above ever overlaps
            # it. The workspace/runtime/scratch allows BELOW survive because
            # SBPL is last-match-wins (verified live).
            parts.append(f'(deny file-read* (subpath "{real_home}"))')
            parts.append(f'(deny file-write* (subpath "{real_home}"))')
        parts.append("(allow file-read* "
                     + subpaths([real_ws] + runtime + real_scratch) + ")")
        parts.append("(allow file-write* " + subpaths([real_ws] + real_scratch) + ")")

        if network == "deny":
            # (deny default) already denies network*; the explicit clause
            # keeps the intent auditable in the profile text itself.
            parts.append("(deny network*)")
        elif network == "loopback":
            # Port-PINNED loopback (the M29b upgrade over M27's
            # `localhost:*`): outbound only to the run's own twin/service
            # ports, so the candidate cannot reach unrelated host loopback
            # services (local DBs, debug ports, credential proxies).
            # Inbound: a LISTENING candidate (M20 HTTP oracle) needs bind +
            # inbound on localhost; these are network-bind/network-inbound
            # SPECIFICALLY — NOT `(allow network* (local ip ...))`, which
            # M27 measured as a security regression that re-opened real
            # external egress. External egress stays denied with these
            # clauses present (re-measured live against 1.1.1.1:443).
            for p in sorted(ports):
                parts.append(f'(allow network-outbound (remote ip "localhost:{p}"))')
            parts.append('(allow network-bind (local ip "localhost:*"))')
            parts.append('(allow network-inbound (local ip "localhost:*"))')
        else:  # unrestricted
            # Same network semantics candidate_network="unrestricted" always
            # had — full egress — while files stay default-deny. DNS needs
            # one mach-lookup: getaddrinfo() is serviced by dnssd over Mach
            # IPC, so an unrestricted-network candidate without this allow
            # cannot resolve ANY name (measured); with it, resolution works.
            # deny/loopback modes deliberately OMIT it — that is what closes
            # the M27-documented DNS exfil residual.
            parts.append("(allow network*)")
            parts.append(f'(allow mach-lookup (global-name "{_MACH_DNS_SERVICE}"))')

        # DEAD LAST so no allow above (nor any future edit that forgets the
        # ordering rule) can override the control-root denial. file-read*
        # includes file-read-metadata: the holdout's existence/shape is not
        # even statable.
        parts.append(f'(deny file-read* (subpath "{real_deny}"))')
        parts.append(f'(deny file-write* (subpath "{real_deny}"))')
        return ["sandbox-exec", "-p", "".join(parts)]


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

    # M29b: honest legacy passthrough — bwrap's ro-bind / keeps the whole
    # host READABLE by the candidate, and pretending otherwise would be a
    # fake claim. M29c replaces this with a real mount+PID-namespace
    # default-deny; until then the supervisor reports
    # host_isolation.mode="legacy_allow_host_read" for this backend.
    supports_default_deny = False

    def wrap_candidate_prefix(self, deny_root, workspace, network="unrestricted",
                              allowed_loopback_ports=None, scratch_dirs=()):
        # allowed_loopback_ports/scratch_dirs are accepted for signature
        # parity but meaningless here: the legacy argv has no per-port
        # network filtering (network is all-or-nothing via --unshare-net).
        return self.wrap_prefix(deny_root, workspace, network=network)


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


def _bootstrap_look_up(service_name):
    """kern_return_t of a Mach bootstrap lookup for `service_name` in THIS
    process: 0 = service visible/reachable, non-zero = not (1100
    BOOTSTRAP_NOT_PRIVILEGED when a sandbox denies the lookup, measured).
    Used both for the parent-side non-vacuity baseline (the services must be
    reachable OUTSIDE the sandbox or "denied inside" proves nothing) and,
    inline in the wrapped child, as the keychain/DNS discriminator."""
    libc = ctypes.CDLL(None, use_errno=True)
    bootstrap_port = ctypes.c_uint.in_dll(libc, "bootstrap_port")
    port = ctypes.c_uint(0)
    return libc.bootstrap_look_up(bootstrap_port, service_name.encode(), ctypes.byref(port))


def probe_candidate_confinement(backend, deny_root, workspace, network,
                                allowed_loopback_ports=None, scratch_dirs=()):
    """Fail-closed live proof of the M29b default-deny CANDIDATE profile.
    Returns (ok, report) where report is the structured dict the supervisor
    folds into the manifest `host_isolation` field:
    {"mode", "network", "checks": {...}, "residuals": [...], "detail"}.

    The wrapped child performs eleven checks, one marker line each (mirrors
    probe_denial's discipline: only a full, well-formed transcript from a
    zero-exit child counts; anything short/garbled/nonzero → not ok):
      control-root canary read DENIED; outside-workspace canary read DENIED
      (a temp-dir stand-in for ~/.ssh — probing the real ~/.ssh is
      ENOENT-ambiguous when the file is absent, so the unambiguous $HOME
      check is a LISTING of $HOME itself, which always exists); $HOME
      listing DENIED; workspace write ALLOWED + content physically verified
      by the parent (non-vacuity: a sandbox that denies everything would
      "pass" every denial check); outside write DENIED + physically
      verified absent; subprocess spawn ALLOWED (candidates must still be
      able to run); keychain bootstrap lookup DENIED; DNS bootstrap lookup
      per mode; network per mode including the non-vacuous port-pinning
      pair (connect to the probe's own ALLOWED listener succeeds AND a
      second live-but-unallowed listener is DENIED).

    Honest-residual policy (plan §Task 1/2): a keychain-OPEN result is a
    LEAK → ok=False (measured CLOSED on this backend; if it ever opens the
    profile is broken and the run must refuse, not shrug). A DNS-OPEN
    result at deny/loopback is recorded as RESIDUAL_DNS_OPEN with ok
    preserved — the supervisor marks the run unqualified for it (the plan's
    "measured truth over aspiration" fallback), because file isolation is
    independently proven. `unrestricted` skips the network checks (nothing
    is asked to be denied) and records RESIDUAL_NET_UNRESTRICTED.
    RESIDUAL_METADATA is always present: the profile's broad
    file-read-metadata allow (required for exec-time path resolution,
    measured) leaves stat/existence of paths outside $HOME/deny_root
    visible.

    Linux/legacy backends (no `supports_default_deny`): delegates to the
    existing probe_denial + probe_network_denial pair and reports
    mode="legacy_allow_host_read" with RESIDUAL_HOST_READ_OPEN — the honest
    truth that the candidate can still read the host there until M29c.
    """
    if network not in _NETWORK_MODES:
        return False, {"mode": None, "network": network, "checks": {},
                       "residuals": [], "detail": f"unknown candidate_network mode {network!r}"}
    if backend is None or not backend.available():
        return False, {"mode": None, "network": network, "checks": {},
                       "residuals": [], "detail": "no sandbox backend available"}

    if not getattr(backend, "supports_default_deny", False):
        legacy_ok = probe_denial(backend, deny_root, workspace)
        net_ok, net_reason = probe_network_denial(backend, deny_root, workspace, network)
        report = {
            "mode": "legacy_allow_host_read",
            "network": network,
            "checks": {"legacy_denial_probe": bool(legacy_ok),
                       "legacy_network_probe": bool(net_ok)},
            "residuals": [RESIDUAL_HOST_READ_OPEN],
            "detail": ("legacy candidate wrapper (host reads open until M29c); "
                       f"network probe: {net_reason}"),
        }
        return bool(legacy_ok and net_ok), report

    home = os.path.expanduser("~")
    if not os.path.isabs(home) or not os.path.isdir(home):
        return False, {"mode": "default_deny", "network": network, "checks": {},
                       "residuals": [],
                       "detail": f"cannot resolve an absolute $HOME to probe ({home!r})"}

    # Non-vacuity baselines: the Mach services must be reachable from THIS
    # (unwrapped) process, else "denied inside the wrapper" is meaningless.
    try:
        kc_base = _bootstrap_look_up(_MACH_KEYCHAIN_SERVICE)
        dns_base = _bootstrap_look_up(_MACH_DNS_SERVICE)
    except (OSError, ValueError, AttributeError) as exc:
        return False, {"mode": "default_deny", "network": network, "checks": {},
                       "residuals": [], "detail": f"bootstrap baseline unavailable: {exc}"}
    if kc_base != 0 or dns_base != 0:
        return False, {"mode": "default_deny", "network": network, "checks": {},
                       "residuals": [],
                       "detail": (f"bootstrap baseline not visible outside the sandbox "
                                  f"(SecurityServer={kc_base}, dnssd={dns_base}) — "
                                  "denial inside would be vacuous")}

    if network in ("deny", "loopback"):
        try:
            baseline = socket.create_connection(
                (_NET_PROBE_EXTERNAL_HOST, _NET_PROBE_EXTERNAL_PORT), timeout=3)
            baseline.close()
        except OSError as exc:
            return False, {"mode": "default_deny", "network": network, "checks": {},
                           "residuals": [],
                           "detail": (f"baseline connect to {_NET_PROBE_EXTERNAL_HOST}:"
                                      f"{_NET_PROBE_EXTERNAL_PORT} failed — probe "
                                      f"environment unusable ({exc})")}

    canary_token = "DF-CANARY-" + uuid.uuid4().hex
    deny_canary = os.path.join(deny_root, ".confine-canary-" + uuid.uuid4().hex)
    outside_dir = tempfile.mkdtemp(prefix="df-confine-probe-")
    outside_canary = os.path.join(outside_dir, "canary.txt")
    outside_write = os.path.join(outside_dir, "leak.txt")
    ws_probe = os.path.join(workspace, ".confine-ws-probe-" + uuid.uuid4().hex)
    allowed_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    denied_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try:
            with open(deny_canary, "w", encoding="utf-8") as f:
                f.write(canary_token)
            with open(outside_canary, "w", encoding="utf-8") as f:
                f.write(canary_token)
        except OSError as exc:
            return False, {"mode": "default_deny", "network": network, "checks": {},
                           "residuals": [], "detail": f"could not plant canaries: {exc}"}
        # Two REAL listeners: pinning is proven against live sockets, never
        # against a connection-refused artifact of a dead port. listen(1)
        # with no accept() completes a single TCP handshake fine.
        allowed_sock.bind(("127.0.0.1", 0))
        allowed_sock.listen(1)
        allowed_port = allowed_sock.getsockname()[1]
        denied_sock.bind(("127.0.0.1", 0))
        denied_sock.listen(1)
        denied_port = denied_sock.getsockname()[1]

        # Sensitive system-data targets to prove the carve-outs bite: only
        # those that EXIST and are readable UNWRAPPED right now (a file the
        # parent itself can't read would make "denied inside" vacuous, and a
        # missing path would give a misleading ENOENT). A dir is "readable"
        # if it lists; a file if a byte reads.
        def _readable_unwrapped(p):
            try:
                if os.path.isdir(p):
                    os.listdir(p)
                    return True
                with open(p, "rb") as fh:
                    fh.read(1)
                return True
            except OSError:
                return False
        sysdata_targets = [p for p in _SYSTEM_DATA_PROBE_TARGETS if _readable_unwrapped(p)]

        probe_ports = list(allowed_loopback_ports or ())
        if network == "loopback":
            probe_ports.append(allowed_port)
        try:
            prefix = backend.wrap_candidate_prefix(
                deny_root, workspace, network=network,
                allowed_loopback_ports=probe_ports, scratch_dirs=scratch_dirs)
        except SandboxError as exc:
            return False, {"mode": "default_deny", "network": network, "checks": {},
                           "residuals": [], "detail": f"wrap_candidate_prefix raised: {exc}"}

        code = (
            "import ctypes, os, socket, subprocess, sys\n"
            "deny_canary, outside_canary, outside_write, ws_probe, home = sys.argv[1:6]\n"
            "network, allowed_port, denied_port = sys.argv[6], int(sys.argv[7]), int(sys.argv[8])\n"
            "ext_host, ext_port = sys.argv[9], int(sys.argv[10])\n"
            "sysdata = [p for p in sys.argv[11].split(chr(10)) if p]\n"
            "out = []\n"
            "def read_denied(path):\n"
            "    try:\n"
            "        if os.path.isdir(path):\n"        # a dir 'leaks' if it lists
            "            os.listdir(path)\n"
            "        else:\n"
            "            open(path, 'rb').read(1)\n"    # bytes: binary keychains don't UnicodeDecode
            "        return 'DF-READ-LEAKED'\n"
            "    except PermissionError:\n"
            "        return 'DF-READ-DENIED'\n"
            "    except Exception:\n"
            "        return 'DF-READ-AMBIGUOUS'\n"  # ENOENT etc. is NOT proof of denial
            "out.append(read_denied(deny_canary))\n"
            "out.append(read_denied(outside_canary))\n"
            "try:\n"
            "    os.listdir(home)\n"
            "    out.append('DF-HOME-LEAKED')\n"
            "except PermissionError:\n"
            "    out.append('DF-HOME-DENIED')\n"
            "except Exception:\n"
            "    out.append('DF-HOME-AMBIGUOUS')\n"
            "try:\n"
            "    open(ws_probe, 'w').write('DF-WS-CONTENT')\n"
            "    out.append('DF-WS-WRITE-OK')\n"
            "except Exception:\n"
            "    out.append('DF-WS-WRITE-DENIED')\n"
            "try:\n"
            "    open(outside_write, 'w').write('leak')\n"
            "    out.append('DF-WRITE-LEAKED')\n"
            "except Exception:\n"
            "    out.append('DF-WRITE-DENIED')\n"
            "try:\n"
            "    p = subprocess.run([sys.executable, '-c', 'print(\"spawned\")'],\n"
            "                       capture_output=True, text=True, timeout=15)\n"
            "    out.append('DF-SPAWN-OK' if p.stdout.strip() == 'spawned' else 'DF-SPAWN-DENIED')\n"
            "except Exception:\n"
            "    out.append('DF-SPAWN-DENIED')\n"
            "def look(name):\n"
            "    try:\n"
            "        libc = ctypes.CDLL(None, use_errno=True)\n"
            "        bp = ctypes.c_uint.in_dll(libc, 'bootstrap_port')\n"
            "        port = ctypes.c_uint(0)\n"
            "        return libc.bootstrap_look_up(bp, name.encode(), ctypes.byref(port))\n"
            "    except Exception:\n"
            "        return -1\n"  # lookup machinery itself broken: treated as denied-side but distinct
            f"kc = look({_MACH_KEYCHAIN_SERVICE!r})\n"
            "out.append('DF-KC-OPEN' if kc == 0 else 'DF-KC-DENIED')\n"
            f"dns = look({_MACH_DNS_SERVICE!r})\n"
            "out.append('DF-DNS-OPEN' if dns == 0 else 'DF-DNS-DENIED')\n"
            "def conn(host, port):\n"
            "    try:\n"
            "        socket.create_connection((host, port), timeout=3).close()\n"
            "        return True\n"
            "    except OSError:\n"
            "        return False\n"
            "if network == 'unrestricted':\n"
            "    out += ['DF-NET-SKIP', 'DF-NET-SKIP', 'DF-NET-SKIP']\n"
            "else:\n"
            "    out.append('DF-NET-EXTERNAL-LEAKED' if conn(ext_host, ext_port) else 'DF-NET-EXTERNAL-DENIED')\n"
            "    out.append('DF-NET-LOOPBACK-ALLOWED' if conn('127.0.0.1', allowed_port) else 'DF-NET-LOOPBACK-DENIED')\n"
            "    out.append('DF-PORT-LEAKED' if conn('127.0.0.1', denied_port) else 'DF-PORT-DENIED')\n"
            # System-data carve-outs: every parent-selected target (real,
            # readable-unwrapped) must be DENIED. Empty list -> SKIP (nothing
            # to prove on this host); any leak/ambiguity -> not all denied.
            "if not sysdata:\n"
            "    out.append('DF-SYSDATA-SKIP')\n"
            "else:\n"
            "    res = [read_denied(p) for p in sysdata]\n"
            "    out.append('DF-SYSDATA-DENIED' if all(r == 'DF-READ-DENIED' for r in res) "
            "else 'DF-SYSDATA-LEAKED:' + ','.join(f'{p}={r}' for p, r in zip(sysdata, res) if r != 'DF-READ-DENIED'))\n"
            "sys.stdout.write(chr(10).join(out))\n"
        )
        argv = prefix + [sys.executable, "-c", code,
                         deny_canary, outside_canary, outside_write, ws_probe, home,
                         network, str(allowed_port), str(denied_port),
                         _NET_PROBE_EXTERNAL_HOST, str(_NET_PROBE_EXTERNAL_PORT),
                         "\n".join(sysdata_targets)]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  errors="replace", timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            return False, {"mode": "default_deny", "network": network, "checks": {},
                           "residuals": [],
                           "detail": "wrapped confinement-probe process failed to launch or timed out"}

        lines = [l.strip() for l in proc.stdout.split("\n")]
        if proc.returncode != 0 or len(lines) < 12:
            return False, {"mode": "default_deny", "network": network, "checks": {},
                           "residuals": [],
                           "detail": (f"confinement probe transcript malformed "
                                      f"(rc={proc.returncode}, lines={len(lines)}): "
                                      f"stdout={proc.stdout!r} stderr={proc.stderr[:500]!r}")}

        # Physical evidence beats transcript evidence in both directions: a
        # leak file on disk is a leak whatever the child printed, and the
        # workspace write must really contain what the child claims it wrote.
        outside_leaked = os.path.exists(outside_write)
        try:
            with open(ws_probe, encoding="utf-8") as f:
                ws_written = f.read() == "DF-WS-CONTENT"
        except OSError:
            ws_written = False

        checks = {
            "control_root_read": lines[0],
            "outside_read": lines[1],
            "home_read": lines[2],
            "workspace_write": lines[3],
            "outside_write": lines[4],
            "subprocess_spawn": lines[5],
            "keychain": lines[6],
            "dns": lines[7],
            "net_external": lines[8],
            "net_loopback_allowed_port": lines[9],
            "net_loopback_other_port": lines[10],
            "system_data_carveout": lines[11],
        }
        residuals = [RESIDUAL_METADATA]
        core_ok = (
            lines[0] == "DF-READ-DENIED"
            and lines[1] == "DF-READ-DENIED"
            and lines[2] == "DF-HOME-DENIED"
            and lines[3] == "DF-WS-WRITE-OK" and ws_written
            and lines[4] == "DF-WRITE-DENIED" and not outside_leaked
            and lines[5] == "DF-SPAWN-OK"
        )
        # System-data carve-outs (keychain files, brew service confs/DB data):
        # a real readable-unwrapped target read back inside the sandbox is a
        # LEAK -> hard failure. SKIP (no such target on this host) is OK; only
        # an explicit DF-SYSDATA-LEAKED fails.
        sysdata_line = lines[11]
        sysdata_ok = sysdata_line in ("DF-SYSDATA-DENIED", "DF-SYSDATA-SKIP")
        if sysdata_line.startswith("DF-SYSDATA-LEAKED"):
            residuals.append(RESIDUAL_SYSTEM_DATA_OPEN)
        # Keychain: measured CLOSED on this backend; OPEN means the profile
        # is broken → hard failure, never a shrugging residual.
        kc_ok = lines[6] == "DF-KC-DENIED"
        if lines[6] == "DF-KC-OPEN":
            residuals.append(RESIDUAL_KEYCHAIN_OPEN)
        dns_ok = True
        if network in ("deny", "loopback"):
            if lines[7] != "DF-DNS-DENIED":
                # Open resolver at a denying mode: honest residual (the run
                # becomes unqualified), file isolation is independently proven.
                residuals.append(RESIDUAL_DNS_OPEN)
        else:
            # unrestricted: egress (and therefore DNS) open BY DESIGN of the
            # configured candidate_network mode, not a profile defect.
            residuals.append(RESIDUAL_NET_UNRESTRICTED)
        if network == "deny":
            net_ok = (lines[8] == "DF-NET-EXTERNAL-DENIED"
                      and lines[9] == "DF-NET-LOOPBACK-DENIED"
                      and lines[10] == "DF-PORT-DENIED")
        elif network == "loopback":
            net_ok = (lines[8] == "DF-NET-EXTERNAL-DENIED"
                      and lines[9] == "DF-NET-LOOPBACK-ALLOWED"
                      and lines[10] == "DF-PORT-DENIED")
        else:
            net_ok = (lines[8] == lines[9] == lines[10] == "DF-NET-SKIP")

        ok = bool(core_ok and kc_ok and dns_ok and net_ok and sysdata_ok)
        detail = "all confinement checks passed" if ok else (
            f"confinement checks failed: {checks!r}")
        return ok, {"mode": "default_deny", "network": network,
                    "checks": checks, "residuals": residuals, "detail": detail}
    finally:
        allowed_sock.close()
        denied_sock.close()
        for path in (deny_canary, ws_probe):
            try:
                os.unlink(path)
            except OSError:
                pass
        shutil.rmtree(outside_dir, ignore_errors=True)
