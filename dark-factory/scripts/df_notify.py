"""Budget-alert notification delivery (M18 Task 1). Stdlib only.

``deliver(sink, event, *, timeout_s=10, redactor=None)`` ships one small JSON
event to an operator-configured sink:

  http(s)://...   POST json.dumps(event) (Content-Type: application/json).
                  2xx -> (True, "delivered"). Any other status, or a network
                  failure/timeout, -> (False, reason).
  file:///abs     append one ndjson line to the file (creating it, and its
                  parent directories, if needed). -> (True, "delivered") on
                  success, (False, reason) on any I/O error.
  anything else   unsupported scheme -> (False, "unsupported sink scheme").

``event`` is passed through ``redactor.redact_obj`` first when a redactor is
given, so no credential VALUE configured for this run ever reaches the sink
-- the same discipline supervisor.py's ``_redacted_write`` choke point
applies to every other persisted/transmitted artifact (M11).

CRITICAL SEMANTIC -- notification is FAIL-SOFT, the opposite of the M13
audit sink (which is fail-CLOSED when required): a down alert channel is an
operator inconvenience, not an integrity failure, so ``deliver()`` NEVER
raises. Every failure mode -- a bad sink string, an unreachable host, a
non-2xx response, a permission error writing the file -- comes back as
``(False, reason)``. ``NotifyError`` exists only as the internal signal
between this module's own helpers and ``deliver()``'s catch-all; it is never
raised to a caller of ``deliver()``.

``deliver_durable(sink, event, spool_dir, *, attempts=1, timeout_s=10,
redactor=None)`` (M22 Task 2) upgrades the same fail-soft delivery to
AT-LEAST-ONCE: it retries ``deliver`` up to `attempts` times, and only if
every attempt fails does it append the REDACTED event to
``<spool_dir>/pending.ndjson`` and return ``(False, "spooled")`` instead of
silently dropping it. ``flush_spool(sink, spool_dir, *, timeout_s=10,
redactor=None)`` re-attempts every spooled event and rewrites the file with
only what's still undelivered. Both NEVER raise, same discipline as
``deliver()``. This is a LOCAL DISK SPOOL, not a real message queue -- no
cross-host durability, no ordering guarantee, no dedup beyond the one file;
see references/budget.md for the honest scope statement.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request


class NotifyError(RuntimeError):
    """Internal only -- deliver() catches this (and everything else) and
    returns (False, reason) instead. Never propagates out of deliver()."""


def _post_http(sink: str, body: bytes, timeout_s: int) -> None:
    req = urllib.request.Request(
        sink, data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status = resp.status
    except urllib.error.HTTPError as e:
        raise NotifyError(f"http sink returned HTTP {e.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise NotifyError(f"http sink unreachable: {e}") from None
    if not (200 <= status < 300):
        raise NotifyError(f"http sink returned HTTP {status}")


def _append_file(netloc: str, path: str, line: str) -> None:
    if netloc or not path or not os.path.isabs(path):
        raise NotifyError(
            "file sink requires an absolute path with no host component "
            "(file:///abs/...)"
        )
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError as e:
        raise NotifyError(f"file sink write failed: {e}") from None


def deliver(sink: str, event: dict, *, timeout_s: int = 10, redactor=None) -> tuple:
    """Best-effort delivery of `event` to `sink`. NEVER raises -- every
    failure path returns (False, reason); success returns (True, "delivered")."""
    try:
        payload = redactor.redact_obj(event) if redactor is not None else event
        parsed = urllib.parse.urlsplit(sink)
        scheme = parsed.scheme
        if scheme in ("http", "https"):
            _post_http(sink, json.dumps(payload).encode("utf-8"), timeout_s)
        elif scheme == "file":
            _append_file(parsed.netloc, parsed.path, json.dumps(payload))
        else:
            raise NotifyError("unsupported sink scheme")
        return True, "delivered"
    except NotifyError as e:
        return False, str(e)
    except Exception as e:  # belt-and-suspenders: a down alert channel must
        # never fail the run it's alerting about -- catch literally anything.
        return False, f"delivery failed: {e}"


_SPOOL_FILE = "pending.ndjson"


def deliver_durable(sink: str, event: dict, spool_dir: str, *, attempts: int = 1,
                     timeout_s: int = 10, redactor=None) -> tuple:
    """At-least-once delivery (M22 Task 2): try ``deliver`` up to `attempts`
    times; if every attempt fails, append the REDACTED event as one ndjson
    line to ``<spool_dir>/pending.ndjson`` (creating the dir if needed) and
    return ``(False, "spooled")``. A success on ANY attempt returns
    ``(True, "delivered")`` immediately -- no spooling.

    STILL FAIL-SOFT, same discipline as ``deliver``: NEVER raises. A local
    spool is at-least-once, not a real message queue -- no cross-host
    durability, no ordering guarantee, no dedup beyond this one file.
    """
    try:
        n = int(attempts)
    except Exception:
        n = 1
    if n < 1:
        n = 1

    reason = "delivery failed"
    for _ in range(n):
        ok, reason = deliver(sink, event, timeout_s=timeout_s, redactor=redactor)
        if ok:
            return True, "delivered"

    # Every attempt failed -- spool the REDACTED event (never the raw one;
    # same choke point as deliver()'s own redaction, applied here too since
    # deliver() redacts only what it SENDS, not what we persist ourselves).
    try:
        payload = redactor.redact_obj(event) if redactor is not None else event
        os.makedirs(spool_dir, exist_ok=True)
        path = os.path.join(spool_dir, _SPOOL_FILE)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")
        return False, "spooled"
    except Exception as e:  # spooling itself must not raise either -- fall
        # back to a plain failure report rather than propagate.
        return False, f"spool failed: {e}"


def flush_spool(sink: str, spool_dir: str, *, timeout_s: int = 10, redactor=None) -> dict:
    """Re-attempt delivery of every event in ``<spool_dir>/pending.ndjson``
    (M22 Task 2). Rewrites the file with ONLY the events still undelivered
    (empties/truncates it once everything ships) and returns
    ``{"flushed": int, "remaining": int}``. Absent spool file -> both 0.
    NEVER raises.
    """
    path = os.path.join(spool_dir, _SPOOL_FILE)
    try:
        # errors="replace": a spool file corrupted at the byte level (disk bit
        # rot, a stray non-UTF8 write) must NOT raise UnicodeDecodeError (a
        # ValueError, not an OSError) out of a fail-soft flush — degrade the bad
        # bytes to a line that simply won't JSON-parse (kept, not flushed).
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
    except OSError:
        return {"flushed": 0, "remaining": 0}

    flushed = 0
    remaining_lines = []
    for line in lines:
        try:
            event = json.loads(line)
        except Exception:
            # Corrupt line -- can't safely re-send garbage; keep it rather
            # than silently drop, but it doesn't count as flushed.
            remaining_lines.append(line)
            continue
        ok, _reason = deliver(sink, event, timeout_s=timeout_s, redactor=redactor)
        if ok:
            flushed += 1
        else:
            remaining_lines.append(line)

    try:
        with open(path, "w", encoding="utf-8") as f:
            if remaining_lines:
                f.write("\n".join(remaining_lines) + "\n")
    except OSError:
        pass  # best-effort rewrite -- NEVER raise out of flush_spool

    return {"flushed": flushed, "remaining": len(remaining_lines)}
