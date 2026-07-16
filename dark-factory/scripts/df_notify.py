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
