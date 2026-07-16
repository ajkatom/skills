"""M18 Task 1: df_notify (budget-alert delivery) + budget.notification_sink
config validation + supervisor BUDGET_ALERT/BUDGET_PAUSE wiring.

Notification is FAIL-SOFT -- the opposite of the M13 audit sink (fail-CLOSED):
a delivery failure never raises out of deliver() and never changes the run's
exit code. The delivered payload goes through the M11 redactor (when one is
configured) before it leaves the process, exactly like every other persisted
artifact (see supervisor._redacted_write).
"""
import http.server
import json
import os
import socket
import threading

import pytest

import df_config
import df_notify
import supervisor
from df_creds import Redactor
from test_config import write_config
from test_supervisor import FAKE, read_journal, setup_control


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _closed_port() -> int:
    """A port nothing is listening on -- guaranteed connection failure,
    unlike a magic constant that might behave differently across platforms."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _CaptureHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        self.server.received.append(
            {"body": body, "content_type": self.headers.get("Content-Type")}
        )
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args):  # noqa: A002 -- keep test output quiet
        pass


class _CaptureServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr):
        self.received = []
        super().__init__(addr, _CaptureHandler)


def _serve_capture():
    """In-process capturing HTTP receiver on a background daemon thread --
    mirrors df_audit_receiver.serve()'s (store_dir, port=0) -> (httpd, port)
    pattern (M13), minus the store: here we just remember what was POSTed."""
    httpd = _CaptureServer(("127.0.0.1", 0))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, httpd.server_address[1]


# ---------------------------------------------------------------------------
# df_notify.deliver
# ---------------------------------------------------------------------------

def test_deliver_file_sink_appends_ndjson_line(tmp_path):
    path = tmp_path / "alerts.ndjson"
    sink = "file://" + str(path)

    ok, reason = df_notify.deliver(sink, {"event": "BUDGET_ALERT", "estimated_usd": 1.0})
    assert ok is True
    assert reason == "delivered"

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0]) == {"event": "BUDGET_ALERT", "estimated_usd": 1.0}

    # A second delivery appends -- never overwrites/truncates.
    ok2, _ = df_notify.deliver(sink, {"event": "BUDGET_PAUSE"})
    assert ok2 is True
    lines2 = path.read_text(encoding="utf-8").splitlines()
    assert len(lines2) == 2


def test_deliver_http_sink_posts_json(tmp_path):
    httpd, port = _serve_capture()
    try:
        sink = f"http://127.0.0.1:{port}/hook"
        event = {"event": "BUDGET_ALERT", "estimated_usd": 2.5, "builder_calls": 3}
        ok, reason = df_notify.deliver(sink, event)
        assert ok is True
        assert reason == "delivered"

        assert len(httpd.received) == 1
        received = httpd.received[0]
        assert received["content_type"] == "application/json"
        assert json.loads(received["body"]) == event
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_deliver_unreachable_http_returns_false_not_raise(tmp_path):
    port = _closed_port()
    sink = f"http://127.0.0.1:{port}/hook"
    ok, reason = df_notify.deliver(sink, {"event": "BUDGET_ALERT"}, timeout_s=2)
    assert ok is False
    assert isinstance(reason, str) and reason


def test_deliver_unsupported_scheme_returns_false_not_raise(tmp_path):
    ok, reason = df_notify.deliver("ftp://example.com/hook", {"event": "BUDGET_ALERT"})
    assert ok is False
    assert "unsupported sink scheme" in reason


def test_deliver_never_raises_on_garbage_sink():
    # Belt-and-suspenders: even a wildly malformed sink string must come back
    # as (False, reason), never as a propagated exception.
    ok, reason = df_notify.deliver("not a url at all", {"event": "x"})
    assert ok is False
    assert isinstance(reason, str)


def test_deliver_redacts_secret_when_redactor_passed(tmp_path):
    path = tmp_path / "alerts.ndjson"
    sink = "file://" + str(path)
    secret = "sekrit-token-abc123"
    redactor = Redactor([secret])

    ok, _ = df_notify.deliver(
        sink, {"event": "BUDGET_ALERT", "note": f"key={secret}"}, redactor=redactor
    )
    assert ok is True

    text = path.read_text(encoding="utf-8")
    assert secret not in text
    assert Redactor.PLACEHOLDER in text


def test_deliver_no_redactor_passes_through(tmp_path):
    path = tmp_path / "alerts.ndjson"
    sink = "file://" + str(path)
    ok, _ = df_notify.deliver(sink, {"event": "BUDGET_ALERT", "note": "plain"})
    assert ok is True
    assert "plain" in path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# df_config: budget.notification_sink scheme validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("sink", [
    "http://ops.example.com/hook",
    "https://ops.example.com/hook",
])
def test_config_accepts_http_https_sink(tmp_path, sink):
    cr = tmp_path / "control"
    write_config(cr, budget={"notification_sink": sink})
    cfg = df_config.load_config(str(cr))
    assert cfg["_budget"]["notification_sink"] == sink


def test_config_accepts_file_abs_sink(tmp_path):
    cr = tmp_path / "control"
    abs_path = str(tmp_path / "alerts.ndjson")
    sink = "file://" + abs_path
    write_config(cr, budget={"notification_sink": sink})
    cfg = df_config.load_config(str(cr))
    assert cfg["_budget"]["notification_sink"] == sink


def test_config_empty_sink_still_default_ok(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"notification_sink": ""})
    cfg = df_config.load_config(str(cr))
    assert cfg["_budget"]["notification_sink"] == ""


def test_config_rejects_bare_path_sink(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"notification_sink": "/var/log/alerts.ndjson"})
    with pytest.raises(df_config.ConfigError, match="notification_sink"):
        df_config.load_config(str(cr))


def test_config_rejects_unsupported_scheme_sink(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"notification_sink": "ftp://ops.example.com/hook"})
    with pytest.raises(df_config.ConfigError, match="notification_sink"):
        df_config.load_config(str(cr))


def test_config_rejects_relative_file_sink(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"notification_sink": "file://relative/path.ndjson"})
    with pytest.raises(df_config.ConfigError, match="notification_sink"):
        df_config.load_config(str(cr))


# ---------------------------------------------------------------------------
# supervisor: BUDGET_ALERT / BUDGET_PAUSE notification wiring (monkeypatched
# deliver -- delivery mechanics are already covered above).
# ---------------------------------------------------------------------------

def _set_budget(cr, budget):
    cfg_path = cr / "config.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg["budget"] = budget
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")


def test_budget_alert_delivers_and_journals_notify_sent(tmp_path, monkeypatch):
    # FAKE needs exactly 2 builder calls to converge. max_calls=2, alert_at=0.5:
    # before call 1, builder_calls=0 -- 0 >= 0.5*2=1 is false, no alert, admitted.
    # before call 2, builder_calls=1 -- 1 >= 1 is true, ALERT fires; calls_after=2
    # is NOT > max_calls=2, so this same admission is NOT a pause -- an alert
    # that fires without also pausing, unlike test_85_percent_alert's dollar
    # cap (which happens to pause in the very same admission check).
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _set_budget(cr, {
        "billing": "subscription", "max_calls": 2, "alert_at": 0.5,
        "notification_sink": "https://ops.example.com/hook",
    })

    calls = []

    def fake_deliver(sink, event, *, timeout_s=10, redactor=None):
        calls.append((sink, event))
        return True, "delivered"

    monkeypatch.setattr(df_notify, "deliver", fake_deliver)

    rc = supervisor.run(str(cr), None)
    assert rc == 0  # an alert never blocks -- unchanged from pre-M18 behavior

    assert len(calls) == 1
    sink, event = calls[0]
    assert sink == "https://ops.example.com/hook"
    assert event["event"] == "BUDGET_ALERT"

    entries, _ = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "NOTIFY_SENT" in states
    assert "NOTIFY_FAILED" not in states


def test_budget_pause_notify_failed_does_not_change_exit(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _set_budget(cr, {
        "billing": "api", "per_call_usd": 1.0, "max_usd": 1.0,
        "notification_sink": "https://ops.example.com/hook",
    })

    def fake_deliver(sink, event, *, timeout_s=10, redactor=None):
        return False, "channel down"

    monkeypatch.setattr(df_notify, "deliver", fake_deliver)

    rc = supervisor.run(str(cr), None)
    assert rc == 10  # PAUSED -- exit code identical to the pre-M18 pause path

    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "BUDGET_PAUSE" in states
    assert "NOTIFY_FAILED" in states
    failed = next(e for e in entries if e["state"] == "NOTIFY_FAILED")
    assert failed["data"]["reason"] == "channel down"

    run_dir = cr / "runs" / run_id
    assert not (run_dir / "manifest.json").exists()  # pause is still non-terminal


def test_no_notification_sink_never_calls_deliver(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _set_budget(cr, {"billing": "subscription", "max_calls": 2, "alert_at": 0.5})

    def fail_if_called(*args, **kwargs):
        raise AssertionError("deliver() must not be called when notification_sink is unset")

    monkeypatch.setattr(df_notify, "deliver", fail_if_called)

    rc = supervisor.run(str(cr), None)
    assert rc == 0

    entries, _ = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "BUDGET_ALERT" in states
    assert "NOTIFY_SENT" not in states
    assert "NOTIFY_FAILED" not in states
