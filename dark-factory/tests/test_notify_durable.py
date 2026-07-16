"""M22 Task 2: durable at-least-once notification delivery.

CRITICAL SEMANTIC (unchanged from M18, see test_notify.py): notification
stays FAIL-SOFT -- a permanently-down sink NEVER fails the run. "Durable"
here means at-least-once via a local disk SPOOL + bounded retry, NOT a real
message queue: no cross-host durability, no ordering guarantees, no dedup
beyond the spool file itself. Spooled events carry NO secret values -- the
redactor is applied BEFORE the event ever touches disk, exactly like M18's
in-flight delivery path.
"""
import json
import os
import socket

import pytest

import df_config
import df_notify
import supervisor
from df_creds import Redactor
from test_config import write_config
from test_supervisor import FAKE, setup_control
from test_notify import _serve_capture, _closed_port


# ---------------------------------------------------------------------------
# df_notify.deliver_durable
# ---------------------------------------------------------------------------

def test_deliver_durable_live_receiver_delivers_spool_stays_empty(tmp_path):
    httpd, port = _serve_capture()
    try:
        sink = f"http://127.0.0.1:{port}/hook"
        spool_dir = str(tmp_path / ".notify-spool")
        event = {"event": "BUDGET_ALERT", "estimated_usd": 1.0}

        ok, reason = df_notify.deliver_durable(sink, event, spool_dir)
        assert ok is True
        assert reason == "delivered"

        assert len(httpd.received) == 1
        # Nothing spooled -- no spool file (or dir) was ever created.
        assert not os.path.exists(os.path.join(spool_dir, "pending.ndjson"))
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_deliver_durable_unreachable_sink_spools_and_never_raises(tmp_path):
    port = _closed_port()
    sink = f"http://127.0.0.1:{port}/hook"
    spool_dir = str(tmp_path / ".notify-spool")
    event = {"event": "BUDGET_ALERT", "estimated_usd": 2.0}

    ok, reason = df_notify.deliver_durable(sink, event, spool_dir, timeout_s=2)
    assert ok is False
    assert reason == "spooled"

    pending = os.path.join(spool_dir, "pending.ndjson")
    assert os.path.exists(pending)
    lines = open(pending, encoding="utf-8").read().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0]) == event


def test_deliver_durable_never_raises_on_garbage_sink(tmp_path):
    spool_dir = str(tmp_path / ".notify-spool")
    ok, reason = df_notify.deliver_durable("not a url at all", {"event": "x"}, spool_dir)
    assert ok is False
    assert reason == "spooled"
    assert os.path.exists(os.path.join(spool_dir, "pending.ndjson"))


def test_deliver_durable_retries_attempts_then_spools(tmp_path):
    port = _closed_port()
    sink = f"http://127.0.0.1:{port}/hook"
    spool_dir = str(tmp_path / ".notify-spool")
    event = {"event": "BUDGET_PAUSE"}

    calls = []
    orig_deliver = df_notify.deliver

    def counting_deliver(*args, **kwargs):
        calls.append(1)
        return orig_deliver(*args, **kwargs)

    import df_notify as _dn
    real = _dn.deliver
    _dn.deliver = counting_deliver
    try:
        ok, reason = df_notify.deliver_durable(
            sink, event, spool_dir, attempts=3, timeout_s=2
        )
    finally:
        _dn.deliver = real

    assert ok is False
    assert reason == "spooled"
    assert len(calls) == 3

    pending = os.path.join(spool_dir, "pending.ndjson")
    lines = open(pending, encoding="utf-8").read().splitlines()
    assert len(lines) == 1


def test_deliver_durable_redacts_secret_in_spool_file(tmp_path):
    port = _closed_port()
    sink = f"http://127.0.0.1:{port}/hook"
    spool_dir = str(tmp_path / ".notify-spool")
    secret = "sekrit-token-xyz789"
    redactor = Redactor([secret])

    ok, reason = df_notify.deliver_durable(
        sink, {"event": "BUDGET_ALERT", "note": f"key={secret}"}, spool_dir,
        timeout_s=2, redactor=redactor,
    )
    assert ok is False
    assert reason == "spooled"

    text = open(os.path.join(spool_dir, "pending.ndjson"), encoding="utf-8").read()
    assert secret not in text
    assert Redactor.PLACEHOLDER in text


def test_deliver_durable_succeeds_on_a_later_attempt_no_spool(tmp_path):
    # First attempt fails (unreachable), second succeeds -- deliver_durable
    # must not spool once ANY attempt within the budget succeeds.
    httpd, port = _serve_capture()
    dead_port = _closed_port()
    spool_dir = str(tmp_path / ".notify-spool")
    event = {"event": "BUDGET_ALERT"}

    calls = {"n": 0}
    orig_deliver = df_notify.deliver

    def flaky_deliver(sink, ev, *, timeout_s=10, redactor=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return orig_deliver(f"http://127.0.0.1:{dead_port}/hook", ev,
                                 timeout_s=2, redactor=redactor)
        return orig_deliver(f"http://127.0.0.1:{port}/hook", ev,
                             timeout_s=timeout_s, redactor=redactor)

    import df_notify as _dn
    real = _dn.deliver
    _dn.deliver = flaky_deliver
    try:
        ok, reason = df_notify.deliver_durable(
            "http://placeholder/hook", event, spool_dir, attempts=2, timeout_s=2
        )
    finally:
        _dn.deliver = real
        httpd.shutdown()
        httpd.server_close()

    assert ok is True
    assert reason == "delivered"
    assert not os.path.exists(os.path.join(spool_dir, "pending.ndjson"))


# ---------------------------------------------------------------------------
# df_notify.flush_spool
# ---------------------------------------------------------------------------

def test_flush_spool_absent_file_returns_zero_counts(tmp_path):
    spool_dir = str(tmp_path / ".notify-spool")
    result = df_notify.flush_spool("http://127.0.0.1:1/hook", spool_dir)
    assert result == {"flushed": 0, "remaining": 0}


def test_flush_spool_now_reachable_delivers_and_empties(tmp_path):
    port = _closed_port()
    sink = f"http://127.0.0.1:{port}/hook"
    spool_dir = str(tmp_path / ".notify-spool")
    event = {"event": "BUDGET_ALERT", "estimated_usd": 3.0}

    ok, reason = df_notify.deliver_durable(sink, event, spool_dir, timeout_s=2)
    assert (ok, reason) == (False, "spooled")

    httpd, live_port = _serve_capture()
    try:
        live_sink = f"http://127.0.0.1:{live_port}/hook"
        result = df_notify.flush_spool(live_sink, spool_dir, timeout_s=5)
        assert result == {"flushed": 1, "remaining": 0}
        assert len(httpd.received) == 1
        assert json.loads(httpd.received[0]["body"]) == event

        pending = os.path.join(spool_dir, "pending.ndjson")
        assert open(pending, encoding="utf-8").read().strip() == ""
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_flush_spool_still_down_events_remain_counts_correct(tmp_path):
    port = _closed_port()
    sink = f"http://127.0.0.1:{port}/hook"
    spool_dir = str(tmp_path / ".notify-spool")

    df_notify.deliver_durable(sink, {"event": "BUDGET_ALERT"}, spool_dir, timeout_s=2)
    df_notify.deliver_durable(sink, {"event": "BUDGET_PAUSE"}, spool_dir, timeout_s=2)

    pending = os.path.join(spool_dir, "pending.ndjson")
    assert len(open(pending, encoding="utf-8").read().splitlines()) == 2

    result = df_notify.flush_spool(sink, spool_dir, timeout_s=2)
    assert result == {"flushed": 0, "remaining": 2}
    assert len(open(pending, encoding="utf-8").read().splitlines()) == 2


def test_flush_spool_mixed_some_deliver_some_remain(tmp_path):
    spool_dir = str(tmp_path / ".notify-spool")
    pending = os.path.join(spool_dir, "pending.ndjson")
    os.makedirs(spool_dir, exist_ok=True)
    with open(pending, "w", encoding="utf-8") as f:
        f.write(json.dumps({"event": "A"}) + "\n")
        f.write(json.dumps({"event": "B"}) + "\n")

    def picky_deliver(sink, event, *, timeout_s=10, redactor=None):
        if event["event"] == "A":
            return True, "delivered"
        return False, "still down"

    orig = df_notify.deliver
    df_notify.deliver = picky_deliver
    try:
        result = df_notify.flush_spool("http://irrelevant/hook", spool_dir)
    finally:
        df_notify.deliver = orig

    assert result == {"flushed": 1, "remaining": 1}
    lines = open(pending, encoding="utf-8").read().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0]) == {"event": "B"}


def test_flush_spool_never_raises_on_malformed_sink(tmp_path):
    spool_dir = str(tmp_path / ".notify-spool")
    os.makedirs(spool_dir, exist_ok=True)
    with open(os.path.join(spool_dir, "pending.ndjson"), "w", encoding="utf-8") as f:
        f.write(json.dumps({"event": "X"}) + "\n")

    result = df_notify.flush_spool("not a url at all", spool_dir)
    assert result == {"flushed": 0, "remaining": 1}


# ---------------------------------------------------------------------------
# df_config: budget.notification_durable / budget.notification_attempts
# ---------------------------------------------------------------------------

def test_config_notification_durable_defaults_false(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"billing": "subscription"})
    cfg = df_config.load_config(str(cr))
    assert cfg["_budget"]["notification_durable"] is False
    assert cfg["_budget"]["notification_attempts"] == 3


def test_config_notification_durable_true_and_attempts(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"billing": "subscription",
                              "notification_durable": True,
                              "notification_attempts": 5})
    cfg = df_config.load_config(str(cr))
    assert cfg["_budget"]["notification_durable"] is True
    assert cfg["_budget"]["notification_attempts"] == 5


def test_config_notification_durable_must_be_bool(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"notification_durable": "yes"})
    with pytest.raises(df_config.ConfigError, match="notification_durable"):
        df_config.load_config(str(cr))


@pytest.mark.parametrize("bad", [0, -1, 1.5, True, "3"])
def test_config_notification_attempts_must_be_int_ge_1(tmp_path, bad):
    cr = tmp_path / "control"
    write_config(cr, budget={"notification_attempts": bad})
    with pytest.raises(df_config.ConfigError, match="notification_attempts"):
        df_config.load_config(str(cr))


# ---------------------------------------------------------------------------
# supervisor: durable notify + spool flush wiring (monkeypatched deliver --
# delivery/spool mechanics are already covered above).
# ---------------------------------------------------------------------------

def _set_budget(cr, budget):
    cfg_path = cr / "config.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg["budget"] = budget
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")


def _read_journal_for(cr, run_id):
    lines = (cr / "runs" / run_id / "journal.jsonl").read_text(encoding="utf-8")
    return [json.loads(l) for l in lines.strip().splitlines()]


def test_supervisor_durable_down_sink_spools_and_run_still_converges(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _set_budget(cr, {
        "billing": "subscription", "max_calls": 2, "alert_at": 0.5,
        "notification_sink": "https://ops.example.com/hook",
        "notification_durable": True, "notification_attempts": 2,
    })

    def fake_deliver(sink, event, *, timeout_s=10, redactor=None):
        return False, "channel down"

    monkeypatch.setattr(df_notify, "deliver", fake_deliver)

    rc = supervisor.run(str(cr), None)
    assert rc == 0  # fail-soft -- exit unchanged from the non-durable case

    runs = os.listdir(cr / "runs")
    assert len(runs) == 1
    entries = _read_journal_for(cr, runs[0])
    states = [e["state"] for e in entries]
    assert "NOTIFY_SPOOLED" in states
    assert "NOTIFY_FAILED" not in states

    pending = cr / ".notify-spool" / "pending.ndjson"
    assert pending.exists()
    lines = pending.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 1
    assert all(json.loads(l)["event"] == "BUDGET_ALERT" for l in lines)


def test_supervisor_later_run_flushes_spool(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _set_budget(cr, {
        "billing": "subscription", "max_calls": 2, "alert_at": 0.5,
        "notification_sink": "https://ops.example.com/hook",
        "notification_durable": True, "notification_attempts": 1,
    })

    def fake_deliver_down(sink, event, *, timeout_s=10, redactor=None):
        return False, "channel down"

    monkeypatch.setattr(df_notify, "deliver", fake_deliver_down)
    rc1 = supervisor.run(str(cr), None)
    assert rc1 == 0
    runs_after_1 = set(os.listdir(cr / "runs"))

    pending = cr / ".notify-spool" / "pending.ndjson"
    assert pending.exists()
    assert len(pending.read_text(encoding="utf-8").splitlines()) >= 1

    def fake_deliver_up(sink, event, *, timeout_s=10, redactor=None):
        return True, "delivered"

    monkeypatch.setattr(df_notify, "deliver", fake_deliver_up)
    rc2 = supervisor.run(str(cr), None)
    assert rc2 == 0

    # Invocation IDs are timestamp+random-uuid -- two runs within the same
    # second do NOT sort chronologically by name, so identify the SECOND
    # run by set difference rather than trusting lexical order.
    runs_after_2 = set(os.listdir(cr / "runs"))
    assert len(runs_after_2) == 2
    second_run = next(iter(runs_after_2 - runs_after_1))
    entries2 = _read_journal_for(cr, second_run)
    states2 = [e["state"] for e in entries2]
    assert "NOTIFY_FLUSH" in states2
    flush_entry = next(e for e in entries2 if e["state"] == "NOTIFY_FLUSH")
    assert flush_entry["data"]["flushed"] >= 1
    assert flush_entry["data"]["remaining"] == 0

    # Spool file is now empty -- fully flushed.
    assert pending.read_text(encoding="utf-8").strip() == ""


def test_supervisor_non_durable_byte_identical_to_m18(tmp_path, monkeypatch):
    # Absent notification_durable (default False) -- no NOTIFY_FLUSH, no
    # spool dir ever created, exactly the M18 best-effort path.
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _set_budget(cr, {
        "billing": "subscription", "max_calls": 2, "alert_at": 0.5,
        "notification_sink": "https://ops.example.com/hook",
    })

    def fake_deliver(sink, event, *, timeout_s=10, redactor=None):
        return False, "channel down"

    monkeypatch.setattr(df_notify, "deliver", fake_deliver)
    rc = supervisor.run(str(cr), None)
    assert rc == 0

    runs = os.listdir(cr / "runs")
    entries = _read_journal_for(cr, runs[0])
    states = [e["state"] for e in entries]
    assert "NOTIFY_FAILED" in states
    assert "NOTIFY_SPOOLED" not in states
    assert "NOTIFY_FLUSH" not in states
    assert not (cr / ".notify-spool").exists()
