"""DF-08/M35: crash-safe model dispatch.

Covers: DISPATCH_INTENT/DISPATCH_RESULT bracketing every builder call,
reserved spend committed to state.json BEFORE the call (never understated),
UNKNOWN_OUTCOME fail-closed on resume after a mid-dispatch crash (no silent
re-dispatch), and `resume --decision reconcile` as the explicit operator
override.
"""
import json

import pytest

import supervisor
from df_common import sha256_str
from test_budget import _set_budget
from test_supervisor import FAKE, setup_control, read_journal


def _dispatch_intents(entries):
    return [e for e in entries if e["state"] == "DISPATCH_INTENT"]


def _dispatch_results(entries):
    return [e for e in entries if e["state"] == "DISPATCH_RESULT"]


def test_normal_run_brackets_each_builder_call_with_intent_then_result(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    rc = supervisor.run(str(cr), None)
    assert rc == 0

    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert states.count("BUILD") == 2  # FAKE: buggy then fixed-by-feedback

    intents = _dispatch_intents(entries)
    results = _dispatch_results(entries)
    assert len(intents) == 2
    assert len(results) == 2
    assert [i["data"]["iteration"] for i in intents] == [1, 2]
    assert [r["data"]["iteration"] for r in results] == [1, 2]
    assert all(r["data"]["status"] == "ok" for r in results)

    # Deterministic, stable-per-(run, iteration) idempotency key.
    for i in intents:
        expected_key = sha256_str(f"{run_id}:{i['data']['iteration']}")
        assert i["data"]["idempotency_key"] == expected_key
    for i, r in zip(intents, results):
        assert i["data"]["idempotency_key"] == r["data"]["idempotency_key"]

    # Ordering: for each iteration, DISPATCH_INTENT -> DISPATCH_RESULT -> BUILD.
    for iteration in (1, 2):
        idx_intent = next(n for n, e in enumerate(entries)
                          if e["state"] == "DISPATCH_INTENT" and e["data"]["iteration"] == iteration)
        idx_result = next(n for n, e in enumerate(entries)
                          if e["state"] == "DISPATCH_RESULT" and e["data"]["iteration"] == iteration)
        idx_build = next(n for n, e in enumerate(entries)
                         if e["state"] == "BUILD" and e["data"]["iteration"] == iteration)
        assert idx_intent < idx_result < idx_build

    # Terminal manifest budget numbers unchanged vs pre-M35: 2 builder calls,
    # no cost estimate configured (subscription default from setup_control).
    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["budget"]["builder_calls"] == 2
    assert manifest["budget"]["billing"] == "subscription"


def test_reserved_spend_committed_to_state_before_dispatch_resolves(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _set_budget(cr, {"billing": "api", "per_call_usd": 2.0, "max_usd": 100.0})

    real_invoke = supervisor.invoke_adapter
    seen = {}

    def spy(*a, **kw):
        # Called from inside _run_loop, AFTER DISPATCH_INTENT was journaled
        # and the reservation committed to state.json -- assert the state on
        # disk already reflects it, before the call itself has resolved.
        run_dir = None
        runs_dir = cr / "runs"
        if runs_dir.is_dir():
            names = sorted(n for n in runs_dir.iterdir())
            if names:
                run_dir = names[0]
        if run_dir is not None and (run_dir / "state.json").exists():
            state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
            seen.setdefault("builder_calls", []).append(state["builder_calls"])
            seen.setdefault("estimated_usd", []).append(state["estimated_usd"])
        return real_invoke(*a, **kw)

    monkeypatch.setattr(supervisor, "invoke_adapter", spy)
    rc = supervisor.run(str(cr), None)
    assert rc == 0
    # Call 1 observed builder_calls already == 1 (not 0) and estimated_usd
    # already == 2.0 (not 0.0) -- the increment happened before dispatch.
    assert seen["builder_calls"] == [1, 2]
    assert seen["estimated_usd"] == [2.0, 4.0]


def test_crash_mid_dispatch_yields_unknown_outcome_no_redispatch_and_counted_spend(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _set_budget(cr, {"billing": "api", "per_call_usd": 2.0, "max_usd": 100.0})

    calls = {"n": 0}
    real_invoke = supervisor.invoke_adapter

    def crashing_invoke(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            # Simulate a process crash AFTER the paid request would have
            # gone out (DISPATCH_INTENT + reservation already journaled/
            # committed by _run_loop before this call) but before any
            # result is observed.
            raise RuntimeError("simulated crash mid-dispatch")
        return real_invoke(*a, **kw)

    monkeypatch.setattr(supervisor, "invoke_adapter", crashing_invoke)
    with pytest.raises(RuntimeError, match="simulated crash mid-dispatch"):
        supervisor.run(str(cr), None)
    assert calls["n"] == 1

    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "DISPATCH_INTENT" in states
    assert "DISPATCH_RESULT" not in states  # never resolved
    assert "BUILD" not in states  # the call never returned

    run_dir = cr / "runs" / run_id
    assert (run_dir / "state.json").exists()  # crash left a resumable run
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    # Reserved spend WAS counted even though the call's outcome is unknown.
    assert state["builder_calls"] == 1
    assert state["estimated_usd"] == 2.0
    assert state["next_iter"] == 1

    # Plain resume --decision continue must NOT silently re-dispatch.
    rc2 = supervisor.resume(str(cr), "continue")
    assert rc2 == supervisor.UNKNOWN_OUTCOME
    assert calls["n"] == 1  # no second invoke_adapter call happened

    entries2, _ = read_journal(cr)
    states2 = [e["state"] for e in entries2]
    assert "UNKNOWN_OUTCOME" in states2
    assert not (run_dir / "manifest.json").exists()  # still non-terminal
    assert (run_dir / "state.json").exists()  # still resumable

    # A second plain `continue` is equally refused (idempotent fail-closed).
    rc3 = supervisor.resume(str(cr), "continue")
    assert rc3 == supervisor.UNKNOWN_OUTCOME
    assert calls["n"] == 1

    # Operator explicitly reconciles: proceeds, re-dispatching iteration 1.
    rc4 = supervisor.resume(str(cr), "reconcile")
    assert rc4 == 0  # FAKE converges: buggy iter1 (retried), fixed iter2
    assert calls["n"] == 3  # crash(1) + retried iter1(2) + iter2(3), all real calls after the crash

    entries3, run_id3 = read_journal(cr)
    assert run_id3 == run_id
    states3 = [e["state"] for e in entries3]
    assert "DISPATCH_RECONCILED" in states3
    assert states3.count("DISPATCH_INTENT") == 3  # crashed attempt + 2 real dispatches
    assert states3.count("DISPATCH_RESULT") == 2  # only the 2 real calls resolved
    assert states3.count("BUILD") == 2
    assert "CONVERGED" in states3

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    # Honest duplicate-spend accounting: crash reservation (1 call) + the
    # reconciled retry + the converging 2nd iteration = 3 reserved calls,
    # never silently dropped or double-counted away.
    assert manifest["budget"]["builder_calls"] == 3
    assert manifest["budget"]["estimated_usd"] == 6.0
    assert not (run_dir / "state.json").exists()  # cleared at terminal


def test_unresolved_dispatch_intent_helper_ignores_pre_m35_journal(tmp_path):
    run_dir = tmp_path / "runs" / "r1"
    run_dir.mkdir(parents=True)
    (run_dir / "journal.jsonl").write_text(
        json.dumps({"ts": "x", "state": "BUILD", "data": {"iteration": 1}}) + "\n",
        encoding="utf-8",
    )
    assert supervisor._unresolved_dispatch_intent(str(run_dir)) is None


def test_unresolved_dispatch_intent_helper_detects_gap(tmp_path):
    run_dir = tmp_path / "runs" / "r1"
    run_dir.mkdir(parents=True)
    lines = [
        {"ts": "x", "state": "DISPATCH_INTENT",
         "data": {"iteration": 1, "idempotency_key": "k1", "reserved_calls": 1, "reserved_usd": 2.0}},
    ]
    (run_dir / "journal.jsonl").write_text(
        "\n".join(json.dumps(l) for l in lines) + "\n", encoding="utf-8")
    unresolved = supervisor._unresolved_dispatch_intent(str(run_dir))
    assert unresolved is not None
    assert unresolved["idempotency_key"] == "k1"

    # Adding the matching DISPATCH_RESULT resolves it.
    lines.append({"ts": "y", "state": "DISPATCH_RESULT",
                  "data": {"iteration": 1, "idempotency_key": "k1", "status": "ok"}})
    (run_dir / "journal.jsonl").write_text(
        "\n".join(json.dumps(l) for l in lines) + "\n", encoding="utf-8")
    assert supervisor._unresolved_dispatch_intent(str(run_dir)) is None


def test_crash_after_dispatch_result_replays_instead_of_redispatching(tmp_path, monkeypatch):
    # RA-06/M46: a crash that lands AFTER iteration 1's DISPATCH_RESULT ok was
    # journaled (the paid builder call COMPLETED and wrote the workspace) but
    # BEFORE the iteration finalized and next_iter advanced must, on plain
    # `resume --decision continue`, REPLAY the recorded result (verify the
    # already-persisted workspace) -- NEVER re-dispatch a second PAID call.
    # This is the RESOLVED counterpart to the M35 UNRESOLVED->UNKNOWN_OUTCOME
    # test above (which stays green): resolved auto-skips, unresolved reconciles.
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _set_budget(cr, {"billing": "api", "per_call_usd": 2.0, "max_usd": 100.0})

    calls = {"n": 0}
    real_invoke = supervisor.invoke_adapter

    def counting_invoke(*a, **kw):
        calls["n"] += 1
        return real_invoke(*a, **kw)

    monkeypatch.setattr(supervisor, "invoke_adapter", counting_invoke)

    # Crash simulation: raise inside the POST-dispatch verify on the first
    # builder call only (gated on calls["n"] >= 1 so a pre-build gate can't
    # trip it; one-shot via `armed`). At that point DISPATCH_RESULT ok is
    # journaled and the buggy workspace is written, but state.json is still the
    # DISPATCH_1 save (next_iter == 1), so resume re-enters iteration 1.
    real_run_all = supervisor.run_all
    crash = {"armed": True}

    def crashing_run_all(*a, **kw):
        if crash["armed"] and calls["n"] >= 1:
            crash["armed"] = False
            raise RuntimeError("simulated crash post-dispatch-result")
        return real_run_all(*a, **kw)

    monkeypatch.setattr(supervisor, "run_all", crashing_run_all)

    with pytest.raises(RuntimeError, match="simulated crash post-dispatch-result"):
        supervisor.run(str(cr), None)
    assert calls["n"] == 1  # iteration 1 dispatched exactly once

    entries, run_id = read_journal(cr)
    intents = _dispatch_intents(entries)
    results = _dispatch_results(entries)
    assert len(intents) == 1
    assert len(results) == 1 and results[0]["data"]["status"] == "ok"

    run_dir = cr / "runs" / run_id
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    assert state["next_iter"] == 1          # iteration NOT finalized before crash
    assert state["builder_calls"] == 1      # reserved spend committed at intent time
    assert state["estimated_usd"] == 2.0

    # Plain `continue`: the RESOLVED dispatch is replayed, not re-dispatched.
    rc = supervisor.resume(str(cr), "continue")
    assert rc == 0                          # FAKE converges (iter1 buggy -> iter2 fixed)
    # THE regression assertion: the builder was NOT paid again for iteration 1.
    # calls["n"] == 2 means only iteration 2's real call was added; a re-dispatch
    # bug would make this 3 (re-run iter1 + iter2).
    assert calls["n"] == 2

    entries2, _ = read_journal(cr)
    states2 = [e["state"] for e in entries2]
    replayed = [e for e in entries2 if e["state"] == "DISPATCH_REPLAYED"]
    assert len(replayed) == 1
    assert replayed[0]["data"]["iteration"] == 1
    # The replay matched iteration 1's EXACT dispatch key (recorded result),
    # not a fresh dispatch.
    assert replayed[0]["data"]["idempotency_key"] == sha256_str(f"{run_id}:1")
    # Iteration 1 was never re-dispatched: still exactly one INTENT for it, plus
    # iteration 2's -- and iteration 1 has no SECOND DISPATCH_RESULT.
    assert [e["data"]["iteration"] for e in _dispatch_intents(entries2)] == [1, 2]
    assert [e["data"]["iteration"] for e in _dispatch_results(entries2)] == [1, 2]
    assert "CONVERGED" in states2

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    # Budget NOT double-counted: iteration 1's reserved call (committed pre-crash,
    # reloaded on resume, NOT re-committed on replay) + iteration 2's real call
    # = 2 calls / $4.0. A re-dispatch would show 3 / $6.0.
    assert manifest["budget"]["builder_calls"] == 2
    assert manifest["budget"]["estimated_usd"] == 4.0
    assert not (run_dir / "state.json").exists()  # cleared at terminal


def test_resolved_dispatch_result_helper(tmp_path):
    run_dir = tmp_path / "runs" / "r1"
    run_dir.mkdir(parents=True)
    inv = "INV"
    key = sha256_str(f"{inv}:1")

    # No journal at all -> None (never a false positive; unresolved path intact).
    assert supervisor._resolved_dispatch_result(str(run_dir), inv, 1) is None

    lines = [{"ts": "a", "state": "DISPATCH_INTENT",
              "data": {"iteration": 1, "idempotency_key": key}}]
    (run_dir / "journal.jsonl").write_text(
        "\n".join(json.dumps(l) for l in lines) + "\n", encoding="utf-8")
    # Intent but NO result -> None (this is precisely the UNKNOWN/reconcile case
    # that _unresolved_dispatch_intent owns; the two helpers stay disjoint).
    assert supervisor._resolved_dispatch_result(str(run_dir), inv, 1) is None

    # An ERROR result must NOT trigger replay (an errored dispatch already
    # terminated its run; it is never resumed into a re-dispatch).
    lines.append({"ts": "b", "state": "DISPATCH_RESULT",
                  "data": {"iteration": 1, "idempotency_key": key, "status": "error"}})
    (run_dir / "journal.jsonl").write_text(
        "\n".join(json.dumps(l) for l in lines) + "\n", encoding="utf-8")
    assert supervisor._resolved_dispatch_result(str(run_dir), inv, 1) is None

    # A SUCCESSFUL result for iteration 1 -> returns its recorded data dict.
    lines.append({"ts": "c", "state": "DISPATCH_RESULT",
                  "data": {"iteration": 1, "idempotency_key": key, "status": "ok"}})
    (run_dir / "journal.jsonl").write_text(
        "\n".join(json.dumps(l) for l in lines) + "\n", encoding="utf-8")
    got = supervisor._resolved_dispatch_result(str(run_dir), inv, 1)
    assert got is not None and got["status"] == "ok" and got["idempotency_key"] == key
    # Keys are per-iteration: iteration 2 has no ok result -> None.
    assert supervisor._resolved_dispatch_result(str(run_dir), inv, 2) is None


def test_second_concurrent_run_refused_by_lock(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    lock = supervisor.acquire_lock(str(cr))
    try:
        with pytest.raises(supervisor.LockError):
            supervisor.acquire_lock(str(cr))
    finally:
        supervisor.release_lock(lock)
