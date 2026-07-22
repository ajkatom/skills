"""M77 (Codex R9, NEW — found by applying R9's own method corrections beyond the
findings it reported): the resumable checkpoint (state.json) + the M36a FSM chain
are UNSIGNED, so a same-user writer (no audit key) can forge control-plane state
that resume trusts.

The M36a FSM chain (fsm_chain.jsonl) is a plain sha256 chain: an attacker can
rewrite it AND set state.json's recorded head to match (it detects accidental
corruption, not tampering). And the security-critical fields it never bound are
trusted raw:
  * `build_approved_through` — forge it HIGH to skip the before-build approval pause
    (H1/directed modes) and run un-approved builds;
  * `builder_calls` / `estimated_usd` — forge them LOW to defeat the budget ceiling.

Fix: on a SIGNED run, every state.json write anchors a signed `resumable-state`
token binding its EXACT bytes at a monotonic seq (chain key `{run_id}.resumable-
state.{seq:08d}`). On resume, before any override / budget / approval decision reads
the state, _authenticate_resumable_state requires the loaded checkpoint to BE the
latest signed state: highest anchored seq (no replay) AND the token for (run_id,
seq, sha256(state.json now)) anchored (no forged field). Signed runs only; unsigned
tiers are not detection-grade.
"""
import json
import os

import supervisor
from test_supervisor import FAKE, setup_control


def _states(run_dir):
    return [json.loads(l)["state"]
            for l in (run_dir / "journal.jsonl").read_text().splitlines()]


def _rundir(cr):
    return cr / "runs" / os.listdir(cr / "runs")[0]


def _signed_run(tmp_path, checkpoint="pause"):
    cr = setup_control(tmp_path, FAKE, checkpoint=checkpoint)
    cfg = json.loads((cr / "config.json").read_text())
    cfg["audit"] = {"signing": True, "key_path": str(tmp_path / "keys" / "audit.key")}
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return cr


def _edit_state(run_dir, **fields):
    st = json.loads((run_dir / "state.json").read_text())
    st.update(fields)
    (run_dir / "state.json").write_text(json.dumps(st), encoding="utf-8")


# --- the two exploits the finding names -----------------------------------------

def test_forged_build_approved_through_refused(tmp_path):
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    _edit_state(rd, build_approved_through=999)  # skip the approval gate
    assert supervisor.resume(str(cr), "continue") == 2
    assert "STATE_INTEGRITY_REFUSED" in _states(rd)


def test_forged_budget_counters_refused(tmp_path):
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    _edit_state(rd, estimated_usd=0.0, builder_calls=0)  # reset the spend ceiling
    assert supervisor.resume(str(cr), "continue") == 2
    assert "STATE_INTEGRITY_REFUSED" in _states(rd)


def test_forged_fsm_head_or_phase_refused(tmp_path):
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    # a forged phase changes the digest; even if the attacker also rewrites the
    # UNSIGNED fsm chain to keep FSM validation happy, the signed state anchor refuses
    _edit_state(rd, phase="AWAIT_SHIP")
    assert supervisor.resume(str(cr), "continue") == 2
    assert "STATE_INTEGRITY_REFUSED" in _states(rd)


# --- anti-replay + missing/deleted anchor ---------------------------------------

def test_replayed_older_seq_refused(tmp_path):
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    st = json.loads((rd / "state.json").read_text())
    assert isinstance(st.get("state_seq"), int) and st["state_seq"] >= 1
    _edit_state(rd, state_seq=st["state_seq"] - 1)  # replay an earlier checkpoint
    assert supervisor.resume(str(cr), "continue") == 2
    assert "STATE_INTEGRITY_REFUSED" in _states(rd)


def test_missing_state_seq_refused(tmp_path):
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    _edit_state(rd, state_seq=None)  # a forged / pre-M77 signed state
    assert supervisor.resume(str(cr), "continue") == 2
    assert "STATE_INTEGRITY_REFUSED" in _states(rd)


def test_deleted_whole_chain_refused(tmp_path):
    # Deleting the whole audit-chain.jsonl erases the state anchors while an empty
    # chain still "verifies" — a signed run with no state anchor fails closed.
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    (cr / "audit-chain.jsonl").unlink()
    # (source-identity authenticates first and also fails closed here; both refuse.)
    assert supervisor.resume(str(cr), "continue") == 2


# --- no false positives ---------------------------------------------------------

def test_legit_signed_resume_authenticates(tmp_path):
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    rc = supervisor.resume(str(cr), "continue")
    assert rc != 2
    assert "STATE_INTEGRITY_VERIFIED" in _states(rd)
    assert "STATE_INTEGRITY_REFUSED" not in _states(rd)


def test_unsigned_run_has_no_state_seq_and_resumes(tmp_path):
    # Unsigned (cooperative) tier: no anchoring, state_seq is None, resume proceeds
    # (M77 is signed-tier detection-grade only).
    cr = setup_control(tmp_path, FAKE, checkpoint="pause")
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    assert json.loads((rd / "state.json").read_text()).get("state_seq") is None
    rc = supervisor.resume(str(cr), "continue")
    assert rc != 2
    assert "STATE_INTEGRITY_REFUSED" not in _states(rd)


def test_truncation_gate_closes_replay_residual(tmp_path, monkeypatch):
    # Opus M77 review — the truncation-REPLAY residual (roll all files back to an
    # earlier signed checkpoint to revert budget) is the inherited M73 truncatability
    # and is CLOSED by a required off-box sink: _verify_chain_untruncated then detects
    # the shortened chain. Verify M77 honours that gate — when the untruncated probe
    # reports truncation, the state auth fails closed regardless of digest/seq match.
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    cfg = supervisor.load_config(str(cr))
    cfg["_control_root"] = str(cr)
    rid = os.path.basename(str(rd))
    state = supervisor.load_state(str(rd))
    # sanity: with the probe passing (no sink → ok), an untampered state authenticates
    assert supervisor._authenticate_resumable_state(cfg, str(cr), str(rd), rid, state)[0]
    # a required-sink truncation signal must fail the state auth closed
    monkeypatch.setattr(supervisor, "_verify_chain_untruncated",
                        lambda *a, **k: (False, "off-box sink shows a longer committed chain "
                                         "(local tail-truncated)"))
    ok, why = supervisor._authenticate_resumable_state(cfg, str(cr), str(rd), rid, state)
    assert ok is False and "truncat" in why.lower()


def test_helper_authenticates_then_refuses_on_tamper(tmp_path):
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    cfg = supervisor.load_config(str(cr))
    cfg["_control_root"] = str(cr)
    rid = os.path.basename(str(rd))
    state = supervisor.load_state(str(rd))
    ok, _why = supervisor._authenticate_resumable_state(cfg, str(cr), str(rd), rid, state)
    assert ok is True
    _edit_state(rd, build_approved_through=42)
    state2 = supervisor.load_state(str(rd))
    ok2, why2 = supervisor._authenticate_resumable_state(cfg, str(cr), str(rd), rid, state2)
    assert ok2 is False and "anchor" in why2
