"""M77 (Codex R9-05): DF-R9-05 — audit signing is STICKY across resume; a run that
STARTED signed cannot be resumed UNSIGNED by editing the same-user-writable
config.json (`audit.signing: true` -> `false`).

`audit.signing` is derived fresh from config.json on every resume, and config.json
lives UNDER the control root (same-user writable, the dark-factory threat model). A
same-user attacker who does NOT hold the HMAC audit key could therefore flip
`audit.signing` to false and resume — the resumed run then took the unsigned /
no-enforcement path for EVERYTHING (source-identity authentication, ship-completion
authentication, chain verification), silently bypassing the detection-grade signed
model and reaching the exact DF-R9-03 downgrade M76 otherwise closes.

Fix: a run that has a SIGNED source-identity anchor in the audit chain (every signed
run anchors one at first dispatch, or fails closed there — M76) provably started
signed. On resume, if that anchor is present but the freshly loaded config now says
`audit.signing: false`, REFUSE (fail closed): a run cannot switch signed -> unsigned
across a resume. The anchor's presence is read WITHOUT the key (a signed entry
carries a `sig`; an unsigned entry never does), so the detection needs no key and a
forged entry only causes a (safe) refuse, never a bypass.

Robust guarantee = the signed chain anchor. Residual (documented, consistent with
M76): an attacker who ALSO deletes the entire signed chain leaves no local signed
evidence on a sink-less run — the acknowledged construction limit; a required off-box
sink makes even that deletion independently detectable.
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


def _flip_unsigned(cr):
    cfg = json.loads((cr / "config.json").read_text())
    cfg["audit"] = {"signing": False}
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")


def _delete_source_event(run_dir):
    jp = run_dir / "journal.jsonl"
    keep = [l for l in jp.read_text().splitlines()
            if json.loads(l).get("state") != "SOURCE_IDENTITY"]
    jp.write_text("\n".join(keep) + "\n")


def _drift(monkeypatch):
    monkeypatch.setattr(supervisor, "_source_identity_field",
                        lambda: {"commit": "drifted", "clean": True,
                                 "dirty": False, "tree_digest": "f" * 64})


def _blank_source_identity_sig(cr):
    # Attacker blanks the `sig` on the source-identity anchor. `sig` is NOT part of
    # chain_hash, so this does NOT break chain linkage — a `sig`-based detector would
    # then read the run as unsigned.
    cp = cr / "audit-chain.jsonl"
    out = []
    for l in cp.read_text().splitlines():
        if not l.strip():
            continue
        e = json.loads(l)
        if ".source-identity." in str(e.get("invocation", "")):
            e["sig"] = ""
        out.append(json.dumps(e))
    cp.write_text("\n".join(out) + "\n")


# --- the exploit: flip audit.signing -> false and resume ------------------------

def test_signed_config_downgrade_refused(tmp_path):
    # A signed run pauses; the attacker edits config.json audit.signing -> false and
    # resumes. The run STARTED signed (a signed source-identity anchor exists), so the
    # unsigned resume is refused fail-closed rather than silently bypassing the signed
    # model.
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    _flip_unsigned(cr)
    assert supervisor.resume(str(cr), "continue") == 2
    assert "AUDIT_SIGNING_DOWNGRADE_REFUSED" in _states(rd)


def test_signed_config_downgrade_plus_source_delete_refused(tmp_path, monkeypatch):
    # The full DF-R9-03 combination: flip signing off AND delete the source-identity
    # evidence AND drift the source. The downgrade is refused BEFORE (and independent
    # of) the source-identity path, so it fails closed on the signing anchor.
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    _flip_unsigned(cr)
    _delete_source_event(rd)
    (rd / supervisor.SOURCE_IDENTITY_FILE).unlink()
    _drift(monkeypatch)
    assert supervisor.resume(str(cr), "continue") == 2
    assert "AUDIT_SIGNING_DOWNGRADE_REFUSED" in _states(rd)


# --- the detector -----------------------------------------------------------------

def test_run_started_signed_true_for_signed_run(tmp_path):
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    rid = os.path.basename(str(rd))
    assert supervisor._run_started_signed(str(cr), rid) is True


def test_run_started_signed_false_for_cooperative_run(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="pause")
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    rid = os.path.basename(str(rd))
    assert supervisor._run_started_signed(str(cr), rid) is False


def test_signing_downgrade_survives_sig_blanking(tmp_path):
    # A control-root attacker can BLANK the source-identity anchor's `sig` (not part of
    # chain_hash, so chain linkage is untouched) to try to make an honestly-signed run
    # read as unsigned. Presence-keyed detection is immune — the entry is still there —
    # so the downgrade is still refused.
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    rid = os.path.basename(str(rd))
    _blank_source_identity_sig(cr)
    assert supervisor._run_started_signed(str(cr), rid) is True
    _flip_unsigned(cr)
    assert supervisor.resume(str(cr), "continue") == 2
    assert "AUDIT_SIGNING_DOWNGRADE_REFUSED" in _states(rd)


# --- no false positives -----------------------------------------------------------

def test_legit_signed_resume_not_refused(tmp_path):
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    rc = supervisor.resume(str(cr), "continue")
    assert rc != 2
    assert "AUDIT_SIGNING_DOWNGRADE_REFUSED" not in _states(rd)


def test_legit_cooperative_resume_not_refused(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="pause")
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    rc = supervisor.resume(str(cr), "continue")
    assert rc != 2
    assert "AUDIT_SIGNING_DOWNGRADE_REFUSED" not in _states(rd)


# --- the OTHER re-entry into a signing-sensitive phase: `ship` --------------------
# The ship subcommand re-derives signing fresh from config.json too, but is ALREADY
# fail-closed against a signing flip: _ship_eligible binds the run to its sealed
# config_sha256, so ANY config.json edit (including audit.signing) drifts the policy
# hash and refuses BEFORE any ship-completion authentication runs. This regression
# test locks in that protection so the ship path can never silently regress into the
# same downgrade the resume guard closes.

def test_signed_ship_refuses_signing_downgrade(tmp_path):
    from test_ship import _base_config, _rev_ship, build_sealed_run
    cr = tmp_path / "control"
    marker = tmp_path / "SHOULD_NOT_SHIP"
    cfg, run_dir, _oid, _rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", _rev_ship(marker), signed=True),
        {"app.txt": "v1"})
    # Flip audit.signing off BEFORE any ship — the sealed config_sha256 no longer
    # matches, so the ship is refused fail-closed and the action never runs. (An
    # intact signed ship is the existing test_reversible_ship_ships_on_sealed_bytes
    # control.)
    config = json.loads((cr / "config.json").read_text())
    config["audit"] = {"signing": False}
    (cr / "config.json").write_text(json.dumps(config), encoding="utf-8")
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 2
    assert not marker.exists()
