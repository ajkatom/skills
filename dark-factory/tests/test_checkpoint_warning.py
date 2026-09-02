"""Regression: the DF-R12-01 "checkpoint did not land" warning path crashed.

`attach_custody` (and the waiver-attach twin) guarded the required-sink warning
with `... and sink.get("required")`, but `sink` was never defined in either
function scope — so the exact moment the warning exists for (the chain-length
checkpoint fails to land on a REQUIRED sink, run left not off-box-complete)
raised NameError instead of surfacing the warning. This pins the fixed
behavior: attach still succeeds (the record push itself landed), and the
warning is printed.
"""
import json
import os

import df_custody
import supervisor
from test_enterprise_config import (
    _approver, _enterprise_control, _fake_invoke, _patch_enterprise_probes, _sink_receiver)


def _sign_over_manifest(cr, run_dir, pairs):
    mb = (run_dir / "manifest.json").read_bytes()
    (cr / "custody-signatures.json").write_text(json.dumps(
        [{"approver": pub, "sig": df_custody.sign_manifest(priv, mb)} for priv, pub in pairs]),
        encoding="utf-8")


def test_custody_attach_survives_failed_checkpoint_and_warns(tmp_path, monkeypatch, capsys):
    priv_a, pub_a = _approver()
    priv_b, pub_b = _approver()
    with _sink_receiver(tmp_path) as (sink_url, _store):
        cr = _enterprise_control(tmp_path, [pub_a, pub_b], threshold=2,
                                 sink_url=sink_url, candidate_network="deny")
        _patch_enterprise_probes(monkeypatch)
        monkeypatch.setattr(supervisor, "invoke_adapter", _fake_invoke)
        assert supervisor.run(str(cr), None) == 3  # CUSTODY_PENDING
        run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
        _sign_over_manifest(cr, run_dir, [(priv_a, pub_a), (priv_b, pub_b)])

        # The attestation record push succeeds, but the dense chain-length
        # checkpoint does NOT land — the exact DF-R12-01 warning condition.
        monkeypatch.setattr(supervisor, "_checkpoint_chain_to_sink",
                            lambda cfg, control_root: False)

        assert supervisor.attach_custody(str(cr), str(run_dir)) == 0
        err = capsys.readouterr().err
        assert "custody chain-length checkpoint did not land" in err
        assert "NOT off-box-complete" in err
