"""M90 (DF-R12-02): hardened `production_ready` must prove a REAL remote/WORM sink,
not merely `confirmed_offbox`.

`confirmed_offbox` proves a reachable append-only-keyed sink, NOT a different trust
domain — a same-host `http-append` receiver returns the same probe statuses. The
hardened-h4 predicate accepted that as production-ready even though the project's own
runbook (references/live-validation.md) says a same-host receiver is only "mechanism
tested." Fix: hardened production GO requires a server-authentic s3-objectlock ship
receipt (server_issued + version_id + read-back verified) — the same WORM proof
enterprise already requires — else the run is reported `mechanism_ready` with
`production_ready` false.

'Why it was missed' (per the audit): M82 tested the completeness STATE (unconfirmed
vs confirmed_offbox) but treated "confirmed" as equivalent to "different trust domain";
it never traced the provenance needed to establish that semantic claim.
"""
import df_evidence_bundle as EB
from test_m70_production_evidence import _full_bundle


def _verdict(profile, mutate=None):
    bundle, manifest = _full_bundle(profile)
    if mutate:
        mutate(bundle, manifest)
    ready, unmet = EB._production_verdict(bundle, {"manifest_verified": True}, manifest, profile)
    return bundle, ready, unmet


def test_hardened_same_host_sink_is_not_production_ready():
    # A same-host receiver: confirmed_offbox but no s3-objectlock WORM receipt.
    def same_host(b, mf):
        b["audit_chain"] = {"verified": True, "untruncated": True,
                            "completeness": "confirmed_offbox",
                            "completeness_message": "same-host test receiver returned 404"}
        b["ship_sink_receipt"] = {"present": True, "kind": "http-append",
                                  "server_issued": False, "verified": True}
    _bundle, ready, unmet = _verdict("hardened-h4", same_host)
    assert ready is False
    assert any("remote/WORM sink provenance" in u for u in unmet)


def test_hardened_missing_receipt_is_not_production_ready():
    # r12 repro #3 shape: receipts removed entirely.
    def strip(b, mf):
        b["ship_sink_receipt"] = {"present": False}
    _bundle, ready, unmet = _verdict("hardened-h4", strip)
    assert ready is False
    assert any("remote/WORM sink provenance" in u for u in unmet)


def test_hardened_with_real_worm_receipt_is_production_ready():
    # The unmutated fixture carries a server-authentic s3-objectlock receipt.
    _bundle, ready, unmet = _verdict("hardened-h4")
    assert ready is True, unmet


def test_hardened_without_worm_is_mechanism_ready():
    # The honest middle state: prod False, mechanism True when the ONLY gap is WORM
    # provenance. This asserts the exact derivation build_bundle applies
    # (`[u for u in production_unmet if u != _HARDENED_WORM_UNMET] == []`).
    bundle, manifest = _full_bundle("hardened-h4")
    bundle["ship_sink_receipt"] = {"present": True, "kind": "http-append",
                                   "server_issued": False, "verified": True}
    ready, unmet = EB._production_verdict(bundle, {"manifest_verified": True},
                                          manifest, "hardened-h4")
    mechanism_ready = len([u for u in unmet if u != EB._HARDENED_WORM_UNMET]) == 0
    assert ready is False
    assert mechanism_ready is True  # everything sound except the live WORM sink
    assert unmet == [EB._HARDENED_WORM_UNMET]  # the sole gap is provenance


def test_hardened_broken_core_is_not_mechanism_ready():
    # A genuine defect (not just missing WORM) must NOT read as mechanism_ready.
    def break_core(b, mf):
        b["ship_sink_receipt"] = {"present": False}   # no WORM
        b["qualified"] = False                        # AND a real defect
    _bundle, ready, unmet = _verdict("hardened-h4", break_core)
    _unmet_wo_worm = [u for u in unmet if u != EB._HARDENED_WORM_UNMET]
    assert ready is False
    assert len(_unmet_wo_worm) >= 1  # a non-provenance failure remains → not mechanism_ready


def test_enterprise_still_requires_its_own_worm_receipt():
    # Enterprise already required the s3-objectlock receipt; M90 must not weaken it.
    def strip(b, mf):
        b["ship_sink_receipt"] = {"present": False}
    _bundle, ready, unmet = _verdict("enterprise", strip)
    assert ready is False
    assert any("s3-objectlock ship receipt" in u for u in unmet)
