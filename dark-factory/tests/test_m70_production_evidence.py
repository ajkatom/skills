"""M70 (Codex R8): DF-R8-02 authenticated final-ship + signed idempotent re-entry
proof, and DF-R8-03 exhaustive production profiles + field-name fixes.

  * DF-R8-02 — the production bundle read the writable ship_result.json and
    required only the string "SHIPPED" plus a `shipped and not unresolved`
    re-entry flag; a terminal re-entry returned before recording any positive
    event. Now: the exact ship_result bytes must be anchored in the signed chain,
    and an authenticated terminal re-entry records a signed SHIP_REENTRY_VERIFIED
    token binding those exact bytes + a nonce — the positive proof the mandated
    'ship again, prove idempotence' exercise ran with no redispatch.
  * DF-R8-03 — the profile predicate was not exhaustive and read two manifest keys
    by the wrong name (`seccomp` vs sealed `enterprise_seccomp`;
    `qualification_sink_receipt.json` vs custody's `custody_sink_receipt.json`).
    Now: image digest-pinning, enterprise seccomp/denial/confinement, custody +
    release receipt byte-binding, release-scope coverage, and sealed config policy
    are all required, each with a negative mutation.
"""
import json
import sys

import supervisor
import df_evidence_bundle as EB
from test_ship import build_sealed_run, _base_config
from test_m49_ship_integrity import _counter_action


def _mk(p):
    p.mkdir(parents=True, exist_ok=True)
    return p


def _signed_shipped_run(tmp_path):
    """A signed standard run with one reversible action, shipped once (SHIPPED)."""
    dep, _ = _counter_action(tmp_path, name="deploy", reversible=True)
    cr = tmp_path / "control"
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [dep]}, signed=True),
        {"a.txt": "v1"})
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    return cr, run_dir, cfg, rid


# ---------------------------------------------------------------------------
# DF-R8-02 — authenticated final ship + signed re-entry proof
# ---------------------------------------------------------------------------

def test_reentry_records_signed_verified_event(tmp_path):
    cr, run_dir, cfg, rid = _signed_shipped_run(tmp_path)
    # a second ship on the terminal SHIPPED authenticates it and runs nothing
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    events = [json.loads(l) for l in
              (run_dir / "ship_journal.jsonl").read_text().splitlines()]
    rv = [e for e in events if e.get("state") == "SHIP_REENTRY_VERIFIED"]
    assert len(rv) == 1 and rv[0]["data"]["anchored"] is True
    # no new action was dispatched on re-entry
    intents = [e for e in events if e.get("state") == "SHIP_ACTION_INTENT"]
    assert len(intents) == 1  # only the original ship's intent


def test_bundle_authenticates_ship_result_and_reentry(tmp_path):
    cr, run_dir, cfg, rid = _signed_shipped_run(tmp_path)
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0  # re-entry
    bundle, err = EB.assemble(str(cr), str(run_dir), require_production=True,
                              profile="hardened-h4")
    assert err is None
    assert bundle["ship_result"]["authenticated"] is True
    assert bundle["reentry"]["reentry_verified"]["verified"] is True


def test_tampered_ship_result_is_not_authenticated(tmp_path):
    cr, run_dir, cfg, rid = _signed_shipped_run(tmp_path)
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    p = run_dir / "ship_result.json"
    p.write_text(p.read_text().replace("SHIPPED", "SHIPPED "))  # 1-byte tamper
    bundle, _ = EB.assemble(str(cr), str(run_dir), require_production=True,
                            profile="hardened-h4")
    assert bundle["ship_result"]["authenticated"] is False
    # the anchored re-entry token binds the ORIGINAL bytes, so it no longer matches
    assert bundle["reentry"]["reentry_verified"]["verified"] is False


def test_no_reentry_means_no_reentry_verified(tmp_path):
    cr, run_dir, cfg, rid = _signed_shipped_run(tmp_path)  # shipped once, no re-entry
    bundle, _ = EB.assemble(str(cr), str(run_dir), require_production=True,
                            profile="hardened-h4")
    # the ship_result IS anchored, but there is no positive re-entry proof yet
    assert bundle["ship_result"]["authenticated"] is True
    assert bundle["reentry"]["reentry_verified"]["verified"] is False


def test_planted_reentry_event_without_anchor_is_not_verified(tmp_path):
    cr, run_dir, cfg, rid = _signed_shipped_run(tmp_path)
    # attacker journals a SHIP_REENTRY_VERIFIED with a made-up nonce (no anchor)
    text = (run_dir / "ship_result.json").read_text()
    import df_common
    sha = df_common.sha256_str(text)
    with open(run_dir / "ship_journal.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "t", "state": "SHIP_REENTRY_VERIFIED",
                            "data": {"ship_result_sha256": sha, "nonce": "forged",
                                     "anchored": True}}) + "\n")
    bundle, _ = EB.assemble(str(cr), str(run_dir), require_production=True,
                            profile="hardened-h4")
    assert bundle["reentry"]["reentry_verified"]["verified"] is False


# ---------------------------------------------------------------------------
# DF-R8-03 — exhaustive profile predicate + field-name fixes
# ---------------------------------------------------------------------------

def _full_bundle(profile):
    """A production bundle dict + manifest with EVERY required fact satisfied for
    `profile`. Each negative test mutates exactly one fact."""
    common = {
        "source": {"sealed_commit": "a" * 40, "sealed_clean": True, "matches_sealed": True},
        "audit_chain": {"verified": True}, "config_sha256": "c" * 64,
        "ship_result": {"outcome": "SHIPPED", "authenticated": True,
                        "actions": [{"name": "deploy", "status": "ok", "reversible": True}]},
        "reentry": {"no_duplicate_or_unknown_actions": True,
                    "reentry_verified": {"verified": True}},
        "release": {"present": False, "verified": None, "action_names": None},
        "custody": {"verified": True}, "denial_probe_passed": True,
        "enterprise_egress": {"probed": True, "passed": True},
        "enterprise_seccomp": {"profile": "df.json", "probe": "verified"},
        "builder_confinement": {"enabled": True, "probe": "unverified"},
        "ship_sink_receipt": {"present": True, "kind": "s3-objectlock",
                              "server_issued": True, "version_id": "v1", "verified": True},
        "custody_sink_receipt": {"present": True, "verified": True},
        "release_sink_receipt": {"present": True, "verified": True},
        "image": {"pinned": True, "resolved_image_digest": "sha256:" + "b" * 64,
                  "image": "r/x@sha256:" + "b" * 64},
    }
    digest = "sha256:" + "b" * 64
    manifest = {"container": {"resolved_image_digest": digest, "image_pinned": True,
                              "image": "r/x@sha256:" + "b" * 64},
                "enterprise_seccomp": {"profile": "df.json", "probe": "verified"}}
    if profile == "hardened-h4":
        common.update({"effective_tier": "hardened", "qualified": True})
        manifest["intervention_mode"] = "H4"
    else:
        common.update({"effective_tier": "enterprise", "qualified": True})
    return common, manifest


def _ready(profile, mutate=None):
    bundle, manifest = _full_bundle(profile)
    if mutate:
        mutate(bundle, manifest)
    return EB._production_verdict(bundle, {"manifest_verified": True}, manifest, profile)


def test_full_hardened_profile_is_ready():
    ready, unmet = _ready("hardened-h4")
    assert ready, unmet


def test_full_enterprise_profile_is_ready():
    ready, unmet = _ready("enterprise")
    assert ready, unmet


def test_hardened_mutable_image_tag_is_not_ready():
    def m(b, mf):
        b["image"] = {"pinned": False, "resolved_image_digest": "sha256:" + "b" * 64,
                      "image": "mutable:latest"}
        mf["container"] = {"resolved_image_digest": "sha256:" + "b" * 64,
                           "image_pinned": False, "image": "mutable:latest"}
    ready, unmet = _ready("hardened-h4", m)
    assert not ready and any("digest-pinned" in u for u in unmet)


def test_sha256_pinned_reference_passes_without_resolved_digest():
    # A cryptographically-pinned @sha256 image reference is sufficient on its own —
    # a docker outage that left resolved_image_digest None must not falsely fail it.
    def m(b, mf):
        b["image"] = {"pinned": False, "resolved_image_digest": None,
                      "image": "registry/x@sha256:" + "b" * 64}
        mf["container"] = {"resolved_image_digest": None, "image_pinned": False,
                           "image": "registry/x@sha256:" + "b" * 64}
    ready, unmet = _ready("hardened-h4", m)
    assert ready, unmet


def test_enterprise_missing_seccomp_is_not_ready():
    ready, unmet = _ready("enterprise", lambda b, mf: b.update({"enterprise_seccomp": None}))
    assert not ready and any("seccomp" in u for u in unmet)


def test_enterprise_missing_denial_probe_is_not_ready():
    ready, unmet = _ready("enterprise", lambda b, mf: b.update({"denial_probe_passed": False}))
    assert not ready and any("denial" in u for u in unmet)


def test_enterprise_missing_builder_confinement_is_not_ready():
    ready, unmet = _ready("enterprise",
                          lambda b, mf: b.update({"builder_confinement": {"enabled": False}}))
    assert not ready and any("confinement" in u for u in unmet)


def test_enterprise_missing_custody_receipt_is_not_ready():
    ready, unmet = _ready("enterprise",
                          lambda b, mf: b.update({"custody_sink_receipt": {"present": False}}))
    assert not ready and any("custody sink receipt" in u for u in unmet)


def test_release_scope_must_cover_irreversible_actions():
    def m(b, mf):
        b["ship_result"]["actions"] = [{"name": "deploy", "status": "ok", "reversible": False}]
        b["release"] = {"present": True, "verified": True, "action_names": ["other"]}
        b["release_sink_receipt"] = {"present": True, "verified": True}
    ready, unmet = _ready("enterprise", m)
    assert not ready and any("scope does not cover" in u for u in unmet)


def test_missing_reentry_verified_is_not_ready():
    ready, unmet = _ready("hardened-h4",
                          lambda b, mf: b.update({"reentry": {"no_duplicate_or_unknown_actions": True,
                                                              "reentry_verified": {"verified": False}}}))
    assert not ready and any("SHIP_REENTRY_VERIFIED" in u for u in unmet)


def test_unauthenticated_ship_result_is_not_ready():
    def m(b, mf):
        b["ship_result"]["authenticated"] = False
    ready, unmet = _ready("hardened-h4", m)
    assert not ready and any("not anchored in the signed audit chain" in u for u in unmet)
