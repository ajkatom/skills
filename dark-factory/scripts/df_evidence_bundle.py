"""M60 (Codex R5 arbitration §"Required evidence bundle"): assemble the
production-validation evidence bundle from a COMPLETED run.

Codex's arbitration (audit/10) splits acceptance into "code-complete" and
"production-validated release GO". The latter requires a representative live
hardened-H4 / enterprise exercise whose evidence is independently verifiable.
This module reads a finished control root + run dir and emits ONE JSON bundle
with exactly the fields the arbitration enumerates, pulled from the SEALED
artifacts (manifest, ship result, custody attestation, sink receipts, audit
chain) — never re-derived or re-run. It is a read-only reporter: it makes no
network calls and mutates nothing.

The bundle NEVER contains a credential value — it reports credential/env NAMES
and allowlists only (the same barrier the manifest itself keeps). A defensive
scrub pass drops any field whose key looks secret-bearing.

Run it AFTER a live exercise completes (see references/live-validation.md):

    supervisor.py evidence-bundle <control_root> --run-dir <run_dir> \\
        [--out bundle.json] [--key-path <audit_pub_or_priv_key>]

Exit 0 = a bundle was assembled (it may still show gaps the operator must read);
exit 2 = the run dir / manifest is missing or unreadable (nothing to report).
"""
import json
import os
import subprocess

import df_common


# Keys whose VALUES must never appear in the bundle (defense in depth; the
# source artifacts are already barrier-clean, this is a second gate).
_SECRET_KEY_HINTS = ("secret", "token", "password", "passwd", "privkey",
                     "private_key", "api_key", "apikey", "access_key",
                     "secret_key", "credential_value")


def _looks_secret(key):
    k = str(key).lower()
    return any(h in k for h in _SECRET_KEY_HINTS)


def _scrub(obj):
    """Recursively drop any mapping entry whose KEY looks secret-bearing,
    replacing its value with the marker '<omitted:secret-key>'. Lists/scalars
    pass through. This never inspects values (a value that merely looks like a
    token under a benign key is left — the source artifacts don't carry raw
    secret values, and guessing on values risks redacting real evidence like a
    sha256)."""
    if isinstance(obj, dict):
        return {k: ("<omitted:secret-key>" if _looks_secret(k) else _scrub(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    return obj


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f), None
    except FileNotFoundError:
        return None, "absent"
    except (OSError, json.JSONDecodeError) as e:
        return None, f"unreadable ({e})"


def _source_commit(control_root):
    """The exact git commit of the SKILL source (this repo), or None. Best
    effort — a bundle from a non-git checkout just records None."""
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        out = subprocess.run(["git", "-C", here, "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _ship_receipt(run_dir, basename):
    """Pull the server-issued off-box facts from a sink receipt sidecar (key +
    version_id + etag + body_sha256), never the whole receipt (which is already
    barrier-clean, but we report only the identity fields the auditor needs)."""
    obj, err = _read_json(os.path.join(run_dir, basename))
    if obj is None:
        return {"present": False, "reason": err}
    return {"present": True, "kind": obj.get("kind"),
            "sink_key": obj.get("sink_key"), "version_id": obj.get("version_id"),
            "etag": obj.get("etag"), "body_sha256": obj.get("body_sha256"),
            "server_issued": obj.get("server_issued")}


def _reentry_proof(run_dir):
    """Evidence that a re-entry did NOT duplicate a real action: the ship
    journal's SHIP_STARTED already_done set + any DISPATCH_RECONCILED /
    SHIP_EVIDENCE_RESIGNED / SHIP_TERMINAL_ANCHOR_RESOLVED markers. The operator
    runs `ship` twice in the live exercise; a duplicated action would show a
    second SHIP_ACTION_RESULT `ok` for the same idempotency_key, which this
    surfaces as `duplicate_completions`."""
    path = os.path.join(run_dir, "ship_journal.jsonl")
    if not os.path.exists(path):
        return {"ship_journal_present": False}
    ok_by_idk = {}
    markers = []
    started = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            state, d = e.get("state"), e.get("data", {})
            if state == "SHIP_STARTED":
                started.append(sorted(d.get("already_done") or []))
            elif state == "SHIP_ACTION_RESULT" and d.get("status") == "ok":
                ok_by_idk.setdefault(d.get("idempotency_key"), 0)
                ok_by_idk[d["idempotency_key"]] += 1
            elif state in ("DISPATCH_RECONCILED", "SHIP_EVIDENCE_RESIGNED",
                           "SHIP_TERMINAL_ANCHOR_RESOLVED", "SHIP_RECONCILED"):
                markers.append(state)
    duplicates = {k: n for k, n in ok_by_idk.items() if n > 1}
    return {"ship_journal_present": True,
            "ship_started_already_done": started,
            "recovery_markers": markers,
            "duplicate_completions": duplicates,
            "no_duplicate_actions": not duplicates}


def _verify_chain_output(control_root, key):
    """Run the same signed-chain verification `verify-chain` does, capturing the
    (ok, message) as evidence — not just a boolean."""
    import df_audit_chain
    chain_path = os.path.join(control_root, "audit-chain.jsonl")
    try:
        entries = df_audit_chain.read_chain(chain_path)
    except df_audit_chain.ChainError as e:
        return {"present": False, "reason": str(e)}
    signed = any("sig" in e for e in entries)
    if signed and key is None:
        return {"present": True, "signed": True, "verified": None,
                "message": "UNVERIFIED (signed chain; supply --key-path)"}
    ok, msg = df_audit_chain.verify_chain(chain_path, audit_key=key)
    return {"present": True, "signed": signed, "verified": bool(ok), "message": msg}


def assemble(control_root, run_dir, key=None):
    """Return (bundle_dict, error). error is a string only when the run is
    unreadable (no manifest); otherwise the bundle is returned with per-section
    presence flags so a partial live exercise still produces a readable report."""
    manifest, mf_err = _read_json(os.path.join(run_dir, "manifest.json"))
    if manifest is None:
        return None, f"manifest.json {mf_err} in {run_dir}"
    if not isinstance(manifest, dict):
        return None, f"manifest.json is not a JSON object in {run_dir}"

    container = manifest.get("container") or {}
    ship_result, _ = _read_json(os.path.join(run_dir, "ship_result.json"))
    custody, _ = _read_json(os.path.join(run_dir, "custody_attestation.json"))

    bundle = {
        "bundle_version": "1",
        "source_commit": _source_commit(control_root),
        "control_root": os.path.abspath(control_root),
        "run_dir": os.path.abspath(run_dir),
        # exact source + config identity
        "config_sha256": manifest.get("config_sha256"),
        "spec_sha256": manifest.get("spec_sha256"),
        "scenario_set_sha256": manifest.get("scenario_set_sha256"),
        # tiers (DF-R5-04)
        "requested_tier": manifest.get("requested_tier", manifest.get("tier")),
        "effective_tier": manifest.get("effective_tier", manifest.get("tier")),
        "qualified": manifest.get("qualified"),
        "outcome": manifest.get("outcome"),
        # image identity across the whole run (DF-R5-09)
        "image": {"pinned": container.get("image_pinned"),
                  "resolved_image_digest": container.get("resolved_image_digest"),
                  "image": container.get("image")},
        # isolation / confinement / seccomp / egress probes
        "host_isolation": manifest.get("host_isolation"),
        "denial_probe_passed": manifest.get("denial_probe_passed"),
        "sandbox_backend": manifest.get("sandbox_backend"),
        "builder_confinement": manifest.get("builder_confinement"),
        "seccomp": manifest.get("seccomp"),
        "enterprise_egress": manifest.get("enterprise_egress"),
        # adapter + support-file identity (DF-R5-03)
        "adapter_sha256": manifest.get("adapter_sha256"),
        "builder_identity": manifest.get("builder_identity"),
        # sealed manifest + artifact identity. M60 opus review 2c: hash the RAW
        # on-disk bytes — the value an auditor compares against the sealed
        # manifest.sha256 sidecar / chain-anchored digest. A re-serialization
        # (ensure_ascii differences) silently diverges on any non-ASCII byte.
        "manifest_sha256": df_common.sha256_file(os.path.join(run_dir, "manifest.json")),
        "artifact_object_id": manifest.get("artifact_object_id")
            or (ship_result or {}).get("ship_workspace_object_id"),
        # signed chain verification
        "audit_chain": _verify_chain_output(control_root, key),
        # custody (enterprise)
        "custody": {
            "manifest_field": manifest.get("custody"),
            "attestation_present": custody is not None,
            "threshold": (custody or {}).get("threshold"),
            "approver_count": len((custody or {}).get("signatures") or [])
                if custody else None,
        },
        # off-box sink receipts — key + version + bytes hash (DF-R5-07)
        "ship_sink_receipt": _ship_receipt(run_dir, "ship_sink_receipt.json"),
        "qualification_sink_receipt": _ship_receipt(run_dir, "qualification_sink_receipt.json"),
        "release_sink_receipt": _ship_receipt(run_dir, "release_sink_receipt.json"),
        # ship + release results
        "ship_result": {
            "present": ship_result is not None,
            "outcome": (ship_result or {}).get("outcome"),
            "actions": [{"name": a.get("name"), "status": a.get("status"),
                         "reversible": a.get("reversible")}
                        for a in (ship_result or {}).get("actions", [])],
        },
        # re-entry idempotency proof (no duplicated real actions)
        "reentry": _reentry_proof(run_dir),
    }
    # Second-gate scrub: never emit a secret-bearing value.
    return _scrub(bundle), None
