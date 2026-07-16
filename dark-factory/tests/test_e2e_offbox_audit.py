"""M13 Task 3 e2e: hash-chained audit log + off-box sink, end to end. Driven
as real supervisor CLI subprocess calls (mirroring test_e2e_budget.py /
test_e2e_security.py's `_run`/`_journal` conventions).

  (a) two sequential runs in one control root -> `audit-chain.jsonl` gets two
      LINKED entries (genesis -> hash1 -> hash2); `verify-chain <control_root>`
      exits 0 "OK: 2 entries". Corrupting one entry's `manifest_sha256` makes
      `verify-chain` exit 1, naming the break.
  (b) `audit.signing: true` -> every chain entry carries a `sig`;
      `verify-chain --key-path <key>` exits 0; WITHOUT the key it refuses
      (fail-closed, mirroring verify-manifest's UNVERIFIED semantics) rather
      than silently reporting OK.
  (c) an `http-append` sink (the reference receiver, in-process on an
      ephemeral port): a run pushes its chain entry; `audit_sink_receipt.json`
      lands in run_dir; `audit_events.jsonl` has AUDIT_SINK_OK; the receiver
      actually holds the entry (GET returns the exact pushed bytes).
  (d) `required: true` against a closed port -> fail-closed: nonzero exit,
      AUDIT_SINK_FAILED in `audit_events.jsonl`, no `audit_sink_receipt.json`
      -- but `audit_chain.json` IS still there (the local chain is written
      before the sink is ever pushed to). `required: false` against the same
      closed port -> the run still converges normally, AUDIT_SINK_WARN.

Throughout: audit-anchor events (AUDIT_CHAINED / AUDIT_SINK_*) live in
`audit_events.jsonl`, NEVER in the finalize-sealed journal.jsonl -- these
tests assert both that the events land in the event log AND that nothing
AUDIT_* touched journal.jsonl (so verify-manifest's whole-file journal seal
stays valid).
"""
import json
import os
import socket
import subprocess
import sys

import df_audit_chain
import df_audit_receiver
from test_supervisor import FAKE, setup_control

SUP = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "supervisor.py"
)


def _run(cr, *args, timeout=60):
    return subprocess.run(
        [sys.executable, SUP, *args, "--control-root", str(cr)],
        capture_output=True, text=True, timeout=timeout,
    )


def _verify_chain(cr, key_path=None, timeout=30):
    argv = [sys.executable, SUP, "verify-chain", str(cr)]
    if key_path:
        argv += ["--key-path", str(key_path)]
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def _set_audit(cr, audit):
    cfg_path = cr / "config.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg["audit"] = audit
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")


def _journal(run_dir):
    lines = (run_dir / "journal.jsonl").read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(l) for l in lines]


def _audit_events(run_dir):
    """The audit-anchor event log (AUDIT_CHAINED / AUDIT_SINK_*). These live
    in their OWN unhashed `audit_events.jsonl`, NEVER in journal.jsonl --
    journal.jsonl is sealed by finalize_manifest and its whole-file hash must
    stay valid (verify-manifest), so nothing may append to it afterward."""
    path = run_dir / "audit_events.jsonl"
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(l) for l in lines if l.strip()]


def _closed_port() -> int:
    """A port nothing is listening on -- guaranteed ECONNREFUSED (see
    test_audit_sink.py's identical helper)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _chain_entries(cr):
    path = cr / "audit-chain.jsonl"
    return [json.loads(l) for l in path.read_text(encoding="utf-8").strip().splitlines()]


# ---------------------------------------------------------------------------
# (a) two sequential runs -> linked chain, verify-chain, tamper detection
# ---------------------------------------------------------------------------

def test_two_sequential_runs_chain_linked_and_verify_chain_detects_tamper(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")

    p1 = _run(cr, "run")
    assert p1.returncode == 0, p1.stderr
    p2 = _run(cr, "run")
    assert p2.returncode == 0, p2.stderr

    entries = _chain_entries(cr)
    assert len(entries) == 2
    assert entries[0]["prev_chain_hash"] == df_audit_chain.GENESIS
    assert entries[1]["prev_chain_hash"] == entries[0]["chain_hash"]
    assert entries[0]["invocation"] != entries[1]["invocation"]
    assert "sig" not in entries[0] and "sig" not in entries[1]  # unsigned by default

    # every run_dir carries its own audit_chain.json sidecar, and it's NOT a
    # manifest field (binding-circularity: the entry binds the manifest's
    # own digest, so it can't live inside that manifest). Match run_dir <->
    # chain entry by invocation, NOT directory-listing/append order -- two
    # fast sequential runs can share the same second-resolution timestamp
    # prefix, so a lexicographic dir sort isn't guaranteed to match chain
    # (chronological append) order.
    run_ids = os.listdir(cr / "runs")
    assert len(run_ids) == 2
    entries_by_invocation = {e["invocation"]: e for e in entries}
    assert set(run_ids) == set(entries_by_invocation)
    for run_id in run_ids:
        run_dir = cr / "runs" / run_id
        entry = entries_by_invocation[run_id]
        sidecar = json.loads((run_dir / "audit_chain.json").read_text(encoding="utf-8"))
        assert sidecar == entry
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        assert "audit_chain" not in manifest and "audit_sink" not in manifest
        # audit-anchor events live in audit_events.jsonl, NOT journal.jsonl
        # (which finalize_manifest already sealed). journal.jsonl must not
        # carry any AUDIT_* line -- that would break its whole-file hash.
        assert "AUDIT_CHAINED" not in [e["state"] for e in _journal(run_dir)]
        ev = _audit_events(run_dir)
        chained = next(e for e in ev if e["state"] == "AUDIT_CHAINED")
        assert chained["data"]["chain_hash"] == entry["chain_hash"]
        assert chained["data"]["prev"] == entry["prev_chain_hash"]
        # the journal seal is intact AFTER anchoring -- verify-manifest still
        # OK (whole-file journal hash, unweakened by M13).
        vm = subprocess.run(
            [sys.executable, SUP, "verify-manifest", "--run-dir", str(run_dir)],
            capture_output=True, text=True, timeout=30,
        )
        assert vm.returncode == 0, vm.stdout + vm.stderr
        assert vm.stdout.strip() == "OK"

    ok = _verify_chain(cr)
    assert ok.returncode == 0, ok.stderr
    assert ok.stdout.strip() == "OK: 2 entries"

    # corrupt the FIRST entry's manifest_sha256 (rewrite the ndjson file by hand)
    chain_path = cr / "audit-chain.jsonl"
    lines = chain_path.read_text(encoding="utf-8").strip().splitlines()
    corrupted = json.loads(lines[0])
    corrupted["manifest_sha256"] = "f" * 64
    lines[0] = json.dumps(corrupted)
    chain_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    bad = _verify_chain(cr)
    assert bad.returncode == 1
    assert not bad.stdout.strip().startswith("OK")
    assert entries[0]["invocation"] in bad.stdout or "tampered" in bad.stdout.lower()


# ---------------------------------------------------------------------------
# (a') journal seal is NOT weakened by the audit feature -- the exact attacks
#      a prefix+trailing-allowlist scheme would have let through are caught,
#      because journal.jsonl is hashed WHOLE and nothing appends to it after
#      finalize.
# ---------------------------------------------------------------------------

def _run_dir_of(cr):
    return cr / "runs" / os.listdir(cr / "runs")[0]


def test_journal_seal_is_whole_file_and_unweakened_by_audit(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    p = _run(cr, "run")
    assert p.returncode == 0, p.stderr
    run_dir = _run_dir_of(cr)

    # baseline: an honest run verifies, and NOTHING was appended to journal
    # after finalize (no AUDIT_* lines, no manifest journal_bytes field).
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert "journal_bytes" not in manifest
    assert not any(e["state"].startswith("AUDIT_") for e in _journal(run_dir))

    def _verify():
        return subprocess.run(
            [sys.executable, SUP, "verify-manifest", "--run-dir", str(run_dir)],
            capture_output=True, text=True, timeout=30,
        )

    assert _verify().stdout.strip() == "OK"

    jp = run_dir / "journal.jsonl"
    original = jp.read_text(encoding="utf-8")

    # Attack 1: append a forged line that WEARS an allowlisted state but
    # carries an attacker payload. A whole-file hash catches ANY append.
    jp.write_text(
        original + json.dumps({"ts": "later", "state": "AUDIT_CHAINED",
                               "data": {"forged": "smuggled payload"}}) + "\n",
        encoding="utf-8",
    )
    r = _verify()
    assert r.returncode == 4 and "TAMPERED" in r.stdout

    # Attack 2: truncate the journal (e.g. drop trailing lines). A whole-file
    # hash of a shorter file no longer matches journal_sha256.
    truncated = "\n".join(original.strip().splitlines()[:-1]) + "\n"
    jp.write_text(truncated, encoding="utf-8")
    r = _verify()
    assert r.returncode == 4 and "TAMPERED" in r.stdout

    # restore -> OK again (proves the two failures were the edits, not a flake)
    jp.write_text(original, encoding="utf-8")
    assert _verify().stdout.strip() == "OK"


# ---------------------------------------------------------------------------
# (b) signed chain: sig present, verify-chain --key-path OK, no key refuses
# ---------------------------------------------------------------------------

def test_signed_chain_verifies_with_key_and_refuses_without(tmp_path):
    kp = tmp_path / "keys" / "audit.key"
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _set_audit(cr, {"signing": True, "key_path": str(kp)})

    p = _run(cr, "run")
    assert p.returncode == 0, p.stderr

    entries = _chain_entries(cr)
    assert len(entries) == 1
    assert "sig" in entries[0] and entries[0]["sig"]

    ok = _verify_chain(cr, key_path=kp)
    assert ok.returncode == 0, ok.stderr
    assert ok.stdout.strip() == "OK: 1 entries"

    # fail-closed: a signed chain verified WITHOUT the key must never read OK
    # (mirrors verify-manifest's UNVERIFIED-without-key semantics).
    no_key = _verify_chain(cr)
    assert no_key.returncode == 1
    assert "UNVERIFIED" in no_key.stdout
    assert "--key-path" in no_key.stdout

    # wrong key -> TAMPERED-style failure, not OK
    wrong_kp = tmp_path / "keys" / "wrong.key"
    import df_audit
    df_audit.load_or_create_key(str(wrong_kp))
    wrong = _verify_chain(cr, key_path=wrong_kp)
    assert wrong.returncode == 1
    assert "OK: 1 entries" not in wrong.stdout


# ---------------------------------------------------------------------------
# (c) http-append sink: receipt sidecar, AUDIT_SINK_OK, receiver holds entry
# ---------------------------------------------------------------------------

def test_http_append_sink_pushes_entry_and_receiver_holds_it(tmp_path):
    store_dir = tmp_path / "sink-store"
    httpd, port = df_audit_receiver.serve(str(store_dir), port=0)
    try:
        cr = setup_control(tmp_path, FAKE, checkpoint="auto")
        _set_audit(cr, {"sink": {"kind": "http-append", "url": f"http://127.0.0.1:{port}"}})

        p = _run(cr, "run")
        assert p.returncode == 0, p.stderr

        run_id = os.listdir(cr / "runs")[0]
        run_dir = cr / "runs" / run_id
        receipt_path = run_dir / "audit_sink_receipt.json"
        assert receipt_path.exists()
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        assert receipt["kind"] == "http-append"

        ev = _audit_events(run_dir)
        ok_entry = next(e for e in ev if e["state"] == "AUDIT_SINK_OK")
        assert ok_entry["data"]["kind"] == "http-append"
        assert "AUDIT_SINK_FAILED" not in [e["state"] for e in ev]
        assert "AUDIT_SINK_WARN" not in [e["state"] for e in ev]
        # and none of it leaked into the sealed journal
        assert not any(e["state"].startswith("AUDIT_") for e in _journal(run_dir))

        entry = _chain_entries(cr)[0]
        import urllib.request
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/audit/{entry['invocation']}", timeout=5
        ) as resp:
            stored = resp.read()
        assert json.loads(stored) == entry

        assert (run_dir / "audit_chain.json").exists()
    finally:
        httpd.shutdown()
        httpd.server_close()


# ---------------------------------------------------------------------------
# (d) required-sink fail-closed vs. required:false best-effort
# ---------------------------------------------------------------------------

def test_required_sink_failure_is_fail_closed(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _set_audit(cr, {"sink": {
        "kind": "http-append",
        "url": f"http://127.0.0.1:{_closed_port()}",
        "required": True,
    }})

    p = _run(cr, "run")
    assert p.returncode != 0
    assert p.returncode == 3  # _anchor_audit's fail-closed 3, not the normal converge 0

    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    assert not (run_dir / "audit_sink_receipt.json").exists()
    assert (run_dir / "audit_chain.json").exists()  # local chain still written

    states = [e["state"] for e in _audit_events(run_dir)]
    assert "AUDIT_SINK_FAILED" in states
    assert "AUDIT_SINK_WARN" not in states
    assert "AUDIT_CHAINED" in states
    assert not any(e["state"].startswith("AUDIT_") for e in _journal(run_dir))

    # the terminal manifest itself is untouched by the sink failure -- the
    # run genuinely converged; only the process exit + event log reflect it.
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] == "COMPLETE_UNQUALIFIED"
    assert "audit_sink" not in manifest
    # and the sealed journal still verifies -- the fail-closed run did not
    # corrupt the manifest's whole-file journal hash.
    vm = subprocess.run(
        [sys.executable, SUP, "verify-manifest", "--run-dir", str(run_dir)],
        capture_output=True, text=True, timeout=30,
    )
    assert vm.returncode == 0 and vm.stdout.strip() == "OK"


def test_non_required_sink_failure_warns_and_converges(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _set_audit(cr, {"sink": {
        "kind": "http-append",
        "url": f"http://127.0.0.1:{_closed_port()}",
        "required": False,
    }})

    p = _run(cr, "run")
    assert p.returncode == 0, p.stderr  # converges normally despite the sink failure

    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    assert not (run_dir / "audit_sink_receipt.json").exists()
    assert (run_dir / "audit_chain.json").exists()

    states = [e["state"] for e in _audit_events(run_dir)]
    assert "AUDIT_SINK_WARN" in states
    assert "AUDIT_SINK_FAILED" not in states
    assert not any(e["state"].startswith("AUDIT_") for e in _journal(run_dir))
