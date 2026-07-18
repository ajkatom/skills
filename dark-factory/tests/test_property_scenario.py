"""M43a Task 3: `when.property` — validation + execution + THE BARRIER.

Execution runs against deterministic stub CLIs written into a tmp workspace
(no real infra). The barrier tests are the load-bearing ones: a property
failure's counterexample (the generated input) exists ONLY in the runner's
control-plane result dict; the projected feedback carries behavior-id +
"property_violated" and nothing else, and the runner writes NOTHING into the
workspace.
"""
import copy
import json
import os

import pytest

import df_gates
import df_generate
import id_feedback
import run_scenarios


def prop_scenario(**kw):
    sc = {
        "ir_version": "0.4",
        "id": "BHV-KV-P1",
        "behavior_id": "BHV-KV",
        "title": "round trip over generated pairs",
        "given": "a kv.py exists",
        "class": "boundary",
        "when": {"property": {
            "generate": {
                "vars": {
                    "k": {"kind": "string", "charset": "alnum", "min_len": 1, "max_len": 8},
                    "v": {"kind": "string", "charset": "alnum", "min_len": 6, "max_len": 12},
                },
                "cases": 5,
                "seed": 7,
            },
            "steps": [
                {"run": ["python3", "kv.py", "put", "{k}", "{v}"]},
                {"run": ["python3", "kv.py", "get", "{k}"]},
            ],
            "timeout_s": 10,
        }},
        "then": {"invariant": {"name": "round_trip",
                               "args": {"value": "v", "observe_step": 1}}},
    }
    sc.update(kw)
    return sc


GOOD_KV = """\
import json, os, sys
STORE = "store.json"
def load():
    return json.load(open(STORE)) if os.path.exists(STORE) else {}
cmd = sys.argv[1]
if cmd == "put":
    d = load(); d[sys.argv[2]] = sys.argv[3]
    json.dump(d, open(STORE, "w")); print("ok")
elif cmd == "get":
    d = load()
    if sys.argv[2] in d: print(d[sys.argv[2]])
    else: print("missing", file=sys.stderr); sys.exit(1)
"""

# BUG: silently truncates stored values -- exactly the class of defect a fixed
# example misses (a short fixed value round-trips fine) and a generated one
# catches.
BUGGY_KV = GOOD_KV.replace("d[sys.argv[2]] = sys.argv[3]",
                           "d[sys.argv[2]] = sys.argv[3][:5]")


def make_ws(tmp_path, body, name="kv.py"):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    (ws / name).write_text(body, encoding="utf-8")
    return ws


# --- validation -------------------------------------------------------------

def write_and_load(tmp_path, sc):
    d = tmp_path / "scen"
    d.mkdir(exist_ok=True)
    (d / "p.json").write_text(json.dumps(sc), encoding="utf-8")
    return run_scenarios.load_scenarios(str(d))


def test_valid_property_scenario_loads(tmp_path):
    scs = write_and_load(tmp_path, prop_scenario())
    assert scs[0]["id"] == "BHV-KV-P1"


def test_property_plus_run_rejected(tmp_path):
    sc = prop_scenario()
    sc["when"]["run"] = ["python3", "kv.py"]
    with pytest.raises(run_scenarios.OracleError, match="EXACTLY ONE"):
        write_and_load(tmp_path, sc)


def test_property_then_with_cli_key_rejected(tmp_path):
    sc = prop_scenario()
    sc["then"]["exit_code"] = 0
    with pytest.raises(run_scenarios.OracleError, match="invariant"):
        write_and_load(tmp_path, sc)


def test_property_then_without_invariant_rejected(tmp_path):
    sc = prop_scenario(then={"exit_code": 0})
    with pytest.raises(run_scenarios.OracleError, match="invariant"):
        write_and_load(tmp_path, sc)


def test_undeclared_placeholder_rejected(tmp_path):
    sc = prop_scenario()
    sc["when"]["property"]["steps"][0]["run"].append("{typo}")
    with pytest.raises(run_scenarios.OracleError, match="typo"):
        write_and_load(tmp_path, sc)


def test_json_braces_are_not_placeholders(tmp_path):
    # A literal JSON body brace ({"value": ...}) must NOT be parsed as a
    # placeholder -- only identifier-shaped {name} is.
    sc = prop_scenario()
    sc["when"]["property"]["steps"][0]["run"].append('{"value": "{v}"}')
    write_and_load(tmp_path, sc)  # must not raise


def test_cases_over_ceiling_rejected(tmp_path):
    sc = prop_scenario()
    sc["when"]["property"]["generate"]["cases"] = df_generate.MAX_CASES + 1
    with pytest.raises(run_scenarios.OracleError, match="cases"):
        write_and_load(tmp_path, sc)


def test_missing_seed_rejected(tmp_path):
    sc = prop_scenario()
    del sc["when"]["property"]["generate"]["seed"]
    with pytest.raises(run_scenarios.OracleError, match="seed"):
        write_and_load(tmp_path, sc)


def test_unknown_invariant_rejected(tmp_path):
    sc = prop_scenario()
    sc["then"]["invariant"]["name"] = "always_good"
    with pytest.raises(run_scenarios.OracleError, match="invariant.name"):
        write_and_load(tmp_path, sc)


def test_observe_step_out_of_range_rejected(tmp_path):
    sc = prop_scenario()
    sc["then"]["invariant"]["args"]["observe_step"] = 9
    with pytest.raises(run_scenarios.OracleError, match="observe_step"):
        write_and_load(tmp_path, sc)


def test_empty_steps_rejected(tmp_path):
    sc = prop_scenario()
    sc["when"]["property"]["steps"] = []
    with pytest.raises(run_scenarios.OracleError, match="steps"):
        write_and_load(tmp_path, sc)


def test_bad_timeout_rejected(tmp_path):
    sc = prop_scenario()
    sc["when"]["property"]["steps"] = [{"run": ["python3", "kv.py", "get", "{k}"]}]
    sc["when"]["property"]["timeout_s"] = 0
    with pytest.raises(run_scenarios.OracleError, match="timeout_s"):
        write_and_load(tmp_path, sc)


def test_existing_run_scenario_unaffected(tmp_path):
    """Back-compat: an ordinary when.run scenario still validates + runs
    through the same load path with a property scenario present beside it."""
    d = tmp_path / "scen"
    d.mkdir()
    run_sc = {
        "ir_version": "0.1", "id": "BHV-KV-S1", "behavior_id": "BHV-KV",
        "title": "", "given": "",
        "when": {"run": ["python3", "-c", "print('ok')"], "timeout_s": 10},
        "then": {"exit_code": 0, "stdout_equals": "ok"},
    }
    (d / "a.json").write_text(json.dumps(run_sc), encoding="utf-8")
    (d / "b.json").write_text(json.dumps(prop_scenario()), encoding="utf-8")
    scs = run_scenarios.load_scenarios(str(d))
    assert [s["id"] for s in scs] == ["BHV-KV-S1", "BHV-KV-P1"]


# --- execution: round_trip --------------------------------------------------

def test_round_trip_passes_on_correct_stub(tmp_path):
    ws = make_ws(tmp_path, GOOD_KV)
    res = run_scenarios.run_scenario(prop_scenario(), str(ws))
    assert res["pass"] and res["taxonomy"] is None
    pinfo = res["observed"]["property"]
    assert pinfo["counterexample"] is None
    assert pinfo["cases"] == pinfo["cases_run"] == 5
    assert pinfo["seed"] == 7 and pinfo["invariant"] == "round_trip"


def test_round_trip_fails_on_buggy_stub_with_counterexample(tmp_path):
    ws = make_ws(tmp_path, BUGGY_KV)
    res = run_scenarios.run_scenario(prop_scenario(), str(ws))
    assert not res["pass"]
    assert res["taxonomy"] == "property_violated"
    cx = res["observed"]["property"]["counterexample"]
    assert cx is not None
    # The counterexample is complete enough to replay: case index + the
    # generated vars + the per-step observations (control-plane audit data).
    assert set(cx["vars"]) == {"k", "v"}
    assert len(cx["vars"]["v"]) >= 6  # min_len guarantees the bug fires
    assert cx["observations"]


def test_property_run_is_deterministic(tmp_path):
    ws = make_ws(tmp_path, BUGGY_KV)
    a = run_scenarios.run_scenario(prop_scenario(), str(ws))
    (ws / "store.json").unlink()  # reset candidate state between runs
    b = run_scenarios.run_scenario(prop_scenario(), str(ws))
    ca, cb = (r["observed"]["property"]["counterexample"] for r in (a, b))
    assert ca["case_index"] == cb["case_index"]
    assert ca["vars"] == cb["vars"]


# --- execution: robust fuzz -------------------------------------------------

FRAGILE = """\
import sys
v = sys.argv[1]
if not v.isalnum():
    raise ValueError("cannot handle %r" % v)   # traceback => robustness bug
print("stored", v)
"""

HARDENED = """\
import sys
v = sys.argv[1]
if not v.isalnum():
    print("error: rejected input", file=sys.stderr)
    sys.exit(2)
print("stored", v)
"""


def fuzz_scenario():
    return {
        "ir_version": "0.4",
        "id": "BHV-IN-P1",
        "behavior_id": "BHV-IN",
        "title": "never crashes on generated input",
        "given": "",
        "class": "failure",
        "when": {"property": {
            "generate": {
                "vars": {"x": {"kind": "string", "charset": "ascii_printable",
                               "min_len": 8, "max_len": 16}},
                "cases": 20,
                "seed": 99,
            },
            "steps": [{"run": ["python3", "app.py", "{x}"]}],
            "timeout_s": 10,
        }},
        "then": {"invariant": {"name": "robust"}},
    }


def test_fuzz_flags_fragile_stub_and_passes_hardened(tmp_path):
    # Guard: the fixed seed must generate at least one non-alnum input, or
    # the fixture proves nothing (deterministic, so this can never flake).
    cases = df_generate.generate_cases(fuzz_scenario()["when"]["property"]["generate"])
    assert any(not c["x"].isalnum() for c in cases)

    ws = make_ws(tmp_path, FRAGILE, name="app.py")
    res = run_scenarios.run_scenario(fuzz_scenario(), str(ws))
    assert res["taxonomy"] == "property_violated"
    assert "stack trace" in res["observed"]["property"]["counterexample"]["detail"]

    ws2 = tmp_path / "ws2"
    ws2.mkdir()
    (ws2 / "app.py").write_text(HARDENED, encoding="utf-8")
    res2 = run_scenarios.run_scenario(fuzz_scenario(), str(ws2))
    assert res2["pass"], res2


def test_error_contract_over_malformed_inputs(tmp_path):
    sc = fuzz_scenario()
    sc["when"]["property"]["generate"]["vars"]["bad"] = {"kind": "malformed", "base": "x"}
    sc["when"]["property"]["steps"] = [{"run": ["python3", "app.py", "{bad}"]}]
    sc["then"] = {"invariant": {"name": "error_contract"}}

    # A stub that silently accepts everything violates the error contract.
    accepting = make_ws(tmp_path, "import sys\nprint('ok')\n", name="app.py")
    res = run_scenarios.run_scenario(sc, str(accepting))
    assert res["taxonomy"] == "property_violated"
    assert "silently accepted" in res["observed"]["property"]["counterexample"]["detail"]

    # A stub that always rejects cleanly honors it.
    rejecting = tmp_path / "wsr"
    rejecting.mkdir()
    (rejecting / "app.py").write_text(
        "import sys\nprint('error: bad', file=sys.stderr)\nsys.exit(2)\n",
        encoding="utf-8")
    res2 = run_scenarios.run_scenario(sc, str(rejecting))
    assert res2["pass"], res2


# --- execution: repeats (idempotent) ---------------------------------------

def test_idempotent_runner_executes_terminal_step_twice(tmp_path):
    # A counter that INCREMENTS on read is not idempotent; one that SETS is.
    counting = """\
import os, sys
n = int(open("n.txt").read()) if os.path.exists("n.txt") else 0
n += 1
open("n.txt", "w").write(str(n))
print(n)
"""
    sc = {
        "ir_version": "0.4", "id": "BHV-ID-P1", "behavior_id": "BHV-ID",
        "title": "", "given": "",
        "when": {"property": {
            "generate": {"vars": {"k": {"kind": "int", "min": 0, "max": 9}},
                         "cases": 2, "seed": 3},
            "steps": [{"run": ["python3", "app.py", "{k}"]}],
            "timeout_s": 10,
        }},
        "then": {"invariant": {"name": "idempotent"}},
    }
    ws = make_ws(tmp_path, counting, name="app.py")
    res = run_scenarios.run_scenario(sc, str(ws))
    assert res["taxonomy"] == "property_violated"

    setting = "import sys\nopen('n.txt', 'w').write(sys.argv[1])\nprint(sys.argv[1])\n"
    ws2 = tmp_path / "ws2"
    ws2.mkdir()
    (ws2 / "app.py").write_text(setting, encoding="utf-8")
    res2 = run_scenarios.run_scenario(sc, str(ws2))
    assert res2["pass"], res2


# --- bounds -----------------------------------------------------------------

def test_hanging_step_is_bounded_by_per_case_timeout(tmp_path):
    sc = fuzz_scenario()
    sc["when"]["property"]["timeout_s"] = 0.5
    sc["when"]["property"]["generate"]["cases"] = 3
    ws = make_ws(tmp_path, "import time\ntime.sleep(60)\n", name="app.py")
    import time as _t
    t0 = _t.time()
    res = run_scenarios.run_scenario(sc, str(ws))
    elapsed = _t.time() - t0
    assert res["taxonomy"] == "timeout"
    # Bounded: the FIRST hanging case aborts the scenario -- nowhere near
    # 3 x 60s of candidate sleep.
    assert elapsed < 30
    cx = res["observed"]["property"]["counterexample"]
    assert cx["case_index"] == 0 and "timeout" in cx["detail"]


def test_missing_program_is_crash(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    sc = fuzz_scenario()
    sc["when"]["property"]["steps"] = [{"run": ["./no-such-binary", "{x}"]}]
    res = run_scenarios.run_scenario(sc, str(ws))
    assert res["taxonomy"] == "crash"


# --- Finding 1 regression: hostile http header value never crashes the runner


HERE = os.path.dirname(os.path.abspath(__file__))
HTTP_FIXTURE = os.path.join(HERE, "fixtures", "http_oracle_fixture_server")


def _http_crlf_scenario():
    """A property HTTP scenario whose templated Authorization header carries a
    CRLF (header-injection shape) -- exactly what a bytes-charset /
    malformed:control_chars generator can substitute. A `choice` with a
    literal CRLF option makes the trigger DETERMINISTIC for the regression
    (the fuzz generators produce the same class of value, non-deterministically
    per seed). http.client raises a BARE ValueError on such a header; before
    the fix that propagated through run_all and aborted the whole verify pass
    (embedding the value in the traceback)."""
    crlf = "Bearer a\r\nInjected: 1"
    return {
        "ir_version": "0.4", "id": "BHV-HDR-P1", "behavior_id": "BHV-HDR",
        "title": "hostile header never crashes the runner", "given": "",
        "class": "failure",
        "when": {"property": {
            "generate": {"vars": {"h": {"kind": "choice", "options": [crlf]}},
                         "cases": 3, "seed": 1},
            "steps": [{"http": {
                "start": ["python3", "svc.py"],
                "port_env": "PORT",
                "ready_path": "/health",
                "request": {"method": "GET", "path": "/health",
                            "headers": {"Authorization": "{h}"}},
            }}],
            "timeout_s": 10,
        }},
        "then": {"invariant": {"name": "robust"}},
    }, crlf


def _http_fixture_ws(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "svc.py").write_text(
        open(HTTP_FIXTURE, encoding="utf-8").read(), encoding="utf-8")
    return ws


def test_http_hostile_header_is_crash_not_unhandled_exception(tmp_path):
    sc, crlf = _http_crlf_scenario()
    ws = _http_fixture_ws(tmp_path)
    # The whole point: run_scenario RETURNS (does not raise) even though
    # http.client would raise ValueError on the CRLF header. The service is
    # reachable (ready probe on /health succeeds), so the ValueError fires on
    # the REQUEST path -> caught -> http_status stays None -> the step "did
    # not complete" -> a clean, bounded verdict, never an unhandled traceback.
    res = run_scenarios.run_scenario(sc, str(ws))
    # A clean, bounded verdict: the ValueError on the CRLF header becomes a
    # connection-level failure -> http_status None -> the step "did not
    # complete" -> taxonomy "crash" (the existing honest mapping), with the
    # offending case recorded. Crucially: run_scenario RETURNED -- no
    # unhandled traceback embedding the generated value.
    assert res["taxonomy"] == "crash"
    cx = res["observed"]["property"]["counterexample"]
    assert cx["case_index"] == 0 and "crash" in cx["detail"]


def test_http_hostile_header_does_not_abort_run_all(tmp_path):
    """run_all is the real blast radius: an unhandled ValueError here would
    abort the entire verify pass (supervisor only guards OracleError). Prove a
    full run_all over the hostile-header scenario completes and returns a
    normal report -- no exception escapes, so the generated value cannot reach
    a caller via a traceback."""
    sc, crlf = _http_crlf_scenario()
    ws = _http_fixture_ws(tmp_path)
    d = tmp_path / "scen"
    d.mkdir()
    (d / "p.json").write_text(json.dumps(sc), encoding="utf-8")
    report = run_scenarios.run_all(str(d), str(ws))  # must NOT raise
    assert report["count"] == 1
    assert report["results"][0]["taxonomy"] == "crash"
    # The generated CRLF value is nowhere in the value-free feedback.
    fb = id_feedback.project_feedback(report)
    assert crlf not in json.dumps(fb)


# --- THE BARRIER ------------------------------------------------------------

def test_counterexample_never_reaches_feedback_or_workspace(tmp_path):
    """The load-bearing M43a barrier proof at the unit level, stated HONESTLY
    (the e2e variant lives in test_e2e_property.py). After a property
    violation:
      1. the projected feedback carries ONLY behavior-id + 'property_violated'
         (and passes the structural leak validator) -- no generated value, no
         counterexample detail;
      2. the HIGH-VALUE secret -- the counterexample detail and the
         invariant/args config -- appears in NO workspace byte;
      3. the runner wrote nothing to the workspace: every file it did not
         hand the candidate is byte-identical, and the ONLY new file is the
         candidate's OWN state (store.json);
      4. HONEST BOUNDARY (asserted, not allowlisted): the candidate's own
         state legitimately DOES retain the generated INPUT -- store.json
         contains the generated value -- because a step's side effect
         persists its input exactly as a fixed input would. That is safe: a
         property invariant is generic, so a leaked input is not gameable, and
         it is NOT the runner leaking a secret."""
    ws = make_ws(tmp_path, BUGGY_KV)
    before = {p: (ws / p).read_bytes() for p in os.listdir(ws)}

    res = run_scenarios.run_scenario(prop_scenario(), str(ws))
    assert res["taxonomy"] == "property_violated"
    cx = res["observed"]["property"]["counterexample"]

    # (1) feedback is impoverished + value-free.
    report = {"report_version": "0.1", "all_pass": False, "results": [res]}
    fb = id_feedback.project_feedback(report)
    id_feedback.validate_feedback(fb)  # structural: only behavior_id+taxonomy
    assert fb["failures"] == [{"behavior_id": "BHV-KV",
                               "taxonomy": ["property_violated"]}]
    fb_text = json.dumps(fb)
    for secret in (cx["vars"]["k"], cx["vars"]["v"], cx["detail"]):
        assert secret not in fb_text

    # (2) the HIGH-VALUE secret is absent from every workspace byte. The
    # counterexample detail and the invariant name/args are control-plane;
    # none may appear anywhere the builder can read. (Concatenate ALL
    # workspace files -- no allowlist.)
    after_files = os.listdir(ws)
    all_ws_bytes = b"".join((ws / name).read_bytes() for name in after_files)
    high_value_secrets = [
        cx["detail"],
        prop_scenario()["then"]["invariant"]["name"],   # "round_trip"
        "observe_step",                                  # the args config
    ]
    for secret in high_value_secrets:
        assert secret.encode() not in all_ws_bytes, secret

    # (3) the runner wrote nothing: only the candidate's own store.json is new,
    # and every pre-existing file is byte-identical.
    assert set(after_files) == set(before) | {"store.json"}
    for name, content in before.items():
        assert (ws / name).read_bytes() == content

    # (4) HONEST BOUNDARY: the candidate's own state DID retain the generated
    # input -- assert on CONTENTS (not an allowlist), and pin WHY it is safe.
    # The generated KEY is stored verbatim by the `put` step (the value is
    # truncated here only because THIS stub is the buggy one under test).
    store_bytes = (ws / "store.json").read_bytes()
    assert cx["vars"]["k"].encode() in store_bytes  # the input persisted...
    assert cx["detail"] not in store_bytes.decode(errors="replace")  # ...but no secret


def test_feedback_validator_accepts_property_violated_and_rejects_extras():
    fb = {
        "feedback_version": "0.1", "channel": "ids", "total": 1,
        "failing_count": 1,
        "failures": [{"behavior_id": "BHV-X", "taxonomy": ["property_violated"]}],
    }
    id_feedback.validate_feedback(fb)  # in the fixed vocabulary now
    smuggle = copy.deepcopy(fb)
    smuggle["failures"][0]["counterexample"] = {"v": "secret"}
    with pytest.raises(id_feedback.FeedbackLeakError):
        id_feedback.validate_feedback(smuggle)


# --- gate integration -------------------------------------------------------

def test_validate_oracle_flags_vacuous_property_scenario():
    sc = prop_scenario()
    sc["when"]["property"]["generate"]["vars"]["v"]["min_len"] = 0  # ""-capable
    assert df_gates.validate_oracle([sc]) == ["BHV-KV-P1"]
    assert df_gates.validate_oracle([prop_scenario()]) == []


def test_property_counts_toward_class_coverage():
    behaviors = [{"id": "BHV-KV"}]
    policy = {"required_classes": ["happy", "boundary"], "min_per_class": 1}
    happy = {"id": "BHV-KV-S1", "behavior_id": "BHV-KV", "class": "happy"}
    adq = df_gates.check_adequacy(behaviors, [happy, prop_scenario()], policy)
    assert adq["under_covered"] == []
    adq2 = df_gates.check_adequacy(behaviors, [happy], policy)
    assert adq2["under_covered"] == [{"behavior": "BHV-KV", "missing": ["boundary"]}]


# ============================================================================
# M43b — concurrency oracle: PARALLEL execution with ENGINEERED-RELIABLE races
# ============================================================================
# Determinism discipline (the plan's hard requirement — NO flaky tests): the
# racy stubs put a deliberate 0.2s sleep BETWEEN the read and the write of a
# read-modify-write, so with a 0.2s window and near-simultaneous worker spawns
# every worker READS before any worker WRITES — the lost update / duplicate is
# RELIABLE, not luck. The locked (fcntl.flock) variants serialize regardless of
# timing, so they PASS reliably. The GENERATED inputs are seeded, so which
# distinct values the workers write is reproducible.

# A shared counter incremented read-modify-write. RACY: the sleep guarantees
# all workers read the same value and all write value+1 -> duplicate values ->
# serializable_counter sees the lost update.
RACY_COUNTER = """\
import os, time
F = "counter.txt"
n = int(open(F).read()) if os.path.exists(F) else 0
time.sleep(0.2)
open(F, "w").write(str(n + 1))
print(n + 1)
"""

# ATOMIC: an exclusive flock serializes the read-modify-write -> the N workers
# print 1..N (distinct, contiguous) regardless of interleaving.
ATOMIC_COUNTER = """\
import os, time, fcntl
fd = open("counter.txt", "a+")
fcntl.flock(fd, fcntl.LOCK_EX)
fd.seek(0)
data = fd.read().strip()
n = int(data) if data else 0
time.sleep(0.02)
n += 1
fd.seek(0); fd.truncate(); fd.write(str(n)); fd.flush()
fcntl.flock(fd, fcntl.LOCK_UN)
print(n)
"""

# A shared collection appended read-modify-write, printing the resulting list
# (one item per line). RACY: each worker's read reflects only its OWN append ->
# no single read ever shows all writes -> no_lost_update fires.
RACY_APPEND = """\
import os, sys, time, json
F = "coll.json"
item = sys.argv[1]
d = json.load(open(F)) if os.path.exists(F) else []
time.sleep(0.2)
d.append(item)
json.dump(d, open(F, "w"))
for x in d:
    print(x)
"""

# ATOMIC: flock serializes; the LAST writer reads back every prior append plus
# its own -> some read reflects all N writes -> no_lost_update holds.
ATOMIC_APPEND = """\
import os, sys, time, json, fcntl
item = sys.argv[1]
fd = open("coll.json", "a+")
fcntl.flock(fd, fcntl.LOCK_EX)
fd.seek(0)
data = fd.read().strip()
d = json.loads(data) if data else []
time.sleep(0.02)
d.append(item)
fd.seek(0); fd.truncate(); fd.write(json.dumps(d)); fd.flush()
fcntl.flock(fd, fcntl.LOCK_UN)
for x in d:
    print(x)
"""

# Same logical op (append a FIXED item) under a lock, WITHOUT dedup: serialized
# accumulation means each worker reads back a different length -> divergent ->
# idempotent_under_concurrency fires (reliably, no timing needed).
NONIDEMPOTENT = """\
import sys, json, os, fcntl
item = sys.argv[1]
fd = open("coll.json", "a+")
fcntl.flock(fd, fcntl.LOCK_EX)
fd.seek(0)
data = fd.read().strip()
d = json.loads(data) if data else []
d.append(item)
fd.seek(0); fd.truncate(); fd.write(json.dumps(d)); fd.flush()
fcntl.flock(fd, fcntl.LOCK_UN)
print(len(d))
"""

# Idempotent: an UPSERT into a set — N identical ops converge to ONE member, so
# every worker reads back the same single value.
IDEMPOTENT = """\
import sys, json, os, fcntl
item = sys.argv[1]
fd = open("coll.json", "a+")
fcntl.flock(fd, fcntl.LOCK_EX)
fd.seek(0)
data = fd.read().strip()
d = set(json.loads(data)) if data else set()
d.add(item)
fd.seek(0); fd.truncate(); fd.write(json.dumps(sorted(d))); fd.flush()
fcntl.flock(fd, fcntl.LOCK_UN)
print(",".join(sorted(d)))
"""

HANG = "import time\ntime.sleep(60)\n"


def conc_scenario(argv, invariant, *, vars_, per_worker_vars, workers=3,
                  attempts=3, cases=2, seed=1, timeout_s=10, args=None):
    inv = {"name": invariant}
    if args is not None:
        inv["args"] = args
    return {
        "ir_version": "0.4", "id": "BHV-C-P1", "behavior_id": "BHV-C",
        "title": "concurrency", "given": "", "class": "failure",
        "when": {"property": {
            "generate": {"vars": vars_, "cases": cases, "seed": seed},
            "steps": [{"run": argv}],
            "concurrency": {"workers": workers, "attempts": attempts,
                            "per_worker_vars": per_worker_vars},
            "timeout_s": timeout_s,
        }},
        "then": {"invariant": inv},
    }


def stub_ws(tmp_path, body, name="app.py", sub="ws"):
    ws = tmp_path / sub
    ws.mkdir(exist_ok=True)
    (ws / name).write_text(body, encoding="utf-8")
    return ws


# --- serializable_counter (the canonical lost-update detector) ---------------

def _counter_scenario(invariant="serializable_counter"):
    # A dummy declared var (generate.vars must be non-empty); the counter is
    # SHARED, so per_worker_vars is empty and no arg is templated.
    return conc_scenario(["python3", "app.py"], invariant,
                         vars_={"w": {"kind": "int", "min": 0, "max": 9}},
                         per_worker_vars=[], workers=3, attempts=3)


def test_racy_counter_fails_serializable_reliably(tmp_path):
    ws = stub_ws(tmp_path, RACY_COUNTER)
    res = run_scenarios.run_scenario(_counter_scenario(), str(ws))
    assert res["taxonomy"] == "property_violated", res
    cx = res["observed"]["property"]["counterexample"]
    assert cx is not None
    assert "attempt_index" in cx and isinstance(cx["case_index"], int)
    assert len(cx["workers"]) == 3  # full per-worker evidence recorded


def test_atomic_counter_passes_serializable_reliably(tmp_path):
    ws = stub_ws(tmp_path, ATOMIC_COUNTER)
    res = run_scenarios.run_scenario(_counter_scenario(), str(ws))
    assert res["pass"], res
    pinfo = res["observed"]["property"]
    assert pinfo["counterexample"] is None
    assert pinfo["workers"] == 3 and pinfo["attempts"] == 3


# --- no_lost_update ---------------------------------------------------------

def _append_scenario():
    return conc_scenario(
        ["python3", "app.py", "{item}"], "no_lost_update",
        vars_={"item": {"kind": "string", "charset": "alnum",
                        "min_len": 8, "max_len": 12}},
        per_worker_vars=["item"], workers=3, attempts=3, args={"value": "item"})


def test_racy_append_fails_no_lost_update_reliably(tmp_path):
    ws = stub_ws(tmp_path, RACY_APPEND)
    res = run_scenarios.run_scenario(_append_scenario(), str(ws))
    assert res["taxonomy"] == "property_violated", res
    assert "lost" in res["observed"]["property"]["counterexample"]["detail"]


def test_atomic_append_passes_no_lost_update_reliably(tmp_path):
    ws = stub_ws(tmp_path, ATOMIC_APPEND)
    res = run_scenarios.run_scenario(_append_scenario(), str(ws))
    assert res["pass"], res


# --- idempotent_under_concurrency -------------------------------------------

def _idem_scenario():
    return conc_scenario(
        ["python3", "app.py", "{k}"], "idempotent_under_concurrency",
        vars_={"k": {"kind": "string", "charset": "alnum", "min_len": 4, "max_len": 6}},
        per_worker_vars=[], workers=3, attempts=2)  # k SHARED (same op)


def test_nonidempotent_stub_fails(tmp_path):
    ws = stub_ws(tmp_path, NONIDEMPOTENT)
    res = run_scenarios.run_scenario(_idem_scenario(), str(ws))
    assert res["taxonomy"] == "property_violated", res
    assert "divergent" in res["observed"]["property"]["counterexample"]["detail"]


def test_idempotent_stub_passes(tmp_path):
    ws = stub_ws(tmp_path, IDEMPOTENT)
    res = run_scenarios.run_scenario(_idem_scenario(), str(ws))
    assert res["pass"], res


# --- no_crash_no_hang: a HANG is a failure, BOUNDED by the per-case deadline -

def test_hanging_worker_fails_no_crash_no_hang_and_is_bounded(tmp_path):
    sc = conc_scenario(["python3", "app.py"], "no_crash_no_hang",
                       vars_={"w": {"kind": "int", "min": 0, "max": 9}},
                       per_worker_vars=[], workers=3, attempts=1, cases=1,
                       timeout_s=0.5)
    ws = stub_ws(tmp_path, HANG)
    import time as _t
    t0 = _t.time()
    res = run_scenarios.run_scenario(sc, str(ws))
    elapsed = _t.time() - t0
    assert res["taxonomy"] == "property_violated", res
    assert "timeout" in res["observed"]["property"]["counterexample"]["detail"]
    # Bounded: killed at the ~0.5s per-case deadline (plus reap grace), nowhere
    # near 3 workers x 60s of sleep — proof the hung worker was reaped, not left
    # to run.
    assert elapsed < 20, elapsed


def test_clean_stub_passes_no_crash_no_hang(tmp_path):
    sc = conc_scenario(["python3", "app.py"], "no_crash_no_hang",
                       vars_={"w": {"kind": "int", "min": 0, "max": 9}},
                       per_worker_vars=[], workers=3, attempts=2)
    ws = stub_ws(tmp_path, "print('ok')\n")
    res = run_scenarios.run_scenario(sc, str(ws))
    assert res["pass"], res


# --- validation: the concurrency block <-> concurrency invariant coupling ----

def test_concurrency_block_requires_concurrency_invariant(tmp_path):
    sc = _counter_scenario()
    sc["then"] = {"invariant": {"name": "robust"}}  # sequential invariant
    with pytest.raises(run_scenarios.OracleError, match="concurrency invariant"):
        write_and_load(tmp_path, sc)


def test_concurrency_invariant_requires_concurrency_block(tmp_path):
    sc = _counter_scenario()
    del sc["when"]["property"]["concurrency"]
    with pytest.raises(run_scenarios.OracleError, match="concurrency block"):
        write_and_load(tmp_path, sc)


def test_bad_workers_rejected_at_load(tmp_path):
    sc = _counter_scenario()
    sc["when"]["property"]["concurrency"]["workers"] = 99
    with pytest.raises(run_scenarios.OracleError, match="workers"):
        write_and_load(tmp_path, sc)


def test_no_lost_update_value_not_per_worker_rejected(tmp_path):
    sc = _append_scenario()
    sc["when"]["property"]["concurrency"]["per_worker_vars"] = []
    with pytest.raises(run_scenarios.OracleError, match="per_worker_vars"):
        write_and_load(tmp_path, sc)


def test_concurrency_scenario_loads_and_is_sharp(tmp_path):
    scs = write_and_load(tmp_path, _counter_scenario())
    assert scs[0]["id"] == "BHV-C-P1"
    # The M7 discrimination gate treats it uniformly and finds it sharp.
    assert df_gates.validate_oracle(scs) == []


# --- Finding 1 regression: a degenerate per-worker domain is not a false GREEN

def _degenerate_no_lost_update():
    # value var `item` has a ZERO-ENTROPY domain (min==max) => every worker
    # writes the SAME value => a lost update is unobservable => a genuinely-racy
    # candidate would PASS vacuously without the fix.
    sc = conc_scenario(
        ["python3", "app.py", "{item}"], "no_lost_update",
        vars_={"item": {"kind": "int", "min": 5, "max": 5}},
        per_worker_vars=["item"], workers=3, attempts=3, args={"value": "item"})
    return sc


def test_degenerate_domain_no_lost_update_rejected_at_load(tmp_path):
    # Belt-and-suspenders: the scenario cannot even LOAD, so it never reaches a
    # build/run where a racy candidate could false-pass.
    with pytest.raises(run_scenarios.OracleError, match="zero-entropy"):
        write_and_load(tmp_path, _degenerate_no_lost_update())


def test_degenerate_domain_flagged_by_gate_every_seed():
    # And the M7 discrimination gate flags it directly (for a scenario built in
    # memory, bypassing load), for every seed — parity with M43a's structural
    # vacuity check.
    for seed in range(20):
        sc = _degenerate_no_lost_update()
        sc["when"]["property"]["generate"]["seed"] = seed
        assert df_gates.validate_oracle([sc]) == ["BHV-C-P1"], seed


def test_racy_candidate_with_degenerate_domain_would_pass_proving_the_gap(tmp_path):
    # Demonstrates WHY the load/gate rejection matters: if such a scenario DID
    # run, the racy read-modify-write candidate returns a false GREEN (the lost
    # update is invisible because every worker writes the identical value). This
    # is the exact hole the load-time rejection + gate flag close upstream.
    sc = _degenerate_no_lost_update()  # not loaded => validation bypassed
    ws = stub_ws(tmp_path, RACY_APPEND)
    res = run_scenarios.run_scenario(sc, str(ws))
    assert res["pass"] is True  # vacuous pass — WHY it must be blocked at load
    # ...and it IS blocked at load (the guard above), so this can never be a
    # real run.


# --- back-compat: absent concurrency => M43a observed shape (no conc fields) --

def test_absent_concurrency_is_m43a_shape(tmp_path):
    ws = make_ws(tmp_path, GOOD_KV)
    res = run_scenarios.run_scenario(prop_scenario(), str(ws))
    assert "workers" not in res["observed"]["property"]
    assert "attempts" not in res["observed"]["property"]


# --- THE BARRIER: per-worker counterexample stays control-plane --------------

def test_concurrency_counterexample_stays_control_plane(tmp_path):
    ws = stub_ws(tmp_path, RACY_COUNTER)
    res = run_scenarios.run_scenario(_counter_scenario(), str(ws))
    assert res["taxonomy"] == "property_violated"
    report = {"report_version": "0.1", "all_pass": False, "results": [res]}
    fb = id_feedback.project_feedback(report)
    id_feedback.validate_feedback(fb)  # structural: only behavior_id + taxonomy
    assert fb["failures"] == [{"behavior_id": "BHV-C",
                               "taxonomy": ["property_violated"]}]
