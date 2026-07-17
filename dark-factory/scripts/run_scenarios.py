"""Oracle IR v0.2 runner (the verifier's executable check contract). Stdlib only.

IR v0.2: one JSON file per scenario:
  {
    "ir_version": "0.1",
    "id": "BHV-001-S1",              # scenario id
    "behavior_id": "BHV-001",         # ^BHV-[A-Za-z0-9-]{1,32}$
    "title": "...", "given": "...",   # human view; NEVER crosses the barrier
    "when": {"run": ["cmd", ...], "timeout_s": 10},
    "then": {"exit_code": 0,
             "stdout_equals"|"stdout_contains"|
             "stderr_equals"|"stderr_contains": "...",
             "twin_observed": {"twin": "<name>", "contains": "<nonempty str>"},
             "stdout_echoes_twin": {"twin": "<name>"}}   # >= 1 assertion
  }
`twin_observed` passes iff the per-scenario observation DELTA for that twin
(the ndjson lines a twin appended to its observer file WHILE this scenario's
command ran, and only then) contains `contains` as a raw-line substring.
`stdout_echoes_twin` passes iff at least one `token` recorded in that delta
appears verbatim in this scenario's stdout; zero tokens recorded is a fail
(no evidence of a live, echoing call). Both produce taxonomy
"no_twin_evidence" on failure -- this is evidence FROM THE TWIN's own
observer state, not from anything the candidate's own output claims, so a
builder cannot forge it by pattern-matching stdout.

Taxonomy priority on failure: timeout > crash > wrong_exit_code >
wrong_output > no_twin_evidence. Equality assertions strip one trailing
newline from both sides.

M20 Task 1: a NEW, additive `when.http` scenario type (a first-class HTTP
service check, alongside the existing `when.run` CLI check):
  "when": {"http": {"start": ["cmd", ...],       # argv that launches the
                                                   # service, same as `run`
                     "port_env": "PORT",          # optional: this env var is
                                                   # set to a chosen ephemeral
                                                   # port before `start` runs,
                                                   # so the service can bind
                                                   # it (the primary mechanism
                                                   # for locating the service
                                                   # -- a service that binds
                                                   # :0 and self-reports its
                                                   # port is out of scope v1)
                     "ready_path": "/health",     # polled on 127.0.0.1:<port>
                                                   # until any response, or a
                                                   # deadline (fail-closed)
                     "request": {"method": "GET", "path": "/...",
                                 "headers": {...}, "body": "..."}}}
`then` for an http scenario uses `http_status` (int), `body_contains`
(substring of the raw response body), `json_equals`/`json_contains` (a
subset match against the parsed JSON body), `json_path`
({"a.b[0]": value} -- a dotted+indexed accessor, NOT full JSONPath), and
(M20 Task 2) `twin_observed` (composes with an http scenario exactly like
it does with a CLI one -- `stdout_echoes_twin` has no http analogue and is
CLI-only). `evaluate_http` maps these onto the SAME fixed taxonomy
vocabulary as CLI scenarios: no response at all -> "crash" (fail-closed --
a service that never becomes ready or dies before answering is never a
vacuous pass); `http_status` mismatch -> "wrong_exit_code" (the http
analogue of an exit code); a body/json/json_path mismatch ->
"wrong_output"; a `twin_observed` mismatch -> "no_twin_evidence".

M20 Task 2: `load_scenarios`/`_validate` now enforces, BEFORE any build,
across all cohorts: a scenario's `when` has EXACTLY ONE of `run`/`http`
(both or neither -> `OracleError` naming the id); an http scenario's `then`
must use >=1 http key and no CLI-only key, and vice versa for a `when.run`
scenario (mismatched then/when -> `OracleError`); `when.http` requires
`start` (non-empty argv list) + `request` (method+path); `ir_version`
accepts `"0.1"`/`"0.2"`/`"0.3"`. Existing `when.run` scenarios are
completely unaffected (same code path, unchanged).
"""
import glob
import http.client
import json
import os
import re
import signal
import socket
import subprocess
import time

IR_VERSION = "0.1"
# M20 Task 2: ir_version 0.2/0.3 are additive bumps (twin evidence, then the
# http scenario type) -- a control root written against any of them loads
# unchanged. IR_VERSION is kept as the "current/default" constant other
# modules may reference; IR_VERSIONS is the accepted set at load time.
IR_VERSIONS = {"0.1", "0.2", "0.3"}
BEHAVIOR_RE = re.compile(r"^BHV-[A-Za-z0-9-]{1,32}$")
CLI_ONLY_THEN_KEYS = {
    "exit_code",
    "stdout_equals",
    "stdout_contains",
    "stderr_equals",
    "stderr_contains",
}
TWIN_THEN_KEYS = {"twin_observed", "stdout_echoes_twin"}
ASSERT_KEYS = CLI_ONLY_THEN_KEYS | TWIN_THEN_KEYS


class OracleError(ValueError):
    pass


# --- DF-02 / M29a Task 1: candidate scenario env sanitization --------------
# Candidate code (the built app under test) must NOT inherit the full host
# environment. Before this, both scenario launchers built the child env as
# `dict(os.environ, **env_extra)` -- so generated code could see
# SSH_AUTH_SOCK, HTTP_PROXY, AWS_*, OPENAI_API_KEY, and anything else in the
# operator's shell. `candidate_env` replaces that: a small, explicit
# allowlist of "a normal program needs this to run" host vars, UNION
# `env_extra` (trusted, supervisor-injected -- twin endpoints, the M11
# credential allowlist -- and passed through unfiltered, since the
# supervisor already decided what belongs there; it is not raw host env).
# A denylist is applied to the inherited/allowlisted portion as a
# belt-and-suspenders scrub, in case the allowlist is ever loosened by
# mistake to overlap something dangerous.

# Exact-name allowlist: what a normal program needs to run at all (locale,
# temp dirs, shell/user identity, PATH/HOME). Deliberately NOT extended for
# convenience -- anything a candidate legitimately needs beyond this must be
# threaded through env_extra by the supervisor, not silently inherited here.
_CANDIDATE_ENV_ALLOWLIST_NAMES = {
    "PATH", "HOME", "LANG", "LANGUAGE", "TMPDIR", "TMP", "TEMP", "TERM",
    "TZ", "PWD", "SHELL", "USER", "LOGNAME",
}
# Prefix form: every LC_* locale var (LC_ALL, LC_CTYPE, LC_COLLATE, ...) --
# a prefix rather than an enumeration so a locale var this list doesn't name
# yet still gets through.
_CANDIDATE_ENV_ALLOWLIST_PREFIXES = ("LC_",)

# Exact-name denylist: known-dangerous single vars that don't fit a prefix
# or substring rule below.
_CANDIDATE_ENV_DENYLIST_NAMES = {
    "SSH_AUTH_SOCK", "SSH_AGENT_PID", "SSH_CONNECTION",
    "GH_TOKEN", "GITHUB_TOKEN", "DOCKER_HOST", "KUBECONFIG",
}
# Prefix form: whole cloud/provider credential families.
_CANDIDATE_ENV_DENYLIST_PREFIXES = (
    "AWS_", "GOOGLE_", "GCP_", "AZURE_", "ANTHROPIC_", "OPENAI_", "GEMINI_",
)
# Substring form (case-insensitive, matched against the uppercased name):
# catches *_PROXY/*_proxy plus anything that reads as a credential by name,
# regardless of vendor prefix.
_CANDIDATE_ENV_DENYLIST_SUBSTRINGS = (
    "PROXY", "SECRET", "TOKEN", "PASSWORD", "APIKEY", "API_KEY", "CREDENTIAL",
)


def _is_denylisted_env_name(name: str) -> bool:
    if name in _CANDIDATE_ENV_DENYLIST_NAMES:
        return True
    if name.startswith(_CANDIDATE_ENV_DENYLIST_PREFIXES):
        return True
    upper = name.upper()
    return any(substr in upper for substr in _CANDIDATE_ENV_DENYLIST_SUBSTRINGS)


def candidate_env(env_extra: dict | None) -> dict:
    """The env a candidate scenario subprocess actually runs under.

    = {allowlisted subset of os.environ, denylist-scrubbed} UNION (env_extra
    or {}). env_extra is trusted/supervisor-injected (DF_TWIN_* endpoints,
    the M11 credential allowlist) and is passed through WITHOUT denylist
    filtering -- it must still reach the candidate, and scrubbing it would
    break the twin/credential wiring this runner depends on. A denylisted
    name showing up in env_extra would mean the supervisor itself injected
    something it shouldn't have, so that's asserted against defensively
    rather than silently dropped (silently dropping could mask a real bug in
    the caller).
    """
    env = {}
    for name, value in os.environ.items():
        allowlisted = (
            name in _CANDIDATE_ENV_ALLOWLIST_NAMES
            or name.startswith(_CANDIDATE_ENV_ALLOWLIST_PREFIXES)
        )
        if allowlisted and not _is_denylisted_env_name(name):
            env[name] = value

    env_extra = env_extra or {}
    bad = [name for name in env_extra if _is_denylisted_env_name(name)]
    assert not bad, (
        f"candidate_env: env_extra contained denylisted name(s) {bad!r} -- "
        f"the supervisor should never inject these; check the caller"
    )
    env.update(env_extra)
    return env


def _validate_twin_then(then: dict, fname: str) -> None:
    """Load-time shape validation for the twin-evidence assertion keys.

    Deliberately does NOT check the `twin` name against any known-twins set
    -- that requires runtime context (which twins this runner was given,
    `run_all`'s `observer_files`) that isn't available here. That check
    happens in `run_all`, before any scenario in the call runs.
    """
    if "twin_observed" in then:
        spec = then["twin_observed"]
        if not isinstance(spec, dict) or set(spec) != {"twin", "contains"}:
            raise OracleError(
                f"{fname}: twin_observed must be {{'twin': str, 'contains': str}}")
        if not isinstance(spec["twin"], str) or not spec["twin"]:
            raise OracleError(f"{fname}: twin_observed.twin must be a non-empty string")
        if not isinstance(spec["contains"], str) or not spec["contains"]:
            raise OracleError(f"{fname}: twin_observed.contains must be a non-empty string")
    if "stdout_echoes_twin" in then:
        spec = then["stdout_echoes_twin"]
        if not isinstance(spec, dict) or set(spec) != {"twin"}:
            raise OracleError(f"{fname}: stdout_echoes_twin must be {{'twin': str}}")
        if not isinstance(spec["twin"], str) or not spec["twin"]:
            raise OracleError(f"{fname}: stdout_echoes_twin.twin must be a non-empty string")


def _validate_http_when(http_spec, fname: str, sc_id: str) -> None:
    """Load-time shape validation for `when.http` (M20 Task 2). Requires
    `start` (a non-empty argv list of strings) and `request` (an object
    with a non-empty `method` + `path`); `port_env`/`ready_path`/
    `timeout_s` are optional and NOT shape-checked here (execution fails
    closed -- "crash"/"timeout" -- on anything malformed at runtime, same
    discipline as an unreachable `when.run` command)."""
    if not isinstance(http_spec, dict):
        raise OracleError(f"{fname} ({sc_id}): when.http must be an object")
    start = http_spec.get("start")
    if not isinstance(start, list) or not start or not all(isinstance(x, str) for x in start):
        raise OracleError(f"{fname} ({sc_id}): when.http.start must be a non-empty list of strings")
    request = http_spec.get("request")
    if not isinstance(request, dict):
        raise OracleError(f"{fname} ({sc_id}): when.http.request must be an object")
    if not isinstance(request.get("method"), str) or not request["method"]:
        raise OracleError(f"{fname} ({sc_id}): when.http.request.method must be a non-empty string")
    if not isinstance(request.get("path"), str) or not request["path"]:
        raise OracleError(f"{fname} ({sc_id}): when.http.request.path must be a non-empty string")


def _validate(sc: dict, fname: str) -> None:
    if sc.get("ir_version") not in IR_VERSIONS:
        raise OracleError(f"{fname}: ir_version must be one of {sorted(IR_VERSIONS)}")
    for key in ("id", "behavior_id", "title", "given", "when", "then"):
        if key not in sc:
            raise OracleError(f"{fname}: missing {key!r}")
    if not BEHAVIOR_RE.fullmatch(sc["behavior_id"]):
        raise OracleError(f"{fname}: invalid behavior_id {sc['behavior_id']!r}")
    if "cohort" in sc and sc["cohort"] not in ("dev", "final"):
        raise OracleError(f"{fname}: cohort must be 'dev' or 'final', got {sc['cohort']!r}")

    sc_id = sc["id"]
    when = sc["when"]
    has_run = "run" in when
    has_http = "http" in when
    # M20 Task 2: a scenario has EXACTLY ONE of when.run / when.http -- both
    # or neither is an oracle defect (ambiguous or dead scenario), caught
    # BEFORE any build, naming the scenario id so it's unambiguous which
    # scenario file is at fault even if several share similar filenames.
    if has_run == has_http:
        raise OracleError(
            f"{fname} ({sc_id}): when must have EXACTLY ONE of 'run' or 'http', "
            f"got run={has_run} http={has_http}"
        )

    then = sc["then"]
    if not isinstance(then, dict):
        raise OracleError(f"{fname} ({sc_id}): then must be an object")
    then_keys = set(then)

    if has_http:
        _validate_http_when(when["http"], fname, sc_id)
        mismatched = then_keys & CLI_ONLY_THEN_KEYS
        if mismatched:
            raise OracleError(
                f"{fname} ({sc_id}): then has CLI-only key(s) {sorted(mismatched)} on an "
                f"http scenario -- mismatched then/when"
            )
        if not (then_keys & HTTP_ASSERT_KEYS):
            raise OracleError(
                f"{fname} ({sc_id}): an http scenario's then needs >=1 http assertion key "
                f"{sorted(HTTP_ASSERT_KEYS)}"
            )
        # `twin_observed` composes with an http scenario (the started service
        # may itself call a twin); `stdout_echoes_twin` does NOT (an http
        # scenario has no "stdout" to echo into) and is intentionally
        # excluded here -- it falls through to the "unknown key" error below.
        allowed = HTTP_ASSERT_KEYS | {"twin_observed"}
        if then_keys - allowed:
            raise OracleError(
                f"{fname} ({sc_id}): then has unknown key(s) {sorted(then_keys - allowed)} "
                f"for an http scenario"
            )
    else:
        run = when.get("run")
        if not isinstance(run, list) or not run or not all(isinstance(x, str) for x in run):
            raise OracleError(f"{fname} ({sc_id}): when.run must be a non-empty list of strings")
        mismatched = then_keys & HTTP_ASSERT_KEYS
        if mismatched:
            raise OracleError(
                f"{fname} ({sc_id}): then has http key(s) {sorted(mismatched)} on a CLI "
                f"(when.run) scenario -- mismatched then/when"
            )
        if not (then_keys & ASSERT_KEYS) or then_keys - ASSERT_KEYS:
            raise OracleError(f"{fname} ({sc_id}): then needs >=1 known assertion key {sorted(ASSERT_KEYS)}")

    _validate_twin_then(then, fname)


def load_scenarios(scenarios_dir: str, extra_scenarios_dir: str | None = None) -> list:
    """Load scenarios from `scenarios_dir` (the control-plane, human-authored
    set) unioned with `extra_scenarios_dir` if given (M15: the supervisor's
    brownfield-generated dev-cohort regression scenarios, written per-run to
    `<run_dir>/generated-scenarios/`). A scenario id present in BOTH dirs is
    an oracle defect (ambiguous which one applies), not silently resolved --
    OracleError names the id and both source dirs.
    """
    scs = []
    seen_ids: dict[str, str] = {}
    dirs = [scenarios_dir] + ([extra_scenarios_dir] if extra_scenarios_dir else [])
    for d in dirs:
        for path in sorted(glob.glob(os.path.join(d, "*.json"))):
            with open(path, encoding="utf-8") as f:
                sc = json.load(f)
            _validate(sc, os.path.basename(path))
            sc.setdefault("cohort", "dev")
            if sc["id"] in seen_ids:
                raise OracleError(
                    f"duplicate scenario id {sc['id']!r} in both {seen_ids[sc['id']]!r} "
                    f"and {d!r}"
                )
            seen_ids[sc["id"]] = d
            scs.append(sc)
    if not scs:
        raise OracleError(f"no scenarios found in {scenarios_dir}")
    return scs


def _norm(s: str) -> str:
    return s[:-1] if s.endswith("\n") else s


def evaluate_then(then: dict, observed: dict) -> str | None:
    """Pure assertion evaluator: returns the failure taxonomy or None (pass).

    `observed` has keys exit_code (int|None), stdout (str), stderr (str),
    and (M12) twin_observations ({name: [str lines]}) and twin_tokens
    ({name: [str]}) -- both ABSENT keys behave as empty dicts, so twin
    assertions fail closed (no evidence recorded => fail) while every
    scenario that doesn't ask for twin evidence is completely unaffected.
    Priority: exit_code, then output, then twin evidence -- checked in that
    order and the first mismatch wins (a scenario with wrong output never
    reports "no_twin_evidence" even if its twin assertion would also fail).
    Equality assertions strip one trailing newline from both sides (see
    _norm).
    """
    if "exit_code" in then and observed["exit_code"] != then["exit_code"]:
        return "wrong_exit_code"
    if (
        ("stdout_equals" in then and _norm(observed["stdout"]) != _norm(then["stdout_equals"]))
        or ("stdout_contains" in then and then["stdout_contains"] not in observed["stdout"])
        or ("stderr_equals" in then and _norm(observed["stderr"]) != _norm(then["stderr_equals"]))
        or ("stderr_contains" in then and then["stderr_contains"] not in observed["stderr"])
    ):
        return "wrong_output"
    if "twin_observed" in then:
        spec = then["twin_observed"]
        lines = observed.get("twin_observations", {}).get(spec["twin"], [])
        if not any(spec["contains"] in line for line in lines):
            return "no_twin_evidence"
    if "stdout_echoes_twin" in then:
        spec = then["stdout_echoes_twin"]
        tokens = observed.get("twin_tokens", {}).get(spec["twin"], [])
        if not tokens or not any(tok in observed["stdout"] for tok in tokens):
            return "no_twin_evidence"
    return None


HTTP_ASSERT_KEYS = {
    "http_status", "body_contains", "json_equals", "json_contains", "json_path",
}

_JSON_PATH_TOKEN_RE = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def _json_path_get(obj, path: str):
    """Resolve a small dotted+indexed accessor ("a.b[0]") against `obj`.

    NOT full JSONPath (see module docstring / scenario-format honest-scope
    note) -- just dotted keys and `[i]` list indices, composable in any
    order (`a.b[0]`, `a[0].b`, `a[0][1]`, ...). Raises KeyError/IndexError/
    TypeError on any missing key, out-of-range index, or type mismatch
    (dict expected but got something else, etc.) -- the caller treats any
    of those as a mismatch, never a silent None.
    """
    cur = obj
    for m in _JSON_PATH_TOKEN_RE.finditer(path):
        key, idx = m.group(1), m.group(2)
        if idx is not None:
            if not isinstance(cur, list):
                raise TypeError(f"{path}: expected a list, got {type(cur).__name__}")
            cur = cur[int(idx)]
        else:
            if not isinstance(cur, dict) or key not in cur:
                raise KeyError(f"{path}: missing key {key!r}")
            cur = cur[key]
    return cur


def _json_contains(sub, full) -> bool:
    """True iff `sub` is a subset of `full`: every key/value pair in a
    `sub` dict must be present (recursively) in the matching `full` dict;
    lists and scalars are compared by equality. An empty `sub` dict is
    vacuously a subset of anything (mirrors the CLI oracle's empty-string
    tautology -- caught by the mutation gate, not rejected here)."""
    if isinstance(sub, dict):
        if not isinstance(full, dict):
            return False
        return all(k in full and _json_contains(v, full[k]) for k, v in sub.items())
    return sub == full


def evaluate_http(then: dict, observed: dict) -> str | None:
    """Pure HTTP assertion evaluator: returns the failure taxonomy or None.

    `observed` = {"http_status": int|None, "body": str, "json": <parsed
    JSON, or None if the body wasn't valid JSON>}. Maps onto the SAME fixed
    taxonomy vocabulary as `evaluate_then` (no new constant):
      - no response at all (`http_status` is None) -> "crash", regardless
        of what `then` asks for -- fail-closed, never a vacuous pass for a
        service that never became ready or died before answering.
      - `http_status` mismatch -> "wrong_exit_code" (the http analogue of
        an exit code).
      - `body_contains` / `json_equals` / `json_contains` / `json_path`
        mismatch -> "wrong_output". A json_* assertion against
        observed["json"] is None (body wasn't parseable JSON) is always a
        mismatch.
      - (M20 Task 2) `twin_observed` mismatch -> "no_twin_evidence" --
        composes with an http scenario exactly like it does with a CLI one
        (`evaluate_then`): the http service the scenario started may itself
        call a twin, and `observed["twin_observations"]` (populated by the
        SAME offset-delta plumbing `run_scenario` uses) is checked here,
        last in priority. `stdout_echoes_twin` has no http analogue (an
        http scenario has no "stdout" to echo into) and is intentionally
        NOT checked here -- load-time validation keeps it CLI-only.
    Priority: no-response, then status, then body/json, then twin evidence
    -- checked in that order, the first mismatch wins (mirrors
    evaluate_then's priority discipline: a wrong status never reports
    "wrong_output"/"no_twin_evidence" even if a later assertion would also
    fail).
    """
    if observed.get("http_status") is None:
        return "crash"
    if "http_status" in then and observed["http_status"] != then["http_status"]:
        return "wrong_exit_code"
    body = observed.get("body", "")
    json_obs = observed.get("json")
    if "body_contains" in then and then["body_contains"] not in body:
        return "wrong_output"
    if "json_equals" in then and (json_obs is None or json_obs != then["json_equals"]):
        return "wrong_output"
    if "json_contains" in then and (
        json_obs is None or not _json_contains(then["json_contains"], json_obs)
    ):
        return "wrong_output"
    if "json_path" in then:
        if json_obs is None:
            return "wrong_output"
        for path, expected in then["json_path"].items():
            try:
                actual = _json_path_get(json_obs, path)
            except (KeyError, IndexError, TypeError):
                return "wrong_output"
            if actual != expected:
                return "wrong_output"
    if "twin_observed" in then:
        spec = then["twin_observed"]
        lines = observed.get("twin_observations", {}).get(spec["twin"], [])
        if not any(spec["contains"] in line for line in lines):
            return "no_twin_evidence"
    return None


def _pick_ephemeral_port() -> int:
    """Bind to 127.0.0.1:0 to let the OS choose a free port, then close
    immediately so the child service can bind it. Small TOCTOU window
    (another process could grab the port before the child binds it) is
    accepted -- same tradeoff every "pick a free port for a child" pattern
    makes; a bind failure in the child surfaces as never-ready -> "crash",
    fail-closed, never a silent pass."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _http_probe(host: str, port: int, path: str, timeout: float) -> int:
    """Issue a bare GET and return the status code, or raise on any
    connection-level failure (used for the readiness poll -- ANY response,
    not just 2xx, counts as ready)."""
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


def _reap_process_group(proc: subprocess.Popen, pgid: int | None) -> None:
    """Mirror df_twins.TwinSet.stop()'s single-process discipline: SIGTERM
    the captured pgid, reap the direct child, then SIGKILL the group if
    anything is still alive. `pgid` is captured at launch time (== proc.pid
    under start_new_session=True), never re-resolved later, so an already-
    exited direct child (e.g. a shell wrapper) never causes a backgrounded
    grandchild in the same group to leak (see df_twins.py for the full
    macOS race explanation). Always called from a `finally` -- no orphan
    service process, ever, even on assertion failure or timeout."""
    if pgid is None:
        try:
            proc.terminate()
        except (OSError, ProcessLookupError):
            pass
        try:
            proc.wait(timeout=3)
        except (subprocess.TimeoutExpired, OSError):
            try:
                proc.kill()
            except (OSError, ProcessLookupError):
                pass
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        pass

    grace_deadline = time.time() + 3
    try:
        proc.wait(timeout=max(0.0, grace_deadline - time.time()))
    except (subprocess.TimeoutExpired, OSError):
        pass

    try:
        os.killpg(pgid, 0)
    except (ProcessLookupError, PermissionError, OSError):
        return  # group is empty (or gone) -- nothing left to reap

    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass

    kill_deadline = time.time() + 2
    while time.time() < kill_deadline:
        try:
            os.killpg(pgid, 0)
        except (ProcessLookupError, OSError):
            break
        time.sleep(0.02)


def _run_http_scenario(
    sc: dict,
    workspace: str,
    exec_wrapper: list | None,
    env_extra: dict | None,
    timeout_s: float,
) -> dict:
    """Start `sc["when"]["http"]["start"]` in `workspace` (under the same
    exec_wrapper/twin-env as a CLI scenario), poll `ready_path` until any
    response or a deadline, issue the one configured `request`, and return
    `observed` = {"http_status": int|None, "body": str, "json": parsed|None}
    for `evaluate_http`. `http_status` stays None (fail-closed -- never a
    vacuous pass) if the service never becomes ready, dies before
    answering, or the request itself fails at the connection level. The
    service is ALWAYS reaped by process group in `finally`, whatever
    happened above -- no orphan, even on timeout or a crash mid-poll.
    """
    http_spec = sc["when"]["http"]
    start_argv = http_spec["start"]
    port_env = http_spec.get("port_env")
    ready_path = http_spec.get("ready_path", "/")
    req_spec = http_spec.get("request", {})
    method = req_spec.get("method", "GET")
    path = req_spec.get("path", "/")
    headers = req_spec.get("headers") or {}
    req_body = req_spec.get("body")

    observed = {"http_status": None, "body": "", "json": None}

    port = _pick_ephemeral_port()
    env = candidate_env(env_extra)
    if port_env:
        env[port_env] = str(port)

    command = (list(exec_wrapper) if exec_wrapper else []) + start_argv

    proc = None
    pgid = None
    try:
        try:
            proc = subprocess.Popen(
                command,
                cwd=workspace,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            # Capture pgid NOW while the child is definitely alive -- see
            # _reap_process_group / df_twins.py for why this must not be
            # re-resolved later via os.getpgid(proc.pid).
            pgid = proc.pid
        except OSError:
            return observed  # never started -> http_status stays None -> "crash"

        deadline = time.time() + timeout_s
        ready = False
        while time.time() < deadline:
            if proc.poll() is not None:
                break  # process exited before ready -> fail closed, not ready
            remaining = max(0.05, deadline - time.time())
            try:
                _http_probe("127.0.0.1", port, ready_path, timeout=min(1.0, remaining))
                ready = True
                break
            except (OSError, ConnectionError, http.client.HTTPException):
                time.sleep(0.05)

        if not ready:
            return observed  # never ready within the deadline -> "crash"

        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout_s)
            try:
                body_bytes = req_body.encode("utf-8") if isinstance(req_body, str) else req_body
                conn.request(method, path, body=body_bytes, headers=headers)
                resp = conn.getresponse()
                raw = resp.read()
                text = raw.decode("utf-8", errors="replace")
                observed["http_status"] = resp.status
                observed["body"] = text
                try:
                    observed["json"] = json.loads(text)
                except (json.JSONDecodeError, ValueError):
                    observed["json"] = None
            finally:
                conn.close()
        except (OSError, ConnectionError, http.client.HTTPException):
            pass  # request failed at the connection level -> status stays None

        return observed
    finally:
        if proc is not None:
            _reap_process_group(proc, pgid)


def _run_http_and_evaluate(
    sc: dict,
    workspace: str,
    exec_wrapper: list | None,
    env_extra: dict | None,
    observer_files: dict | None,
) -> dict:
    """The http-scenario counterpart of the run_scenario body below: same
    result shape (id/behavior_id/pass/taxonomy/observed), same twin-delta
    plumbing (a twin the http service happens to call still produces
    observable evidence under `observed["twin_observations"/"twin_tokens"]`
    for reporting -- `evaluate_http` itself only inspects the http keys)."""
    http_spec = sc["when"]["http"]
    timeout_s = http_spec.get("timeout_s", sc["when"].get("timeout_s", 30))
    offsets = _observer_offsets(observer_files)
    observed = _run_http_scenario(sc, workspace, exec_wrapper, env_extra, timeout_s)
    twin_observations, twin_tokens = _read_twin_deltas(observer_files, offsets)
    observed["twin_observations"] = twin_observations
    observed["twin_tokens"] = twin_tokens
    taxonomy = evaluate_http(sc["then"], observed)
    return {
        "id": sc["id"],
        "behavior_id": sc["behavior_id"],
        "pass": taxonomy is None,
        "taxonomy": taxonomy,
        "observed": observed,
    }


def _observer_offsets(observer_files: dict | None) -> dict:
    offsets = {}
    for name, path in (observer_files or {}).items():
        offsets[name] = os.path.getsize(path) if os.path.exists(path) else 0
    return offsets


def _read_twin_deltas(observer_files: dict | None, offsets: dict) -> tuple[dict, dict]:
    """Read each observer file from its pre-run offset to EOF (the delta this
    scenario's command produced) and split it into (twin_observations,
    twin_tokens). Lines are parsed tolerantly: an unparseable line is kept
    as a raw string in twin_observations (so `contains` can still match raw
    text) but contributes no token."""
    observations, tokens = {}, {}
    for name, path in (observer_files or {}).items():
        content = ""
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                f.seek(offsets.get(name, 0))
                content = f.read()
        obs_lines, tok_list = [], []
        for line in content.splitlines():
            if not line.strip():
                continue
            obs_lines.append(line)
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and isinstance(obj.get("token"), str):
                tok_list.append(obj["token"])
        observations[name] = obs_lines
        tokens[name] = tok_list
    return observations, tokens


def run_scenario(sc: dict, workspace: str, exec_wrapper: list | None = None, env_extra: dict | None = None,
                 observer_files: dict | None = None) -> dict:
    # M20 Task 1: `when.http` is a NEW, additive path -- dispatched here so
    # `run_all` (which just calls run_scenario per scenario, unchanged)
    # picks it up automatically. Every existing `when.run` scenario falls
    # through to the unchanged code below (byte-identical).
    if "http" in sc["when"]:
        return _run_http_and_evaluate(sc, workspace, exec_wrapper, env_extra, observer_files)
    timeout = sc["when"].get("timeout_s", 30)
    observed = {"exit_code": None, "stdout": "", "stderr": ""}
    taxonomy = None
    command = (list(exec_wrapper) if exec_wrapper else []) + sc["when"]["run"]
    env = candidate_env(env_extra)
    # M12: snapshot each observer file's size BEFORE the candidate runs, so
    # only lines appended DURING this scenario's command are attributed to
    # it -- a scenario that makes zero twin calls gets an empty delta, never
    # a previous scenario's leftover lines.
    offsets = _observer_offsets(observer_files)
    # DF-02/M29a Task 2: give CLI scenarios the SAME start_new_session +
    # process-group-reap discipline as _run_http_scenario, so a candidate
    # that setsid's/double-forks a background child (or just leaves a
    # detached subprocess running) never survives past this call -- no
    # orphan, ever, whether the command finishes normally, times out, or
    # fails to launch at all.
    proc = None
    pgid = None
    try:
        try:
            proc = subprocess.Popen(
                command,
                cwd=workspace,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            # Capture pgid NOW while the child is definitely alive -- mirrors
            # _run_http_scenario (see _reap_process_group for why this must
            # not be re-resolved later via os.getpgid(proc.pid)).
            pgid = proc.pid
            stdout, stderr = proc.communicate(timeout=timeout)
            observed = {
                "exit_code": proc.returncode,
                "stdout": stdout,
                "stderr": stderr,
            }
        except subprocess.TimeoutExpired:
            taxonomy = "timeout"
        except (FileNotFoundError, PermissionError, OSError):
            taxonomy = "crash"
    finally:
        if proc is not None:
            _reap_process_group(proc, pgid)

    twin_observations, twin_tokens = _read_twin_deltas(observer_files, offsets)
    observed["twin_observations"] = twin_observations
    observed["twin_tokens"] = twin_tokens

    if taxonomy is None:
        taxonomy = evaluate_then(sc["then"], observed)

    return {
        "id": sc["id"],
        "behavior_id": sc["behavior_id"],
        "pass": taxonomy is None,
        "taxonomy": taxonomy,
        "observed": observed,
    }


def run_all(
    scenarios_dir: str,
    workspace: str,
    exec_wrapper: list | None = None,
    env_extra: dict | None = None,
    cohort: str | None = None,
    observer_files: dict | None = None,
    extra_scenarios_dir: str | None = None,
) -> dict:
    scs = load_scenarios(scenarios_dir, extra_scenarios_dir=extra_scenarios_dir)
    # Load-time validation (M12): a twin assertion naming a twin this runner
    # doesn't know about is an oracle defect, caught BEFORE any scenario in
    # this call runs. This is checked over the FULL, UNFILTERED scenario set
    # (all cohorts) on EVERY run_all call -- like the shape validation in
    # _validate_twin_then -- so a typo'd twin name in a cohort="final"
    # scenario surfaces on the very first dev-cohort run, not only once the
    # sealed final exam eventually runs (which may be never, or only after
    # burning the whole iteration/budget cap). observer_files=None means zero
    # known twins, so ANY twin assertion errors here (correct: none configured).
    known_twins = set(observer_files) if observer_files else set()
    for sc in scs:
        then = sc["then"]
        for key in ("twin_observed", "stdout_echoes_twin"):
            if key in then and then[key]["twin"] not in known_twins:
                raise OracleError(
                    f"{sc['id']}: {key} references unknown twin {then[key]['twin']!r}")
    if cohort is not None:
        scs = [sc for sc in scs if sc["cohort"] == cohort]
    results = [run_scenario(sc, workspace, exec_wrapper, env_extra, observer_files=observer_files)
               for sc in scs]
    return {
        "report_version": "0.1",
        "cohort": cohort if cohort is not None else "all",
        "results": results,
        "all_pass": all(r["pass"] for r in results) if results else True,
        "count": len(results),
    }
