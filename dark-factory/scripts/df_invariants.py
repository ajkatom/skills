"""df_invariants: the FIXED invariant vocabulary for property scenarios (M43a).

WHY this module exists: a `when.property` scenario asserts an INVARIANT over
many generated inputs (df_generate). The invariant comes from HERE — a fixed,
validated vocabulary evaluated over per-case step observations — never
operator- or agent-supplied executable code (same philosophy as the `then`
assertion keys: declarative, no code-eval surface on the verifier side).

Observations are the SAME dicts the existing evaluators consume: a CLI step
observation is {"exit_code": int|None, "stdout": str, "stderr": str}
(run_scenarios.evaluate_then's shape); an HTTP step observation is
{"http_status": int|None, "body": str, "json": parsed|None}
(run_scenarios.evaluate_http's shape). Every invariant dispatches on that
shape per observation, so CLI and HTTP steps mix freely.

REPEATS: `idempotent` and `deterministic` are relations over RE-EXECUTION,
so the runner must execute extra steps. NEEDS_REPEAT declares which
("terminal": re-run the last step once; "all": re-run the whole step list) —
the runner consults it, and the extra observations arrive in
`observations["repeat"]`. A missing/short repeat list is a FAIL (never a
vacuous pass): the invariant cannot hold on evidence that was never gathered.

DISCRIMINATION (`invariant_is_discriminating`): the property analogue of the
M42 sharpness battery. The invariant vocabulary itself is fixed and tested,
but a CONFIGURATION can still be vacuous — e.g. `round_trip` over a var whose
generator can emit the empty string ("" is a substring of every output, so
those cases can never fail). The gate constructs violating observation
batteries the invariant MUST reject and flags any survivor, so a vacuous
property is caught at the M7 pre-build gate, not silently green forever.

Pure, deterministic, stdlib only. Runtime guards `raise` InvariantError
(never bare `assert` — the suite runs under `python -O`).
"""

INVARIANT_NAMES = (
    "round_trip", "idempotent", "deterministic",
    "robust", "never_crashes", "error_contract",
    "monotonic", "sorted",
)

# Aliases: never_crashes IS robust, sorted IS monotonic (the plan names both
# spellings; one implementation each, so behavior can never drift apart).
_CANONICAL = {"never_crashes": "robust", "sorted": "monotonic"}

# Which invariants need the runner to EXECUTE extra (repeat) steps per case.
NEEDS_REPEAT = {"idempotent": "terminal", "deterministic": "all"}

# The stack-trace tell for `robust`/`error_contract`: an app that honors its
# error contract prints a diagnostic, not an interpreter backtrace. One fixed
# marker (CPython's) — other runtimes' crash shapes still surface via exit
# codes / 5xx, this is the belt-and-suspenders for "exit 1 but actually blew
# up".
_TRACEBACK_MARKER = "Traceback (most recent call last"

# Allowed args per canonical invariant name — a FIXED vocabulary like the
# `then` assertion keys; an unknown arg is a validation error, not ignored
# (silently ignoring a typo'd arg would let a misconfigured invariant run
# with default semantics the author didn't intend).
_ALLOWED_ARGS = {
    "round_trip": {"value", "key", "observe_step"},
    "idempotent": set(),
    "deterministic": set(),
    "robust": {"allowed_exits"},
    "error_contract": {"observe_step", "error_contains"},
    "monotonic": {"observe_step", "order"},
}

# M43b: the FIXED concurrency-invariant vocabulary. DISTINCT from
# INVARIANT_NAMES because these are evaluated over a PER-WORKER observation
# LIST (workers that ran the step sequence in parallel), not a single
# {steps, repeat} execution — a different signature (evaluate_concurrency_
# invariant), and a different validator (they couple to the concurrency block).
# A property scenario uses EXACTLY ONE family: a concurrency invariant iff a
# `when.property.concurrency` block is present (cross-checked in run_scenarios).
# No aliases — one spelling each.
CONCURRENCY_INVARIANT_NAMES = (
    "no_lost_update",
    "no_crash_no_hang",
    "idempotent_under_concurrency",
    "serializable_counter",
)

# Allowed args per concurrency invariant (same fail-closed discipline as
# _ALLOWED_ARGS — an unknown arg is a validation error, never ignored).
_CONC_ALLOWED_ARGS = {
    # `value` names the per-worker var carrying each worker's DISTINCT write;
    # it MUST be in per_worker_vars (else every worker writes the same value
    # and a lost update is unobservable — validated below).
    "no_lost_update": {"value", "observe_step"},
    # `allowed_exits` mirrors robust — the set of non-crash exit codes.
    "no_crash_no_hang": {"allowed_exits"},
    "idempotent_under_concurrency": {"observe_step"},
    "serializable_counter": {"observe_step"},
}


class InvariantError(ValueError):
    """A malformed `then.invariant` block. Raised at validation time, never
    mid-run — same fail-closed posture as run_scenarios.OracleError."""


def canonical_name(name: str) -> str:
    return _CANONICAL.get(name, name)


def validate_invariant(inv, generate, n_steps: int, where: str) -> None:
    """Fail-closed shape validation for `then.invariant`.

    Checks: `name` is in the fixed vocabulary; `args` (optional) is an object
    carrying ONLY that invariant's allowed args; every var reference names a
    declared generate var; every `observe_step` indexes a real step. Runs at
    load time (run_scenarios._validate), so a bad invariant is caught before
    any build."""
    if not isinstance(inv, dict):
        raise InvariantError(f"{where}: invariant must be an object")
    unknown = set(inv) - {"name", "args"}
    if unknown:
        raise InvariantError(f"{where}: invariant has unknown key(s) {sorted(unknown)}")
    name = inv.get("name")
    if name not in INVARIANT_NAMES:
        raise InvariantError(
            f"{where}: invariant.name must be one of {list(INVARIANT_NAMES)}, "
            f"got {name!r}")
    canon = canonical_name(name)
    args = inv.get("args", {})
    if not isinstance(args, dict):
        raise InvariantError(f"{where}: invariant.args must be an object")
    bad = set(args) - _ALLOWED_ARGS[canon]
    if bad:
        raise InvariantError(
            f"{where}: invariant {name!r} has unknown arg(s) {sorted(bad)} "
            f"(allowed: {sorted(_ALLOWED_ARGS[canon])})")

    declared = set((generate or {}).get("vars", {}))
    if canon == "round_trip":
        value = args.get("value")
        if not isinstance(value, str) or value not in declared:
            raise InvariantError(
                f"{where}: round_trip requires args.value naming a declared "
                f"generate var, got {value!r}")
        key = args.get("key")
        if key is not None and key not in declared:
            raise InvariantError(
                f"{where}: round_trip args.key {key!r} is not a declared generate var")
    if canon == "robust":
        allowed = args.get("allowed_exits")
        if allowed is not None and (
                not isinstance(allowed, list) or not allowed
                or not all(isinstance(x, int) and not isinstance(x, bool) for x in allowed)):
            raise InvariantError(
                f"{where}: robust args.allowed_exits must be a non-empty list of ints")
    if canon == "error_contract":
        ec = args.get("error_contains")
        if ec is not None and (not isinstance(ec, str) or not ec):
            raise InvariantError(
                f"{where}: error_contract args.error_contains must be a non-empty string")
    if canon == "monotonic":
        order = args.get("order", "asc")
        if order not in ("asc", "desc"):
            raise InvariantError(
                f"{where}: monotonic args.order must be 'asc' or 'desc', got {order!r}")
    if "observe_step" in args:
        step = args["observe_step"]
        if not isinstance(step, int) or isinstance(step, bool) or not (0 <= step < n_steps):
            raise InvariantError(
                f"{where}: args.observe_step must be an int in 0..{n_steps - 1}, "
                f"got {step!r}")


def _is_http_obs(obs: dict) -> bool:
    return "http_status" in obs


def _obs_output(obs: dict) -> str:
    """The comparable textual output of an observation: HTTP body / CLI stdout."""
    return obs.get("body", "") if _is_http_obs(obs) else obs.get("stdout", "")


def _obs_signature(obs: dict):
    """The tuple two observations are compared by for idempotent/deterministic.
    CLI: (exit_code, stdout, stderr). HTTP: (http_status, body) — the parsed
    `json` field is derived from body, so comparing it too would be redundant."""
    if _is_http_obs(obs):
        return ("http", obs.get("http_status"), obs.get("body", ""))
    return ("cli", obs.get("exit_code"), obs.get("stdout", ""), obs.get("stderr", ""))


def _pick_step(steps: list, args: dict):
    """The observation `observe_step` points at (default: the terminal step)."""
    idx = args.get("observe_step", len(steps) - 1)
    if not (0 <= idx < len(steps)):
        return None
    return steps[idx]


def _inv_round_trip(case_vars, observations, args):
    obs = _pick_step(observations["steps"], args)
    if obs is None:
        return False, "observe_step out of range for the recorded steps"
    value = case_vars.get(args["value"], "")
    out = _obs_output(obs)
    if value not in out:
        return False, (f"round_trip: generated value for var {args['value']!r} "
                       f"absent from the observed output")
    return True, ""


def _inv_idempotent(case_vars, observations, args):
    steps = observations["steps"]
    repeat = observations.get("repeat", [])
    if not steps or not repeat:
        # Fail-closed: no repeat evidence => the relation was never tested.
        return False, "idempotent: no repeat observation was recorded"
    a, b = _obs_signature(steps[-1]), _obs_signature(repeat[-1])
    if a != b:
        return False, "idempotent: repeating the terminal step changed the observation"
    return True, ""


def _inv_deterministic(case_vars, observations, args):
    steps = observations["steps"]
    repeat = observations.get("repeat", [])
    if not steps or len(repeat) != len(steps):
        return False, "deterministic: no full second execution was recorded"
    for i, (a, b) in enumerate(zip(steps, repeat)):
        if _obs_signature(a) != _obs_signature(b):
            return False, f"deterministic: step {i} observation differed across executions"
    return True, ""


def _obs_crash_fragment(obs, allowed):
    """The reason ONE observation reads as a crash rather than a clean run, or
    None if it is clean. Extracted from _inv_robust so the M43b concurrency
    invariant `no_crash_no_hang` applies the byte-identical crash criteria (a
    concurrency crash must be judged exactly as a sequential one). The returned
    fragment is suffixed onto a caller-chosen `step N`/`worker N step M` prefix,
    so the M43a `robust:` messages (and the tests matching them) are unchanged."""
    if _is_http_obs(obs):
        status = obs.get("http_status")
        if status is None:
            return "got no HTTP response at all"
        if status >= 500:
            return f"returned HTTP {status}"
        return None
    code = obs.get("exit_code")
    if code is None:
        return "never produced an exit code"
    if allowed is not None:
        if code not in allowed:
            return f"exited {code}, not in allowed_exits"
    elif not (0 <= code < 128):
        # Negative = killed by signal (subprocess convention); >=128 is the
        # shell's signal-death encoding. Either way: a crash, not a clean exit.
        return f"died abnormally (exit {code})"
    if _TRACEBACK_MARKER in obs.get("stderr", ""):
        return "stderr carries an interpreter stack trace"
    return None


def _inv_robust(case_vars, observations, args):
    allowed = args.get("allowed_exits")
    everything = list(observations["steps"]) + list(observations.get("repeat", []))
    for i, obs in enumerate(everything):
        frag = _obs_crash_fragment(obs, allowed)
        if frag is not None:
            return False, f"robust: step {i} {frag}"
    return True, ""


def _inv_error_contract(case_vars, observations, args):
    obs = _pick_step(observations["steps"], args)
    if obs is None:
        return False, "observe_step out of range for the recorded steps"
    contains = args.get("error_contains")
    if _is_http_obs(obs):
        status = obs.get("http_status")
        if status is None:
            return False, "error_contract: no HTTP response at all (crashed, not failed cleanly)"
        if not (400 <= status < 500):
            return False, (f"error_contract: expected a 4xx rejection, got HTTP {status}")
        body = obs.get("body", "")
        if contains is not None:
            if contains not in body:
                return False, "error_contract: 4xx body lacks the declared error marker"
        else:
            json_obs = obs.get("json")
            if not ((isinstance(json_obs, dict) and "error" in json_obs)
                    or "error" in body.lower()):
                return False, "error_contract: 4xx response carries no error indication"
        return True, ""
    code = obs.get("exit_code")
    if code is None:
        return False, "error_contract: step never produced an exit code (crashed/hung)"
    if code == 0:
        return False, "error_contract: malformed input was silently accepted (exit 0)"
    stderr = obs.get("stderr", "")
    if _TRACEBACK_MARKER in stderr:
        return False, "error_contract: rejection is an interpreter stack trace, not a clean error"
    if contains is not None:
        if contains not in stderr:
            return False, "error_contract: stderr lacks the declared error marker"
    elif not stderr.strip():
        return False, "error_contract: non-zero exit but no error message on stderr"
    return True, ""


def _inv_monotonic(case_vars, observations, args):
    obs = _pick_step(observations["steps"], args)
    if obs is None:
        return False, "observe_step out of range for the recorded steps"
    order = args.get("order", "asc")
    if _is_http_obs(obs) and isinstance(obs.get("json"), list):
        items = obs["json"]
    else:
        items = [ln for ln in _obs_output(obs).splitlines() if ln]
    try:
        ordered = sorted(items, reverse=(order == "desc"))
    except TypeError:
        # Unorderable mixed types can never be "sorted" — fail closed.
        return False, "monotonic: observed items are not mutually orderable"
    if items != ordered:
        return False, f"monotonic: observed output is not sorted {order}"
    return True, ""


_EVALUATORS = {
    "round_trip": _inv_round_trip,
    "idempotent": _inv_idempotent,
    "deterministic": _inv_deterministic,
    "robust": _inv_robust,
    "error_contract": _inv_error_contract,
    "monotonic": _inv_monotonic,
}


def evaluate_invariant(inv: dict, case_vars: dict, observations: dict):
    """Evaluate one case: (ok, detail). `observations` = {"steps": [obs,...],
    "repeat": [obs,...]} (repeat empty unless NEEDS_REPEAT asked for it).
    `detail` may reference generated values — it is CONTROL-PLANE-GRADE text
    (counterexample territory) and must never cross the barrier; the runner
    keeps it inside the verifier report only."""
    name = canonical_name(inv["name"])
    fn = _EVALUATORS.get(name)
    if fn is None:
        # Unreachable after validate_invariant, but fail closed anyway — a
        # skipped validation must never become a silent pass.
        raise InvariantError(f"unknown invariant {inv.get('name')!r}")
    return fn(case_vars, observations, inv.get("args", {}))


# --- Discrimination gate (the property analogue of M42 sharpness) -----------


def _cli_obs(exit_code, stdout="", stderr=""):
    return {"exit_code": exit_code, "stdout": stdout, "stderr": stderr}


def _http_obs(status, body="", json_obs=None):
    return {"http_status": status, "body": body, "json": json_obs}


def _tweak(s: str) -> str:
    """A same-length string guaranteed to differ from `s` and (for non-empty
    `s`) not to contain it — mirrors df_gates._tweak_last_char."""
    if not s:
        return "\x01"
    return s[:-1] + ("Y" if s[-1] == "X" else "X")


def _battery(inv: dict, generate: dict):
    """The violating-observation battery for `inv`: a list of
    (kind, case_vars, observations) entries the invariant MUST reject. A
    survivor (invariant accepts one) means the configuration is vacuous on
    that axis. `kind` labels are category names — barrier-safe, never a
    generated value — so they can appear in gate output and author feedback."""
    name = canonical_name(inv["name"])
    args = inv.get("args", {})
    out = []
    if name == "round_trip":
        # Observation-rejection check: given a NON-EMPTY value, an output that
        # does NOT contain it must be rejected (proves the invariant actually
        # inspects the observation). A fixed sentinel value, so this is
        # deterministic and needs no sampling. The COMPLEMENTARY vacuity --
        # "the value var can itself generate '', which every output trivially
        # contains" -- is caught STRUCTURALLY in invariant_is_discriminating
        # (from the generator spec, for every seed), not by hoping a sampled
        # case happened to draw an empty string.
        idx = args.get("observe_step", 0)
        steps = [_cli_obs(0, stdout="")] * (max(idx, 0) + 1)
        sentinel = {args["value"]: "DF_ROUNDTRIP_SENTINEL"}
        out.append(("round_trip:absent_value", sentinel,
                    {"steps": steps, "repeat": []}))
    elif name == "idempotent":
        base = _cli_obs(0, stdout="state=1")
        changed = _cli_obs(0, stdout="state=2")
        out.append(("idempotent:changed_repeat", {},
                    {"steps": [base], "repeat": [changed]}))
        out.append(("idempotent:missing_repeat", {},
                    {"steps": [base], "repeat": []}))
    elif name == "deterministic":
        base = _cli_obs(0, stdout="out-A")
        changed = _cli_obs(0, stdout="out-B")
        out.append(("deterministic:changed_second_pass", {},
                    {"steps": [base], "repeat": [changed]}))
        out.append(("deterministic:missing_repeat", {},
                    {"steps": [base], "repeat": []}))
    elif name == "robust":
        out.append(("robust:crash_none", {},
                    {"steps": [_cli_obs(None)], "repeat": []}))
        out.append(("robust:signal_death", {},
                    {"steps": [_cli_obs(-11)], "repeat": []}))
        out.append(("robust:stack_trace", {},
                    {"steps": [_cli_obs(0, stderr=_TRACEBACK_MARKER + ")\nBoom")],
                     "repeat": []}))
        out.append(("robust:http_500", {},
                    {"steps": [_http_obs(500, body="oops")], "repeat": []}))
        out.append(("robust:http_no_response", {},
                    {"steps": [_http_obs(None)], "repeat": []}))
    elif name == "error_contract":
        out.append(("error_contract:silent_accept", {},
                    {"steps": [_cli_obs(0, stdout="ok")], "repeat": []}))
        out.append(("error_contract:crash", {},
                    {"steps": [_cli_obs(None)], "repeat": []}))
        out.append(("error_contract:stack_trace", {},
                    {"steps": [_cli_obs(1, stderr=_TRACEBACK_MARKER + ")\nBoom")],
                     "repeat": []}))
        out.append(("error_contract:http_ok", {},
                    {"steps": [_http_obs(200, body="{}", json_obs={})], "repeat": []}))
        out.append(("error_contract:http_5xx", {},
                    {"steps": [_http_obs(500, body="boom")], "repeat": []}))
        if args.get("error_contains"):
            out.append(("error_contract:wrong_error", {},
                        {"steps": [_cli_obs(1, stderr=_tweak(args["error_contains"]))],
                         "repeat": []}))
    elif name == "monotonic":
        order = args.get("order", "asc")
        unsorted = "b\na\n" if order == "asc" else "a\nb\n"
        out.append(("monotonic:unsorted", {},
                    {"steps": [_cli_obs(0, stdout=unsorted)], "repeat": []}))
    return out


def _value_var_can_emit_empty(generate: dict, var_name: str) -> bool:
    """True iff the declared generator for `var_name` CAN produce the empty
    string. Structural (reads the SPEC, not sampled output), so the verdict is
    the same for every seed:
      - string with min_len == 0    -> a zero-length draw is possible
      - choice whose options list contains ""
      - malformed (ANY base)        -> its fixed `empty` variant always yields ""
      - int / json                  -> str(int)/json.dumps() is never "" (a JSON
                                       empty-string scalar serializes to '\"\"',
                                       length 2), so these can never be empty.
    An unknown/missing var is treated as "cannot" (validation already requires
    round_trip's value to be a declared var; a defensive False keeps this a
    pure predicate)."""
    spec = (generate or {}).get("vars", {}).get(var_name)
    if not isinstance(spec, dict):
        return False
    kind = spec.get("kind")
    if kind == "string":
        return spec.get("min_len", 0) == 0
    if kind == "choice":
        return "" in (spec.get("options") or [])
    if kind == "malformed":
        return True
    return False


def _var_can_emit_distinct(spec) -> bool:
    """True iff the declared generator for a var CAN produce >=2 DISTINCT
    values. Structural (reads the SPEC, not sampled), so the verdict is the same
    for EVERY seed. A ZERO-ENTROPY domain yields the SAME value for every
    worker — a per-worker "write identity" that is not actually distinct, which
    makes a distinctness-dependent invariant (no_lost_update: N workers writing
    N distinct values) VACUOUS: `written` collapses to one element, so a
    genuinely-racy candidate can never be caught (a false GREEN in a verifier).
      - int      -> >=2 iff min < max
      - string   -> >=2 iff max_len >= 1 (any 1-char draw picks from a charset
                    of >=2 symbols, and min_len==0 adds "" as a second value);
                    max_len == 0 means only "" is possible -> ONE value
      - choice   -> >=2 iff the options have >=2 DISTINCT entries
      - json     -> always >=2 (the scalar menu alone has 4+ values)
      - malformed-> always >=2 (the variant menu produces many)
    An unknown/missing var is treated as "cannot" (a defensive False keeps this
    a pure predicate; validation already requires value to be a declared var)."""
    if not isinstance(spec, dict):
        return False
    kind = spec.get("kind")
    if kind == "int":
        return spec.get("min") < spec.get("max")
    if kind == "string":
        return spec.get("max_len", 0) >= 1
    if kind == "choice":
        return len(set(spec.get("options") or [])) >= 2
    if kind in ("json", "malformed"):
        return True
    return False


def _structural_checks(inv: dict, generate: dict):
    """Vacuity checks derived from the GENERATOR SPEC rather than a sampled
    observation battery — for vacuities a sampled battery cannot RELIABLY see.
    Yields (kind, is_vacuous) pairs; is_vacuous True means the configuration is
    inert on that axis (a survivor). Deterministic for every seed.

    Today the one such check is round_trip over a value var that can emit "":
    "" is a substring of EVERY output, so those cases can never fail. A sampled
    sweep of the first N cases misses this whenever N draws happen to be
    non-empty (empty strings are rare for a moderate max_len), so it must be a
    STRUCTURAL determination, not a probabilistic one."""
    if canonical_name(inv["name"]) == "round_trip":
        value_var = inv.get("args", {}).get("value", "")
        yield ("round_trip:empty_value",
               _value_var_can_emit_empty(generate, value_var))


def invariant_is_discriminating(inv: dict, generate: dict) -> dict:
    """The property analogue of df_gates.sharpness: run the violating battery
    (+ the structural vacuity checks) and report
    {"passed", "killed", "total", "survivors"} (same shape, so the M7 gate and
    author feedback treat property scenarios uniformly). `passed` iff EVERY
    violation was rejected AND no structural vacuity was found. Fully
    deterministic: the battery is fixed sentinels and the structural checks
    read the generator spec, so the verdict is identical for every seed."""
    survivors = []
    killed = 0
    for kind, case_vars, observations in _battery(inv, generate):
        ok, _detail = evaluate_invariant(inv, case_vars, observations)
        if ok:
            survivors.append(kind)
        else:
            killed += 1
    total = killed + len(survivors)
    # Structural vacuity (fixes the probabilistic round_trip sampling): a
    # count toward `killed` when the check passes (the gate DID verify
    # non-vacuity), a survivor when it fails -- for every seed, not ~53% of them.
    for kind, is_vacuous in _structural_checks(inv, generate):
        total += 1
        if is_vacuous:
            survivors.append(kind)
        else:
            killed += 1
    return {
        "passed": not survivors,
        "killed": killed,
        "total": total,
        "survivors": sorted(set(survivors)),
    }


# ============================================================================
# M43b — the concurrency-invariant family (over PER-WORKER observation lists)
# ============================================================================
# WHY a separate family: a concurrency invariant judges the JOINT outcome of N
# workers that ran the step sequence in PARALLEL against the same candidate
# state — lost updates, corruption/crash under parallelism, non-idempotent
# concurrent retries. The evidence is therefore a LIST of per-worker results,
# not one execution. A per-worker result is:
#     {"steps": [obs, ...],         # this worker's step observations
#      "taxonomy": None|"timeout"|"crash",   # did the worker COMPLETE?
#      "vars": {var: str, ...}}     # this worker's substituted vars
# `taxonomy` is the runner's honest verdict: a worker killed at the per-case
# deadline is "timeout" (a HANG), a worker whose step never launched/answered
# is "crash". `no_crash_no_hang` is the invariant that turns those into a
# failure; the others require taxonomy None first (a worker that did not finish
# cannot be reasoned about as serialized/merged/consistent).
#
# ONE STRIKE: the runner stops at the FIRST attempt (across all cases) whose
# invariant returns not-ok — a single observed violation IS a real bug. A PASS
# is PROBABILISTIC detection (absence of an observed race is not proof of
# race-freedom); workers x attempts x cases quantify the effort and are
# recorded in the manifest. That honesty is documented, not hidden.


def validate_concurrency_invariant(inv, concurrency, generate, n_steps, where):
    """Fail-closed validation for a `then.invariant` that names a CONCURRENCY
    invariant (called by run_scenarios when a `when.property.concurrency` block
    is present). Mirrors validate_invariant, plus the coupling to the
    concurrency block: `no_lost_update` requires `args.value` to name a var
    that is BOTH declared AND in per_worker_vars — otherwise every worker
    writes the same value and a lost update can never be observed (a vacuous
    configuration, rejected at load, not silently green)."""
    if not isinstance(inv, dict):
        raise InvariantError(f"{where}: invariant must be an object")
    unknown = set(inv) - {"name", "args"}
    if unknown:
        raise InvariantError(f"{where}: invariant has unknown key(s) {sorted(unknown)}")
    name = inv.get("name")
    if name not in CONCURRENCY_INVARIANT_NAMES:
        raise InvariantError(
            f"{where}: with a concurrency block, invariant.name must be one of "
            f"{list(CONCURRENCY_INVARIANT_NAMES)}, got {name!r}")
    args = inv.get("args", {})
    if not isinstance(args, dict):
        raise InvariantError(f"{where}: invariant.args must be an object")
    bad = set(args) - _CONC_ALLOWED_ARGS[name]
    if bad:
        raise InvariantError(
            f"{where}: invariant {name!r} has unknown arg(s) {sorted(bad)} "
            f"(allowed: {sorted(_CONC_ALLOWED_ARGS[name])})")

    if "observe_step" in args:
        step = args["observe_step"]
        if not isinstance(step, int) or isinstance(step, bool) or not (0 <= step < n_steps):
            raise InvariantError(
                f"{where}: args.observe_step must be an int in 0..{n_steps - 1}, "
                f"got {step!r}")

    if name == "no_crash_no_hang":
        allowed = args.get("allowed_exits")
        if allowed is not None and (
                not isinstance(allowed, list) or not allowed
                or not all(isinstance(x, int) and not isinstance(x, bool) for x in allowed)):
            raise InvariantError(
                f"{where}: no_crash_no_hang args.allowed_exits must be a non-empty "
                f"list of ints")

    if name == "no_lost_update":
        declared = set((generate or {}).get("vars", {}))
        pwv = set((concurrency or {}).get("per_worker_vars", []))
        value = args.get("value")
        if not isinstance(value, str) or value not in declared:
            raise InvariantError(
                f"{where}: no_lost_update requires args.value naming a declared "
                f"generate var, got {value!r}")
        if value not in pwv:
            raise InvariantError(
                f"{where}: no_lost_update args.value {value!r} must be in "
                f"per_worker_vars (else every worker writes the same value and a "
                f"lost update is unobservable)")
        # Being in per_worker_vars is NOT enough: a ZERO-ENTROPY domain (a
        # min==max int, a single-distinct-option choice, a max_len==0 string)
        # makes every worker's DISTINCT draw identical, so `written` collapses
        # to one value and a genuinely-racy candidate PASSES vacuously — a
        # false GREEN. Reject it at LOAD (structural, every-seed), the
        # belt-and-suspenders complement to the gate's discrimination survivor.
        if not _var_can_emit_distinct((generate or {}).get("vars", {}).get(value)):
            raise InvariantError(
                f"{where}: no_lost_update args.value {value!r} has a zero-entropy "
                f"domain (cannot produce >=2 distinct per-worker writes) — a lost "
                f"update would be unobservable")


def _worker_step_obs(worker, args):
    """The observation `observe_step` points at within ONE worker's step list
    (default: that worker's terminal step). None if the worker has no step at
    that index (e.g. it crashed before reaching it)."""
    steps = worker.get("steps") or []
    if not steps:
        return None
    idx = args.get("observe_step", len(steps) - 1)
    if not (0 <= idx < len(steps)):
        return None
    return steps[idx]


def _parse_counter(text: str):
    """The integer a `serializable_counter` step printed: the LAST non-empty
    line parsed as an int (a stub may print a banner then the value). None if
    there is no parseable integer — fail-closed, never a vacuous pass."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return None
    try:
        return int(lines[-1])
    except (TypeError, ValueError):
        return None


def _conc_no_crash_no_hang(case_vars, workers, args):
    allowed = args.get("allowed_exits")
    for wi, worker in enumerate(workers):
        tax = worker.get("taxonomy")
        if tax is not None:
            # A hang (timeout) or a failed/dead step — the concurrency bug this
            # invariant exists to catch. "timeout" is a HANG killed at the
            # per-case deadline (never an orphan; the runner reaps it).
            return False, f"no_crash_no_hang: worker {wi} did not complete ({tax})"
        for si, obs in enumerate(worker.get("steps") or []):
            frag = _obs_crash_fragment(obs, allowed)
            if frag is not None:
                return False, f"no_crash_no_hang: worker {wi} step {si} {frag}"
    return True, ""


def _conc_serializable_counter(case_vars, workers, args):
    n = len(workers)
    values = []
    for wi, worker in enumerate(workers):
        if worker.get("taxonomy") is not None:
            return False, (f"serializable_counter: worker {wi} did not complete "
                           f"({worker.get('taxonomy')})")
        obs = _worker_step_obs(worker, args)
        if obs is None:
            return False, f"serializable_counter: worker {wi} has no observed step"
        value = _parse_counter(_obs_output(obs))
        if value is None:
            return False, f"serializable_counter: worker {wi} printed no integer counter"
        values.append(value)
    # N concurrent increments must produce N DISTINCT contiguous values (a
    # permutation of [min .. min+N-1]). A DUPLICATE means two workers read the
    # same prior value and both wrote value+1 -> a lost update. A GAP means a
    # write vanished. Both are the classic read-modify-write race.
    if len(set(values)) != n:
        return False, "serializable_counter: duplicate counter value(s) — a lost update"
    if max(values) - min(values) != n - 1:
        return False, "serializable_counter: counter values are not contiguous — a write vanished"
    return True, ""


def _conc_no_lost_update(case_vars, workers, args):
    value_var = args["value"]
    written = set()
    for worker in workers:
        if worker.get("taxonomy") is not None:
            return False, (f"no_lost_update: a worker did not complete "
                           f"({worker.get('taxonomy')})")
        v = worker.get("vars", {}).get(value_var, "")
        if v:
            written.add(v)
    if not written:
        return False, "no_lost_update: no worker wrote a non-empty value"
    # The strongest OBSERVABLE that no update was lost: SOME worker's terminal
    # read reflected ALL distinct writes at once (the last serialized writer
    # sees every prior commit). Under a read-modify-write race each writer
    # overwrites the others, so NO single read ever contains them all -> the
    # high-water mark stays below the write count -> a lost update. A torn /
    # empty read also fails (a partial value is not a full written value).
    best = 0
    for worker in workers:
        obs = _worker_step_obs(worker, args)
        if obs is None:
            continue
        read_lines = {ln for ln in _obs_output(obs).splitlines() if ln}
        best = max(best, len(written & read_lines))
    if best != len(written):
        return False, ("no_lost_update: no observation reflected all concurrent "
                       "writes at once — an update was lost or torn")
    return True, ""


def _conc_idempotent_under_concurrency(case_vars, workers, args):
    signatures = set()
    for wi, worker in enumerate(workers):
        if worker.get("taxonomy") is not None:
            return False, (f"idempotent_under_concurrency: worker {wi} did not "
                           f"complete ({worker.get('taxonomy')})")
        obs = _worker_step_obs(worker, args)
        if obs is None:
            return False, f"idempotent_under_concurrency: worker {wi} has no observed step"
        signatures.add(_obs_signature(obs))
    # N workers ran the SAME logical operation. Idempotent-under-concurrency
    # means the system CONVERGED: every worker observed the SAME terminal
    # result regardless of interleaving. Divergent observations (one sees
    # "created", another an accumulated duplicate / an error) = a
    # non-idempotent concurrent handler.
    if len(signatures) > 1:
        return False, ("idempotent_under_concurrency: workers observed divergent "
                       "results — the concurrent operation is not idempotent")
    return True, ""


_CONC_EVALUATORS = {
    "no_lost_update": _conc_no_lost_update,
    "no_crash_no_hang": _conc_no_crash_no_hang,
    "idempotent_under_concurrency": _conc_idempotent_under_concurrency,
    "serializable_counter": _conc_serializable_counter,
}


def evaluate_concurrency_invariant(inv: dict, case_vars: dict,
                                   worker_observations: list, args: dict):
    """Evaluate one (case, attempt): (ok, detail) over the PER-WORKER
    observation list. `detail` may reference generated values — CONTROL-PLANE
    grade, exactly like evaluate_invariant's — and must never cross the
    barrier; the runner keeps it inside the verifier report only."""
    name = inv["name"]
    fn = _CONC_EVALUATORS.get(name)
    if fn is None:
        # Unreachable after validation, but fail closed — a skipped validation
        # must never become a silent pass.
        raise InvariantError(f"unknown concurrency invariant {name!r}")
    return fn(case_vars, worker_observations, args or {})


# --- Concurrency discrimination (the property analogue, over worker sets) ----


def _worker(steps, taxonomy=None, vars=None):
    return {"steps": list(steps), "taxonomy": taxonomy, "vars": dict(vars or {})}


def _concurrency_battery(inv: dict):
    """The violating PER-WORKER batteries a concurrency invariant MUST reject.
    A survivor (the invariant accepts one) means the configuration is vacuous.
    `kind` labels are barrier-safe category names, never a generated value."""
    name = inv["name"]
    args = inv.get("args", {})
    out = []
    if name == "no_crash_no_hang":
        clean = _worker([_cli_obs(0, stdout="ok")])
        out.append(("no_crash_no_hang:hang",
                    {}, [clean, _worker([], taxonomy="timeout")]))
        out.append(("no_crash_no_hang:crash_taxonomy",
                    {}, [clean, _worker([], taxonomy="crash")]))
        out.append(("no_crash_no_hang:no_exit",
                    {}, [clean, _worker([_cli_obs(None)])]))
        out.append(("no_crash_no_hang:signal_death",
                    {}, [clean, _worker([_cli_obs(-11)])]))
        out.append(("no_crash_no_hang:stack_trace",
                    {}, [clean, _worker([_cli_obs(0, stderr=_TRACEBACK_MARKER + ")\nBoom")])]))
        out.append(("no_crash_no_hang:http_500",
                    {}, [clean, _worker([_http_obs(500, body="oops")])]))
    elif name == "serializable_counter":
        out.append(("serializable_counter:duplicate", {},
                    [_worker([_cli_obs(0, stdout="1")]),
                     _worker([_cli_obs(0, stdout="1")])]))
        out.append(("serializable_counter:gap", {},
                    [_worker([_cli_obs(0, stdout="1")]),
                     _worker([_cli_obs(0, stdout="3")])]))
        out.append(("serializable_counter:non_integer", {},
                    [_worker([_cli_obs(0, stdout="x")]),
                     _worker([_cli_obs(0, stdout="y")])]))
        out.append(("serializable_counter:incomplete_worker", {},
                    [_worker([_cli_obs(0, stdout="1")]),
                     _worker([], taxonomy="timeout")]))
    elif name == "no_lost_update":
        value_var = args.get("value", "v")
        wa = _worker([_cli_obs(0, stdout="DF_A")], vars={value_var: "DF_A"})
        wb = _worker([_cli_obs(0, stdout="DF_B")], vars={value_var: "DF_B"})
        # Each read reflects only its OWN write -> high-water mark 1 < 2 writes.
        out.append(("no_lost_update:lost", {}, [wa, wb]))
        # A worker that never finished.
        out.append(("no_lost_update:incomplete_worker", {},
                    [wa, _worker([], taxonomy="crash", vars={value_var: "DF_B"})]))
        # Every read empty (torn/absent) -> nothing merged.
        out.append(("no_lost_update:empty_reads", {},
                    [_worker([_cli_obs(0, stdout="")], vars={value_var: "DF_A"}),
                     _worker([_cli_obs(0, stdout="")], vars={value_var: "DF_B"})]))
    elif name == "idempotent_under_concurrency":
        out.append(("idempotent_under_concurrency:divergent", {},
                    [_worker([_cli_obs(0, stdout="X")]),
                     _worker([_cli_obs(0, stdout="Y")])]))
        out.append(("idempotent_under_concurrency:incomplete_worker", {},
                    [_worker([_cli_obs(0, stdout="X")]),
                     _worker([], taxonomy="crash")]))
    return out


def _concurrency_structural_checks(inv: dict, generate: dict):
    """Vacuity checks derived from the GENERATOR SPEC (not a synthetic battery)
    — the concurrency analogue of _structural_checks, and the fix for the
    battery's blind spot: the fixed battery hardcodes DISTINCT worker values, so
    it can never see that the REAL per-worker generator produces IDENTICAL ones.
    Yields (kind, is_vacuous); is_vacuous True = a survivor. Deterministic for
    every seed.

    no_lost_update over a value var with a ZERO-ENTROPY domain (min==max int,
    single-distinct-option choice, max_len==0 string) is vacuous: every worker
    writes the same value, `written` has one element, and a genuinely-racy
    candidate can never be caught. This must be STRUCTURAL (read the spec), not
    sampled, so it is flagged for EVERY seed."""
    if inv["name"] == "no_lost_update":
        value_var = inv.get("args", {}).get("value", "")
        spec = (generate or {}).get("vars", {}).get(value_var)
        yield ("no_lost_update:degenerate_domain", not _var_can_emit_distinct(spec))


def concurrency_invariant_is_discriminating(inv: dict, generate: dict) -> dict:
    """The concurrency analogue of invariant_is_discriminating: run the
    violating per-worker battery PLUS the generator-spec structural vacuity
    checks, and report {passed, killed, total, survivors} (same shape, so the
    M7 gate and author feedback treat every property kind uniformly). `passed`
    iff EVERY violation was rejected AND no structural vacuity was found.

    `generate` is REQUIRED (threaded through df_gates.sharpness_scenario like
    the M43a path) — without it the degenerate-domain vacuity that the fixed
    battery structurally cannot see (it hardcodes distinct worker values) would
    ride green. Fully deterministic: the battery is fixed synthetic worker sets
    and the structural checks read the spec, so the verdict needs no seed."""
    survivors = []
    killed = 0
    for kind, case_vars, workers in _concurrency_battery(inv):
        ok, _detail = evaluate_concurrency_invariant(inv, case_vars, workers,
                                                     inv.get("args", {}))
        if ok:
            survivors.append(kind)
        else:
            killed += 1
    total = killed + len(survivors)
    # Structural vacuity (the fix for a false GREEN the synthetic battery cannot
    # see): a count toward `killed` when the check passes (the gate DID verify
    # non-vacuity), a survivor when it fails — for every seed.
    for kind, is_vacuous in _concurrency_structural_checks(inv, generate):
        total += 1
        if is_vacuous:
            survivors.append(kind)
        else:
            killed += 1
    return {
        "passed": not survivors,
        "killed": killed,
        "total": total,
        "survivors": sorted(set(survivors)),
    }
