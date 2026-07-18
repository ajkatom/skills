"""Pre-build gate logic (M7). Stdlib only, pure/unit-testable.

Sharpness (M42 Task 2, generalizing M7/M20's single-mutant check): a
scenario's `then` is "sharp" iff it rejects a BATTERY of near-miss
mutant OBSERVATIONS -- one per asserted dimension -- not merely a single
synthetic garbage output. The old `is_discriminating` built ONE compound
mutant that perturbed EVERY channel at once; a `then` passed as long as
ANY channel differed. That let an inert sub-assertion ride along: e.g.
`{"exit_code": 0, "stdout_contains": ""}` passed (the mutant also flipped
the exit code, so evaluate_then returned "wrong_exit_code"), even though
the stdout check asserts nothing. `sharpness` ISOLATES each asserted
dimension (mutating only that channel, holding the others at values that
satisfy the `then`) so a `then` must be independently discriminating on
EVERY assertion it makes. HONEST SCOPE (documented in
references/scenario-adequacy.md, not overclaimed): this proves the
scenario's ASSERTION is sharp against wrong OBSERVATIONS -- it mutates the
observation deterministically with NO build. It is NOT full code-mutation
testing of the built artifact (mutate the app, re-run) -- that is
language-specific and a heavier future step.

Coverage: `behaviors.json` (control-plane, human-declared) lists the
spec's behavior IDs. `check_coverage` traces each declared behavior to
its dev/final scenarios, reporting gaps (uncovered_dev) and scenarios
whose behavior_id was never declared (orphan_scenarios).

Adequacy (M42 Task 1): `check_adequacy` requires each declared behavior
to be covered by the policy's `required_classes` (happy/boundary/failure),
not just ">=1 scenario" -- structurally killing happy-path-only test sets.
"""
import copy
import json
import os
import re

import df_invariants
import run_scenarios

_BEHAVIOR_ID_RE = re.compile(r"^BHV-[A-Za-z0-9-]{1,32}$")


class GateError(ValueError):
    pass


_HTTP_THEN_KEYS = {"http_status", "body_contains", "json_equals", "json_contains", "json_path"}


def _is_http_then(then: dict) -> bool:
    return bool(set(then) & _HTTP_THEN_KEYS)


def scenario_class(sc: dict) -> str:
    """The scenario's class, defaulting to happy (M42 Task 1). Central so the
    absent-=>happy back-compat rule is stated in exactly one place."""
    return sc.get("class", run_scenarios.DEFAULT_SCENARIO_CLASS)


# --- Sharpness battery (M42 Task 2) ----------------------------------------
# Each helper returns a list of (mutant_kind, observation) pairs for ONE
# asserted dimension. A near-miss mutant SATISFIES every OTHER assertion in
# the `then` (so only the dimension under test is in play) but perturbs the
# dimension under test into a value a genuine assertion of that kind MUST
# reject. A mutant the `then` ACCEPTS (evaluate returns None => pass) is a
# SURVIVOR: proof the assertion is inert on that dimension. Mutant kinds are
# category labels ("stdout_equals:empty") -- barrier-safe (they name a shape,
# never a holdout value), so they can be fed back to an author unchanged.


def _tweak_last_char(s: str) -> str:
    """Return `s` with its final character forced to a different one, so the
    result is guaranteed unequal to `s` AND (for a non-empty `s`) does not
    contain `s` as a substring. Empty `s` -> a single sentinel char (which
    trivially 'contains' the empty string -- that is how an inert
    `contains: ""` assertion is exposed as a survivor)."""
    if not s:
        return "\x01"
    return s[:-1] + ("Y" if s[-1] == "X" else "X")


def _cli_string_mutants(channel_key: str, value: str, is_equals: bool):
    """Near-miss stdout/stderr/body observations for one string assertion.

    A near-miss mutant must genuinely MISS -- i.e. it must be a value the
    assertion SHOULD reject. Two subtleties this handles (both learned from
    over-flagging real scenarios):
      * EQUALS to the EMPTY string (`stderr_equals: ""` = "no error output") is
        a LEGITIMATE assertion, not a tautology: it rejects any non-empty
        output (whitespace/char-changed/appended). The empty-string mutant here
        is the IDENTITY (== the asserted-correct value), NOT a miss, so it is
        NOT generated -- otherwise every honest "assert empty" check would be
        wrongly flagged.
      * CONTAINS the EMPTY string (`stdout_contains: ""`) is a genuine
        tautology -- EVERY output contains "" so NO value can miss it. The
        empty mutant is emitted and (correctly) SURVIVES, flagging it inert.
    `is_equals` also distinguishes *_equals (rejects supersets/reorderings too)
    from *_contains (a superset legitimately still contains the substring, so
    an 'appended noise' mutant is NOT required to die)."""
    prefix = f"{channel_key}_{'equals' if is_equals else 'contains'}"
    mutants = []
    if is_equals:
        norm = run_scenarios._norm(value)
        raw = [
            (f"{prefix}:char_changed", _tweak_last_char(value)),
            (f"{prefix}:whitespace_only", "   " if norm != "   " else "\t\t"),
            (f"{prefix}:appended_noise", value + "\x00EXTRA"),
            (f"{prefix}:empty", ""),
        ]
        if value:
            raw.append((f"{prefix}:truncated", value[:-1]))
        lines = value.split("\n")
        if len(lines) >= 2:
            raw.append((f"{prefix}:wrong_order", "\n".join(reversed(lines))))
        # Equality compares after newline-normalization (run_scenarios._norm),
        # so a "mutant" whose NORMALIZED form equals the asserted value is the
        # IDENTITY, not a miss (e.g. truncating the trailing "\n" _norm strips
        # anyway; or the empty mutant when the value is itself empty). Drop
        # every such identity so the battery only ever tests genuine misses --
        # this is what keeps `stderr_equals: ""` (assert-empty) correctly sharp.
        mutants = [(k, mv) for (k, mv) in raw if run_scenarios._norm(mv) != norm]
    else:  # contains
        # The empty mutant is ALWAYS emitted: for a non-empty `value` it is a
        # genuine miss (empty does not contain value) that a sharp check kills;
        # for value=="" it SURVIVES, which is exactly the tautology signal.
        mutants.append((f"{prefix}:empty", ""))
        if value:
            mutants.append((f"{prefix}:char_changed", _tweak_last_char(value)))
            mutants.append((f"{prefix}:truncated", value[:-1]))
    return mutants


def _ideal_cli_observed(then: dict) -> dict:
    """A base observation that PASSES `then`, used as the fixed backdrop while
    one dimension is mutated. Best-effort for pathological key combinations
    (e.g. stdout_equals + stdout_echoes_twin whose token must live inside the
    fixed stdout) -- an imperfect backdrop can only ever cause a mutant to be
    rejected for a second reason (still 'killed', fail-closed), never a false
    survivor."""
    stdout = then.get("stdout_equals")
    if stdout is None:
        stdout = then.get("stdout_contains", "")
    stderr = then.get("stderr_equals")
    if stderr is None:
        stderr = then.get("stderr_contains", "")
    twin_observations, twin_tokens = {}, {}
    if "twin_observed" in then:
        spec = then["twin_observed"]
        twin_observations[spec["twin"]] = [f"df-ideal {spec['contains']} line"]
    if "stdout_echoes_twin" in then:
        spec = then["stdout_echoes_twin"]
        # The echoed token must appear in stdout to satisfy the assertion. A
        # substring of the pinned stdout is always safe; if stdout is empty
        # (no stdout assertion pins it) inject a token and echo it.
        if stdout:
            token = stdout if len(stdout) <= 32 else stdout[:32]
        else:
            token = "DFTWINECHO"
            stdout = token
        twin_tokens[spec["twin"]] = [token]
    return {
        "exit_code": then.get("exit_code", 0),
        "stdout": stdout,
        "stderr": stderr,
        "twin_observations": twin_observations,
        "twin_tokens": twin_tokens,
    }


def _cli_mutants(then: dict):
    """The full CLI near-miss battery. Each entry is `(kind, obs, target_then)`
    where `target_then` is the `then` REDUCED to just the ONE assertion the
    mutant tests. sharpness() evaluates the mutant against `target_then`, not
    the full `then`, so the kill is ATTRIBUTED to the dimension under test --
    a SIBLING assertion on the same channel (e.g. a sharp `stdout_equals`
    alongside an inert `stdout_contains: ""`) can no longer mask an inert
    sub-assertion by killing the mutant for the wrong reason (the fail-open bug
    a whole-`then` evaluation had)."""
    base = _ideal_cli_observed(then)
    out = []
    if "exit_code" in then:
        target = {"exit_code": then["exit_code"]}
        for kind, code in (
            ("exit_code:plus_one", then["exit_code"] + 1),
            ("exit_code:minus_one", then["exit_code"] - 1),
            ("exit_code:wrong", 999999 if then["exit_code"] != 999999 else -999999),
            ("exit_code:crash_none", None),
        ):
            obs = copy.deepcopy(base)
            obs["exit_code"] = code
            out.append((kind, obs, target))
    for chan in ("stdout", "stderr"):
        for suffix, is_eq in (("equals", True), ("contains", False)):
            key = f"{chan}_{suffix}"
            if key in then:
                target = {key: then[key]}
                for kind, val in _cli_string_mutants(chan, then[key], is_eq):
                    obs = copy.deepcopy(base)
                    obs[chan] = val
                    out.append((kind, obs, target))
    if "twin_observed" in then:
        spec = then["twin_observed"]
        c = spec["contains"]
        target = {"twin_observed": then["twin_observed"]}
        # wrong_token: a recorded line that does NOT contain the asserted
        # substring (tweak the last char -> same length, differs, so `c` can't
        # be a substring). partial_token: only meaningful when len(c) >= 2 --
        # `c[:-1]` is a genuine shorter partial that does not contain `c`; for a
        # single-char `c` there is no partial (and a wrapped one could
        # accidentally re-contain it -- the bug this guard prevents).
        variants = [
            ("twin_observed:no_evidence", {}),
            ("twin_observed:wrong_token", {spec["twin"]: [_tweak_last_char(c)]}),
        ]
        if len(c) >= 2:
            variants.append(("twin_observed:partial_token", {spec["twin"]: [c[:-1]]}))
        for kind, obsdict in variants:
            obs = copy.deepcopy(base)
            obs["twin_observations"] = obsdict
            out.append((kind, obs, target))
    if "stdout_echoes_twin" in then:
        spec = then["stdout_echoes_twin"]
        target = {"stdout_echoes_twin": then["stdout_echoes_twin"]}
        for kind, toks in (
            ("stdout_echoes_twin:no_evidence", {}),
            ("stdout_echoes_twin:token_absent", {spec["twin"]: ["\x00NOTINSTDOUT\x00"]}),
        ):
            obs = copy.deepcopy(base)
            obs["twin_tokens"] = toks
            out.append((kind, obs, target))
    return out


def _json_set_path(root, path: str, value):
    """Set `value` at a dotted+indexed `path` (the accessor grammar of
    run_scenarios._json_path_get), auto-vivifying dicts/lists so the built
    object satisfies a `json_path` assertion. Best-effort (see
    _ideal_cli_observed's note): a path this can't build cleanly only risks a
    mutant dying for a second reason, never a false survivor."""
    tokens = [(m.group(1), m.group(2)) for m in run_scenarios._JSON_PATH_TOKEN_RE.finditer(path)]
    cur = root
    for i, (key, idx) in enumerate(tokens):
        last = i == len(tokens) - 1
        nxt_is_idx = (not last) and tokens[i + 1][1] is not None
        if idx is not None:
            index = int(idx)
            if not isinstance(cur, list):
                return root  # backdrop shape clash; give up (fail-closed downstream)
            while len(cur) <= index:
                cur.append(None)
            if last:
                cur[index] = value
            else:
                if not isinstance(cur[index], (dict, list)):
                    cur[index] = [] if nxt_is_idx else {}
                cur = cur[index]
        else:
            if not isinstance(cur, dict):
                return root
            if last:
                cur[key] = value
            else:
                if not isinstance(cur.get(key), (dict, list)):
                    cur[key] = [] if nxt_is_idx else {}
                cur = cur[key]
    return root


def _ideal_http_json(then: dict):
    """Build a JSON body that satisfies whatever json_* assertions `then`
    makes (or None if it makes none)."""
    if "json_equals" in then:
        return copy.deepcopy(then["json_equals"])
    if "json_contains" not in then and "json_path" not in then:
        return None
    obj: dict = {}
    if "json_contains" in then and isinstance(then["json_contains"], dict):
        obj = copy.deepcopy(then["json_contains"])
    if "json_path" in then and isinstance(then["json_path"], dict):
        for path, value in then["json_path"].items():
            _json_set_path(obj, path, copy.deepcopy(value))
    return obj


def _ideal_http_observed(then: dict) -> dict:
    body = then.get("body_contains", "")
    obs = {
        "http_status": then.get("http_status", 200),
        "body": body,
        "json": _ideal_http_json(then),
    }
    if "twin_observed" in then:
        spec = then["twin_observed"]
        obs["twin_observations"] = {spec["twin"]: [f"df-ideal {spec['contains']} line"]}
    return obs


def _flip_type(value):
    """A same-slot value of a DIFFERENT JSON type (str<->int, etc.), for the
    'type changed' near-miss."""
    if isinstance(value, str):
        return 0 if value != "0" else 1
    if isinstance(value, bool):
        return "true"
    if isinstance(value, (int, float)):
        return "df-str"
    if value is None:
        return "df-nonnull"
    return None  # container -> scalar


def _http_mutants(then: dict):
    """The full HTTP near-miss battery. Like _cli_mutants, each entry is
    `(kind, obs, target_then)` -- the mutant is evaluated against the `then`
    REDUCED to the single assertion under test, so a sharp sibling (e.g. a
    `json_equals` alongside an inert `body_contains: ""`) cannot mask an inert
    sub-assertion. The one shared `json:not_parseable` mutant targets ALL json
    keys together (they all read observed["json"]; a null body must fail every
    one) -- it is a robustness check, never the inert-exposing mutant."""
    base = _ideal_http_observed(then)
    out = []
    if "http_status" in then:
        s = then["http_status"]
        target = {"http_status": then["http_status"]}
        for kind, code in (
            ("http_status:plus_one", s + 1),
            ("http_status:minus_one", s - 1),
            ("http_status:nearby_500", 500 if s != 500 else 502),
            ("http_status:crash_none", None),
        ):
            obs = copy.deepcopy(base)
            obs["http_status"] = code
            out.append((kind, obs, target))
    if "body_contains" in then:
        target = {"body_contains": then["body_contains"]}
        for kind, val in _cli_string_mutants("body", then["body_contains"], is_equals=False):
            obs = copy.deepcopy(base)
            obs["body"] = val
            out.append((kind, obs, target))
    json_keys = [k for k in ("json_equals", "json_contains", "json_path") if k in then]
    if json_keys:
        # A json_* assertion against a non-JSON body must always fail. Target
        # every json key together (a null body fails each).
        obs = copy.deepcopy(base)
        obs["json"] = None
        out.append(("json:not_parseable", obs, {k: then[k] for k in json_keys}))
    if "json_equals" in then:
        target = {"json_equals": then["json_equals"]}
        for kind, obj in _json_dict_mutants(then["json_equals"], strict=True):
            obs = copy.deepcopy(base)
            obs["json"] = obj
            out.append((f"json_equals:{kind}", obs, target))
    if "json_contains" in then:
        target = {"json_contains": then["json_contains"]}
        for kind, obj in _json_dict_mutants(then["json_contains"], strict=False):
            obs = copy.deepcopy(base)
            obs["json"] = obj
            out.append((f"json_contains:{kind}", obs, target))
    if "json_path" in then:
        target = {"json_path": then["json_path"]}
        for kind, obj in _json_path_mutants(then["json_path"]):
            obs = copy.deepcopy(base)
            obs["json"] = obj
            out.append((f"json_path:{kind}", obs, target))
    if "twin_observed" in then:
        spec = then["twin_observed"]
        c = spec["contains"]
        target = {"twin_observed": then["twin_observed"]}
        obs = copy.deepcopy(base)
        obs["twin_observations"] = {}
        out.append(("twin_observed:no_evidence", obs, target))
        obs2 = copy.deepcopy(base)
        obs2["twin_observations"] = {spec["twin"]: [_tweak_last_char(c)]}
        out.append(("twin_observed:wrong_token", obs2, target))
    return out


def _json_dict_mutants(expected: dict, strict: bool):
    """Near-miss JSON bodies for a json_equals (strict) / json_contains
    (subset) assertion. For subset (`strict=False`) an EXTRA field is NOT a
    required kill (the subset still matches), mirroring the string
    contains/equals split."""
    out = []
    if not isinstance(expected, dict) or not expected:
        # A non-dict or EMPTY expected is degenerate: json_contains {} is a
        # vacuous subset of everything (survivor => flagged as inert); an
        # empty json_equals {} still rejects any non-empty body (handled by
        # the extra-field mutant below).
        out.append(("value_changed", {"__df_mutant__": "x"}))
        return out
    keys = list(expected.keys())
    k0 = keys[0]
    changed = copy.deepcopy(expected)
    changed[k0] = _mutate_scalar(changed[k0])
    out.append(("value_changed", changed))
    removed = copy.deepcopy(expected)
    del removed[k0]
    out.append(("key_removed", removed))
    flipped = copy.deepcopy(expected)
    flipped[k0] = _flip_type(flipped[k0])
    out.append(("type_changed", flipped))
    if strict:
        extra = copy.deepcopy(expected)
        extra["__df_extra__"] = "df"
        out.append(("extra_field", extra))
    return out


def _json_path_mutants(pathmap: dict):
    out = []
    if not isinstance(pathmap, dict) or not pathmap:
        out.append(("value_changed", {"__df_mutant__": "x"}))
        return out
    path0 = next(iter(pathmap))
    expected0 = pathmap[path0]
    changed = _ideal_http_json({"json_path": pathmap})
    _json_set_path(changed, path0, _mutate_scalar(expected0))
    out.append(("value_changed", changed))
    flipped = _ideal_http_json({"json_path": pathmap})
    _json_set_path(flipped, path0, _flip_type(expected0))
    out.append(("type_changed", flipped))
    out.append(("missing", {}))  # empty object -> the path resolves nowhere
    return out


def _mutate_scalar(value):
    """A value of the SAME type but different (for the 'value changed' near
    miss), so a strict/subset match on that key fails without a type flip."""
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value + 1
    if isinstance(value, str):
        return _tweak_last_char(value)
    if value is None:
        return "df-was-null"
    if isinstance(value, list):
        return value + ["__df__"]
    if isinstance(value, dict):
        return {**value, "__df__": "x"}
    return "__df__"


def sharpness(then: dict) -> dict:
    """Run the near-miss battery for `then` and report sharpness.

    Returns {"passed": bool, "killed": int, "total": int,
             "survivors": [mutant_kind, ...]}. `passed` is True iff EVERY
    mutant was rejected (killed) -- i.e. the `then` is independently
    discriminating on every dimension it asserts. `survivors` (sorted,
    de-duped) are the mutant KINDS the `then` accepted; empty iff passed.
    Deterministic, stdlib-only, NO build (mutates the observation, reusing
    run_scenarios.evaluate_then/evaluate_http)."""
    if _is_http_then(then):
        mutants = _http_mutants(then)
        evaluate = run_scenarios.evaluate_http
    else:
        mutants = _cli_mutants(then)
        evaluate = run_scenarios.evaluate_then
    survivors = []
    killed = 0
    for kind, obs, target_then in mutants:
        # Evaluate against `target_then` (the `then` reduced to the ONE
        # assertion under test), NOT the full `then` -- so the kill is
        # attributed to that assertion. Evaluating the full `then` would let a
        # sharp SIBLING assertion on the same channel kill the mutant and mask
        # an inert co-assertion (fail-open). None => the assertion ACCEPTED the
        # near-miss => not sharp on this axis => survivor.
        if evaluate(target_then, obs) is None:
            survivors.append(kind)
        else:
            killed += 1
    return {
        "passed": not survivors,
        "killed": killed,
        "total": len(mutants),
        "survivors": sorted(set(survivors)),
    }


def is_discriminating(then: dict) -> bool:
    """Back-compat shim (M42): now the battery-backed sharpness verdict. A
    `then` is discriminating iff it is sharp on EVERY asserted dimension. Kept
    so any caller/test that asks the boolean question still works, while the
    underlying check is the strengthened battery."""
    return sharpness(then)["passed"]


def sharpness_scenario(sc: dict) -> dict:
    """Scenario-level sharpness dispatch (M43a). A run/http scenario's
    sharpness is the `then` mutant battery above. A PROPERTY scenario's
    sharpness is INVARIANT DISCRIMINATION (df_invariants) -- the invariant
    must reject a constructed violating-observation battery, so a vacuous
    (always-true) configuration (e.g. round_trip over a var that can generate
    the empty string) is gate-flagged, not silently green. Discrimination
    needs the `generate` spec (the round_trip vacuity sweep samples the
    scenario's own seeded cases), which is why this dispatch is
    scenario-level, not then-level. Same report shape either way
    ({passed, killed, total, survivors}), so the M7 gate and author feedback
    treat every scenario kind uniformly."""
    if "property" in sc.get("when", {}):
        inv = sc["then"]["invariant"]
        # M43b: a concurrency property's sharpness is CONCURRENCY invariant
        # discrimination (a violating per-worker battery the invariant must
        # reject — a lost update, a hang, a torn read), so a vacuous
        # concurrency invariant is gate-flagged just like a vacuous M43a one.
        if inv["name"] in df_invariants.CONCURRENCY_INVARIANT_NAMES:
            # Pass `generate` (like the M43a path) so the degenerate-domain
            # vacuity the synthetic battery cannot see (a zero-entropy
            # per-worker value var -> identical writes -> a genuinely-racy
            # candidate false-passes no_lost_update) is gate-flagged.
            return df_invariants.concurrency_invariant_is_discriminating(
                inv, sc["when"]["property"]["generate"])
        return df_invariants.invariant_is_discriminating(
            inv, sc["when"]["property"]["generate"])
    return sharpness(sc["then"])


def validate_oracle(scenarios: list) -> list[str]:
    """Return the sorted list of scenario ids whose oracle is NOT sharp (a
    near-miss mutant / violating observation survived). Same signature +
    fail-closed role as before; the check underneath is the M42 battery for
    run/http scenarios and (M43a) invariant discrimination for property
    scenarios."""
    return sorted(sc["id"] for sc in scenarios if not sharpness_scenario(sc)["passed"])


def sharpness_survivors(scenarios: list) -> dict:
    """id -> sorted survivor mutant-kinds, for every scenario that is NOT sharp
    (barrier-safe category labels only). Empty dict iff all sharp."""
    out = {}
    for sc in scenarios:
        rep = sharpness_scenario(sc)
        if not rep["passed"]:
            out[sc["id"]] = rep["survivors"]
    return out


def sharpness_manifest(scenarios: list) -> dict:
    """The auditable "how sharp were the checks" summary for the manifest:
    scenario count, the WEAKEST kill count seen, and the ids of any scenarios
    that still have survivors (empty on a passing gate, since the gate refuses
    to build otherwise)."""
    reports = {sc["id"]: sharpness_scenario(sc) for sc in scenarios}
    min_killed = min((r["killed"] for r in reports.values()), default=0)
    weakest = sorted(i for i, r in reports.items() if not r["passed"])
    return {
        "scenarios": len(scenarios),
        "min_killed": min_killed,
        "weakest": weakest,
    }


# --- Adequacy: class-typed coverage (M42 Task 1) ---------------------------

def default_adequacy_policy() -> dict:
    """Today's back-compat policy: happy-only, one scenario per class. Every
    pre-M42 scenario (implicitly happy) satisfies it, so absent config the
    adequacy gate is a no-op."""
    return {"required_classes": ["happy"], "min_per_class": 1}


def check_adequacy(behaviors: list[dict], scenarios: list[dict], policy: dict) -> dict:
    """Per-behavior class coverage against `policy` (required_classes +
    min_per_class). A behavior is adequately covered iff, for EACH required
    class, at least `min_per_class` scenarios of that class name it. The gate
    PASSES iff under_covered == [] (enforced by the caller, not here).

    Only scenarios whose behavior_id is DECLARED contribute (orphans are the
    coverage gate's concern, not adequacy's). A scenario with no `class`
    counts as happy (scenario_class). Property scenarios (M43a) count toward
    class coverage exactly like run/http ones -- a fuzz/robustness property is
    naturally a `failure`/`boundary` scenario, so a policy requiring those
    classes is satisfiable by properties. Report is barrier-safe: behavior
    ids + class names + integer counts only, never any `then` content."""
    required = list(policy.get("required_classes") or ["happy"])
    min_per = int(policy.get("min_per_class", 1))
    declared_ids = {b["id"] for b in behaviors}

    per_behavior = {bid: {cls: 0 for cls in run_scenarios.SCENARIO_CLASSES}
                    for bid in declared_ids}
    for sc in scenarios:
        bid = sc.get("behavior_id")
        if bid not in declared_ids:
            continue
        per_behavior[bid][scenario_class(sc)] += 1

    under_covered = []
    for bid in sorted(declared_ids):
        missing = [cls for cls in required if per_behavior[bid].get(cls, 0) < min_per]
        if missing:
            under_covered.append({"behavior": bid, "missing": missing})

    return {
        "checked": True,
        "required_classes": required,
        "min_per_class": min_per,
        "per_behavior_class_coverage": {bid: per_behavior[bid] for bid in sorted(declared_ids)},
        "under_covered": under_covered,
    }


def load_behaviors(control_root: str) -> list[dict] | None:
    """Load + validate `<control_root>/behaviors.json` if present.

    Returns the `behaviors` list, or None if the file is absent (coverage
    is optional). Raises GateError on any malformed content.
    """
    path = os.path.join(control_root, "behaviors.json")
    if not os.path.exists(path):
        return None

    with open(path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise GateError(f"behaviors.json is not valid JSON: {e}") from e

    if not isinstance(data, dict):
        raise GateError("behaviors.json must be a JSON object")
    behaviors = data.get("behaviors")
    if not isinstance(behaviors, list):
        raise GateError('behaviors.json must have a "behaviors" list')

    seen_ids = set()
    for entry in behaviors:
        if not isinstance(entry, dict):
            raise GateError(f"behaviors.json entry is not an object: {entry!r}")
        bid = entry.get("id")
        if not isinstance(bid, str) or not _BEHAVIOR_ID_RE.match(bid):
            raise GateError(f"behaviors.json entry has invalid id: {bid!r}")
        if bid in seen_ids:
            raise GateError(f"behaviors.json has duplicate id: {bid}")
        seen_ids.add(bid)
        description = entry.get("description")
        if description is not None and not isinstance(description, str):
            raise GateError(
                f"behaviors.json entry {bid} has non-string description"
            )

    return behaviors


def check_coverage(behaviors: list[dict], scenarios: list[dict]) -> dict:
    """Trace declared behaviors to dev/final scenarios.

    A behavior is dev-covered iff >=1 scenario with that behavior_id has
    cohort "dev". The gate PASSES iff uncovered_dev == [] and
    orphan_scenarios == [] (enforced by the caller, not here).
    """
    declared_ids = {b["id"] for b in behaviors}

    dev_covered = set()
    final_covered = set()
    orphan_scenarios = []
    for sc in scenarios:
        bid = sc.get("behavior_id")
        if bid not in declared_ids:
            orphan_scenarios.append(sc["id"])
            continue
        if sc.get("cohort") == "dev":
            dev_covered.add(bid)
        elif sc.get("cohort") == "final":
            final_covered.add(bid)

    uncovered_dev = declared_ids - dev_covered

    return {
        "checked": True,
        "behaviors": sorted(declared_ids),
        "uncovered_dev": sorted(uncovered_dev),
        "orphan_scenarios": sorted(set(orphan_scenarios)),
        "final_covered": sorted(final_covered),
    }
