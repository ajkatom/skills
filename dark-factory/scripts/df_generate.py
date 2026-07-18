"""df_generate: seeded, declarative input generators for property scenarios (M43a).

WHY this module exists: M43a lets the oracle assert an INVARIANT over many
machine-generated inputs (`when.property`). The inputs come from HERE — a
FIXED, validated generator vocabulary, never operator- or agent-supplied
executable code (the oracle's whole philosophy: declarative like the `then`
assertion keys, no arbitrary-code surface on the verifier side).

DETERMINISM (load-bearing, tested): `generate_cases(spec)` is a pure function
of (seed, spec). It uses `random.Random(seed)` — CPython's Mersenne Twister,
whose sequence for a given seed is stable across runs and platforms — and
consumes the stream in a FIXED order (cases outermost; within a case, vars in
sorted-name order, non-`malformed` vars before `malformed` ones so a
malformed var's base is available regardless of declaration order). Same
(seed, spec) ⇒ byte-identical cases, so a property run is reproducible and a
counterexample is replayable from the manifest's recorded seed alone.

BOUNDED (fail-closed at validation time, before any build): `cases` is capped
at MAX_CASES, every string length at MAX_STRING_LEN — a generate block can
never describe unbounded work. Timeouts are the runner's job
(run_scenarios._run_property_and_evaluate), not this module's.

All generated values are STRINGS: substitution into a step's argv/URL/body is
literal string interpolation (`{var}` → value), so a typed value (int, json)
is rendered to its canonical text here, once, deterministically.

Stdlib only. Pure (no I/O). Runtime guards `raise` GenerateError (never bare
`assert` — the suite runs under `python -O`).
"""
import hashlib
import json
import random
import string

# The hard ceiling on cases per property scenario — validated here so a
# generate block that asks for more is rejected at LOAD time (M7 pre-build
# gate territory), never discovered mid-run. 500 is deliberately modest: a
# property scenario runs UNDER the per-case candidate subprocess machinery,
# so cases are seconds-scale, not microseconds-scale like an in-process
# QuickCheck — the value is in input DIVERSITY, not raw count.
MAX_CASES = 500
# Ceiling on any generated string's length (and on a `malformed` oversize
# variant) — bounds memory and argv size; an OS argv limit overflow would
# surface as a confusing spawn failure, not a clean validation error.
MAX_STRING_LEN = 4096

# M43b concurrency ceilings — validated at LOAD time (like MAX_CASES) so a
# concurrency block asking for more is rejected before any build, never
# discovered mid-run. Each (case, attempt) launches `workers` REAL candidate
# processes in parallel, so `workers` is the parallelism width and `attempts`
# the number of re-interleavings per case; the product with `cases` is the
# audited detection effort. 16/20 keep a worst-case run (500*20*16 spawns)
# bounded by the runner's PROPERTY_MAX_TOTAL_S wall-clock cap regardless.
MAX_WORKERS = 16
MAX_ATTEMPTS = 20

GENERATOR_KINDS = ("int", "string", "json", "choice", "malformed")
STRING_CHARSETS = ("ascii_printable", "alnum", "unicode", "bytes")
JSON_SHAPES = ("scalar", "scalar_or_object", "array")

# The fixed adversarial-variant menu `malformed` draws from. Each is a pure
# function (rng, base_str) -> str. Named so a control-plane report can say
# WHICH variant class produced a counterexample without quoting the value.
MALFORMED_VARIANTS = (
    "bit_flip",      # one character replaced by a different byte
    "truncate",      # a prefix of the base
    "oversize",      # the base repeated out to MAX_STRING_LEN
    "wrong_type",    # a JSON value of a different type than the base suggests
    "control_chars", # control characters spliced into the base
    "injection",     # classic injection tokens appended/embedded
    "empty",         # the empty string
)

# Injection tokens for the `injection` variant: a fixed, boring list of the
# classic parser-confusers. Deliberately NOT exhaustive or clever — the point
# is "does the app honor its error contract on hostile-looking input", not a
# real exploit corpus. NO raw NUL here: generated values are substituted into
# argv, and execve argv cannot carry NUL — an undeliverable input would fuzz
# the RUNNER's spawn path, not the app. "%00" (the encoded-NUL probe) is the
# deliverable classic instead.
_INJECTION_TOKENS = (
    "'; DROP TABLE t;--",
    "<script>x</script>",
    "$(id)",
    "`id`",
    "{{7*7}}",
    "%s%s%n",
    "../../etc/passwd",
    "%00",
)

_ALNUM = string.ascii_letters + string.digits
# "ascii_printable" excludes newline/tab on purpose: generated values are
# substituted into argv/URLs/bodies where an embedded newline changes framing
# (and the `bytes`/`control_chars` machinery exists precisely to test that
# hostile framing DELIBERATELY, under the fuzz kinds, not by accident here).
_ASCII_PRINTABLE = _ALNUM + string.punctuation + " "
# A small fixed set of non-ASCII codepoint ranges for charset "unicode":
# Latin-1 supplement letters, Greek, CJK, and an emoji block — enough to
# exercise encoding handling without dragging in surrogate/normalization
# minefields that would make failures platform-flaky.
_UNICODE_RANGES = ((0x00C0, 0x00FF), (0x0391, 0x03C9), (0x4E00, 0x4E80), (0x1F600, 0x1F640))


class GenerateError(ValueError):
    """A malformed `generate` block. Raised at validation time (load/gate),
    never mid-run — same fail-closed posture as run_scenarios.OracleError."""


def validate_generate(gen, where: str) -> None:
    """Fail-closed shape validation for a `when.property.generate` block.

    Enforces: `vars` is a non-empty dict of {name: spec} with valid var names
    (they must be usable as `{name}` placeholders); every spec has a KNOWN
    kind with in-bounds parameters; `cases` is an int in 1..MAX_CASES; `seed`
    is present and an int (bool excluded — True would "work" but reads as a
    config bug). A `malformed` var's `base` may name another declared var
    (which must not itself be `malformed` — no adversarial towers) or be a
    literal string.
    """
    if not isinstance(gen, dict):
        raise GenerateError(f"{where}: generate must be an object")
    unknown = set(gen) - {"vars", "cases", "seed"}
    if unknown:
        raise GenerateError(f"{where}: generate has unknown key(s) {sorted(unknown)}")

    seed = gen.get("seed")
    # bool is an int subclass; reject it explicitly so `"seed": true` is a
    # clean validation error rather than a silently-accepted seed of 1.
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise GenerateError(f"{where}: generate.seed is required and must be an int")

    cases = gen.get("cases")
    if not isinstance(cases, int) or isinstance(cases, bool) or not (1 <= cases <= MAX_CASES):
        raise GenerateError(
            f"{where}: generate.cases must be an int in 1..{MAX_CASES}")

    variables = gen.get("vars")
    if not isinstance(variables, dict) or not variables:
        raise GenerateError(f"{where}: generate.vars must be a non-empty object")

    for name, spec in variables.items():
        vwhere = f"{where}: var {name!r}"
        if not isinstance(name, str) or not name.isidentifier():
            raise GenerateError(
                f"{where}: var name {name!r} must be a valid identifier "
                f"(it becomes a {{name}} placeholder)")
        if not isinstance(spec, dict):
            raise GenerateError(f"{vwhere}: spec must be an object")
        kind = spec.get("kind")
        if kind not in GENERATOR_KINDS:
            raise GenerateError(
                f"{vwhere}: kind must be one of {list(GENERATOR_KINDS)}, got {kind!r}")
        _VALIDATORS[kind](spec, variables, vwhere)


def _validate_int(spec, variables, where):
    unknown = set(spec) - {"kind", "min", "max"}
    if unknown:
        raise GenerateError(f"{where}: unknown key(s) {sorted(unknown)}")
    lo, hi = spec.get("min"), spec.get("max")
    for label, v in (("min", lo), ("max", hi)):
        if not isinstance(v, int) or isinstance(v, bool):
            raise GenerateError(f"{where}: {label} must be an int")
    if lo > hi:
        raise GenerateError(f"{where}: min ({lo}) > max ({hi})")


def _validate_string(spec, variables, where):
    unknown = set(spec) - {"kind", "charset", "min_len", "max_len"}
    if unknown:
        raise GenerateError(f"{where}: unknown key(s) {sorted(unknown)}")
    charset = spec.get("charset", "ascii_printable")
    if charset not in STRING_CHARSETS:
        raise GenerateError(
            f"{where}: charset must be one of {list(STRING_CHARSETS)}, got {charset!r}")
    lo = spec.get("min_len", 0)
    hi = spec.get("max_len")
    if not isinstance(hi, int) or isinstance(hi, bool):
        raise GenerateError(f"{where}: max_len is required and must be an int")
    if not isinstance(lo, int) or isinstance(lo, bool):
        raise GenerateError(f"{where}: min_len must be an int")
    if not (0 <= lo <= hi <= MAX_STRING_LEN):
        raise GenerateError(
            f"{where}: need 0 <= min_len <= max_len <= {MAX_STRING_LEN}, "
            f"got min_len={lo} max_len={hi}")


def _validate_json(spec, variables, where):
    unknown = set(spec) - {"kind", "shape"}
    if unknown:
        raise GenerateError(f"{where}: unknown key(s) {sorted(unknown)}")
    shape = spec.get("shape", "scalar")
    if shape not in JSON_SHAPES:
        raise GenerateError(
            f"{where}: shape must be one of {list(JSON_SHAPES)}, got {shape!r}")


def _validate_choice(spec, variables, where):
    unknown = set(spec) - {"kind", "options"}
    if unknown:
        raise GenerateError(f"{where}: unknown key(s) {sorted(unknown)}")
    options = spec.get("options")
    if (not isinstance(options, list) or not options
            or not all(isinstance(o, str) for o in options)):
        raise GenerateError(f"{where}: options must be a non-empty list of strings")


def _validate_malformed(spec, variables, where):
    unknown = set(spec) - {"kind", "base"}
    if unknown:
        raise GenerateError(f"{where}: unknown key(s) {sorted(unknown)}")
    base = spec.get("base")
    if not isinstance(base, str):
        raise GenerateError(f"{where}: base must be a string (a declared var name "
                            f"or a literal)")
    if base in variables:
        base_kind = variables[base].get("kind") if isinstance(variables[base], dict) else None
        if base_kind == "malformed":
            raise GenerateError(
                f"{where}: base {base!r} is itself a malformed var — "
                f"malformed-of-malformed is not allowed")


_VALIDATORS = {
    "int": _validate_int,
    "string": _validate_string,
    "json": _validate_json,
    "choice": _validate_choice,
    "malformed": _validate_malformed,
}


def _gen_int(rng, spec):
    return str(rng.randint(spec["min"], spec["max"]))


def _gen_string(rng, spec):
    charset = spec.get("charset", "ascii_printable")
    lo = spec.get("min_len", 0)
    hi = spec["max_len"]
    n = rng.randint(lo, hi)
    if charset == "alnum":
        return "".join(rng.choice(_ALNUM) for _ in range(n))
    if charset == "ascii_printable":
        return "".join(rng.choice(_ASCII_PRINTABLE) for _ in range(n))
    if charset == "unicode":
        out = []
        for _ in range(n):
            lo_cp, hi_cp = _UNICODE_RANGES[rng.randrange(len(_UNICODE_RANGES))]
            out.append(chr(rng.randint(lo_cp, hi_cp)))
        return "".join(out)
    # charset == "bytes": raw byte-valued chars 0x01..0xFF. NUL (0x00) is
    # excluded because a generated value is substituted into argv, and execve
    # argv strings cannot contain NUL — it would turn every such case into a
    # spawn error rather than a real robustness probe. The `malformed`
    # control_chars/injection variants still inject NUL into BODIES via the
    # literal token above, where it is legal.
    return "".join(chr(rng.randint(0x01, 0xFF)) for _ in range(n))


def _gen_json(rng, spec):
    shape = spec.get("shape", "scalar")

    def scalar():
        pick = rng.randrange(4)
        if pick == 0:
            return rng.randint(-1000, 1000)
        if pick == 1:
            return "".join(rng.choice(_ALNUM) for _ in range(rng.randint(0, 12)))
        if pick == 2:
            return rng.choice([True, False])
        return None

    if shape == "scalar":
        value = scalar()
    elif shape == "array":
        value = [scalar() for _ in range(rng.randint(0, 5))]
    else:  # scalar_or_object
        if rng.randrange(2) == 0:
            value = scalar()
        else:
            value = {
                "".join(rng.choice(_ALNUM) for _ in range(rng.randint(1, 8))): scalar()
                for _ in range(rng.randint(1, 4))
            }
    # sort_keys pins the serialization: the same rng draws always render to
    # the same text, so the generated STRING (what substitution sees) is as
    # deterministic as the underlying value.
    return json.dumps(value, sort_keys=True)


def _gen_choice(rng, spec):
    return spec["options"][rng.randrange(len(spec["options"]))]


def _malform(rng, base: str) -> str:
    """One deterministic adversarial variant of `base`. The variant class is
    itself an rng draw, so a multi-case run sweeps the whole menu."""
    variant = MALFORMED_VARIANTS[rng.randrange(len(MALFORMED_VARIANTS))]
    if variant == "empty":
        return ""
    if variant == "truncate":
        if not base:
            return ""
        return base[: rng.randrange(len(base))]
    if variant == "oversize":
        unit = base or "A"
        return (unit * (MAX_STRING_LEN // len(unit) + 1))[:MAX_STRING_LEN]
    if variant == "bit_flip":
        if not base:
            return "\x01"
        i = rng.randrange(len(base))
        flipped = chr((ord(base[i]) ^ (1 << rng.randrange(7))) or 0x01)
        return base[:i] + flipped + base[i + 1:]
    if variant == "control_chars":
        ctrl = "".join(chr(rng.randint(0x01, 0x1F)) for _ in range(3))
        i = rng.randrange(len(base) + 1)
        return base[:i] + ctrl + base[i:]
    if variant == "wrong_type":
        # If the base parses as JSON, emit a value of a DIFFERENT JSON type;
        # otherwise emit a bare number where text was expected.
        try:
            parsed = json.loads(base)
        except (json.JSONDecodeError, ValueError):
            return str(rng.randint(-999, 999))
        if isinstance(parsed, str):
            return str(rng.randint(-999, 999))
        return json.dumps("".join(rng.choice(_ALNUM) for _ in range(4)))
    # variant == "injection"
    return base + _INJECTION_TOKENS[rng.randrange(len(_INJECTION_TOKENS))]


def generate_cases(gen: dict) -> list:
    """The generated case list: `cases` dicts of {var_name: str_value}.

    Pure function of (gen["seed"], gen) — see the module docstring for the
    determinism argument. Ordering discipline (the part that MAKES it
    deterministic regardless of JSON key order in the scenario file):
    cases are generated outermost-first; within a case, non-malformed vars
    in sorted-name order, then malformed vars in sorted-name order (so a
    malformed var's `base` reference is always resolved against this same
    case's already-generated value, independent of declaration order).

    Validates first — callers that already validated pay a cheap re-check,
    callers that didn't are still fail-closed.
    """
    validate_generate(gen, "generate_cases")
    rng = random.Random(gen["seed"])
    variables = gen["vars"]
    plain = sorted(n for n in variables if variables[n]["kind"] != "malformed")
    malformed = sorted(n for n in variables if variables[n]["kind"] == "malformed")

    out = []
    for _ in range(gen["cases"]):
        case = {}
        for name in plain:
            spec = variables[name]
            case[name] = _GENERATORS[spec["kind"]](rng, spec)
        for name in malformed:
            base_ref = variables[name]["base"]
            base_value = case[base_ref] if base_ref in case else base_ref
            case[name] = _malform(rng, base_value)
        out.append(case)
    return out


_GENERATORS = {
    "int": _gen_int,
    "string": _gen_string,
    "json": _gen_json,
    "choice": _gen_choice,
}


# --- M43b: the `when.property.concurrency` block ----------------------------
# WHY additive here (not folded into generate_cases): M43a's generate_cases is
# a byte-identical, load-bearing reproducibility contract; touching its stream
# order would change every existing property run's cases. So the per-worker
# values come from a SEPARATE, DERIVED stream (per case) that never perturbs
# the base stream. Absent a concurrency block, nothing below is reached and
# M43a behavior is byte-for-byte unchanged.


def validate_concurrency(conc, variables: dict, where: str) -> None:
    """Fail-closed shape+bounds validation for `when.property.concurrency`.

    Enforces: `workers` is an int in 2..MAX_WORKERS (1 worker is not a
    concurrency test — reject it as a config bug rather than silently running a
    sequential probe under the concurrency invariant); `attempts` is an int in
    1..MAX_ATTEMPTS; `per_worker_vars` (optional) is a list of DISTINCT declared
    var names, none of them `malformed` (malformed values are adversarial fuzz
    variants, not distinct-writer identities — a malformed per-worker value has
    no meaningful "distinctness", and its `empty` variant would collapse the
    lost-update signal). Runs at load time, so a bad block is caught before any
    build — same posture as validate_generate."""
    if not isinstance(conc, dict):
        raise GenerateError(f"{where}: concurrency must be an object")
    unknown = set(conc) - {"workers", "attempts", "per_worker_vars"}
    if unknown:
        raise GenerateError(
            f"{where}: concurrency has unknown key(s) {sorted(unknown)}")

    workers = conc.get("workers")
    if (not isinstance(workers, int) or isinstance(workers, bool)
            or not (2 <= workers <= MAX_WORKERS)):
        raise GenerateError(
            f"{where}: concurrency.workers must be an int in 2..{MAX_WORKERS}")

    attempts = conc.get("attempts")
    if (not isinstance(attempts, int) or isinstance(attempts, bool)
            or not (1 <= attempts <= MAX_ATTEMPTS)):
        raise GenerateError(
            f"{where}: concurrency.attempts must be an int in 1..{MAX_ATTEMPTS}")

    pwv = conc.get("per_worker_vars", [])
    if not isinstance(pwv, list) or not all(isinstance(v, str) for v in pwv):
        raise GenerateError(
            f"{where}: concurrency.per_worker_vars must be a list of strings")
    if len(set(pwv)) != len(pwv):
        raise GenerateError(
            f"{where}: concurrency.per_worker_vars has duplicate name(s)")
    for name in pwv:
        if name not in variables:
            raise GenerateError(
                f"{where}: per_worker_vars entry {name!r} is not a declared "
                f"generate var (declared: {sorted(variables)})")
        if variables[name].get("kind") == "malformed":
            raise GenerateError(
                f"{where}: per_worker_vars entry {name!r} is a malformed var — "
                f"malformed values cannot serve as distinct per-worker identities")


def _derive_seed(base_seed: int, case_index: int) -> int:
    """A stable 64-bit sub-seed for one case's per-worker stream, derived from
    (base_seed, case_index) via SHA-256. WHY not `hash((base_seed, case_index))`
    or `random.Random((base_seed, case_index))`: Python's builtin hash of
    tuples/strings is salted per-process (PYTHONHASHSEED), so it would make the
    per-worker values differ run-to-run — fatal to the reproducibility
    contract. SHA-256 over a canonical repr is identical across runs and
    platforms, so a concurrency counterexample is replayable from the recorded
    seed alone, exactly like M43a's base cases."""
    digest = hashlib.sha256(repr(("df_pwv", base_seed, case_index)).encode()).hexdigest()
    return int(digest[:16], 16)


def per_worker_values(gen: dict, case_index: int, per_worker_vars: list,
                      workers: int) -> list:
    """The per-worker OVERRIDES for one case: a list of length `workers`, each a
    dict {var: value} covering exactly `per_worker_vars` (the shared vars come
    from the base case and are NOT here). Values are drawn from a per-case
    derived stream (see _derive_seed), in worker order then sorted-var order —
    so the result is a deterministic function of (seed, case_index,
    worker_index, var), replayable bit-for-bit.

    DISTINCTNESS is best-effort-but-deterministic: for each var, a worker's
    draw is retried up to a fixed cap if it collides with an earlier worker's
    value for that same var, then accepted regardless. A caller that needs
    reliably-distinct writers (no_lost_update / serializable_counter) chooses a
    var domain wide enough that collisions are astronomically unlikely (e.g.
    string min_len>=8); the cap guarantees TERMINATION and DETERMINISM even
    when the domain is smaller than `workers` (distinctness is simply not
    achievable then, and the invariant's own bar adjusts to the distinct count
    actually written)."""
    variables = gen["vars"]
    rng = random.Random(_derive_seed(gen["seed"], case_index))
    names = sorted(per_worker_vars)
    used = {n: set() for n in names}
    out = []
    for _ in range(workers):
        wvals = {}
        for name in names:
            spec = variables[name]
            gen_fn = _GENERATORS[spec["kind"]]
            value = gen_fn(rng, spec)
            for _retry in range(64):
                if value not in used[name]:
                    break
                value = gen_fn(rng, spec)
            used[name].add(value)
            wvals[name] = value
        out.append(wvals)
    return out
