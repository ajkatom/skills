"""M36a: the four intervention modes (H1..H4) as PAUSE-POINT SETS over the
existing pause mechanism.

A dark-factory run already knows how to PAUSE: write a checkpoint report +
`save_state` + journal `CHECKPOINT` + return `PAUSED`, and later `resume`.
M36a does NOT add any new interactive-prompt machinery; the four modes differ
ONLY in WHICH transitions take that existing pause. This module is the ONE
source of truth for that table -- the supervisor asks these predicates and
never hardcodes a mode name at a decision point.

The four modes (human name aliases in parentheses):
  H1 directed  -- most hands-on: the human approves/edits before every rebuild
                  (i>=2), reviews every non-converged checkpoint, AND approves
                  the ship on convergence.
  H2 supervised-- the FAITHFUL EQUIVALENT of legacy `checkpoint:"pause"`: pause
                  after every non-converged verify (i<cap). This is the
                  DEFAULT, and it reproduces today's observable pause behavior
                  byte-for-byte (no before-build gate, no before-ship gate).
  H3 guarded   -- the FAITHFUL EQUIVALENT of legacy `checkpoint:"auto"`
                  (autonomy 4): run the build/verify loop with NO per-iteration
                  pause, but still PAUSE at a genuine budget guard so a human
                  can intervene before spend continues.
  H4 lights-out-- the FAITHFUL EQUIVALENT of legacy autonomy 5: NO transition
                  ever returns PAUSED. Every condition that would pause in
                  H1..H3 is, under H4, either "run" or a deterministic
                  fail-closed TERMINAL (a budget guard becomes BUDGET_HALTED).
                  This is what "lights-out" MUST mean to be safe: never a
                  silent proceed past a human-needed decision, never an
                  indefinite block. Requires a hardened/enterprise backend
                  (the same tier gate legacy autonomy 5 used).

BEFORE_SHIP (M36b — the pause the plan's table always specified for H1 AND H2,
DEFERRED in M36a, LANDED here): on convergence, after the final exam PASSES and
the security gates PASS and the frozen artifact re-verifies — but BEFORE sealing
COMPLETE_QUALIFIED — H1 and H2 PAUSE for a ship approval. M36a deferred this for
two reasons M36b resolves:

  1. Back-compat. A before-ship pause on H2 (the DEFAULT) fires a SECOND pause
     on every converging run. M36b ACCEPTS this as the intended semantics of a
     supervised mode (a human signs off the ship), and updates the
     converge-after-resume tests to expect the AWAIT_SHIP pause + one more
     `resume` to seal. This is a deliberate behavior change, not a regression.

  2. The pause MECHANISM. A ship-approval pause happens AFTER the builder
     produced the converged artifact, so resuming it must seal WITHOUT
     rebuilding — otherwise it re-dispatches a paid builder call, violating the
     M35 crash-dispatch invariant. M36b adds the SEAL-REENTRY resume path
     (supervisor `_run_loop(resume_ship=True)`): from AWAIT_SHIP, resume
     re-verifies the frozen object, re-runs the security gates over it, and
     seals via the SAME `df_qualify.derive` path — the build for-loop is never
     entered, so `builder_calls` is provably unchanged across the ship-resume.

H3/H4 stay False for BEFORE_SHIP: guarded/lights-out never pause for a human
here. `resume --decision abort` from AWAIT_SHIP seals a SHIP_DECLINED terminal
(qualified False). See references/modes.md for the full rationale.
"""

# --- Pause-point tokens (the columns of the state-transition table) ---------
BEFORE_BUILD = "before_build"      # before each BUILD_i, i>=2 (post-first-feedback)
AFTER_VERIFY = "after_verify"      # after a non-converged VERIFY_i (i<cap)
BEFORE_SHIP = "before_ship"        # on convergence, before seal (H1/H2; M36b)
ON_BUDGET_GUARD = "on_budget_guard"  # the budget admission guard (recoverable pause)

INTERVENTION_MODES = ("H1", "H2", "H3", "H4")

# The authoritative pause-point SET per mode. Everything else in this module is
# a thin predicate over this dict; the supervisor consults the predicates.
# BEFORE_SHIP is in H1 and H2 (M36b): both supervised/directed modes pause for a
# human ship approval on convergence. H3/H4 never do.
_PAUSE_POINTS = {
    "H1": frozenset({BEFORE_BUILD, AFTER_VERIFY, BEFORE_SHIP, ON_BUDGET_GUARD}),
    "H2": frozenset({AFTER_VERIFY, BEFORE_SHIP, ON_BUDGET_GUARD}),
    "H3": frozenset({ON_BUDGET_GUARD}),
    "H4": frozenset(),
}

# Human-name aliases accepted in config and canonicalized to H1..H4. Kept
# permissive (a couple of spellings each) but closed: an unknown string is a
# hard ConfigError, never a silent default.
_ALIASES = {
    "h1": "H1", "directed": "H1",
    "h2": "H2", "supervised": "H2",
    "h3": "H3", "guarded": "H3", "guarded_autonomous": "H3", "guarded-autonomous": "H3",
    "h4": "H4", "lights_out": "H4", "lights-out": "H4", "lightsout": "H4",
}


class ModeError(ValueError):
    """Raised for an unknown/contradictory mode. df_config catches this and
    re-raises as a ConfigError so the operator sees a single error type."""


def canonical_mode(value) -> str:
    """Canonicalize an `intervention_mode` config value (H1..H4 or a human
    alias, case/hyphen-insensitive) to its H-code. Raises ModeError on any
    unknown value -- fail closed, never guess a default here (the DEFAULT when
    nothing is configured is decided by the caller, see legacy_mode)."""
    if not isinstance(value, str):
        raise ModeError(f"intervention_mode must be a string, got {type(value).__name__}")
    key = value.strip().lower().replace(" ", "_")
    if key in _ALIASES:
        return _ALIASES[key]
    raise ModeError(
        f"unknown intervention_mode {value!r}; expected one of "
        f"H1/directed, H2/supervised, H3/guarded, H4/lights_out")


def pause_points(mode: str) -> frozenset:
    """The frozenset of pause-point tokens for `mode` (already canonical)."""
    if mode not in _PAUSE_POINTS:
        raise ModeError(f"not a canonical intervention mode: {mode!r}")
    return _PAUSE_POINTS[mode]


def pauses_before_build(mode: str, iteration: int) -> bool:
    """True iff the run must pause BEFORE building `iteration` under `mode`.
    Only meaningful for i>=2 (there is no pre-build human gate before the very
    first build -- there is no feedback to review yet)."""
    return iteration >= 2 and BEFORE_BUILD in pause_points(mode)


def pauses_after_verify(mode: str) -> bool:
    """True iff a non-converged verify (i<cap) pauses under `mode`. This is the
    single gate legacy `checkpoint:"pause"` had, so H1/H2 -> True, H3/H4 ->
    False (H3/H4 correspond to legacy `auto`, which never paused here)."""
    return AFTER_VERIFY in pause_points(mode)


def pauses_before_ship(mode: str) -> bool:
    """True iff convergence pauses for a human ship-approval before the artifact
    is sealed COMPLETE_QUALIFIED. H1/H2 -> True (M36b); H3/H4 -> False. The
    supervisor takes this pause only AFTER the final exam + gates pass and the
    frozen object re-verifies, and resumes it via the seal-reentry path (no
    builder re-dispatch)."""
    return BEFORE_SHIP in pause_points(mode)


def pauses_on_budget_guard(mode: str) -> bool:
    """True iff the budget admission guard PAUSES (recoverable) under `mode`.
    H1/H2/H3 -> True (a human can raise the cap and resume). H4 -> False: under
    lights-out the same condition is a deterministic fail-closed TERMINAL
    (BUDGET_HALTED), never a silent proceed and never an indefinite block."""
    return ON_BUDGET_GUARD in pause_points(mode)


def is_lights_out(mode: str) -> bool:
    """H4: no transition may ever return PAUSED (asserted by the supervisor)."""
    return mode == "H4"


def requires_hardened(mode: str) -> bool:
    """H4 reuses legacy autonomy-5's tier gate: hardened/enterprise only."""
    return mode == "H4"


# --- Legacy (autonomy, checkpoint) -> mode mapping --------------------------
# Faithful-equivalence justification for each pair (see the module docstring
# for the pause-point sets):
#   (4, "pause") -> H2  legacy pause gated only AFTER verify; H2 == {after_verify}.
#                       NOT H1: H1 additionally gates before-build/before-ship,
#                       which legacy pause did not.
#   (4, "auto")  -> H3  autonomy 4 auto ran the loop with no per-iter pause but
#                       still honored the budget guard; H3 == {on_budget_guard}.
#   (5, "auto")  -> H4  autonomy 5 == lights-out (hardened/enterprise only).
#   (5, "pause") -> REJECTED: contradictory (lights-out that pauses); it was
#                       never a coherent config and stays rejected.
_LEGACY_MAP = {
    (4, "pause"): "H2",
    (4, "auto"): "H3",
    (5, "auto"): "H4",
}


def legacy_mode(autonomy: int, checkpoint: str) -> str:
    """Map a validated legacy (autonomy, checkpoint) pair to a mode. Raises
    ModeError for the contradictory (5, "pause") pair -- fail closed."""
    key = (autonomy, checkpoint)
    if key == (5, "pause"):
        raise ModeError(
            "autonomy 5 (lights-out) with checkpoint 'pause' is contradictory "
            "(lights-out never pauses); use intervention_mode H4 or autonomy 5 "
            "with checkpoint 'auto'")
    if key not in _LEGACY_MAP:
        raise ModeError(f"no legacy mode mapping for (autonomy={autonomy}, checkpoint={checkpoint})")
    return _LEGACY_MAP[key]


def legacy_fields_for(mode: str):
    """The (autonomy, checkpoint) a `mode` is back-compat-equivalent to, so the
    rest of the supervisor (which still reads `cfg['_checkpoint']` and
    `cfg['autonomy']`) keeps working unchanged. H1 shares H2's legacy fields
    (both derive from the `pause` family); H1's extra gates are layered on by
    the mode predicates, not by these legacy fields."""
    return {
        "H1": (4, "pause"),
        "H2": (4, "pause"),
        "H3": (4, "auto"),
        "H4": (5, "auto"),
    }[mode]
