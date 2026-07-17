"""M36a: the SINGLE qualification state machine.

Before M36a `qualified` was computed at the CONVERGED branch as
`eff in _QUALIFYING_TIERS and app_security_qualified` -- and, separately, M29b
sealed `host_isolation.qualified` into the manifest but NEVER folded it into
the top-level `qualified`. THE SECURITY GAP: a standard run whose candidate
host-isolation is `allow_host_read` (or a probe that got `--allow-downgrade`'d)
has `host_isolation.qualified == False` yet still sealed `COMPLETE_QUALIFIED`.

`derive()` is now the ONE place `qualified` is computed. It ANDs five
sub-states and, when not qualified, returns the FIRST failing sub-state's
distinct terminal code by a fixed, documented precedence. Folding
`host_isolation` into the AND closes the gap.

INVARIANT (superset property): because `barrier` and `app_security` are exactly
the two booleans the pre-M36a expression AND-ed, and the new AND only ADDS
`host_isolation`, `control_plane`, and `waiver_validity`, `derive()` can only
ever NEWLY FAIL a run the old code passed -- it can never newly PASS one the old
code failed. That is the fail-closed direction we want.

This module is PURE: it computes over already-decided booleans the supervisor
holds. It invents no new checks (host_isolation.qualified is M29b's;
app_security is M33a's; barrier is the tier gate; control_plane wires the
existing artifact-binding boolean; waiver_validity reuses M33a's waiver result).
"""

# Fixed precedence: the FIRST sub-state that is False decides the code. Ordered
# outermost-guarantee-first: no probe-proven barrier at all is the most
# fundamental miss; a valid-but-limited host isolation is next; then the
# control/integrity plane; then app-security gates; then waiver validity.
SUBSTATES = ("barrier", "host_isolation", "control_plane", "app_security", "waiver_validity")

# Distinct non-qualified terminal code per first-failing sub-state.
_CODES = {
    "barrier": "BARRIER_UNQUALIFIED",          # cooperative / no probe-proven isolation
    "host_isolation": "HOST_ISOLATION_LIMITED",  # M36a security fix: now gates `qualified`
    "control_plane": "CONTROL_PLANE_UNVERIFIED",  # no bound artifact / integrity plane
    "app_security": "SECURITY_GATE_FAILED",     # existing M33a app-security terminal
    "waiver_validity": "WAIVER_INVALID",        # a waiver in play that does not validly cover
}

QUALIFIED_CODE = "QUALIFIED"


def derive(*, barrier: bool, host_isolation: bool, control_plane: bool,
           app_security: bool, waiver_validity: bool) -> dict:
    """Compute the authoritative qualification.

    Returns `{"qualified": bool, "substates": {name: bool}, "code": str}`.
    `qualified` is the AND of all five sub-states. When False, `code` is the
    first-failing sub-state's distinct terminal code (precedence == SUBSTATES
    order). When True, `code` is QUALIFIED. Keyword-only to force call sites to
    name every sub-state (so a future added dimension can't silently default).
    """
    substates = {
        "barrier": bool(barrier),
        "host_isolation": bool(host_isolation),
        "control_plane": bool(control_plane),
        "app_security": bool(app_security),
        "waiver_validity": bool(waiver_validity),
    }
    qualified = all(substates.values())
    if qualified:
        code = QUALIFIED_CODE
    else:
        # Deterministic first-failing-substate precedence.
        code = next(_CODES[name] for name in SUBSTATES if not substates[name])
    return {"qualified": qualified, "substates": substates, "code": code}
