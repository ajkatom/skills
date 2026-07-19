"""M36a Task 2: df_qualify.derive -- the single qualification state machine.
Truth table, first-failing-substate precedence, and the host_isolation gap that
M36a closes. M47 RA-08(a) extends it with the candidate_egress sub-state."""
import df_qualify


def _all_true():
    return dict(barrier=True, host_isolation=True, candidate_egress=True,
                control_plane=True, app_security=True, waiver_validity=True)


def test_all_substates_true_is_qualified():
    q = df_qualify.derive(**_all_true())
    assert q["qualified"] is True
    assert q["code"] == "QUALIFIED"
    assert q["substates"] == {"barrier": True, "host_isolation": True,
                              "candidate_egress": True, "control_plane": True,
                              "app_security": True, "waiver_validity": True}


def test_each_substate_false_in_isolation_gives_its_code():
    cases = {
        "barrier": "BARRIER_UNQUALIFIED",
        "host_isolation": "HOST_ISOLATION_LIMITED",
        "candidate_egress": "CANDIDATE_EGRESS_OPEN",
        "control_plane": "CONTROL_PLANE_UNVERIFIED",
        "app_security": "SECURITY_GATE_FAILED",
        "waiver_validity": "WAIVER_INVALID",
    }
    for sub, code in cases.items():
        args = _all_true()
        args[sub] = False
        q = df_qualify.derive(**args)
        assert q["qualified"] is False
        assert q["code"] == code, sub
        assert q["substates"][sub] is False


def test_first_failing_substate_precedence():
    # When several fail, the FIRST in SUBSTATES order wins (barrier before
    # host_isolation before candidate_egress before control_plane before
    # app_security before waiver).
    q = df_qualify.derive(barrier=False, host_isolation=False, candidate_egress=False,
                          control_plane=False, app_security=False, waiver_validity=False)
    assert q["code"] == "BARRIER_UNQUALIFIED"
    q = df_qualify.derive(barrier=True, host_isolation=False, candidate_egress=False,
                          control_plane=False, app_security=False, waiver_validity=False)
    assert q["code"] == "HOST_ISOLATION_LIMITED"
    q = df_qualify.derive(barrier=True, host_isolation=True, candidate_egress=False,
                          control_plane=False, app_security=False, waiver_validity=False)
    assert q["code"] == "CANDIDATE_EGRESS_OPEN"
    q = df_qualify.derive(barrier=True, host_isolation=True, candidate_egress=True,
                          control_plane=False, app_security=False, waiver_validity=False)
    assert q["code"] == "CONTROL_PLANE_UNVERIFIED"
    q = df_qualify.derive(barrier=True, host_isolation=True, candidate_egress=True,
                          control_plane=True, app_security=False, waiver_validity=False)
    assert q["code"] == "SECURITY_GATE_FAILED"


def test_the_host_isolation_gap_is_closed():
    # THE M36a security fix: pre-M36a `qualified = barrier and app_security`
    # ignored host_isolation. A run that is barrier+app_security qualified but
    # whose host_isolation is limited must now be NOT qualified, with the
    # distinct HOST_ISOLATION_LIMITED code.
    args = _all_true()
    args["host_isolation"] = False
    q = df_qualify.derive(**args)
    assert q["qualified"] is False
    assert q["code"] == "HOST_ISOLATION_LIMITED"


def test_the_candidate_egress_gap_is_closed():
    # M47 RA-08(a): pre-M47 unrestricted candidate egress was non-disqualifying
    # -- a standard+ run sealed COMPLETE_QUALIFIED with the built app's network
    # wide open. A run that is otherwise fully qualified but whose candidate
    # egress is open must now be NOT qualified, with CANDIDATE_EGRESS_OPEN.
    args = _all_true()
    args["candidate_egress"] = False
    q = df_qualify.derive(**args)
    assert q["qualified"] is False
    assert q["code"] == "CANDIDATE_EGRESS_OPEN"


def test_superset_property_never_newly_passes():
    # For every combination of the six booleans, derive() is qualified ONLY when
    # barrier AND app_security are BOTH true (the pre-M36a gate) -- i.e. it can
    # only ever be a SUBSET of the old pass-set (never newly passes something the
    # old code failed). It IS allowed to newly fail (host_isolation,
    # candidate_egress, control_plane, waiver_validity). This proves in
    # particular that adding candidate_egress can ONLY newly fail a run, never
    # newly pass one -- the fail-closed direction RA-08(a) requires.
    import itertools
    for b, h, e, c, a, w in itertools.product([False, True], repeat=6):
        q = df_qualify.derive(barrier=b, host_isolation=h, candidate_egress=e,
                              control_plane=c, app_security=a, waiver_validity=w)
        old_gate = b and a
        if q["qualified"]:
            assert old_gate, (b, h, e, c, a, w)  # never newly PASS


def test_candidate_egress_only_bites_at_a_qualifying_tier_via_precedence():
    # candidate_egress False cannot change the OUTCOME code of a non-qualifying
    # (barrier-False) run: barrier precedes it, so a cooperative run still reads
    # BARRIER_UNQUALIFIED whether or not its egress is open. The tightening is
    # visible ONLY once barrier is satisfied (a qualifying tier).
    q = df_qualify.derive(barrier=False, host_isolation=True, candidate_egress=False,
                          control_plane=True, app_security=True, waiver_validity=True)
    assert q["code"] == "BARRIER_UNQUALIFIED"


def test_substates_tuple_order_is_the_documented_precedence():
    assert df_qualify.SUBSTATES == (
        "barrier", "host_isolation", "candidate_egress", "control_plane",
        "app_security", "waiver_validity")
