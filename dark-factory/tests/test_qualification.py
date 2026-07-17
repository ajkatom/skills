"""M36a Task 2: df_qualify.derive -- the single qualification state machine.
Truth table, first-failing-substate precedence, and the host_isolation gap that
M36a closes."""
import df_qualify


def _all_true():
    return dict(barrier=True, host_isolation=True, control_plane=True,
                app_security=True, waiver_validity=True)


def test_all_substates_true_is_qualified():
    q = df_qualify.derive(**_all_true())
    assert q["qualified"] is True
    assert q["code"] == "QUALIFIED"
    assert q["substates"] == {"barrier": True, "host_isolation": True,
                              "control_plane": True, "app_security": True,
                              "waiver_validity": True}


def test_each_substate_false_in_isolation_gives_its_code():
    cases = {
        "barrier": "BARRIER_UNQUALIFIED",
        "host_isolation": "HOST_ISOLATION_LIMITED",
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
    # host_isolation before control_plane before app_security before waiver).
    q = df_qualify.derive(barrier=False, host_isolation=False, control_plane=False,
                          app_security=False, waiver_validity=False)
    assert q["code"] == "BARRIER_UNQUALIFIED"
    q = df_qualify.derive(barrier=True, host_isolation=False, control_plane=False,
                          app_security=False, waiver_validity=False)
    assert q["code"] == "HOST_ISOLATION_LIMITED"
    q = df_qualify.derive(barrier=True, host_isolation=True, control_plane=False,
                          app_security=False, waiver_validity=False)
    assert q["code"] == "CONTROL_PLANE_UNVERIFIED"
    q = df_qualify.derive(barrier=True, host_isolation=True, control_plane=True,
                          app_security=False, waiver_validity=False)
    assert q["code"] == "SECURITY_GATE_FAILED"


def test_the_host_isolation_gap_is_closed():
    # THE security fix: pre-M36a `qualified = barrier and app_security` ignored
    # host_isolation. A run that is barrier+app_security qualified but whose
    # host_isolation is limited must now be NOT qualified, with the distinct
    # HOST_ISOLATION_LIMITED code.
    args = _all_true()
    args["host_isolation"] = False
    q = df_qualify.derive(**args)
    assert q["qualified"] is False
    assert q["code"] == "HOST_ISOLATION_LIMITED"


def test_superset_property_never_newly_passes():
    # For every combination of the five booleans, derive() is qualified ONLY
    # when barrier AND app_security are BOTH true (the old gate) -- i.e. it can
    # only ever be a SUBSET of the old pass-set (never newly passes something
    # the old code failed). It IS allowed to newly fail (host_isolation etc.).
    import itertools
    for b, h, c, a, w in itertools.product([False, True], repeat=5):
        q = df_qualify.derive(barrier=b, host_isolation=h, control_plane=c,
                              app_security=a, waiver_validity=w)
        old_gate = b and a
        if q["qualified"]:
            assert old_gate, (b, h, c, a, w)  # never newly PASS


def test_substates_tuple_order_is_the_documented_precedence():
    assert df_qualify.SUBSTATES == (
        "barrier", "host_isolation", "control_plane", "app_security", "waiver_validity")
