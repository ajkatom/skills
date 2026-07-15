import df_gates


def test_is_discriminating_true_for_exit_code_and_stdout_equals():
    assert df_gates.is_discriminating({"exit_code": 0, "stdout_equals": "Hello"}) is True


def test_is_discriminating_true_for_exit_code_only():
    assert df_gates.is_discriminating({"exit_code": 0}) is True


def test_is_discriminating_true_for_stdout_contains():
    assert df_gates.is_discriminating({"stdout_contains": "Hello"}) is True


def test_is_discriminating_false_for_empty_stdout_contains():
    # empty substring matches the mutant's stdout, so this check is inert
    assert df_gates.is_discriminating({"stdout_contains": ""}) is False


def test_is_discriminating_false_for_empty_stderr_contains():
    assert df_gates.is_discriminating({"stderr_contains": ""}) is False


def test_is_discriminating_false_for_another_tautology():
    # the substring happens to appear inside the fixed mutant marker text
    # ("\x00DF-MUTANT-\x00"), so this check accidentally accepts the mutant.
    assert df_gates.is_discriminating({"stdout_contains": "MUTANT"}) is False


def test_validate_oracle_returns_inert_ids_from_mixed_list():
    scenarios = [
        {"id": "BHV-001-S1", "then": {"exit_code": 0, "stdout_equals": "Hello"}},
        {"id": "BHV-002-S1", "then": {"stdout_contains": ""}},
        {"id": "BHV-003-S1", "then": {"stdout_contains": "MUTANT"}},
        {"id": "BHV-004-S1", "then": {"stdout_contains": "Hello"}},
    ]
    assert df_gates.validate_oracle(scenarios) == ["BHV-002-S1", "BHV-003-S1"]


def test_validate_oracle_empty_when_all_discriminate():
    scenarios = [
        {"id": "BHV-001-S1", "then": {"exit_code": 0, "stdout_equals": "Hello"}},
        {"id": "BHV-002-S1", "then": {"stdout_contains": "Hello"}},
    ]
    assert df_gates.validate_oracle(scenarios) == []


def test_gate_error_is_value_error_subclass():
    assert issubclass(df_gates.GateError, ValueError)
