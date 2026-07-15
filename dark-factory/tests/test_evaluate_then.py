import pytest

import run_scenarios


BASE_OBSERVED = {"exit_code": 0, "stdout": "ok", "stderr": ""}


@pytest.mark.parametrize(
    "then, observed, expected",
    [
        # exit_code mismatch -> wrong_exit_code
        (
            {"exit_code": 0, "stdout_equals": "ok"},
            {"exit_code": 3, "stdout": "ok", "stderr": ""},
            "wrong_exit_code",
        ),
        # stdout_equals mismatch -> wrong_output
        (
            {"exit_code": 0, "stdout_equals": "ok"},
            {"exit_code": 0, "stdout": "wrong", "stderr": ""},
            "wrong_output",
        ),
        # stdout_contains mismatch -> wrong_output
        (
            {"exit_code": 0, "stdout_contains": "ok"},
            {"exit_code": 0, "stdout": "nope", "stderr": ""},
            "wrong_output",
        ),
        # stderr_equals mismatch -> wrong_output
        (
            {"exit_code": 0, "stderr_equals": "err"},
            {"exit_code": 0, "stdout": "", "stderr": "not-err"},
            "wrong_output",
        ),
        # stderr_contains mismatch -> wrong_output
        (
            {"exit_code": 0, "stderr_contains": "err"},
            {"exit_code": 0, "stdout": "", "stderr": "nope"},
            "wrong_output",
        ),
        # all match -> None (pass)
        (
            {"exit_code": 0, "stdout_equals": "ok"},
            {"exit_code": 0, "stdout": "ok", "stderr": ""},
            None,
        ),
        # exit-code-before-output priority: both wrong -> wrong_exit_code
        (
            {"exit_code": 0, "stdout_equals": "ok"},
            {"exit_code": 3, "stdout": "wrong", "stderr": ""},
            "wrong_exit_code",
        ),
        # trailing-newline strip in stdout_equals equality
        (
            {"exit_code": 0, "stdout_equals": "ok"},
            {"exit_code": 0, "stdout": "ok\n", "stderr": ""},
            None,
        ),
        (
            {"exit_code": 0, "stdout_equals": "ok\n"},
            {"exit_code": 0, "stdout": "ok", "stderr": ""},
            None,
        ),
        # trailing-newline strip in stderr_equals equality
        (
            {"exit_code": 0, "stderr_equals": "err"},
            {"exit_code": 0, "stdout": "", "stderr": "err\n"},
            None,
        ),
        # stdout_contains with no exit_code assertion at all -> only output checked
        (
            {"stdout_contains": "o"},
            {"exit_code": 99, "stdout": "ok", "stderr": ""},
            None,
        ),
    ],
)
def test_evaluate_then_table(then, observed, expected):
    assert run_scenarios.evaluate_then(then, observed) == expected
