"""Virtual test of the myQ voice-command parser.

Run:  python3 -m unittest gemini-myq-gate/tests/test_parse_command.py -v
  or: python3 gemini-myq-gate/tests/test_parse_command.py   (prints a report)

Covers: exact phrases, natural variations, word-number forms, common
speech-to-text mishears, the gate-vs-garage trap, and negatives that must NOT
open anything (including the not-yet-installed door 4).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from parse_command import parse_command  # noqa: E402

GATE = "Gate"
GD1, GD2, GD3 = "Garage Door 1", "Garage Door 2", "Garage Door 3"

# (spoken phrase, expected tile or None)
CASES = [
    # --- canonical ---
    ("open the gate", GATE),
    ("open garage door 1", GD1),
    ("open garage door 2", GD2),
    ("open garage door 3", GD3),
    # --- with the custom wake word left in (AutoVoice may not strip perfectly) ---
    ("sesame open the gate", GATE),
    ("sesame open garage door 2", GD2),
    # --- natural variations ---
    ("gate", GATE),
    ("open gate please", GATE),
    ("garage door one", GD1),
    ("garage door two", GD2),
    ("garage door three", GD3),
    ("open door 3", GD3),
    ("door one", GD1),
    ("open garage 2", GD2),
    ("please open garage door number two", GD2),
    ("can you open the gate", GATE),
    ("OPEN GARAGE DOOR 1", GD1),
    ("Open Garage Door 3.", GD3),
    # --- common speech-to-text mishears (disambiguated by the door cue) ---
    ("open garage door too", GD2),      # two -> too
    ("open garage door to", GD2),
    ("open garage door tree", GD3),     # three -> tree
    ("open garge door one", GD1),       # garage -> garge
    ("open garaje door 3", GD3),
    # --- the classic trap: 'garage' must NOT be read as 'gate' ---
    ("open garage door 1", GD1),
    ("garage door 2", GD2),
    # --- negatives: must return None (flow asks again, opens nothing) ---
    ("", None),
    ("what's the weather", None),
    ("open the front door", None),      # 'door' but no known number
    ("open garage door 4", None),       # 5th not installed yet
    ("garage door four", None),
    ("open garage door 9", None),
    ("turn on the lights", None),
    ("open something", None),
]


class TestParseCommand(unittest.TestCase):
    def test_all_cases(self):
        failures = []
        for phrase, expected in CASES:
            got = parse_command(phrase)
            if got != expected:
                failures.append((phrase, expected, got))
        if failures:
            lines = [f"  {p!r}: expected {e!r}, got {g!r}" for p, e, g in failures]
            self.fail("Mismatches:\n" + "\n".join(lines))

    def test_gate_never_confused_with_garage(self):
        for n in (1, 2, 3):
            self.assertEqual(parse_command(f"open garage door {n}"), f"Garage Door {n}")

    def test_unknown_never_opens_a_door(self):
        for phrase in ("open garage door 4", "front door", "hello", ""):
            self.assertIsNone(parse_command(phrase))


def _report():
    ok = 0
    print(f"{'PHRASE':<40} {'EXPECTED':<16} {'GOT':<16} RESULT")
    print("-" * 84)
    for phrase, expected in CASES:
        got = parse_command(phrase)
        passed = got == expected
        ok += passed
        print(f"{phrase!r:<40} {str(expected):<16} {str(got):<16} "
              f"{'PASS' if passed else 'FAIL'}")
    print("-" * 84)
    print(f"{ok}/{len(CASES)} passed")
    return ok == len(CASES)


if __name__ == "__main__":
    sys.exit(0 if _report() else 1)
