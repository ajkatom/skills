"""Reference implementation of the myQ voice-command parser.

This mirrors, exactly, the If-ladder you build in Tasker for the Galaxy S24
"one smart command" flow. It exists so the brittle part — turning a spoken
sentence into the right myQ tile — can be TESTED before you build anything on
the phone.

Contract (must match the Tasker ladder in galaxy-s24-smart-command.md):
  * Compare case-insensitively.
  * Check "gate" FIRST so a "garage" match can't swallow it.
  * A garage door needs a door/garage cue AND a number (digit or word 1..3).
  * Accept common speech-to-text variants (word numbers, "number two", light
    mishears like "too"->2) but stay conservative: if it's not clearly one of
    the known devices, return None so the flow asks again instead of opening
    the wrong door.

Devices live today: Gate, Garage Door 1, Garage Door 2, Garage Door 3.
The 5th opener is not installed yet; add it in ONE place (KNOWN_DOORS) when it
is, and both this test and the phone ladder stay in sync.
"""

from __future__ import annotations

import re

# The exact tile text as shown in the myQ app. Add the 5th here when ready.
GATE_TILE = "Gate"
KNOWN_DOORS = {
    1: "Garage Door 1",
    2: "Garage Door 2",
    3: "Garage Door 3",
    # 4: "Garage Door 4",   # <- uncomment + set exact name when the 5th is set up
}

# Word/number spellings a speech recognizer may emit, mapped to the digit.
# "too"/"to" -> 2 and "for" -> 4 are common mishears; kept ONLY because they
# are disambiguated by requiring a door/garage cue in the same phrase.
_NUMBER_WORDS = {
    "1": 1, "one": 1, "won": 1,
    "2": 2, "two": 2, "too": 2, "to": 2,
    "3": 3, "three": 3, "tree": 3,
    "4": 4, "four": 4, "for": 4, "fore": 4,
    "5": 5, "five": 5,
}

_DOOR_CUES = ("door", "garage", "garge", "garaje")  # + light mishears
_GATE_CUES = ("gate", "gates", "the gate")


def _normalize(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9 ]+", " ", text)   # drop punctuation
    text = re.sub(r"\s+", " ", text)
    return text


def parse_command(text: str):
    """Return the exact myQ tile name to tap, or None if not understood.

    Mirrors the Tasker If-ladder order precisely.
    """
    if not text:
        return None
    p = _normalize(text)
    tokens = p.split()

    # 1) Gate first.
    if any(cue in p for cue in _GATE_CUES):
        return GATE_TILE

    # 2) Garage door N — need a door/garage cue AND a known number.
    has_door_cue = any(cue in p for cue in _DOOR_CUES)
    if has_door_cue:
        for tok in tokens:
            n = _NUMBER_WORDS.get(tok)
            if n in KNOWN_DOORS:
                return KNOWN_DOORS[n]
        # door cue but a number we don't have (e.g. "door 4" today) -> unknown
        return None

    # 3) No gate, no door cue -> not a command we act on.
    return None


if __name__ == "__main__":
    import sys
    print(parse_command(" ".join(sys.argv[1:])))
