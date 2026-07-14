"""Deterministic ID/taxonomy feedback projection (spec section 6.1). Stdlib only.

This is the ONLY thing that crosses the information barrier back to the
builder. It is a pure structural projection: it reads behavior_id, pass,
and taxonomy from the verifier report and NOTHING else — no titles, no
given/when/then, no observed output, no model call.
"""
import re

TAXONOMY = ("wrong_exit_code", "wrong_output", "timeout", "crash")
BEHAVIOR_RE = re.compile(r"^BHV-[A-Za-z0-9-]{1,32}$")
ALLOWED_TOP = {"feedback_version", "channel", "total", "failing_count", "failures"}
ALLOWED_FAILURE = {"behavior_id", "taxonomy"}


class FeedbackLeakError(ValueError):
    pass


def project_feedback(report: dict) -> dict:
    failing = {}
    for r in report["results"]:
        if not r["pass"]:
            failing.setdefault(r["behavior_id"], set()).add(r["taxonomy"])
    fb = {
        "feedback_version": "0.1",
        "channel": "ids",
        "total": len(report["results"]),
        "failing_count": sum(1 for r in report["results"] if not r["pass"]),
        "failures": [
            {"behavior_id": b, "taxonomy": sorted(t)}
            for b, t in sorted(failing.items())
        ],
    }
    validate_feedback(fb)
    return fb


def validate_feedback(fb: dict) -> None:
    if set(fb) != ALLOWED_TOP:
        raise FeedbackLeakError(f"feedback keys must be exactly {sorted(ALLOWED_TOP)}")
    if fb["feedback_version"] != "0.1" or fb["channel"] != "ids":
        raise FeedbackLeakError("bad feedback_version/channel")
    if not isinstance(fb["total"], int) or not isinstance(fb["failing_count"], int):
        raise FeedbackLeakError("total/failing_count must be ints")
    if not isinstance(fb["failures"], list):
        raise FeedbackLeakError("failures must be a list")
    for f in fb["failures"]:
        if set(f) != ALLOWED_FAILURE:
            raise FeedbackLeakError(f"failure keys must be exactly {sorted(ALLOWED_FAILURE)}")
        if not BEHAVIOR_RE.fullmatch(f["behavior_id"]):
            raise FeedbackLeakError("invalid behavior_id (offending value withheld)")
        if not isinstance(f["taxonomy"], list) or not f["taxonomy"]:
            raise FeedbackLeakError("taxonomy must be a non-empty list")
        for t in f["taxonomy"]:
            if t not in TAXONOMY:
                raise FeedbackLeakError("unknown taxonomy value (offending value withheld)")
