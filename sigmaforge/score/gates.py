from sigmaforge.records import RuleScore

# Reason-codes for the unmeasured precision branches (net-new, additive). They NAME
# the conditions `precision_or_unmeasured` already returns "unmeasured" for, without
# changing that function's return:
REASON_BELOW_FLOOR = "below-floor"  # A12: fewer than min_events evaluated
# Above the floor but tp+fp == 0 -> precision has a ZERO denominator (the rule never
# fired on the benign corpus), so it is "unmeasured" with no benign exemplars to
# measure precision against. This is distinct from below-floor (enough events WERE
# evaluated) and ensures every unmeasured precision cell carries a reason.
REASON_NO_BENIGN_EXEMPLARS = "no-benign-exemplars"


def precision_or_unmeasured(s: RuleScore, min_events: int):
    """A12 floor + A2 coverage: precision only when enough events were actually evaluated."""
    if s.events_evaluated < min_events:
        return "unmeasured"
    denom = s.tp + s.fp
    return s.tp / denom if denom else "unmeasured"


def precision_reason(s: RuleScore, min_events: int) -> str | None:
    """Reason-code for WHY precision is unmeasured, or ``None`` if measurable.

    Net-new + additive (mirrors the two "unmeasured" branches of
    ``precision_or_unmeasured`` WITHOUT changing its numeric return, preserving the
    C1 semantic-equivalence gate):

    - ``REASON_BELOW_FLOOR`` when fewer than ``min_events`` were evaluated (A12 floor), else
    - ``REASON_NO_BENIGN_EXEMPLARS`` when enough events were evaluated but the rule
      never fired (``tp + fp == 0`` -> zero precision denominator), else
    - ``None`` (precision is measurable).
    """
    if s.events_evaluated < min_events:
        return REASON_BELOW_FLOOR
    if s.tp + s.fp == 0:
        return REASON_NO_BENIGN_EXEMPLARS
    return None


def positive_control_ok(rule_fired: bool) -> bool:
    """A2: the pinned known-malicious control event MUST fire before any precision is trusted.
    If it does not fire, the field mapping/logsource is broken -> precision is unmeasurable."""
    return rule_fired


def overfit_flag(fires_original: bool, fires_mutated: bool) -> bool:
    """A2 overfit guard: a behavioural rule fires on both the original and the literal-IOC-mutated
    twin; a literal-string (IOC) rule fires only on the original. True = overfit (literal-only)."""
    return fires_original and not fires_mutated
