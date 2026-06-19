from sigmaforge.records import RuleScore

# Reason-code for the precision-floor unmeasured branch (net-new, additive). NAMES
# the A12 floor condition that `precision_or_unmeasured` already returns
# "unmeasured" for, without changing that function's return.
REASON_BELOW_FLOOR = "below-floor"


def precision_or_unmeasured(s: RuleScore, min_events: int):
    """A12 floor + A2 coverage: precision only when enough events were actually evaluated."""
    if s.events_evaluated < min_events:
        return "unmeasured"
    denom = s.tp + s.fp
    return s.tp / denom if denom else "unmeasured"


def precision_reason(s: RuleScore, min_events: int) -> str | None:
    """Reason-code for WHY precision is unmeasured, or ``None`` if measurable.

    Net-new + additive: ``REASON_BELOW_FLOOR`` when fewer than ``min_events`` were
    evaluated (the A12 floor), else ``None``. Leaves ``precision_or_unmeasured``
    unchanged to preserve the C1 semantic-equivalence gate.
    """
    if s.events_evaluated < min_events:
        return REASON_BELOW_FLOOR
    return None


def positive_control_ok(rule_fired: bool) -> bool:
    """A2: the pinned known-malicious control event MUST fire before any precision is trusted.
    If it does not fire, the field mapping/logsource is broken -> precision is unmeasurable."""
    return rule_fired


def overfit_flag(fires_original: bool, fires_mutated: bool) -> bool:
    """A2 overfit guard: a behavioural rule fires on both the original and the literal-IOC-mutated
    twin; a literal-string (IOC) rule fires only on the original. True = overfit (literal-only)."""
    return fires_original and not fires_mutated
