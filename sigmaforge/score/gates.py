from sigmaforge.records import RuleScore


def precision_or_unmeasured(s: RuleScore, min_events: int):
    """A12 floor + A2 coverage: precision only when enough events were actually evaluated."""
    if s.events_evaluated < min_events:
        return "unmeasured"
    denom = s.tp + s.fp
    return s.tp / denom if denom else "unmeasured"


def positive_control_ok(rule_fired: bool) -> bool:
    """A2: the pinned known-malicious control event MUST fire before any precision is trusted.
    If it does not fire, the field mapping/logsource is broken -> precision is unmeasurable."""
    return rule_fired


def overfit_flag(fires_original: bool, fires_mutated: bool) -> bool:
    """A2 overfit guard: a behavioural rule fires on both the original and the literal-IOC-mutated
    twin; a literal-string (IOC) rule fires only on the original. True = overfit (literal-only)."""
    return fires_original and not fires_mutated
