from sigmaforge.records import RuleScore
from sigmaforge.score.gates import (
    REASON_BELOW_FLOOR,
    overfit_flag,
    positive_control_ok,
    precision_or_unmeasured,
    precision_reason,
)


def test_precision_reason_below_floor():
    s = RuleScore("r", tp=0, fp=0, tn=0, fn=0, events_evaluated=10)
    assert precision_reason(s, min_events=1000) == REASON_BELOW_FLOOR


def test_precision_reason_none_above_floor():
    s = RuleScore("r", tp=10, fp=1, tn=2000, fn=0, events_evaluated=2011)
    assert precision_reason(s, min_events=1000) is None


def test_precision_unmeasured_below_floor():
    s = RuleScore("r1", tp=0, fp=0, tn=5, fn=0, events_evaluated=5)
    assert precision_or_unmeasured(s, min_events=1000) == "unmeasured"


def test_precision_reported_above_floor():
    s = RuleScore("r1", tp=10, fp=1, tn=2000, fn=0, events_evaluated=2011)
    assert precision_or_unmeasured(s, min_events=1000) == 10 / 11


def test_precision_unmeasured_when_rule_never_fires_above_floor():
    s = RuleScore("r1", tp=0, fp=0, tn=2000, fn=0, events_evaluated=2000)
    assert precision_or_unmeasured(s, min_events=1000) == "unmeasured"


def test_positive_control():
    assert positive_control_ok(True) is True
    assert positive_control_ok(False) is False


def test_overfit_flag():
    assert overfit_flag(fires_original=True, fires_mutated=False) is True  # literal-only -> overfit
    assert overfit_flag(fires_original=True, fires_mutated=True) is False  # behavioural
