from sigmaforge.records import RuleScore
from sigmaforge.score.scorer import emit_precision


def test_positive_control_false_forces_all_unmeasured_even_above_floor():
    scores = [RuleScore("r1", tp=10, fp=1, tn=5000, fn=0, events_evaluated=5011)]
    out = emit_precision(scores, positive_control_fired=False, min_events=1000)
    assert out == {"r1": "unmeasured"}  # mapping/control broke -> no precision, period


def test_below_floor_unmeasured_even_with_control():
    scores = [RuleScore("r1", tp=0, fp=0, tn=5, fn=0, events_evaluated=5)]
    out = emit_precision(scores, positive_control_fired=True, min_events=1000)
    assert out == {"r1": "unmeasured"}


def test_precision_emitted_when_control_fires_and_above_floor():
    scores = [RuleScore("r1", tp=10, fp=1, tn=5000, fn=0, events_evaluated=5011)]
    out = emit_precision(scores, positive_control_fired=True, min_events=1000)
    assert out == {"r1": 10 / 11}
