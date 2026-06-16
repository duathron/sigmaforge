from sigmaforge.records import MatchRecord, RuleScore
from sigmaforge.score.adapter import score_rule
from sigmaforge.score.scorer import metrics


def test_fp_keyed_off_label():
    fires = [MatchRecord("r1", "m1", "malicious"), MatchRecord("r1", "b1", "benign")]
    s = score_rule("r1", fires, n_malicious=1, n_benign=3, events_evaluated=4)
    assert (s.tp, s.fp, s.fn, s.tn) == (1, 1, 0, 2)


def test_duplicate_fires_deduped():
    fires = [MatchRecord("r1", "m1", "malicious"), MatchRecord("r1", "m1", "malicious")]
    s = score_rule("r1", fires, n_malicious=1, n_benign=0, events_evaluated=1)
    assert s.tp == 1  # not 2


def test_metrics_use_shipwright_math():
    m = metrics(RuleScore("r1", tp=1, fp=0, tn=2, fn=0, events_evaluated=3))
    assert m["precision"] == 1.0 and m["recall"] == 1.0
