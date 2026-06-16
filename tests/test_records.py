from sigmaforge.records import MatchRecord, RuleScore

def test_matchrecord_is_hashable_and_keyed():
    r = MatchRecord(rule_id="r1", event_id="e1", event_label="benign")
    assert r.rule_id == "r1" and r.event_label == "benign"
    assert len({r, MatchRecord("r1", "e1", "benign")}) == 1  # dedupe across shards

def test_rulescore_holds_counts():
    s = RuleScore(rule_id="r1", tp=2, fp=0, tn=10, fn=1, events_evaluated=13)
    assert s.tp == 2 and s.events_evaluated == 13
