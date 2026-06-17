import pytest

from sigmaforge.records import MatchRecord
from sigmaforge.score.acceptance import assert_one_source, check_corpus


def _f(rid, eid, label="benign"):
    return MatchRecord(rule_id=rid, event_id=eid, event_label=label)


def test_one_source_passes_when_all_fires_loaded():
    loaded = {"RuleA", "RuleB"}
    fires = {_f("RuleA", "e1"), _f("RuleB", "e2"), _f("RuleA", "e3")}
    r = check_corpus("benign", fires, loaded)
    assert r.ok
    assert r.engine_fires == 3
    assert r.scored_fires == 3
    assert r.dropped_titles == ()


def test_title_drop_is_caught_not_silently_dropped():
    # FIX H regression: a fire whose title is NOT in the loaded set must fail the
    # gate (the old two-source path silently dropped these: 767 -> 2).
    loaded = {"RuleA"}
    fires = {_f("RuleA", "e1"), _f("BundledOnlyRule", "e2"), _f("AnotherBundled", "e3")}
    r = check_corpus("benign", fires, loaded)
    assert not r.ok
    assert r.engine_fires == 3
    assert r.scored_fires == 1  # only RuleA would have been scored
    assert set(r.dropped_titles) == {"BundledOnlyRule", "AnotherBundled"}
    assert "title-drop" in r.reason()


def test_engine_equals_scored_distinct_pairs():
    loaded = {"RuleA"}
    # duplicate (RuleA, e1) collapses -> 2 distinct pairs
    fires = [_f("RuleA", "e1"), _f("RuleA", "e1"), _f("RuleA", "e2")]
    r = check_corpus("attack", fires, loaded)
    assert r.ok
    assert r.engine_fires == 2
    assert r.scored_fires == 2


def test_assert_one_source_raises_on_benign_title_drop():
    loaded = {"RuleA"}
    attack = {_f("RuleA", "a1", "malicious")}
    benign = {_f("RuleA", "b1"), _f("Ghost", "b2")}  # benign-side drop (the 767->2 shape)
    with pytest.raises(AssertionError) as exc:
        assert_one_source(loaded, attack, benign)
    assert "benign" in str(exc.value)
    assert "Ghost" in str(exc.value)


def test_assert_one_source_passes_both_corpora():
    loaded = {"RuleA", "RuleB"}
    attack = {_f("RuleA", "a1", "malicious"), _f("RuleB", "a2", "malicious")}
    benign = {_f("RuleA", "b1")}
    results = assert_one_source(loaded, attack, benign)
    assert [r.corpus for r in results] == ["attack", "benign"]
    assert all(r.ok for r in results)
