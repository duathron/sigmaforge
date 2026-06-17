"""FIX B unit tests for sigmaforge.score.recall (per-technique recall logic)."""

from sigmaforge.score.recall import UNMEASURED, per_technique_recall, rule_techniques


def test_rule_techniques_folds_subtechnique_to_parent():
    rule = {"tags": ["attack.persistence", "attack.t1543.003", "attack.t1059.001"]}
    assert rule_techniques(rule) == {"T1543", "T1059"}


def test_rule_techniques_empty_when_no_attack_tag():
    assert rule_techniques({"tags": ["car.2013-07-001", "cve.2021-1234"]}) == set()
    assert rule_techniques({}) == set()


def test_recall_scoped_to_technique_denominator():
    recall, numer, denom, measured = per_technique_recall(
        "R", {"T1059"}, {"a", "b", "c"},
        event_technique={"a": "T1059", "b": "T1059", "c": "T1059"},
        technique_event_counts={"T1059": 50, "T1003": 9999},
    )
    assert (numer, denom) == (3, 50)
    assert recall == 3 / 50
    assert measured == ["T1059"]


def test_recall_only_counts_on_technique_fires():
    recall, numer, denom, _ = per_technique_recall(
        "R", {"T1059"}, {"a", "b"},
        event_technique={"a": "T1059", "b": "T1003"},  # b is off-technique
        technique_event_counts={"T1059": 10},
    )
    assert numer == 1 and denom == 10 and recall == 1 / 10


def test_multi_technique_rule_sums_denominators():
    recall, numer, denom, measured = per_technique_recall(
        "R", {"T1059", "T1003"}, {"a", "b"},
        event_technique={"a": "T1059", "b": "T1003"},
        technique_event_counts={"T1059": 10, "T1003": 20},
    )
    assert denom == 30 and numer == 2 and recall == 2 / 30
    assert measured == ["T1003", "T1059"]


def test_untagged_rule_unmeasured():
    recall, numer, denom, measured = per_technique_recall(
        "R", set(), {"a"}, {"a": "T1059"}, {"T1059": 10}
    )
    assert recall == UNMEASURED and numer == 0 and denom == 0 and measured == []


def test_technique_with_zero_events_unmeasured():
    recall, numer, denom, measured = per_technique_recall(
        "R", {"T1490"}, set(), {"a": "T1059"}, {"T1059": 10}  # no T1490 events
    )
    assert recall == UNMEASURED and denom == 0


def test_partially_present_technique_set_measures_only_present():
    # rule tagged T1059 (present) + T1490 (absent) -> measured against T1059 only
    recall, numer, denom, measured = per_technique_recall(
        "R", {"T1059", "T1490"}, {"a"},
        event_technique={"a": "T1059"},
        technique_event_counts={"T1059": 10},
    )
    assert measured == ["T1059"] and denom == 10 and numer == 1 and recall == 1 / 10
