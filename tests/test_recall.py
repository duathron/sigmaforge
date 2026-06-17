"""FIX B unit tests for sigmaforge.score.recall (per-technique recall logic)."""

from sigmaforge.score.recall import UNMEASURED, per_technique_recall, rule_techniques


def test_rule_techniques_keeps_subtechnique_granularity():
    # FIX B2: do NOT fold to parent — keep the declared tag granularity.
    rule = {"tags": ["attack.persistence", "attack.t1543.003", "attack.t1059.001"]}
    assert rule_techniques(rule) == {"T1543.003", "T1059.001"}


def test_rule_techniques_keeps_bare_parent_tag():
    # A bare parent tag stays bare (it legitimately covers the whole technique).
    assert rule_techniques({"tags": ["attack.t1059"]}) == {"T1059"}


def test_rule_techniques_empty_when_no_attack_tag():
    assert rule_techniques({"tags": ["car.2013-07-001", "cve.2021-1234"]}) == set()
    assert rule_techniques({}) == set()


def test_subtechnique_rule_excludes_sibling_no_dilution():
    """THE BUG (FIX B2): a T1059.001 rule scored against BOTH T1059.001 and T1059.003
    events must count ONLY the T1059.001 events — the sibling T1059.003 events are
    excluded from BOTH denom and numer (no dilution)."""
    recall, numer, denom, measured = per_technique_recall(
        "R",
        {"T1059.001"},
        {"ps1", "ps2", "cmd1"},  # rule fired on two PS events + one cmd-shell sibling
        event_technique={"ps1": "T1059.001", "ps2": "T1059.001", "cmd1": "T1059.003"},
        technique_event_counts={"T1059.001": 58, "T1059.003": 140},
    )
    # denom is 58 (T1059.001 only), NOT 58+140=198. The T1059.003 fire does not count.
    assert denom == 58
    assert numer == 2
    assert recall == 2 / 58
    assert measured == ["T1059.001"]


def test_bare_parent_rule_covers_all_children():
    """A bare-T1059 rule covers ALL T1059.* children (and bare T1059)."""
    recall, numer, denom, measured = per_technique_recall(
        "R",
        {"T1059"},
        {"ps1", "cmd1"},
        event_technique={"ps1": "T1059.001", "cmd1": "T1059.003"},
        technique_event_counts={"T1059.001": 58, "T1059.003": 140, "T1003": 28},
    )
    assert denom == 58 + 140  # all children, T1003 excluded
    assert numer == 2
    assert measured == ["T1059.001", "T1059.003"]


def test_subtechnique_rule_with_no_matching_corpus_bucket_unmeasured():
    """T1027.005 rule against a corpus that only has BARE T1027 -> no exact match,
    and a sub-technique rule does NOT match the bare parent's pool -> unmeasured."""
    recall, numer, denom, measured = per_technique_recall(
        "R", {"T1027.005"}, set(),
        event_technique={},
        technique_event_counts={"T1027": 742},
    )
    assert recall == UNMEASURED and denom == 0 and measured == []


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
