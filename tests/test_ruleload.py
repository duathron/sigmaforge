from sigmaforge.ingest.ruleload import partition_rules


def test_stateful_excluded_and_level_filtered():
    rules = [
        {"title": "stateless_high", "level": "high", "detection": {"sel": {"Image": "x"}, "condition": "sel"}},
        {"title": "corr", "level": "high", "correlation": {"type": "value_count"}},
        {"title": "count_cond", "level": "critical", "detection": {"condition": "sel | count() > 5"}},
        {"title": "low_rule", "level": "low", "detection": {"sel": {"Image": "y"}, "condition": "sel"}},
    ]
    loaded, excluded = partition_rules(rules, levels=("high", "critical"))
    assert [r["title"] for r in loaded] == ["stateless_high"]      # low dropped by level; stateful dropped
    assert {r["title"] for r in excluded} == {"corr", "count_cond"} # stateful, in-level, excluded
    # low_rule is out-of-level: in NEITHER loaded nor excluded
    assert "low_rule" not in [r["title"] for r in loaded] + [r["title"] for r in excluded]
