from sigmaforge.score.coverage import events_evaluated_for_rule, selection_fields


def test_coverage_counts_events_with_selection_fields_present():
    events = [
        {"Image": "a.exe", "CommandLine": "x"},  # has both
        {"Image": "b.exe"},  # missing CommandLine
        {"CommandLine": "y"},  # missing Image
        {"Image": "c.exe", "CommandLine": ""},  # empty -> not present
    ]
    assert events_evaluated_for_rule(events, {"Image", "CommandLine"}) == 1


def test_selection_fields_strips_modifiers():
    rule = {
        "detection": {
            "selection": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": "-enc"},
            "condition": "selection",
        }
    }
    assert selection_fields(rule) == {"Image", "CommandLine"}
