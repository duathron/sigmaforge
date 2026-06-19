"""C2 Task 2.4: render reason-codes inline + data-generated caveats."""

from sigmaforge.report.render import render_report


def _unmeasured_row(recall_reason=None, precision_reason=None):
    return {
        "rule": "Lonely Rule",
        "recall": "unmeasured",
        "precision@COMISET": "unmeasured",
        "tp": 0,
        "fp": 0,
        "events_evaluated": 10,
        "recall_reason": recall_reason,
        "precision_reason": precision_reason,
    }


def test_unmeasured_recall_renders_inline_reason():
    rows = [_unmeasured_row(recall_reason="technique-0-events")]
    md = render_report(rows, {"candidate": 1}, min_events=1000)
    assert "unmeasured (technique-0-events)" in md


def test_unmeasured_precision_renders_inline_reason():
    rows = [_unmeasured_row(precision_reason="below-floor")]
    md = render_report(rows, {"candidate": 1}, min_events=1000)
    assert "unmeasured (below-floor)" in md


def test_measured_row_has_no_reason_suffix():
    rows = [
        {
            "rule": "Measured",
            "recall": 0.5,
            "precision@COMISET": 0.9,
            "tp": 5,
            "fp": 1,
            "events_evaluated": 9000,
            "recall_reason": None,
            "precision_reason": None,
        }
    ]
    md = render_report(rows, {"candidate": 1}, min_events=1000)
    assert "unmeasured" not in md.split("## Per-rule")[1]


def test_caveats_block_generated_from_data_not_hardcoded():
    rows = [_unmeasured_row()]
    caveats = {
        "floor": 1000,
        "recommended_floor": 50000,
        "path_form_split": "66/120 OpTC Image values are bare basenames",
    }
    md = render_report(rows, {"candidate": 1}, min_events=1000, caveats=caveats)
    # the values come from the passed dict, not a literal string baked into render
    assert "50000" in md
    assert "66/120 OpTC Image values are bare basenames" in md


def test_no_caveats_block_when_not_provided():
    md = render_report([_unmeasured_row()], {"candidate": 1}, min_events=1000)
    assert "Caveats" not in md
