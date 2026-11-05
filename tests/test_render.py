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


# --- F8: a rule title is attacker-controlled; it must stay inside its table cell ---

def _evil_row(title):
    return {
        "rule": title,
        "recall": 1.0,
        "precision@COMISET": 1.0,
        "tp": 1,
        "fp": 0,
        "events_evaluated": 10,
    }


def _cells(line):
    import re

    return re.split(r"(?<!\\)\|", line)


def test_rule_title_pipe_cannot_forge_table_cells():
    md = render_report([_evil_row("Evil | 1.0 | 9 | 0 | 9999 | 9999 | 9999 | real")], {})
    lines = md.splitlines()
    header = next(ln for ln in lines if ln.startswith("| rule |"))
    row = next(ln for ln in lines if ln.startswith("| Evil"))
    assert len(_cells(row)) == len(_cells(header))


def test_rule_title_newline_cannot_start_a_markdown_line():
    md = render_report([_evil_row("a\n## injected")], {})
    assert not any(ln.startswith("## injected") for ln in md.splitlines())


def test_rule_title_control_chars_stripped():
    md = render_report([_evil_row("x\x1b[2Jy")], {})
    assert "\x1b" not in md


def test_free_text_fields_cannot_inject_lines_or_cells():
    md = render_report(
        [],
        {},
        source="CO|MISET\n## s",
        corpus_note="n\n## c",
        recall_note="r\n## r",
        caveats={"floor": 1, "k\n## k": "v\n## v", "path_form_split": "p\n## p"},
    )
    for frag in ("## s", "## c", "## r", "## k", "## v", "## p"):
        assert not any(ln.startswith(frag) for ln in md.splitlines()), frag


def test_fp_tuning_and_tautology_titles_are_neutralized():
    row = _evil_row("T\n## own")
    row.update(fp=9, no_benign_exemplars=True)
    md = render_report([row], {})
    assert not any(ln.startswith("## own") for ln in md.splitlines())


def test_benign_title_unchanged():
    md = render_report([_evil_row("Whoami Execution")], {})
    assert "| Whoami Execution | 1.0 | 1.0 |" in md
