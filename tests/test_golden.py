import json
from pathlib import Path

from sigmaforge.ingest.zircolite_runner import parse_detections
from sigmaforge.score.adapter import score_rule

GOLDEN = Path(__file__).parent.parent / "data" / "fixtures" / "golden"


def test_golden_parse_score_chain_exact():
    """Validate the validator: a recorded Zircolite output -> parse -> score must hit known truth."""
    detections = json.loads((GOLDEN / "zircolite_out.json").read_text())
    expected = json.loads((GOLDEN / "expected.json").read_text())
    c = expected["corpus"]

    fires = parse_detections(detections)
    s = score_rule(
        "r_lsass",
        [f for f in fires if f.rule_id == "r_lsass"],
        n_malicious=c["n_malicious"],
        n_benign=c["n_benign"],
        events_evaluated=c["events_evaluated"],
    )
    got = {"tp": s.tp, "fp": s.fp, "tn": s.tn, "fn": s.fn, "events_evaluated": s.events_evaluated}
    assert got == expected["r_lsass"]
