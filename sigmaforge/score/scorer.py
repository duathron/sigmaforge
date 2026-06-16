from shipwright_kit.eval import EvalResult

from sigmaforge.records import RuleScore
from sigmaforge.score.gates import positive_control_ok, precision_or_unmeasured


def metrics(s: RuleScore) -> dict:
    # A9: reuse the validated shipwright_kit.eval math; do not re-derive precision/recall/fpr.
    r = EvalResult(tp=s.tp, fp=s.fp, tn=s.tn, fn=s.fn)
    return {
        "precision": r.precision,
        "recall": r.recall,
        "fpr": r.false_positive_rate,
        "f1": r.f1,
    }


def emit_precision(scores: list[RuleScore], positive_control_fired: bool, min_events: int) -> dict:
    """A2/A12: the ONLY sanctioned precision path. If the positive control did not fire (mapping
    broken), NO rule gets a precision number. Otherwise each rule is floor-gated per coverage."""
    if not positive_control_ok(positive_control_fired):
        return {s.rule_id: "unmeasured" for s in scores}
    return {s.rule_id: precision_or_unmeasured(s, min_events) for s in scores}
