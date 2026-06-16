from shipwright_kit.eval import EvalResult

from sigmaforge.records import RuleScore


def metrics(s: RuleScore) -> dict:
    # A9: reuse the validated shipwright_kit.eval math; do not re-derive precision/recall/fpr.
    r = EvalResult(tp=s.tp, fp=s.fp, tn=s.tn, fn=s.fn)
    return {
        "precision": r.precision,
        "recall": r.recall,
        "fpr": r.false_positive_rate,
        "f1": r.f1,
    }
