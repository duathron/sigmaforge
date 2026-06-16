"""Pure backtest orchestration (testable without live Zircolite).

Two-source scoring (EVTX-recall coherence): recall (tp/fn) from the native-EVTX attack
corpus; precision (fp/tn) + coverage from the COMISET benign corpus. Merged per rule_id.
Precision flows ONLY through emit_precision (A2/A12).
"""

from sigmaforge.records import MatchRecord, RuleScore
from sigmaforge.report.render import render_report
from sigmaforge.score.coverage import events_evaluated_for_rule, selection_fields
from sigmaforge.score.scorer import emit_precision, metrics


def run_backtest(
    loaded_rules: list[dict],
    attack_fires: set[MatchRecord],  # from EVTX attack corpus (recall)
    benign_fires: set[MatchRecord],  # from COMISET benign corpus (precision)
    benign_events: list[dict],  # for coverage counting
    n_attack_malicious: int,  # total attack events (recall denominator)
    positive_control_fired: bool,
    min_events: int,
    source: str = "COMISET",
) -> tuple[list[dict], dict, str]:
    n_benign = len(benign_events)
    scores: list[RuleScore] = []
    for rule in loaded_rules:
        rid = rule["title"]
        fields = selection_fields(rule)
        cov = events_evaluated_for_rule(benign_events, fields)
        a = [f for f in attack_fires if f.rule_id == rid]
        b = [f for f in benign_fires if f.rule_id == rid]
        tp = len({f.event_id for f in a})
        fp = len({f.event_id for f in b})
        scores.append(
            RuleScore(
                rid, tp=tp, fp=fp, tn=max(0, n_benign - fp), fn=max(0, n_attack_malicious - tp), events_evaluated=cov
            )
        )

    precisions = emit_precision(scores, positive_control_fired, min_events)
    rows = []
    for s in scores:
        m = metrics(s)
        rows.append(
            {
                "rule": s.rule_id,
                "recall": m["recall"],
                "precision": m["precision"],
                f"precision@{source}": precisions[s.rule_id],
                "tp": s.tp,
                "fp": s.fp,
                "events_evaluated": s.events_evaluated,
            }
        )
    funnel = {
        "candidate": len(loaded_rules),
        "loaded": len(loaded_rules),
        "stateless": len(loaded_rules),
        "fires": len({s.rule_id for s in scores if s.tp or s.fp}),
        "survives_fp": len([s for s in scores if s.fp == 0 and s.tp]),
    }
    return rows, funnel, render_report(rows, funnel, source=source, min_events=min_events)
