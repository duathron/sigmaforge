"""Pure backtest orchestration (testable without live Zircolite).

Two-source scoring (EVTX-recall coherence):
- RECALL from the native-EVTX attack corpus (all-malicious): tp_recall / attack-events.
- PRECISION/FP from the COMISET benign corpus via the label-aware, deduping `score_rule`
  (A3: a malicious-labelled hit in the benign corpus is a TP, not an FP; MAJOR-5: dedupe
  per (rule_id, event_id)).
Precision flows ONLY through `emit_precision` (A2/A12) — no ungated raw precision is emitted.
"""

from sigmaforge.records import MatchRecord
from sigmaforge.report.render import render_report
from sigmaforge.runmanifest import run_hash
from sigmaforge.score.adapter import score_rule
from sigmaforge.score.coverage import events_evaluated_for_rule, selection_fields
from sigmaforge.score.scorer import emit_precision


def run_backtest(
    loaded_rules: list[dict],
    attack_fires: set[MatchRecord],  # from EVTX attack corpus (recall)
    benign_fires: set[MatchRecord],  # from COMISET benign corpus (precision)
    benign_events: list[dict],  # COMISET events, carry sigmaforge_label (for labels + coverage)
    n_attack_events: int,  # total attack-corpus events (recall denominator)
    positive_control_fired: bool,
    min_events: int,
    source: str = "COMISET",
) -> tuple[list[dict], dict, str]:
    titles = {r["title"] for r in loaded_rules}
    # benign-corpus label split (A3): malicious-labelled benign-corpus events are TP, not FP
    n_ben_mal = sum(1 for e in benign_events if e.get("sigmaforge_label") == "malicious")
    n_ben_ben = len(benign_events) - n_ben_mal

    scores = []
    recall_by_rule: dict[str, float] = {}
    for rule in loaded_rules:
        rid = rule["title"]
        cov = events_evaluated_for_rule(benign_events, selection_fields(rule))
        # precision side: label-aware + dedupe via score_rule on the benign corpus
        b = [f for f in benign_fires if f.rule_id == rid]
        s = score_rule(rid, b, n_malicious=n_ben_mal, n_benign=n_ben_ben, events_evaluated=cov)
        scores.append(s)
        # recall side: unique malicious hits on the all-malicious attack corpus
        tp_recall = len({f.event_id for f in attack_fires if f.rule_id == rid and f.event_label == "malicious"})
        recall_by_rule[rid] = tp_recall / n_attack_events if n_attack_events else 0.0

    precisions = emit_precision(scores, positive_control_fired, min_events)  # the ONLY precision path
    rows = []
    for s in scores:
        rows.append(
            {
                "rule": s.rule_id,
                "recall": recall_by_rule[s.rule_id],
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
    # only score loaded (stateless, level-filtered) rules; ignore any engine fires outside `titles`
    assert all(s.rule_id in titles for s in scores)
    # A11: worker-invariant reproducibility stamp over the aggregated fire set
    rh = run_hash(attack_fires | benign_fires)
    return rows, funnel, render_report(rows, funnel, source=source, min_events=min_events, run_hash=rh)
