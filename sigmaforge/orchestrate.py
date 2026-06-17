"""Pure backtest orchestration (testable without live Zircolite).

Two-source scoring (EVTX-recall coherence):
- RECALL from the native-EVTX attack corpus (all-malicious). FIX B: PER-TECHNIQUE
  recall — each rule is measured against only the attack events of its own ATT&CK
  technique(s) (denom = events of that technique, not the whole corpus). A rule
  with no technique tag, or whose technique has zero attack events, is
  "unmeasured". When the per-technique inputs are not supplied the recall falls
  back to the legacy POOLED denominator `tp_recall / n_attack_events`.
- PRECISION/FP from the COMISET benign corpus via the label-aware, deduping `score_rule`
  (A3: a malicious-labelled hit in the benign corpus is a TP, not an FP; MAJOR-5: dedupe
  per (rule_id, event_id)).
Precision flows ONLY through `emit_precision` (A2/A12) — no ungated raw precision is emitted.
"""

from sigmaforge.records import MatchRecord
from sigmaforge.report.render import render_report
from sigmaforge.runmanifest import run_hash
from sigmaforge.score.acceptance import assert_one_source
from sigmaforge.score.adapter import score_rule
from sigmaforge.score.coverage import (
    benign_events_evaluated_for_rule,
    events_evaluated_for_rule,
    selection_fields,
)
from sigmaforge.score.recall import UNMEASURED, per_technique_recall, rule_techniques
from sigmaforge.score.scorer import emit_precision


def run_backtest(
    loaded_rules: list[dict],
    attack_fires: set[MatchRecord],  # from EVTX attack corpus (recall)
    benign_fires: set[MatchRecord],  # from COMISET benign corpus (precision)
    benign_events: list[dict],  # COMISET events, carry sigmaforge_label (for labels + coverage)
    n_attack_events: int,  # total attack-corpus events (legacy pooled recall denominator)
    positive_control_fired: bool,
    min_events: int,
    source: str = "COMISET",
    # FIX B (per-technique recall). All three must be supplied together to enable it;
    # if any is None, recall falls back to the legacy pooled denominator.
    event_technique: dict[str, str] | None = None,  # event_id -> parent ATT&CK technique
    technique_event_counts: dict[str, int] | None = None,  # technique -> total attack PC events
) -> tuple[list[dict], dict, str]:
    per_technique = event_technique is not None and technique_event_counts is not None
    titles = {r["title"] for r in loaded_rules}
    # benign-corpus label split (A3): malicious-labelled benign-corpus events are TP, not FP
    n_ben_mal = sum(1 for e in benign_events if e.get("sigmaforge_label") == "malicious")
    n_ben_ben = len(benign_events) - n_ben_mal

    scores = []
    recall_by_rule: dict[str, float | str] = {}
    recall_meta_by_rule: dict[str, dict] = {}
    benign_cov_by_rule: dict[str, int] = {}
    for rule in loaded_rules:
        rid = rule["title"]
        fields = selection_fields(rule)
        cov = events_evaluated_for_rule(benign_events, fields)
        # BLOCKER-2: how many BENIGN-labelled events could have produced an FP at all
        benign_cov_by_rule[rid] = benign_events_evaluated_for_rule(benign_events, fields)
        # precision side: label-aware + dedupe via score_rule on the benign corpus
        b = [f for f in benign_fires if f.rule_id == rid]
        s = score_rule(rid, b, n_malicious=n_ben_mal, n_benign=n_ben_ben, events_evaluated=cov)
        scores.append(s)
        # recall side: unique malicious hits on the all-malicious attack corpus
        fired_eids = {f.event_id for f in attack_fires if f.rule_id == rid and f.event_label == "malicious"}
        if per_technique:
            # FIX B: measure the rule against only the events of its own technique(s)
            techs = rule_techniques(rule)
            recall, numer, denom, measured = per_technique_recall(
                rid, techs, fired_eids, event_technique, technique_event_counts
            )
            recall_by_rule[rid] = recall
            recall_meta_by_rule[rid] = {
                "techniques": sorted(techs),
                "measured_techniques": measured,
                "recall_numer": numer,
                "recall_denom": denom,
                "recall_measurable": recall != UNMEASURED,
            }
        else:
            # legacy POOLED recall (fallback when per-technique inputs absent)
            recall_by_rule[rid] = (len(fired_eids) / n_attack_events) if n_attack_events else 0.0
            recall_meta_by_rule[rid] = {"recall_measurable": None}

    precisions = emit_precision(scores, positive_control_fired, min_events)  # the ONLY precision path
    rows = []
    for s in scores:
        # BLOCKER-2 flag: a measured precision with zero benign exemplars carries NO FP signal
        # (fp=0 is true by construction — no benign-labelled event matched the selection).
        no_benign_exemplars = benign_cov_by_rule[s.rule_id] == 0
        meta = recall_meta_by_rule[s.rule_id]
        rows.append(
            {
                "rule": s.rule_id,
                "recall": recall_by_rule[s.rule_id],
                f"precision@{source}": precisions[s.rule_id],
                "tp": s.tp,
                "fp": s.fp,
                "events_evaluated": s.events_evaluated,
                "benign_events_evaluated": benign_cov_by_rule[s.rule_id],
                "no_benign_exemplars": no_benign_exemplars,
                # FIX B per-technique recall provenance (present even in pooled mode, with
                # recall_measurable=None so the report can tell the two modes apart)
                "recall_techniques": meta.get("techniques", []),
                "recall_measured_techniques": meta.get("measured_techniques", []),
                "recall_numer": meta.get("recall_numer"),
                "recall_denom": meta.get("recall_denom"),
                "recall_measurable": meta.get("recall_measurable"),
            }
        )
    funnel = {
        "candidate": len(loaded_rules),
        "loaded": len(loaded_rules),
        "stateless": len(loaded_rules),
        "fires": len({s.rule_id for s in scores if s.tp or s.fp}),
        "survives_fp": len([s for s in scores if s.fp == 0 and s.tp]),
    }
    # FIX H acceptance gate (reconcile-not-relabel): with a ONE-source ruleset
    # (engine compiled from exactly the loaded set), every engine fire must be a
    # loaded rule and engine fires must equal scored fires on BOTH corpora. The
    # old code merely asserted scores ⊆ titles (always true, since scores are
    # built from loaded_rules) and silently dropped engine fires outside `titles`
    # (the 767->2 benign-side gap). This now raises on any such discrepancy.
    assert all(s.rule_id in titles for s in scores)
    assert_one_source(titles, attack_fires, benign_fires)
    # A11: worker-invariant reproducibility stamp over the aggregated fire set
    rh = run_hash(attack_fires | benign_fires)
    if per_technique:
        measurable = sum(1 for r in rows if r["recall_measurable"])
        recall_note = (
            "recall is **per-technique** — each rule is measured against only the attack events "
            "of its own ATT&CK technique(s) (denom = events of that technique, sub-technique folded "
            "to parent), NOT pooled over the whole corpus. Rules with no technique tag, or whose "
            "technique has zero attack events in this corpus, are `unmeasured` (not 0). "
            f"Recall-measurable rules: {measurable}/{len(rows)}."
        )
    else:
        recall_note = (
            "recall is **pooled** (tp / whole-corpus). Per-technique recall (FIX B) is not enabled "
            "for this run."
        )
    return rows, funnel, render_report(
        rows, funnel, source=source, min_events=min_events, run_hash=rh, recall_note=recall_note
    )
