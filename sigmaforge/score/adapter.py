from sigmaforge.records import MatchRecord, RuleScore


def score_rule(
    rule_id: str,
    fires: list[MatchRecord],
    n_malicious: int,
    n_benign: int,
    events_evaluated: int,
) -> RuleScore:
    # Zircolite concatenates filtered_rows across a rule's sigma_queries, so the same
    # event can appear multiple times in `matches`. Dedupe per (rule_id, event_id) BEFORE
    # counting, or tp/fp inflate past n_malicious/n_benign and tn/fn go negative.
    unique = {(f.rule_id, f.event_id): f for f in fires}.values()
    tp = sum(1 for f in unique if f.event_label == "malicious")
    fp = sum(1 for f in unique if f.event_label == "benign")
    fn = max(0, n_malicious - tp)
    tn = max(0, n_benign - fp)
    return RuleScore(rule_id, tp=tp, fp=fp, tn=tn, fn=fn, events_evaluated=events_evaluated)
