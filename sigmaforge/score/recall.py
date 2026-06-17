"""Per-technique recall (FIX B).

The pooled recall `tp / n_attack_events` divides every rule's hits by the WHOLE
process-creation attack corpus. A single-technique rule can match at most the
events of its own technique, so a corpus-wide denominator caps its recall near
zero by construction (a recall-side tautology). FIX B measures each rule against
only the attack events of the rule's own ATT&CK technique(s):

    denom = | attack events whose technique is in the rule's technique set |
    numer = | unique such events the rule fired on |
    recall = numer / denom

A rule with no usable technique tag, or whose technique(s) have ZERO attack
events in the corpus, is "unmeasured" (the sentinel string ``"unmeasured"``),
NOT 0 and NOT pooled — there is simply no event of that technique to measure it
against in this corpus.

Identity contract: ``event_technique`` keys on the SAME event identity the
engine emits (``MatchRecord.event_id`` == ``_stable_event_id``), so a fire and
its ground-truth technique join correctly.
"""

import re

UNMEASURED = "unmeasured"

# attack.t1543.003 -> parent T1543 (sub-technique folded to parent; FIX B step 1)
_TECH_TAG = re.compile(r"^attack\.(t\d{4})(?:\.\d{3})?$", re.IGNORECASE)


def rule_techniques(rule: dict) -> set[str]:
    """Parent ATT&CK technique IDs (e.g. {"T1543"}) from a Sigma rule's tags.

    Sub-techniques are folded to their parent so a rule tagged ``attack.t1543.003``
    is measured against ALL T1543 attack events (the corpus labels at technique
    granularity). Returns an empty set when no usable technique tag is present.
    """
    out: set[str] = set()
    for tag in rule.get("tags") or []:
        m = _TECH_TAG.match(str(tag))
        if m:
            out.add(m.group(1).upper())
    return out


def per_technique_recall(
    rule_id: str,
    techniques: set[str],
    fired_event_ids: set[str],
    event_technique: dict[str, str],
    technique_event_counts: dict[str, int],
) -> tuple[float | str, int, int, list[str]]:
    """Return (recall, numer, denom, measured_techniques).

    - ``techniques``: the rule's parent technique set (may be empty -> unmeasured).
    - ``fired_event_ids``: unique attack event_ids the rule fired on.
    - ``event_technique``: event_id -> parent technique (ground truth).
    - ``technique_event_counts``: technique -> total attack PC events of that technique.

    recall is ``UNMEASURED`` when the rule has no technique tag OR none of its
    techniques have any attack event in the corpus (denom == 0). Otherwise
    numer/denom with numer counting only fires that land on an event whose
    technique is in the rule's set (a fire on an off-technique event does not
    count toward this rule's recall).
    """
    if not techniques:
        return UNMEASURED, 0, 0, []

    measured = sorted(t for t in techniques if technique_event_counts.get(t, 0) > 0)
    denom = sum(technique_event_counts.get(t, 0) for t in measured)
    if denom == 0:
        return UNMEASURED, 0, 0, []

    numer = sum(1 for eid in fired_event_ids if event_technique.get(eid) in techniques)
    return numer / denom, numer, denom, measured
