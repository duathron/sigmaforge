"""Per-technique recall (FIX B), sub-technique-granular (FIX B2).

The pooled recall `tp / n_attack_events` divides every rule's hits by the WHOLE
process-creation attack corpus. A single-technique rule can match at most the
events of its own technique, so a corpus-wide denominator caps its recall near
zero by construction (a recall-side tautology). FIX B measures each rule against
only the attack events of the rule's own ATT&CK technique(s).

FIX B2 — SUB-TECHNIQUE-GRANULAR scoping (no sibling dilution): technique IDs are
kept at full sub-technique granularity on BOTH sides (a rule tagged
``attack.t1059.001`` yields ``T1059.001``; the corpus event keeps ``T1059.001``).
An attack event of technique X counts toward rule R's recall iff (ASYMMETRIC rule):

  * X is EXACTLY one of R's (sub-)technique tags
    (a T1059.001 rule ↔ T1059.001 events ONLY — NOT its T1059.003 siblings), OR
  * R carries a BARE parent tag (T1059 with no sub-technique) and X is ANY child
    of it (T1059.* or bare T1059) — a generic rule legitimately covers the whole
    technique.

A T1059.001 rule is therefore NEVER scored against T1059.003 events (the sibling
dilution that inflated the denominator and deflated recall). A bare-T1059 rule IS
scored against all T1059.* events. Then:

    denom = | attack events matching R per the rule above |
    numer = | unique such events R fired on |
    recall = numer / denom

A rule with no usable technique tag, or whose tags match ZERO attack events in
the corpus, is "unmeasured" (the sentinel string ``"unmeasured"``), NOT 0 and NOT
pooled — there is simply no matching event to measure it against in this corpus.

Identity contract: ``event_technique`` keys on the SAME event identity the
engine emits (``MatchRecord.event_id`` == ``_stable_event_id``), so a fire and
its ground-truth technique join correctly.
"""

import re

UNMEASURED = "unmeasured"

# Keep declared tag granularity: attack.t1059.001 -> T1059.001; bare attack.t1059 -> T1059.
_TECH_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def rule_techniques(rule: dict) -> set[str]:
    """ATT&CK technique IDs from a Sigma rule's tags, at the DECLARED granularity.

    FIX B2: a rule tagged ``attack.t1059.001`` yields ``{"T1059.001"}`` (kept at
    sub-technique granularity, NOT folded to T1059); a rule tagged bare
    ``attack.t1059`` yields ``{"T1059"}``. Returns an empty set when no usable
    technique tag is present.
    """
    out: set[str] = set()
    for tag in rule.get("tags") or []:
        m = _TECH_TAG.match(str(tag))
        if m:
            out.add(m.group(1).upper())
    return out


def _event_matches_rule(event_tech: str | None, techniques: set[str]) -> bool:
    """ASYMMETRIC match (FIX B2): does an event of ``event_tech`` count for a rule
    whose technique set is ``techniques``?

    - exact (sub-)technique match: ``T1059.001`` event ↔ ``T1059.001`` rule tag, OR
    - bare-parent rule covers all children: a rule tagged bare ``T1059`` matches
      any ``T1059`` or ``T1059.*`` event.
    A sub-technique rule (``T1059.001``) does NOT match a sibling (``T1059.003``)
    nor the bare parent's other children.
    """
    if event_tech is None:
        return False
    if event_tech in techniques:
        return True
    parent = event_tech.split(".", 1)[0]
    return parent in techniques  # bare-parent rule tag covers this child


def _technique_event_count_for_rule(
    techniques: set[str], technique_event_counts: dict[str, int]
) -> tuple[int, list[str]]:
    """denom + the corpus technique IDs that contribute to it, per the asymmetric rule.

    A bare-parent tag (T1059) absorbs every corpus T1059 / T1059.* bucket; a
    sub-technique tag (T1059.001) absorbs only the exact T1059.001 bucket.
    """
    contributing: dict[str, int] = {}
    for corpus_tech, count in technique_event_counts.items():
        if count > 0 and _event_matches_rule(corpus_tech, techniques):
            contributing[corpus_tech] = count
    denom = sum(contributing.values())
    return denom, sorted(contributing)


def per_technique_recall(
    rule_id: str,
    techniques: set[str],
    fired_event_ids: set[str],
    event_technique: dict[str, str],
    technique_event_counts: dict[str, int],
) -> tuple[float | str, int, int, list[str]]:
    """Return (recall, numer, denom, measured_techniques).

    - ``techniques``: the rule's (sub-)technique set (may be empty -> unmeasured).
    - ``fired_event_ids``: unique attack event_ids the rule fired on.
    - ``event_technique``: event_id -> technique (ground truth, sub-technique-granular).
    - ``technique_event_counts``: technique -> total attack PC events of that technique.

    recall is ``UNMEASURED`` when the rule has no technique tag OR no corpus
    technique matches its tags per the asymmetric rule (denom == 0). Otherwise
    numer/denom, where numer counts only fires that land on an event whose
    technique matches the rule (a fire on an off-technique / sibling event does
    NOT count toward this rule's recall).
    """
    if not techniques:
        return UNMEASURED, 0, 0, []

    denom, measured = _technique_event_count_for_rule(techniques, technique_event_counts)
    if denom == 0:
        return UNMEASURED, 0, 0, []

    numer = sum(1 for eid in fired_event_ids if _event_matches_rule(event_technique.get(eid), techniques))
    return numer / denom, numer, denom, measured
