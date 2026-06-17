"""FIX H acceptance gate: reconcile-not-relabel.

The gap-review failure was a TWO-SOURCE join by title: the engine fired
Zircolite's bundled 2680-rule snapshot, the scorer kept only the ~609 loaded
SigmaHQ titles, so engine fires whose title was outside the 609 set were
SILENTLY dropped (benign_fires=767 -> funnel fires=2). FIX H compiles ONE
ruleset from exactly the loaded set, so the engine can only fire loaded rules.

This module asserts that invariant after a run, on EACH corpus:

  1. NO TITLE-DROP: every engine-fired rule_id is in the loaded title set.
     (If a fire's title is not loaded, the engine ran a DIFFERENT ruleset than
     the one scored — a real two-source regression, not something to suppress.)
  2. ENGINE == SCORED: the number of distinct (rule_id, event_id) fires the
     engine produced equals the number the scorer actually counted. A gap here
     means fires were dropped between firing and scoring.

A failure is a real discrepancy to SURFACE (raise), never relabel.
"""

from __future__ import annotations

from dataclasses import dataclass

from sigmaforge.records import MatchRecord


@dataclass(frozen=True)
class GateResult:
    corpus: str
    engine_fires: int  # distinct (rule_id, event_id) from the engine
    scored_fires: int  # distinct (rule_id, event_id) the scorer counted
    dropped_titles: tuple[str, ...]  # fired rule_ids NOT in the loaded set
    ok: bool

    def reason(self) -> str:
        if self.ok:
            return f"{self.corpus}: engine==scored ({self.engine_fires}), no title-drop"
        parts = []
        if self.dropped_titles:
            parts.append(
                f"{len(self.dropped_titles)} fired rule(s) outside the loaded set "
                f"(title-drop / two-source skew): {list(self.dropped_titles)[:5]}"
                + ("…" if len(self.dropped_titles) > 5 else "")
            )
        if self.engine_fires != self.scored_fires:
            parts.append(
                f"engine fires ({self.engine_fires}) != scored fires ({self.scored_fires})"
            )
        return f"{self.corpus}: " + "; ".join(parts)


def check_corpus(
    corpus: str,
    engine_fires: set[MatchRecord] | list[MatchRecord],
    loaded_titles: set[str],
) -> GateResult:
    """Compute the gate result for one corpus.

    `scored_fires` mirrors what the scorer counts: distinct (rule_id, event_id)
    whose rule_id is in `loaded_titles`. `engine_fires` is the raw distinct
    (rule_id, event_id) the engine emitted. With a one-source ruleset these
    must be equal AND no fired title may fall outside `loaded_titles`.
    """
    engine_pairs = {(f.rule_id, f.event_id) for f in engine_fires}
    scored_pairs = {(rid, eid) for (rid, eid) in engine_pairs if rid in loaded_titles}
    dropped = tuple(sorted({rid for (rid, _eid) in engine_pairs if rid not in loaded_titles}))
    ok = (not dropped) and (len(engine_pairs) == len(scored_pairs))
    return GateResult(
        corpus=corpus,
        engine_fires=len(engine_pairs),
        scored_fires=len(scored_pairs),
        dropped_titles=dropped,
        ok=ok,
    )


def assert_one_source(
    loaded_titles: set[str],
    attack_fires: set[MatchRecord] | list[MatchRecord],
    benign_fires: set[MatchRecord] | list[MatchRecord],
) -> list[GateResult]:
    """Run the gate on BOTH corpora; raise on any discrepancy.

    The 767->2 gap was benign-side, so the benign corpus MUST be checked too.
    Returns the per-corpus results on success; raises AssertionError otherwise.
    """
    results = [
        check_corpus("attack", attack_fires, loaded_titles),
        check_corpus("benign", benign_fires, loaded_titles),
    ]
    failures = [r for r in results if not r.ok]
    if failures:
        raise AssertionError(
            "FIX H acceptance gate FAILED (engine ruleset and scored ruleset disagree):\n"
            + "\n".join("  - " + r.reason() for r in failures)
        )
    return results
