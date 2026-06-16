import hashlib
import json


def build_manifest(**kw) -> dict:
    """Pin everything that determines a metric, for reproducibility (A4)."""
    kw["level"] = list(kw.get("level", ()))
    return dict(sorted(kw.items()))


def run_hash(aggregated_matches, workers=None) -> str:
    """A4/A11: a stable hash of the aggregated (rule_id, event_id) set.
    `workers` is intentionally NOT hashed — the metric must be worker-count invariant."""
    payload = sorted(f"{r[0]}|{r[1]}" for r in _as_pairs(aggregated_matches))
    return hashlib.sha256(json.dumps(payload).encode()).hexdigest()


def _as_pairs(matches):
    for m in matches:
        if isinstance(m, tuple):
            yield m
        else:  # MatchRecord
            yield (m.rule_id, m.event_id)
