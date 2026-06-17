#!/usr/bin/env python3
"""A12: derive a min-events-per-rule precision floor from the REAL coverage
distribution of the loaded rules over the COMISET benign sample.

The floor exists to separate 'low FP because the rule is good' from 'low FP
because the rule never actually ran' (no events carried its selection fields).
We report the coverage distribution and recommend a floor = a defensible
fraction of the benign sample size, clamped to the level where the bulk of
rules that DO have coverage clear it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import scripts.run_first_backtest as R  # noqa: E402
from sigmaforge.score.coverage import events_evaluated_for_rule, selection_fields  # noqa: E402

BENIGN_SAMPLE = REPO / "data" / "comiset" / "real_benign_sample.jsonl"


def main() -> int:
    fm = R.load_comiset_field_map()
    loaded = R.load_loaded_rules()
    events = []
    for line in open(BENIGN_SAMPLE):
        events.append(R.project_event(json.loads(line)["_source"], fm))
    n = len(events)

    covs = sorted((events_evaluated_for_rule(events, selection_fields(r)) for r in loaded), reverse=True)
    nonzero = [c for c in covs if c > 0]
    zero = len(covs) - len(nonzero)

    out = {
        "benign_sample_size": n,
        "loaded_rules": len(covs),
        "rules_zero_coverage": zero,
        "rules_full_coverage": sum(1 for c in covs if c == n),
        "coverage_p50": nonzero[len(nonzero) // 2] if nonzero else 0,
        "coverage_min_nonzero": min(nonzero) if nonzero else 0,
        "rules_cover_ge_10pct": sum(1 for c in covs if c >= 0.10 * n),
        "rules_cover_ge_50pct": sum(1 for c in covs if c >= 0.50 * n),
        # Recommended floor: 10% of the benign sample (a rule whose selection
        # fields appear in <10% of process-creation events has too little
        # exposure to trust its precision), with an absolute minimum of 200 so
        # tiny samples cannot self-certify.
        "recommended_floor": max(200, int(0.10 * n)),
    }
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
