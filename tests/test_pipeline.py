import json
from pathlib import Path

import pytest

from sigmaforge.pipeline import (  # noqa: F401
    BacktestResult,
    PipelineConfig,
    run_backtest_pipeline,
)

REPO = Path(__file__).resolve().parent.parent
ZIRC = REPO / "Zircolite" / "zircolite.py"


def test_pipeline_exports_exist():
    assert PipelineConfig and BacktestResult and run_backtest_pipeline


@pytest.mark.skipif(not ZIRC.exists(), reason="engine absent (scripts/setup_engine.sh)")
def test_run7_via_pipeline_matches_committed_manifest(monkeypatch):
    monkeypatch.setenv("SIGMAFORGE_HOME", str(REPO))
    committed = json.loads((REPO / "reports/run7_manifest.json").read_text())
    import scripts.run7_backtest as r7  # now a thin caller

    res = r7.run()  # expose a run() returning BacktestResult
    for k in (
        "rules_recall_measurable",
        "rules_precision_measurable",
        "attack_fires",
        "benign_fires",
        "run_hash",
    ):
        assert res.manifest[k] == committed[k], k
    # per-technique rows are NOT in the manifest -> assert against the returned rows
    fired = sorted(
        (r for r in res.rows if isinstance(r["recall"], float) and r["recall"] > 0),
        key=lambda r: r["rule"],  # rows are dicts; key needed so sorted() doesn't TypeError
    )
    assert len(fired) == 70  # run7 observed firing-recall rows
