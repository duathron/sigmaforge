"""End-to-end smoke test through the REAL Zircolite engine on a tiny committed fixture.

Proves the ingest -> Zircolite -> field-mapping -> parse path actually runs and fires,
WITHOUT the 50GB corpora. Skipped automatically when the engine isn't present (CI, or
before `scripts/setup_engine.sh`), so it never breaks the standard test run — it adds
real reproducibility coverage for anyone who has fetched the engine locally.
"""

from pathlib import Path

import pytest

from sigmaforge.ingest.zircolite_runner import run_shard

REPO = Path(__file__).resolve().parent.parent
ZIRCOLITE = REPO / "Zircolite" / "zircolite.py"
FIX = REPO / "data" / "fixtures" / "smoke"
MAPPING = REPO / "data" / "mappings" / "comiset.yaml"

pytestmark = pytest.mark.skipif(
    not ZIRCOLITE.exists(),
    reason="Zircolite engine not present (run scripts/setup_engine.sh) — smoke test needs the real engine",
)


def test_smoke_benign_pipeline_end_to_end(monkeypatch):
    monkeypatch.setenv("SIGMAFORGE_HOME", str(REPO))  # engine working dir = repo root
    fires = run_shard(
        str(FIX / "benign.jsonl"),
        str(FIX / "ruleset.json"),
        mapping_path=str(MAPPING),
        json_input=True,
        corpus_label="benign",
    )
    fired_rules = {f.rule_id for f in fires}
    fired_events = {f.event_id for f in fires}
    # the planted powershell.exe event must fire the fixture rule ...
    assert "Smoke PowerShell" in fired_rules
    assert "smoke-ps-0001" in fired_events
    # ... and the benign cmd.exe / explorer.exe events must NOT.
    assert "smoke-cmd-0002" not in fired_events
    assert "smoke-exp-0003" not in fired_events
