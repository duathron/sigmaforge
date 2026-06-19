"""End-to-end smoke test through the REAL Zircolite engine on a tiny committed fixture.

Proves the ingest -> Zircolite -> field-mapping -> parse path actually runs and fires,
WITHOUT the 50GB corpora. Skipped automatically when the engine isn't present (CI, or
before `scripts/setup_engine.sh`), so it never breaks the standard test run — it adds
real reproducibility coverage for anyone who has fetched the engine locally.
"""

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sigmaforge.ingest.zircolite_runner import run_shard
from sigmaforge.main import app

REPO = Path(__file__).resolve().parent.parent
ZIRCOLITE = REPO / "Zircolite" / "zircolite.py"
FIX = REPO / "data" / "fixtures" / "smoke"
MAPPING = REPO / "data" / "mappings" / "comiset.yaml"


def _clean(s: str) -> str:
    """Strip ANSI + collapse whitespace so assertions don't depend on terminal width."""
    return " ".join(re.sub(r"\x1b\[[0-9;]*m", "", s).split())


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


def test_smoke_hunt_clean_run_via_cli(tmp_path, monkeypatch):
    """`sigmaforge hunt` drives the rules x logs path end-to-end on the fixture:
    runs CLEAN (exit 0), fires the planted PowerShell hit, and emits the
    hits-only unmeasured banner (precision/recall are structurally unmeasured)."""
    monkeypatch.setenv("SIGMAFORGE_HOME", str(REPO))
    out = tmp_path / "hits.json"
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(f"backtest:\n  comiset_mapping: {MAPPING}\n")
    res = CliRunner().invoke(
        app,
        [
            "hunt",
            "--rules",
            str(FIX / "rules"),
            "--logs",
            str(FIX / "benign.jsonl"),
            "--out",
            str(out),
            "--config",
            str(cfg),
        ],
        env={"COLUMNS": "200"},
    )
    assert res.exit_code == 0, res.output
    assert "Traceback" not in res.output
    assert "NOT a quality measurement" in res.output  # banner on stdout
    data = json.loads(out.read_text())
    assert data["precision"] == "unmeasured — unlabeled corpus"
    assert data["recall"] == "unmeasured — unlabeled corpus"
    assert "NOT a quality measurement" in data["banner"]
    assert "Smoke PowerShell" in {h["rule_id"] for h in data["hits"]}


def test_smoke_backtest_benign_only_is_teaching_error_exit_4(tmp_path, monkeypatch):
    """`sigmaforge backtest` against the benign-only fixture (no attack corpus,
    no technique map) is a TEACHING error (exit 4) that points at `hunt`, NOT a
    traceback or an empty report."""
    monkeypatch.setenv("SIGMAFORGE_HOME", str(REPO))
    res = CliRunner().invoke(
        app,
        ["backtest", "--rules", str(FIX / "rules"), "--benign-sample", str(FIX / "benign.jsonl")],
        env={"COLUMNS": "200"},
    )
    assert res.exit_code == 4
    out = _clean(res.output).lower()
    assert "hunt" in out
    assert "Traceback" not in res.output
