import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sigmaforge.main import app

REPO = Path(__file__).resolve().parent.parent
ZIRCOLITE = REPO / "Zircolite" / "zircolite.py"
SMOKE = REPO / "data" / "fixtures" / "smoke"


def _clean(s: str) -> str:
    """Strip ANSI + collapse whitespace so assertions don't depend on terminal width.
    Rich crops option names (e.g. `--min-events` -> `--min-ev…`) on a narrow/no-TTY
    console (as in CI); forcing a wide COLUMNS in invoke + this cleanup keeps the
    help text stable across environments."""
    s = re.sub(r"\x1b\[[0-9;]*m", "", s)
    return " ".join(s.split())


def test_backtest_command_registered():
    res = CliRunner().invoke(app, ["backtest", "--help"], env={"COLUMNS": "200"})
    assert res.exit_code == 0
    out = _clean(res.output)
    assert "recall" in out.lower()
    assert "--floor" in out


def test_classify_removed():
    assert CliRunner().invoke(app, ["classify", "x"]).exit_code != 0


def test_backtest_missing_corpus_is_teaching_error_not_traceback(tmp_path, monkeypatch):
    # no corpora configured -> exit 4, guidance text, no traceback
    monkeypatch.delenv("SIGMAFORGE_HOME", raising=False)
    res = CliRunner().invoke(app, ["backtest", "--rules", str(tmp_path)])
    assert res.exit_code == 4
    out = _clean(res.output).lower()
    assert "corpus" in out and "hunt" in out
    assert "Traceback" not in res.output


def test_backtest_no_engine_is_teaching_error_exit_3(tmp_path, monkeypatch):
    # engine absent -> exit 3, names setup_engine.sh, no traceback
    monkeypatch.delenv("SIGMAFORGE_HOME", raising=False)
    res = CliRunner().invoke(
        app,
        [
            "backtest",
            "--rules",
            str(tmp_path),
            "--attack-corpus",
            str(tmp_path),
            "--technique-map",
            str(tmp_path / "tm.json"),
            "--benign-sample",
            str(tmp_path / "b.jsonl"),
            "--engine-home",
            str(tmp_path),  # no Zircolite/zircolite.py here
        ],
    )
    assert res.exit_code == 3
    out = _clean(res.output).lower()
    assert "setup_engine.sh" in out
    assert "Traceback" not in res.output


# --- C3 Task 3.2: hunt ---------------------------------------------------------


def test_hunt_command_registered():
    res = CliRunner().invoke(app, ["hunt", "--help"], env={"COLUMNS": "200"})
    assert res.exit_code == 0
    out = _clean(res.output)
    assert "--rules" in out and "--logs" in out


def test_hunt_no_engine_is_teaching_error_exit_3(tmp_path, monkeypatch):
    # engine absent -> exit 3, names setup_engine.sh, no traceback. engine_home is
    # pointed (via config) at a dir with no Zircolite/zircolite.py so the preflight
    # fails the same way it would on a fresh pip install.
    monkeypatch.delenv("SIGMAFORGE_HOME", raising=False)
    rules = tmp_path / "r.yml"
    rules.write_text("title: x\n")
    logs = tmp_path / "l.jsonl"
    logs.write_text("{}\n")
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(f"backtest:\n  engine_home: {tmp_path}\n")
    res = CliRunner().invoke(
        app,
        ["hunt", "--rules", str(rules), "--logs", str(logs), "--config", str(cfg)],
        env={"COLUMNS": "200"},
    )
    assert res.exit_code == 3
    out = _clean(res.output).lower()
    assert "setup_engine.sh" in out
    assert "Traceback" not in res.output


@pytest.mark.skipif(
    not ZIRCOLITE.exists(),
    reason="Zircolite engine not present (run scripts/setup_engine.sh) — hunt needs the real engine",
)
def test_hunt_clean_run_hits_only_unmeasured(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGMAFORGE_HOME", str(REPO))
    out = tmp_path / "hits.json"
    # the benign.jsonl fixture is COMISET-shaped ES JSON -> use the COMISET field
    # mapping (the engine mapping override travels via --config).
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(f"backtest:\n  comiset_mapping: {REPO / 'data' / 'mappings' / 'comiset.yaml'}\n")
    res = CliRunner().invoke(
        app,
        [
            "hunt",
            "--rules",
            str(SMOKE / "rules"),
            "--logs",
            str(SMOKE / "benign.jsonl"),
            "--out",
            str(out),
            "--config",
            str(cfg),
        ],
        env={"COLUMNS": "200"},
    )
    assert res.exit_code == 0, res.output
    assert "Traceback" not in res.output
    # banner printed to stdout
    assert "NOT a quality measurement" in res.output
    data = json.loads(out.read_text())
    # quality fields are structurally unmeasured (not absent)
    assert data["precision"] == "unmeasured — unlabeled corpus"
    assert data["recall"] == "unmeasured — unlabeled corpus"
    assert "NOT a quality measurement" in data["banner"]
    # the planted powershell event fired the fixture rule
    fired = {h["rule_id"] for h in data["hits"]}
    assert "Smoke PowerShell" in fired
