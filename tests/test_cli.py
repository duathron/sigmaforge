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


def test_manual_command_renders_bundled_doc():
    # `sigmaforge manual` renders the bundled MANUAL.md (no engine/corpora needed).
    res = CliRunner().invoke(app, ["manual"], env={"COLUMNS": "200"})
    assert res.exit_code == 0, res.output
    out = _clean(res.output)
    assert "two-verb" in out.lower()
    assert "hunt" in out and "backtest" in out
    assert "Exit codes" in out


def test_manual_is_packaged_data():
    # the manual must ship as package data so `sigmaforge manual` works after pip install
    from importlib.resources import files

    assert files("sigmaforge").joinpath("MANUAL.md").is_file()


# --- F8: untrusted Sigma rule text must not be parsed as Rich markup --------------


def _gate_fail_invoke(tmp_path, monkeypatch, message):
    eng = tmp_path / "eng"
    (eng / "Zircolite").mkdir(parents=True)
    (eng / "Zircolite" / "zircolite.py").write_text("")

    def raiser(_cfg):
        raise AssertionError(message)

    monkeypatch.setattr("sigmaforge.pipeline.run_backtest_pipeline", raiser)
    return CliRunner().invoke(
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
            str(eng),
        ],
        env={"COLUMNS": "300"},
    )


def test_gate_fail_with_markup_title_exits_5_and_shows_literal(tmp_path, monkeypatch):
    msg = "fired rule(s) outside the loaded set: ['[/x]', '[bold]PASS[/bold]']"
    res = _gate_fail_invoke(tmp_path, monkeypatch, msg)
    assert res.exit_code == 5
    assert "[/x]" in res.output
    assert "[bold]PASS[/bold]" in res.output
    assert "Traceback" not in res.output


def test_gate_fail_keeps_backslashes_verbatim(tmp_path, monkeypatch):
    msg = r"fired rule(s) outside the loaded set: ['C:\rules\x.yml', '[/x]']"
    res = _gate_fail_invoke(tmp_path, monkeypatch, msg)
    assert res.exit_code == 5
    assert r"C:\rules\x.yml" in res.output
    assert r"C:\\rules" not in res.output
    assert "[/x]" in res.output


def test_gate_fail_does_not_expand_emoji_codes(tmp_path, monkeypatch):
    res = _gate_fail_invoke(tmp_path, monkeypatch, "rule :smile: :warning:")
    assert res.exit_code == 5
    assert ":smile:" in res.output and ":warning:" in res.output


def test_gate_fail_strips_terminal_escapes(tmp_path, monkeypatch):
    res = _gate_fail_invoke(tmp_path, monkeypatch, "title \x1b]0;pwned\x07 \x1b[31mred")
    assert res.exit_code == 5
    assert "\x1b" not in res.output and "\x07" not in res.output
