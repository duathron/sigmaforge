import re

from typer.testing import CliRunner

from sigmaforge.main import app


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
