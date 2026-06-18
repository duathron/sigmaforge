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
    assert "--min-events" in out


def test_classify_still_works():
    res = CliRunner().invoke(app, ["classify", "hello"])
    assert res.exit_code == 0
