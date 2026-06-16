from typer.testing import CliRunner

from sigmaforge.main import app


def test_backtest_command_registered():
    res = CliRunner().invoke(app, ["backtest", "--help"])
    assert res.exit_code == 0
    assert "recall" in res.output.lower()
    assert "--min-events" in res.output


def test_classify_still_works():
    res = CliRunner().invoke(app, ["classify", "hello"])
    assert res.exit_code == 0
