"""Pins for the terminal error sinks: markup escaping, caps, and rule-file failures."""

import random
import time

import pytest
from rich.text import Text
from typer.testing import CliRunner

from sigmaforge.main import _err_safe, _rich_safe, app
from sigmaforge.safe_text import markup_escape, plain_safe_capped

PIECES = ["[", "]", "\\", "/", "link=", "x", " ", "bold", "https://evil"]


def _rand(rng):
    return "".join(rng.choice(PIECES) for _ in range(rng.randint(0, 9)))


@pytest.mark.parametrize("h", [_rich_safe, _err_safe])
def test_pair_fuzz_never_forms_a_live_tag(h):
    rng = random.Random(1234)
    for _ in range(3000):
        a, b = _rand(rng), _rand(rng)
        t = Text.from_markup(f"[red]({h(a)}): {h(b)})[/red]")
        assert [s.style for s in t.spans] == ["red"], (a, b)


@pytest.mark.parametrize("h", [_rich_safe, _err_safe])
def test_value_directly_before_a_trusted_tag_keeps_only_trusted_spans(h):
    rng = random.Random(99)
    for _ in range(3000):
        a = _rand(rng)
        t = Text.from_markup(f"{h(a)}[bold]ok[/bold]")
        assert [s.style for s in t.spans] == ["bold"], a
        assert t.plain.endswith("ok")


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5])
def test_trailing_backslash_runs_do_not_escape_the_trusted_closing_tag(n):
    t = Text.from_markup(f"[bold]{_rich_safe('v' + chr(92) * n)}[/bold]")
    assert [s.style for s in t.spans] == ["bold"]


def test_rule_load_template_with_unterminated_link_and_bracket_reason():
    path, reason = "[link=https://evil", "bad ] x[/link"
    t = Text.from_markup(f"[red]Cannot load rule file[/red] {_rich_safe(path)}: {_err_safe(reason)}")
    assert [s.style for s in t.spans] == ["red"]
    assert "[link=https://evil" in t.plain


def test_markup_escape_is_total_on_every_bracket():
    assert markup_escape("a[b") == "a\\[b"
    assert markup_escape("\\[") == "\\\\\\["
    assert markup_escape("x\\") == "x\\\\" and markup_escape("x\\\\") == "x\\\\"


def test_cut_happens_before_sanitizing():
    out = plain_safe_capped("\x1b" * 5000 + "A" * 100)
    assert "A" not in out and out.endswith("[truncated]")


# --- the gate-FAIL sink is capped and time-bounded ----------------------------------------------


def _fake_engine(tmp_path):
    eng = tmp_path / "eng"
    (eng / "Zircolite").mkdir(parents=True)
    (eng / "Zircolite" / "zircolite.py").write_text("")
    return eng


def _backtest(tmp_path, rules_arg):
    return CliRunner().invoke(
        app,
        [
            "backtest", "--rules", rules_arg, "--attack-corpus", str(tmp_path),
            "--technique-map", str(tmp_path / "tm.json"), "--benign-sample", str(tmp_path / "b.jsonl"),
            "--engine-home", str(_fake_engine(tmp_path)),
        ],
        env={"COLUMNS": "300"},
    )  # fmt: skip


def test_gate_fail_message_is_capped_and_fast(tmp_path, monkeypatch):
    def raiser(_cfg):
        raise AssertionError("Z" * 5_000_000)

    monkeypatch.setattr("sigmaforge.pipeline.run_backtest_pipeline", raiser)
    t0 = time.monotonic()
    res = _backtest(tmp_path, str(tmp_path))
    assert res.exit_code == 5, res.output
    assert 0 < res.output.count("Z") <= 600 and "truncated" in res.output
    assert time.monotonic() - t0 < 5


HOSTILE_DIR = "d\x1b]0;P\x07\u202ex"


def _assert_one_clean_line(res, needle):
    assert res.exit_code == 4, res.output
    assert "Traceback" not in res.output and needle in res.output
    assert "\x1b" not in res.output and "\x07" not in res.output and "\u202e" not in res.output
    assert len(res.output.strip().splitlines()) == 1, res.output


def test_backtest_non_utf8_rule_file_is_one_clean_line(tmp_path):
    d = tmp_path / HOSTILE_DIR
    d.mkdir()
    (d / "a.yml").write_bytes(b"title: \xff\xfe\x80 bad\n")
    _assert_one_clean_line(_backtest(tmp_path, str(d / "*.yml")), "unreadable")


def test_backtest_yaml_that_is_not_a_rule_mapping_is_one_clean_line(tmp_path):
    d = tmp_path / HOSTILE_DIR
    d.mkdir()
    (d / "a.yml").write_text("- just\n- a list\n")
    _assert_one_clean_line(_backtest(tmp_path, str(d / "*.yml")), "malformed rule structure")


def test_backtest_unterminated_link_in_rule_path_stays_literal(tmp_path):
    d = tmp_path / "[link=evil"
    d.mkdir()
    (d / "a.yml").write_text("title: [unclosed\n  x: : :\n")
    res = _backtest(tmp_path, str(d / "*.yml"))
    assert res.exit_code == 4 and "[link=evil" in res.output and "Traceback" not in res.output
