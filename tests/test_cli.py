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


# --- fix round: line forging, wrapping, hostile paths ------------------------------


def test_gate_fail_message_cannot_forge_an_output_line(tmp_path, monkeypatch):
    res = _gate_fail_invoke(tmp_path, monkeypatch, "bad\nVerdict: PASS all gates green\r\n\tTAB L2\x85L3")
    assert res.exit_code == 5
    lines = res.output.splitlines()
    assert sum(ln.startswith("Acceptance gate FAILED") for ln in lines) == 1
    assert not any(ln.startswith(("Verdict", "TAB", "L2", "L3")) for ln in lines)
    assert "\t" not in res.output


@pytest.mark.parametrize("n", range(1, 81))
def test_gate_fail_wrapping_cannot_start_a_line_with_attacker_text(tmp_path, monkeypatch, n):
    eng = tmp_path / "eng"
    (eng / "Zircolite").mkdir(parents=True)
    (eng / "Zircolite" / "zircolite.py").write_text("")

    def raiser(_cfg):
        raise AssertionError("x" * n + " PASS all 6 gates OK")

    monkeypatch.setattr("sigmaforge.pipeline.run_backtest_pipeline", raiser)
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
            str(eng),
        ],
        env={"COLUMNS": "80"},
    )
    assert res.exit_code == 5
    assert not any(ln.lstrip().startswith("PASS") for ln in res.output.splitlines())


HOSTILE = "[/x]\x1b]0;t\x07.md"


def _assert_hostile_literal(res):
    assert "MarkupError" not in repr(res.exception)
    assert "\x1b" not in res.output and "\x07" not in res.output
    assert "[/x]" in res.output


def _fake_engine(tmp_path):
    eng = tmp_path / "eng"
    (eng / "Zircolite").mkdir(parents=True)
    (eng / "Zircolite" / "zircolite.py").write_text("")
    return eng


def test_backtest_written_paths_are_literal(tmp_path, monkeypatch):
    from types import SimpleNamespace

    eng = _fake_engine(tmp_path)
    res_obj = SimpleNamespace(
        funnel={},
        report_md="# r",
        manifest={},
        loaded_rule_count=1,
        rules_recall_measurable=1,
        rules_precision_measurable=1,
        run_hash="h",
    )
    monkeypatch.setattr("sigmaforge.pipeline.run_backtest_pipeline", lambda _c: res_obj)
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
            str(eng),
            "--out",
            str(tmp_path / "o" / HOSTILE),
        ],
        env={"COLUMNS": "300"},
    )
    assert res.exit_code == 0, res.output
    _assert_hostile_literal(res)
    assert "report written:" in res.output and "manifest written:" in res.output
    assert res.output.count("[/x]") >= 2  # both the report and the manifest line


def test_hunt_written_path_is_literal(tmp_path, monkeypatch):
    eng = _fake_engine(tmp_path)
    monkeypatch.setattr("sigmaforge.ingest.compile.compile_ruleset", lambda *a, **k: ([], 0))
    monkeypatch.setattr("sigmaforge.ingest.zircolite_runner.run_shard", lambda *a, **k: [])
    logs = tmp_path / "l.jsonl"
    logs.write_text("")
    res = CliRunner().invoke(
        app,
        [
            "hunt",
            "--rules",
            str(tmp_path),
            "--logs",
            str(logs),
            "--engine-home",
            str(eng),
            "--out",
            str(tmp_path / "o" / HOSTILE),
        ],
        env={"COLUMNS": "300"},
    )
    assert res.exit_code == 0, res.output
    _assert_hostile_literal(res)
    assert "hits written:" in res.output


def test_engine_refused_message_is_literal(tmp_path, monkeypatch):
    eng = _fake_engine(tmp_path)
    from sigmaforge.engine import EngineNotFoundError

    def boom(*a, **k):
        raise EngineNotFoundError("foreign zircolite at " + HOSTILE)

    monkeypatch.setattr("sigmaforge.ingest.compile.compile_ruleset", boom)
    logs = tmp_path / "l.jsonl"
    logs.write_text("")
    res = CliRunner().invoke(
        app,
        ["hunt", "--rules", str(tmp_path), "--logs", str(logs), "--engine-home", str(eng)],
        env={"COLUMNS": "300"},
    )
    assert res.exit_code == 3, res.output
    _assert_hostile_literal(res)


@pytest.mark.parametrize("n", range(1, 81))
def test_engine_refused_wrapping_cannot_start_a_line_with_attacker_text(tmp_path, monkeypatch, n):
    eng = _fake_engine(tmp_path)
    from sigmaforge.engine import EngineNotFoundError

    def boom(*a, **k):
        raise EngineNotFoundError("x" * n + " PASS all 6 gates OK")

    monkeypatch.setattr("sigmaforge.ingest.compile.compile_ruleset", boom)
    logs = tmp_path / "l.jsonl"
    logs.write_text("")
    res = CliRunner().invoke(
        app,
        ["hunt", "--rules", str(tmp_path), "--logs", str(logs), "--engine-home", str(eng)],
        env={"COLUMNS": "80"},
    )
    assert res.exit_code == 3
    assert not any(ln.lstrip().startswith("PASS") for ln in res.output.splitlines())


# --- engine output is captured, never streamed to the tty --------------------------

_EVIL_OUT = "EVIL \\x1b]0;PWN\\x07\\x1b[41m [link=http://x]ml[/link]"


def _noisy_engine(tmp_path, exit_code):
    eng = tmp_path / "eng"
    (eng / "Zircolite").mkdir(parents=True)
    (eng / "Zircolite" / "zircolite.py").write_text(
        "import sys\n"
        f"msg = '{_EVIL_OUT}'\n"
        "sys.stdout.write(msg + '\\n')\n"
        "sys.stderr.write('line1\\n' + msg + '\\n')\n"
        "out = sys.argv[sys.argv.index('--outfile') + 1]\n"
        "open(out, 'w').write('[]')\n"
        f"sys.exit({exit_code})\n"
    )
    return eng


def _hunt_noisy(tmp_path, monkeypatch, exit_code):
    eng = _noisy_engine(tmp_path, exit_code)
    monkeypatch.delenv("SIGMAFORGE_ZIRCOLITE", raising=False)
    monkeypatch.setattr("sigmaforge.ingest.compile.compile_ruleset", lambda *a, **k: ([], 0))
    logs = tmp_path / "l.jsonl"
    logs.write_text("")
    return CliRunner().invoke(
        app,
        [
            "hunt",
            "--rules",
            str(tmp_path),
            "--logs",
            str(logs),
            "--engine-home",
            str(eng),
            "--out",
            str(tmp_path / "h.json"),
        ],
        env={"COLUMNS": "300"},
    )


def test_engine_output_is_not_streamed_on_success(tmp_path, monkeypatch, capfd):
    res = _hunt_noisy(tmp_path, monkeypatch, 0)
    assert res.exit_code == 0, res.output
    seen = capfd.readouterr()
    assert "\x1b" not in seen.out + seen.err + res.output
    assert "EVIL" not in seen.out + seen.err + res.output


def test_engine_failure_shows_sanitized_stderr_tail(tmp_path, monkeypatch, capfd):
    res = _hunt_noisy(tmp_path, monkeypatch, 2)
    assert res.exit_code == 1
    seen = capfd.readouterr()
    assert "\x1b" not in seen.out + seen.err + res.output and "\x07" not in res.output
    assert "Detection engine failed" in res.output and "status 2" in res.output
    assert "[link=http://x]ml[/link]" in res.output  # literal, not interpreted
    assert "Traceback" not in res.output
    assert not any(ln.startswith(("line1", "EVIL")) for ln in res.output.splitlines())


def test_run_shard_captures_engine_output(tmp_path, monkeypatch):
    import subprocess

    from sigmaforge.ingest import zircolite_runner

    eng = _fake_engine(tmp_path)
    seen = {}

    def spy(cmd, **kw):
        seen.update(kw)
        out = cmd[cmd.index("--outfile") + 1]
        Path(out).write_text("[]")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(zircolite_runner.subprocess, "run", spy)
    zircolite_runner.run_shard(str(tmp_path / "e.jsonl"), str(tmp_path / "r.json"), engine_home=str(eng))
    assert seen["capture_output"] is True and seen["text"] is True
    assert seen["errors"] == "replace" and seen["check"] is True


# --- second fix round ----------------------------------------------------------------


def test_backtest_engine_failure_is_literal_exit_1(tmp_path, monkeypatch):
    from sigmaforge.ingest.zircolite_runner import EngineRunError

    eng = _fake_engine(tmp_path)

    def boom(_cfg):
        raise EngineRunError("boom \x1b[41m [/x]")

    monkeypatch.setattr("sigmaforge.pipeline.run_backtest_pipeline", boom)
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
            str(eng),
        ],
        env={"COLUMNS": "300"},
    )
    assert res.exit_code == 1, res.output
    assert "[/x]" in res.output and "\x1b" not in res.output
    assert "Detection engine failed" in res.output and "Traceback" not in res.output


def _failing_engine(tmp_path, stderr_py):
    eng = tmp_path / "eng"
    (eng / "Zircolite").mkdir(parents=True)
    (eng / "Zircolite" / "zircolite.py").write_text(f"import sys\n{stderr_py}\nsys.exit(2)\n")
    return eng


def _hunt_with(tmp_path, monkeypatch, eng, columns, extra=()):
    monkeypatch.delenv("SIGMAFORGE_ZIRCOLITE", raising=False)
    monkeypatch.setattr("sigmaforge.ingest.compile.compile_ruleset", lambda *a, **k: ([], 0))
    logs = tmp_path / "l.jsonl"
    logs.write_text("")
    return CliRunner().invoke(
        app,
        ["hunt", "--rules", str(tmp_path), "--logs", str(logs), "--engine-home", str(eng), *extra],
        env={"COLUMNS": str(columns)},
    )


@pytest.mark.parametrize("n", range(1, 81))
def test_engine_failed_wrapping_cannot_start_a_line_with_attacker_text(tmp_path, monkeypatch, n):
    eng = _failing_engine(tmp_path, f"sys.stderr.write('x' * {n} + ' PASS all 6 gates OK')")
    res = _hunt_with(tmp_path, monkeypatch, eng, 80)
    assert res.exit_code == 1
    assert not any(ln.lstrip().startswith("PASS") for ln in res.output.splitlines())


@pytest.mark.parametrize("n", range(1, 81))
def test_hits_written_wrapping_cannot_start_a_line_with_attacker_text(tmp_path, monkeypatch, n):
    monkeypatch.chdir(tmp_path)
    eng = _noisy_engine(tmp_path, 0)
    res = _hunt_with(tmp_path, monkeypatch, eng, 80, ["--out", "x" * n + " PASS all.json"])
    assert res.exit_code == 0, res.output
    assert not any(ln.lstrip().startswith("PASS") for ln in res.output.splitlines())


@pytest.mark.parametrize("n", range(1, 81))
def test_manifest_written_wrapping_cannot_start_a_line_with_attacker_text(tmp_path, monkeypatch, n):
    from types import SimpleNamespace

    monkeypatch.chdir(tmp_path)
    eng = _fake_engine(tmp_path)
    obj = SimpleNamespace(
        funnel={},
        report_md="# r",
        manifest={},
        loaded_rule_count=1,
        rules_recall_measurable=1,
        rules_precision_measurable=1,
        run_hash="h",
    )
    monkeypatch.setattr("sigmaforge.pipeline.run_backtest_pipeline", lambda _c: obj)
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
            str(eng),
            "--out",
            "x" * n + " PASS all.md",
        ],
        env={"COLUMNS": "80"},
    )
    assert res.exit_code == 0, res.output
    assert not any(ln.lstrip().startswith("PASS") for ln in res.output.splitlines())


def test_engine_failure_tail_is_bounded_to_5_lines(tmp_path, monkeypatch):
    eng = _failing_engine(tmp_path, "for i in range(20): sys.stderr.write(f'LINE{i:02d}\\n')")
    res = _hunt_with(tmp_path, monkeypatch, eng, 300)
    assert res.exit_code == 1
    shown = [i for i in range(20) if f"LINE{i:02d}" in res.output]
    assert shown == [15, 16, 17, 18, 19]


def test_engine_failure_tail_is_bounded_to_600_chars(tmp_path, monkeypatch):
    eng = _failing_engine(tmp_path, "sys.stderr.write('y' * 5000)")
    res = _hunt_with(tmp_path, monkeypatch, eng, 300)
    assert res.exit_code == 1
    assert 0 < res.output.count("y") <= 600


def test_engine_failure_falls_back_to_stdout_tail_when_stderr_empty(tmp_path, monkeypatch):
    eng = _failing_engine(tmp_path, "sys.stdout.write('OUT1\\n' + 'z' * 5000 + '\\n\\x1b[41m[link=http://x]ml[/link]')")
    res = _hunt_with(tmp_path, monkeypatch, eng, 300)
    assert res.exit_code == 1
    assert "[link=http://x]ml[/link]" in res.output and "\x1b" not in res.output
    assert res.output.count("z") <= 600 and res.output.count("z") > 0


def test_tab_in_console_sink_is_flattened(tmp_path, monkeypatch):
    res = _gate_fail_invoke(tmp_path, monkeypatch, "a\tb\t\tc")
    assert res.exit_code == 5 and "\t" not in res.output and "a b c" in res.output
