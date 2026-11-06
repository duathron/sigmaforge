"""Broken user-supplied non-rule inputs (config, technique map, benign sample, COMISET mapping)
end in ONE clean line with the sanitized path and a value-free reason, never a traceback, and
never an echoed value (values can carry ESC/OSC/bidi and Rich markup)."""

import json

import pytest
from typer.testing import CliRunner

from sigmaforge.main import app

HOSTILE = "d\x1b]0;P\x07‮[link=evil"
SECRET = "SECRETVALUE"
HOSTILE_VALUE = SECRET + "\x1b]0;x\x07\u202e[link=https://evil"


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SIGMAFORGE_HOME", raising=False)
    # the engine passes are not under test: stub them so the input handling is what decides
    monkeypatch.setattr("sigmaforge.pipeline.run_shard", lambda *a, **k: [])


def _assert_clean(res, code, needle):
    assert res.exit_code == code, (res.exit_code, res.output, repr(res.exception))
    out = res.output
    assert "Traceback" not in out and needle in out
    assert "\x1b" not in out and "\x07" not in out and "‮" not in out
    assert SECRET not in out
    assert len(out.strip().splitlines()) == 1, out


def _engine(tmp_path):
    eng = tmp_path / "eng"
    (eng / "Zircolite").mkdir(parents=True)
    (eng / "Zircolite" / "zircolite.py").write_text("")
    return eng


def _inputs(tmp_path):
    d = tmp_path / HOSTILE
    d.mkdir(exist_ok=True)
    tm = d / "tm.json"
    tm.write_text(json.dumps({"technique_event_counts": {}, "file_technique": {}, "total_pc": 0}))
    bs = d / "b.jsonl"
    bs.write_text(json.dumps({"_source": {"a": 1}}) + "\n")
    cm = d / "cm.yaml"
    cm.write_text("mappings:\n  _source.a: A\n")
    return {"tm": tm, "bs": bs, "cm": cm}


def _backtest(tmp_path, ins, *extra, config=None):
    args = [
        "backtest", "--rules", str(tmp_path / "no-rules-*.yml"), "--attack-corpus", str(tmp_path),
        "--technique-map", str(ins["tm"]), "--benign-sample", str(ins["bs"]),
        "--comiset-mapping", str(ins["cm"]), "--engine-home", str(_engine(tmp_path)), *extra,
    ]  # fmt: skip
    if config is not None:
        args += ["--config", str(config)]
    return CliRunner().invoke(app, args, env={"COLUMNS": "300"})


def test_baseline_good_inputs_pass_the_input_stage(tmp_path):
    ins = _inputs(tmp_path)
    res = _backtest(tmp_path, ins)
    assert "Cannot load" not in res.output, res.output


# --- technique map ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content,reason",
    [
        (b"{not json " + HOSTILE_VALUE.encode(), "invalid JSON"),
        (b"\xff\xfe" + SECRET.encode(), "unreadable"),
        (json.dumps([HOSTILE_VALUE]).encode(), "malformed"),
        (json.dumps({"technique_event_counts": HOSTILE_VALUE}).encode(), "malformed"),
    ],
)
def test_technique_map_broken_is_one_clean_line(tmp_path, content, reason):
    ins = _inputs(tmp_path)
    ins["tm"].write_bytes(content)
    _assert_clean(_backtest(tmp_path, ins), 4, reason)


def test_technique_map_missing_is_one_clean_line(tmp_path):
    ins = _inputs(tmp_path)
    ins["tm"] = tmp_path / HOSTILE / "absent.json"
    _assert_clean(_backtest(tmp_path, ins), 4, "unreadable")


def test_technique_map_error_names_the_sanitized_path(tmp_path):
    ins = _inputs(tmp_path)
    ins["tm"].write_text("{")
    res = _backtest(tmp_path, ins)
    assert "[link=evil" in res.output and "technique map" in res.output


# --- benign sample ---------------------------------------------------------------------------


def test_benign_sample_missing_is_one_clean_line(tmp_path):
    ins = _inputs(tmp_path)
    ins["bs"] = tmp_path / HOSTILE / "absent.jsonl"
    _assert_clean(_backtest(tmp_path, ins), 4, "unreadable")


@pytest.mark.parametrize(
    "content,reason",
    [
        (b'{"_source": {}}\n{bad ' + HOSTILE_VALUE.encode() + b"\n", "invalid JSON"),
        (b"\xff\xfe" + SECRET.encode() + b"\n", "unreadable"),
        (json.dumps([HOSTILE_VALUE]).encode() + b"\n", "malformed"),
        (json.dumps({"_source": HOSTILE_VALUE}).encode() + b"\n", "malformed"),
    ],
)
def test_benign_sample_bad_line_is_one_clean_line(tmp_path, content, reason):
    ins = _inputs(tmp_path)
    ins["bs"].write_bytes(content)
    _assert_clean(_backtest(tmp_path, ins), 4, reason)


# --- COMISET mapping -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content,reason",
    [
        (b"a: [unclosed " + HOSTILE_VALUE.encode(), "invalid YAML"),
        (b"\xff\xfe" + SECRET.encode(), "unreadable"),
        (("- " + SECRET + "\n").encode(), "malformed"),
        (b"mappings: " + SECRET.encode() + b"\n", "malformed"),
        (b"mappings:\n  1: " + SECRET.encode() + b"\n", "malformed"),
    ],
)
def test_comiset_mapping_broken_is_one_clean_line(tmp_path, content, reason):
    ins = _inputs(tmp_path)
    ins["cm"].write_bytes(content)
    _assert_clean(_backtest(tmp_path, ins), 4, reason)


def test_comiset_mapping_missing_is_one_clean_line(tmp_path):
    ins = _inputs(tmp_path)
    ins["cm"] = tmp_path / HOSTILE / "absent.yaml"
    _assert_clean(_backtest(tmp_path, ins), 4, "unreadable")


# --- config file -----------------------------------------------------------------------------


def _cfg(tmp_path, content: bytes):
    d = tmp_path / HOSTILE
    d.mkdir(exist_ok=True)
    p = d / "config.yaml"
    p.write_bytes(content)
    return p


CONFIG_CASES = [
    (b"a: [unclosed " + HOSTILE_VALUE.encode(), "invalid YAML"),
    (b"a: !" + SECRET.encode() + b" x\n", "invalid YAML"),  # PyYAML puts the tag and a snippet in its message
    (b"\xff\xfe" + SECRET.encode(), "undecodable"),
    (("- " + SECRET + "\n").encode(), "must be a YAML mapping"),
    (("backtest:\n  floor: '" + SECRET + "'\n").encode(), "backtest.floor"),
    (("backtest: " + SECRET + "\n").encode(), "backtest"),
    (("output:\n  default_format: [" + SECRET + "]\n").encode(), "output.default_format"),
    (('backtest:\n  rules: "~' + SECRET + '/x"\n').encode(), "invalid path"),
]


@pytest.mark.parametrize("content,reason", CONFIG_CASES)
def test_backtest_broken_config_is_one_clean_line(tmp_path, content, reason):
    ins = _inputs(tmp_path)
    _assert_clean(_backtest(tmp_path, ins, config=_cfg(tmp_path, content)), 2, reason)


@pytest.mark.parametrize("content,reason", CONFIG_CASES)
def test_hunt_broken_config_is_one_clean_line(tmp_path, content, reason):
    res = CliRunner().invoke(
        app,
        ["hunt", "--rules", str(tmp_path), "--logs", str(tmp_path), "--config", str(_cfg(tmp_path, content))],
        env={"COLUMNS": "300"},
    )
    _assert_clean(res, 2, reason)


def test_config_error_names_the_sanitized_path(tmp_path):
    ins = _inputs(tmp_path)
    res = _backtest(tmp_path, ins, config=_cfg(tmp_path, b"["))
    assert "[link=evil" in res.output and "config" in res.output


def test_config_directory_instead_of_file_is_one_clean_line(tmp_path):
    ins = _inputs(tmp_path)
    d = tmp_path / HOSTILE / "cfgdir"
    d.mkdir(parents=True)
    _assert_clean(_backtest(tmp_path, ins, config=d), 2, "unreadable")
