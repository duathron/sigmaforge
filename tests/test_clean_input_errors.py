"""Broken user-supplied non-rule inputs (config, technique map, benign sample, COMISET mapping)
end in ONE clean line with the sanitized path and a value-free reason, never a traceback, and
never an echoed value (values can carry ESC/OSC/bidi and Rich markup)."""

import json
import os
import subprocess
import sys

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
    (eng / "Zircolite").mkdir(parents=True, exist_ok=True)
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
    _assert_clean(_backtest(tmp_path, ins), 4, "file not found")


def test_technique_map_error_names_the_sanitized_path(tmp_path):
    ins = _inputs(tmp_path)
    ins["tm"].write_text("{")
    res = _backtest(tmp_path, ins)
    assert "[link=evil" in res.output and "technique map" in res.output


# --- benign sample ---------------------------------------------------------------------------


def test_benign_sample_missing_is_one_clean_line(tmp_path):
    ins = _inputs(tmp_path)
    ins["bs"] = tmp_path / HOSTILE / "absent.jsonl"
    _assert_clean(_backtest(tmp_path, ins), 4, "file not found")


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
    _assert_clean(_backtest(tmp_path, ins), 4, "file not found")


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
    _assert_clean(_backtest(tmp_path, ins, config=d), 2, "not a regular file")


# --- fix round 1: depth / range, mapping values, value types --------------------------------

DEEP = 100_000
BIGINT = "9" * 50_000


def test_technique_map_deeply_nested_json_is_one_clean_line(tmp_path):
    ins = _inputs(tmp_path)
    ins["tm"].write_text("[" * DEEP)
    _assert_clean(_backtest(tmp_path, ins), 4, "too deeply nested")


def test_technique_map_huge_int_is_one_clean_line(tmp_path):
    ins = _inputs(tmp_path)
    ins["tm"].write_text('{"technique_event_counts": {}, "file_technique": {}, "total_pc": ' + BIGINT + "}")
    _assert_clean(_backtest(tmp_path, ins), 4, "out of range")


def test_benign_sample_deeply_nested_line_is_one_clean_line(tmp_path):
    ins = _inputs(tmp_path)
    ins["bs"].write_text("[" * DEEP + "\n")
    _assert_clean(_backtest(tmp_path, ins), 4, "too deeply nested")


def test_benign_sample_huge_int_line_is_one_clean_line(tmp_path):
    ins = _inputs(tmp_path)
    ins["bs"].write_text('{"_source": {"a": ' + BIGINT + "}}\n")
    _assert_clean(_backtest(tmp_path, ins), 4, "out of range")


@pytest.mark.parametrize("opener", ["[", "{a: "])
def test_comiset_mapping_deeply_nested_yaml_is_one_clean_line(tmp_path, opener):
    ins = _inputs(tmp_path)
    ins["cm"].write_text(opener * DEEP)
    _assert_clean(_backtest(tmp_path, ins), 4, "too deeply nested")


def test_comiset_mapping_huge_int_is_one_clean_line(tmp_path):
    ins = _inputs(tmp_path)
    ins["cm"].write_text("mappings:\n  _source.a: " + BIGINT + "\n")
    _assert_clean(_backtest(tmp_path, ins), 4, "out of range")


@pytest.mark.parametrize("opener", ["[", "{a: "])
def test_config_deeply_nested_yaml_is_one_clean_line(tmp_path, opener):
    ins = _inputs(tmp_path)
    _assert_clean(_backtest(tmp_path, ins, config=_cfg(tmp_path, (opener * DEEP).encode())), 2, "too deeply nested")


def test_config_huge_int_is_one_clean_line(tmp_path):
    ins = _inputs(tmp_path)
    cfg = _cfg(tmp_path, ("backtest:\n  floor: " + BIGINT + "\n").encode())
    _assert_clean(_backtest(tmp_path, ins, config=cfg), 2, "out of range")


@pytest.mark.parametrize("value", ["[1]", "{k: v}", "5", "null"])
def test_comiset_mapping_non_string_value_is_one_clean_line(tmp_path, value):
    ins = _inputs(tmp_path)
    ins["cm"].write_text(f"mappings:\n  _source.a: {value}\n")
    _assert_clean(_backtest(tmp_path, ins), 4, "malformed")


@pytest.mark.parametrize(
    "tm",
    [
        {"technique_event_counts": {"T1": SECRET}, "file_technique": {}, "total_pc": 0},
        {"technique_event_counts": {"T1": True}, "file_technique": {}, "total_pc": 0},
        {"technique_event_counts": {}, "file_technique": {"f": [SECRET]}, "total_pc": 0},
        {"technique_event_counts": {}, "file_technique": {"f": 3}, "total_pc": 0},
        {"technique_event_counts": {}, "file_technique": {}, "total_pc": True},
        {"technique_event_counts": {}, "file_technique": {}, "total_pc": SECRET},
    ],
)
def test_technique_map_value_types_are_checked(tmp_path, tm):
    ins = _inputs(tmp_path)
    ins["tm"].write_text(json.dumps(tm))
    _assert_clean(_backtest(tmp_path, ins), 4, "malformed")


@pytest.mark.parametrize("label", [[SECRET], {"k": SECRET}, 5, None])
def test_benign_sample_non_string_label_is_one_clean_line(tmp_path, label):
    ins = _inputs(tmp_path)
    ins["bs"].write_text(json.dumps({"_source": {"sigmaforge_label": label}}) + "\n")
    _assert_clean(_backtest(tmp_path, ins), 4, "malformed")


# --- fix round 2: non-regular files, size caps, missing --config, negative counts -------------

posix_only = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX FIFOs")


def _cli_subprocess(tmp_path, ins, config=None, timeout=20):
    """Run the CLI in a child process so a hang fails the test instead of hanging the suite."""
    args = [
        sys.executable, "-m", "sigmaforge.main", "backtest", "--rules", str(tmp_path / "no-rules-*.yml"),
        "--attack-corpus", str(tmp_path), "--technique-map", str(ins["tm"]), "--benign-sample", str(ins["bs"]),
        "--comiset-mapping", str(ins["cm"]), "--engine-home", str(_engine(tmp_path)),
    ]  # fmt: skip
    if config is not None:
        args += ["--config", str(config)]
    env = {**os.environ, "HOME": str(tmp_path / "home"), "COLUMNS": "300"}
    env.pop("SIGMAFORGE_HOME", None)
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)


def _fifo(tmp_path, name="fifo"):
    d = tmp_path / HOSTILE
    d.mkdir(exist_ok=True)
    p = d / name
    os.mkfifo(p)
    return p


@posix_only
@pytest.mark.parametrize("which", ["tm", "bs", "cm"])
def test_fifo_input_is_refused_not_hung(tmp_path, which):
    ins = _inputs(tmp_path)
    ins[which] = _fifo(tmp_path)
    r = _cli_subprocess(tmp_path, ins)
    assert r.returncode == 4, (r.stdout, r.stderr)
    assert "not a regular file" in r.stdout and "Traceback" not in r.stdout + r.stderr


@posix_only
def test_fifo_config_is_refused_not_hung(tmp_path):
    ins = _inputs(tmp_path)
    r = _cli_subprocess(tmp_path, ins, config=_fifo(tmp_path))
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert "not a regular file" in r.stdout and "Traceback" not in r.stdout + r.stderr


@pytest.mark.skipif(not os.path.exists("/dev/zero"), reason="needs /dev/zero")
@pytest.mark.parametrize("which", ["tm", "bs", "cm"])
def test_dev_zero_input_is_refused_not_read(tmp_path, which):
    ins = _inputs(tmp_path)
    ins[which] = "/dev/zero"
    r = _cli_subprocess(tmp_path, ins)
    assert r.returncode == 4, (r.stdout[:300], r.stderr[:300])
    assert "not a regular file" in r.stdout


@pytest.mark.skipif(not os.path.exists("/dev/zero"), reason="needs /dev/zero")
def test_dev_zero_config_is_refused_not_read(tmp_path):
    ins = _inputs(tmp_path)
    r = _cli_subprocess(tmp_path, ins, config="/dev/zero")
    assert r.returncode == 2 and "not a regular file" in r.stdout


def test_config_over_cap_is_refused(tmp_path):
    from sigmaforge import config

    ins = _inputs(tmp_path)
    cfg = _cfg(tmp_path, b"#" * (config.CONFIG_MAX_BYTES + 1))
    _assert_clean(_backtest(tmp_path, ins, config=cfg), 2, "too large")


def test_config_exactly_at_cap_is_accepted(tmp_path):
    from sigmaforge import config

    ins = _inputs(tmp_path)
    cfg = _cfg(tmp_path, b"#" * config.CONFIG_MAX_BYTES)
    assert "Cannot load" not in _backtest(tmp_path, ins, config=cfg).output


@pytest.mark.parametrize(
    "which,cap,content",
    [
        ("tm", "TECHNIQUE_MAP_MAX_BYTES", b'{"technique_event_counts": {}, "file_technique": {}, "total_pc": 0}'),
        ("cm", "COMISET_MAPPING_MAX_BYTES", b"mappings:\n  _source.a: A\n"),
        ("bs", "BENIGN_SAMPLE_MAX_BYTES", b'{"_source": {"a": 1}}\n'),
    ],
)
def test_input_over_cap_is_refused_and_at_cap_is_accepted(tmp_path, monkeypatch, which, cap, content):
    ins = _inputs(tmp_path)
    ins[which].write_bytes(content)
    monkeypatch.setattr(f"sigmaforge.pipeline.{cap}", len(content))
    assert "Cannot load" not in _backtest(tmp_path, ins).output
    monkeypatch.setattr(f"sigmaforge.pipeline.{cap}", len(content) - 1)
    _assert_clean(_backtest(tmp_path, ins), 4, "too large")


def test_benign_sample_cap_counts_bytes_across_lines(tmp_path, monkeypatch):
    ins = _inputs(tmp_path)
    line = b'{"_source": {"a": 1}}\n'
    ins["bs"].write_bytes(line * 50)
    monkeypatch.setattr("sigmaforge.pipeline.BENIGN_SAMPLE_MAX_BYTES", len(line) * 49)
    _assert_clean(_backtest(tmp_path, ins), 4, "too large")


def test_explicit_missing_config_is_an_error_not_a_silent_default(tmp_path):
    ins = _inputs(tmp_path)
    missing = tmp_path / HOSTILE / "absent.yaml"
    _assert_clean(_backtest(tmp_path, ins, config=missing), 2, "file not found")


def test_explicit_missing_config_errors_on_hunt_too(tmp_path):
    res = CliRunner().invoke(
        app,
        ["hunt", "--rules", str(tmp_path), "--logs", str(tmp_path), "--config", str(tmp_path / "absent.yaml")],
        env={"COLUMNS": "300"},
    )
    _assert_clean(res, 2, "file not found")


def test_default_config_missing_is_still_fine(tmp_path):
    ins = _inputs(tmp_path)
    assert "Cannot load" not in _backtest(tmp_path, ins).output


@pytest.mark.parametrize(
    "tm",
    [
        {"technique_event_counts": {}, "file_technique": {}, "total_pc": -1},
        {"technique_event_counts": {"T1": -1}, "file_technique": {}, "total_pc": 0},
    ],
)
def test_technique_map_negative_counts_are_refused(tmp_path, tm):
    ins = _inputs(tmp_path)
    ins["tm"].write_text(json.dumps(tm))
    _assert_clean(_backtest(tmp_path, ins), 4, "malformed")


def test_read_helpers_enforce_the_cap_even_if_the_file_grows_after_fstat(monkeypatch):
    import contextlib
    import io

    from sigmaforge import safe_read

    @contextlib.contextmanager
    def fake_open(path, cap):  # a file that passed the fstat size check, then grew
        yield io.BytesIO(b"x" * (cap + 5))

    monkeypatch.setattr(safe_read, "open_regular", fake_open)
    with pytest.raises(safe_read.ReadRefused, match="too large"):
        safe_read.read_capped("p", 10)
    with pytest.raises(safe_read.ReadRefused, match="too large"):
        list(safe_read.iter_lines_capped("p", 10))


def test_read_helpers_read_exactly_cap_bytes(monkeypatch):
    import contextlib
    import io

    from sigmaforge import safe_read

    @contextlib.contextmanager
    def fake_open(path, cap):
        yield io.BytesIO(b"x" * cap)

    monkeypatch.setattr(safe_read, "open_regular", fake_open)
    assert safe_read.read_capped("p", 10) == b"x" * 10
    assert list(safe_read.iter_lines_capped("p", 10)) == [b"x" * 10]


def test_open_regular_refuses_an_oversized_file_before_reading_it(tmp_path):
    from sigmaforge import safe_read

    f = tmp_path / "big"
    f.write_bytes(b"x" * 11)
    with pytest.raises(safe_read.ReadRefused, match="too large"):
        with safe_read.open_regular(f, 10):
            pytest.fail("must not yield")


def test_iter_lines_never_asks_readline_for_more_than_the_remaining_budget(monkeypatch):
    import contextlib
    import io

    from sigmaforge import safe_read

    asked = []

    class Spy(io.BytesIO):
        def readline(self, size=-1):
            asked.append(size)
            return super().readline(size)

    @contextlib.contextmanager
    def fake_open(path, cap):
        yield Spy(b"ab\ncd\n")

    monkeypatch.setattr(safe_read, "open_regular", fake_open)
    assert list(safe_read.iter_lines_capped("p", 100)) == [b"ab\n", b"cd\n"]
    assert asked and all(0 < n <= 101 for n in asked)
