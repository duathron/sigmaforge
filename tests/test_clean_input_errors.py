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
    rules = tmp_path / "ok-rules.yml"
    rules.write_text("title: t\nlevel: low\n")  # a real file: the manifest hashes the ruleset
    args = [
        "backtest", "--rules", str(rules), "--attack-corpus", str(tmp_path),
        "--technique-map", str(ins["tm"]), "--benign-sample", str(ins["bs"]),
        "--comiset-mapping", str(ins["cm"]), "--engine-home", str(_engine(tmp_path)),
        "--out", str(tmp_path / "run.md"), *extra,
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


# --- fix round 3: parsed-size bounds, rule files through the safe reader, pinned branches ------


def test_caps_are_the_documented_sane_values():
    from sigmaforge import config, pipeline

    mib = 1024 * 1024
    assert config.CONFIG_MAX_BYTES == 1 * mib
    assert pipeline.COMISET_MAPPING_MAX_BYTES == 1 * mib
    assert pipeline.TECHNIQUE_MAP_MAX_BYTES == 8 * mib
    assert pipeline.BENIGN_SAMPLE_MAX_BYTES == 256 * mib
    assert pipeline.BENIGN_SAMPLE_MAX_EVENTS == 500_000
    assert pipeline.RULE_FILE_MAX_BYTES == 1 * mib


def test_benign_sample_event_count_cap(tmp_path, monkeypatch):
    ins = _inputs(tmp_path)
    ins["bs"].write_bytes(b'{"_source": {"a": 1}}\n' * 4)
    monkeypatch.setattr("sigmaforge.pipeline.BENIGN_SAMPLE_MAX_EVENTS", 4)
    assert "Cannot load" not in _backtest(tmp_path, ins).output
    monkeypatch.setattr("sigmaforge.pipeline.BENIGN_SAMPLE_MAX_EVENTS", 3)
    _assert_clean(_backtest(tmp_path, ins), 4, "too many events")


def test_cap_sized_hostile_technique_map_finishes_with_one_line(tmp_path):
    from sigmaforge import pipeline

    ins = _inputs(tmp_path)
    body = b"[" + b"[]," * (pipeline.TECHNIQUE_MAP_MAX_BYTES // 3 - 2) + b"[]]"
    assert len(body) <= pipeline.TECHNIQUE_MAP_MAX_BYTES
    ins["tm"].write_bytes(body)
    r = _cli_subprocess(tmp_path, ins, timeout=120)
    assert r.returncode == 4 and "malformed" in r.stdout and "Traceback" not in r.stdout + r.stderr
    assert len(r.stdout.strip().splitlines()) == 1


def test_technique_map_one_byte_over_the_cap_is_refused(tmp_path):
    from sigmaforge import pipeline

    ins = _inputs(tmp_path)
    ins["tm"].write_bytes(b" " * (pipeline.TECHNIQUE_MAP_MAX_BYTES + 1))
    _assert_clean(_backtest(tmp_path, ins), 4, "too large")


# H2: rule files


def _rules_cli(tmp_path, rules_arg, timeout=20):
    ins = _inputs(tmp_path)
    args = [
        sys.executable, "-m", "sigmaforge.main", "backtest", "--rules", str(rules_arg),
        "--attack-corpus", str(tmp_path), "--technique-map", str(ins["tm"]), "--benign-sample", str(ins["bs"]),
        "--comiset-mapping", str(ins["cm"]), "--engine-home", str(_engine(tmp_path)),
    ]  # fmt: skip
    env = {**os.environ, "HOME": str(tmp_path / "home"), "COLUMNS": "300"}
    env.pop("SIGMAFORGE_HOME", None)
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)


@posix_only
def test_fifo_as_rules_argument_is_refused_not_hung(tmp_path):
    r = _rules_cli(tmp_path, _fifo(tmp_path, "r.yml"))
    assert r.returncode == 4, (r.stdout, r.stderr)
    assert "Cannot load rule file" in r.stdout and "not a regular file" in r.stdout
    assert "Traceback" not in r.stdout + r.stderr


@posix_only
def test_fifo_matched_by_the_rules_glob_is_refused_not_hung(tmp_path):
    d = tmp_path / "rules"
    d.mkdir()
    os.mkfifo(d / "a.yml")
    r = _rules_cli(tmp_path, d / "*.yml")
    assert r.returncode == 4, (r.stdout, r.stderr)
    assert "not a regular file" in r.stdout and "Traceback" not in r.stdout + r.stderr


def test_oversized_rule_file_is_refused(tmp_path, monkeypatch):
    d = tmp_path / "rules"
    d.mkdir()
    (d / "a.yml").write_text("title: t\n" + "#" * 100)
    monkeypatch.setattr("sigmaforge.pipeline.RULE_FILE_MAX_BYTES", 50)
    ins = _inputs(tmp_path)
    res = _backtest(tmp_path, ins)  # sanity: default glob matches nothing
    assert "Cannot load rule file" not in res.output
    args = ["backtest", "--rules", str(d / "*.yml"), "--attack-corpus", str(tmp_path),
            "--technique-map", str(ins["tm"]), "--benign-sample", str(ins["bs"]),
            "--engine-home", str(_engine(tmp_path))]  # fmt: skip
    res = CliRunner().invoke(app, args, env={"COLUMNS": "300"})
    assert res.exit_code == 4 and "Cannot load rule file" in res.output and "too large" in res.output


@posix_only
def test_sha256_file_refuses_a_fifo_without_hanging(tmp_path):
    f = _fifo(tmp_path)
    code = (
        "import sys; from sigmaforge.pipeline import _sha256_file, InputLoadError\n"
        "try:\n    _sha256_file(sys.argv[1], 10, 'x')\nexcept InputLoadError as e:\n    print('refused', e)\n"
    )
    r = subprocess.run([sys.executable, "-c", code, str(f)], capture_output=True, text=True, timeout=20)
    assert r.stdout.strip() == "refused not a regular file", (r.stdout, r.stderr)


def test_sha256_file_hashes_a_regular_file_and_enforces_its_cap(tmp_path):
    import hashlib

    from sigmaforge.pipeline import InputLoadError, _sha256_file

    f = tmp_path / "f"
    f.write_bytes(b"abc" * 1000)
    assert _sha256_file(f, 3000, "x") == hashlib.sha256(b"abc" * 1000).hexdigest()
    with pytest.raises(InputLoadError, match="too large"):
        _sha256_file(f, 2999, "x")


# H3: pinned branches of the safe reader


class _Fake:
    """A file-like object that records the sizes it is asked for."""

    def __init__(self, data=b"", fail=False):
        import io

        self._b, self.fail, self.asked = io.BytesIO(data), fail, []

    def read(self, n=-1):
        self.asked.append(n)
        if self.fail:
            raise OSError("boom")
        return self._b.read(n)

    def readline(self, n=-1):
        self.asked.append(n)
        if self.fail:
            raise OSError("boom")
        return self._b.readline(n)


def _patch_open(monkeypatch, fake):
    import contextlib

    from sigmaforge import safe_read

    @contextlib.contextmanager
    def fake_open(path, cap):
        yield fake

    monkeypatch.setattr(safe_read, "open_regular", fake_open)
    return safe_read


def test_read_capped_asks_for_exactly_cap_plus_one(monkeypatch):
    fake = _Fake(b"x" * 5)
    sr = _patch_open(monkeypatch, fake)
    sr.read_capped("p", 10)
    assert fake.asked == [11]


def test_iter_lines_budget_shrinks_with_every_line(monkeypatch):
    fake = _Fake(b"ab\ncd\n")
    sr = _patch_open(monkeypatch, fake)
    assert list(sr.iter_lines_capped("p", 100)) == [b"ab\n", b"cd\n"]
    assert fake.asked == [101, 98, 95]


def test_stream_and_whole_read_oserror_are_unreadable(monkeypatch):
    sr = _patch_open(monkeypatch, _Fake(fail=True))
    with pytest.raises(sr.ReadRefused, match="unreadable"):
        sr.read_capped("p", 10)
    with pytest.raises(sr.ReadRefused, match="unreadable"):
        list(sr.iter_lines_capped("p", 10))


def test_open_oserror_is_unreadable(tmp_path, monkeypatch):
    from sigmaforge import safe_read

    def boom(*a, **k):
        raise PermissionError(13, "denied")

    monkeypatch.setattr(safe_read.os, "open", boom)
    with pytest.raises(safe_read.ReadRefused, match="unreadable"):
        with safe_read.open_regular(tmp_path / "x", 10):
            pass


def test_explicit_config_exists_oserror_is_unreadable(tmp_path, monkeypatch):
    from pathlib import Path

    from sigmaforge import config

    def boom(self):
        raise PermissionError(13, "denied")

    monkeypatch.setattr(Path, "exists", boom)
    with pytest.raises(config.ConfigError, match="unreadable"):
        config.load(tmp_path / "c.yaml")


@pytest.mark.parametrize("kind", ["non_regular", "too_large"])
def test_descriptor_is_closed_when_the_file_is_refused(tmp_path, monkeypatch, kind):
    from sigmaforge import safe_read

    opened, closed = [], []
    real_open, real_close = os.open, os.close

    def spy_open(*a, **k):
        fd = real_open(*a, **k)
        opened.append(fd)
        return fd

    def spy_close(fd):
        closed.append(fd)
        return real_close(fd)

    monkeypatch.setattr(safe_read.os, "open", spy_open)
    monkeypatch.setattr(safe_read.os, "close", spy_close)
    target = tmp_path if kind == "non_regular" else tmp_path / "big"
    if kind == "too_large":
        target.write_bytes(b"x" * 11)
    with pytest.raises(safe_read.ReadRefused):
        with safe_read.open_regular(target, 10):
            pass
    assert opened and opened == closed


def test_sha256_file_enforces_the_cap_even_if_the_file_grows_after_fstat(monkeypatch):
    import contextlib
    import io

    from sigmaforge import pipeline

    @contextlib.contextmanager
    def fake_open(path, cap):
        yield io.BytesIO(b"x" * (cap + 1))

    monkeypatch.setattr(pipeline, "open_regular", fake_open)
    with pytest.raises(pipeline.InputLoadError, match="too large"):
        pipeline._sha256_file("p", 10, "x")


# --- fix round 4 -------------------------------------------------------------------------------


def _rules_run(tmp_path, rules_file):
    ins = _inputs(tmp_path)
    args = [
        "backtest", "--rules", str(rules_file), "--attack-corpus", str(tmp_path),
        "--technique-map", str(ins["tm"]), "--benign-sample", str(ins["bs"]),
        "--comiset-mapping", str(ins["cm"]), "--engine-home", str(_engine(tmp_path)),
        "--out", str(tmp_path / "run.md"),
    ]  # fmt: skip
    return CliRunner().invoke(app, args, env={"COLUMNS": "300"})


def test_deeply_nested_rule_yaml_is_one_clean_line(tmp_path):
    d = tmp_path / HOSTILE
    d.mkdir()
    (d / "a.yml").write_text("x: " + "[" * 200_000)
    res = _rules_run(tmp_path, d / "a.yml")
    assert res.exit_code == 4 and "Cannot load rule file" in res.output and "too deeply nested" in res.output
    assert "Traceback" not in res.output and len(res.output.strip().splitlines()) == 1


def test_rule_file_with_invalid_utf8_is_unreadable(tmp_path):
    d = tmp_path / HOSTILE
    d.mkdir()
    (d / "a.yml").write_bytes(b"title: \xff\xfe\x80\n")
    res = _rules_run(tmp_path, d / "a.yml")
    assert res.exit_code == 4 and "Cannot load rule file" in res.output and "unreadable" in res.output
    assert "Traceback" not in res.output and len(res.output.strip().splitlines()) == 1


def test_compiled_ruleset_json_gets_the_ruleset_cap_but_a_yaml_rule_keeps_one_mib(tmp_path):
    from sigmaforge import pipeline

    big = b" " * (pipeline.RULE_FILE_MAX_BYTES + 100) + b'{"title": "t", "level": "low"}'
    j = tmp_path / "compiled.json"
    j.write_bytes(big)
    assert "too large" not in _rules_run(tmp_path, j).output
    y = tmp_path / "rule.yml"
    y.write_bytes(big)
    res = _rules_run(tmp_path, y)
    assert res.exit_code == 4 and "Cannot load rule file" in res.output and "too large" in res.output
    j2 = tmp_path / "Compiled2.JSON"  # the suffix test is case-insensitive
    j2.write_bytes(big)
    assert "too large" not in _rules_run(tmp_path, j2).output


def test_compiled_ruleset_json_over_the_ruleset_cap_is_refused(tmp_path, monkeypatch):
    j = tmp_path / "compiled.json"
    j.write_bytes(b"x" * 11)
    monkeypatch.setattr("sigmaforge.pipeline.RULESET_HASH_MAX_BYTES", 10)
    res = _rules_run(tmp_path, j)
    assert res.exit_code == 4 and "too large" in res.output


def test_ruleset_cap_value_is_pinned():
    from sigmaforge import pipeline

    assert pipeline.RULESET_HASH_MAX_BYTES == 16 * 1024 * 1024


def test_manifest_ruleset_hash_call_site_enforces_the_cap(tmp_path, monkeypatch):
    ins = _inputs(tmp_path)
    monkeypatch.setattr("sigmaforge.pipeline.RULESET_HASH_MAX_BYTES", 5)  # the yml rule file is 22 bytes
    res = _backtest(tmp_path, ins)
    assert res.exit_code == 4, res.output
    assert "Cannot load ruleset" in res.output and "too large" in res.output
    assert len(res.output.strip().splitlines()) == 1


def test_sha256_file_read_oserror_is_unreadable(monkeypatch):
    import contextlib

    from sigmaforge import pipeline

    @contextlib.contextmanager
    def fake_open(path, cap):
        yield _Fake(fail=True)

    monkeypatch.setattr(pipeline, "open_regular", fake_open)
    with pytest.raises(pipeline.InputLoadError, match="unreadable"):
        pipeline._sha256_file("p", 10, "x")


# --- fix round 5: aliases, rule file counts and totals, per-line cap ----------------------------


def _alias_bomb(levels=10, fan=9):
    lines = ["title: t", "level: high", "bomb0: &a0 [x]"]
    for i in range(1, levels):
        lines.append(f"bomb{i}: &a{i} [" + ",".join([f"*a{i - 1}"] * fan) + "]")
    lines += ["detection:", f"  condition: *a{levels - 1}"]
    return "\n".join(lines) + "\n"


def test_alias_bomb_rule_is_refused_fast_in_a_subprocess(tmp_path):
    d = tmp_path / HOSTILE
    d.mkdir()
    (d / "a.yml").write_text(_alias_bomb())
    assert len(_alias_bomb()) < 1000
    r = _rules_cli(tmp_path, d / "a.yml", timeout=15)
    assert r.returncode == 4, (r.stdout[:300], r.stderr[:300])
    assert "Cannot load rule file" in r.stdout and "aliases are not allowed" in r.stdout
    assert len(r.stdout.strip().splitlines()) == 1


def test_plain_anchor_without_alias_is_also_refused(tmp_path):
    f = tmp_path / "a.yml"
    f.write_text("title: &t x\nlevel: high\n")
    res = _rules_run(tmp_path, f)
    assert res.exit_code == 4 and "aliases are not allowed" in res.output


def test_alias_in_comiset_mapping_is_refused(tmp_path):
    ins = _inputs(tmp_path)
    ins["cm"].write_text("mappings: &m\n  _source.a: A\nother: *m\n")
    _assert_clean(_backtest(tmp_path, ins), 4, "aliases are not allowed")


def test_alias_in_config_is_refused_with_exit_2(tmp_path):
    ins = _inputs(tmp_path)
    cfg = _cfg(tmp_path, b"x: &a [1]\nbacktest:\n  floor: 5\ny: *a\n")
    _assert_clean(_backtest(tmp_path, ins, config=cfg), 2, "aliases are not allowed")


def test_rule_file_with_too_many_yaml_nodes_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr("sigmaforge.pipeline.RULE_FILE_MAX_NODES", 5)
    f = tmp_path / "a.yml"
    f.write_text("title: t\nlevel: high\nx: [1, 2, 3]\n")
    res = _rules_run(tmp_path, f)
    assert res.exit_code == 4 and "too many YAML nodes" in res.output
    monkeypatch.setattr("sigmaforge.pipeline.RULE_FILE_MAX_NODES", 1000)
    assert "too many YAML nodes" not in _rules_run(tmp_path, f).output


def test_total_yaml_nodes_across_rule_files_are_capped(tmp_path, monkeypatch):
    d = tmp_path / "rules"
    d.mkdir()
    for i in range(3):
        (d / f"r{i}.yml").write_text("title: t\nlevel: low\n")  # 5 nodes each
    monkeypatch.setattr("sigmaforge.pipeline.RULES_MAX_TOTAL_NODES", 14)
    res = _rules_run(tmp_path, d / "*.yml")
    assert res.exit_code == 4 and "too many YAML nodes" in res.output
    monkeypatch.setattr("sigmaforge.pipeline.RULES_MAX_TOTAL_NODES", 15)
    assert "too many YAML nodes" not in _rules_run(tmp_path, d / "*.yml").output


def test_too_many_rule_files_is_refused(tmp_path, monkeypatch):
    d = tmp_path / "rules"
    d.mkdir()
    for i in range(3):
        (d / f"r{i}.yml").write_text("title: t\nlevel: low\n")
    monkeypatch.setattr("sigmaforge.pipeline.MAX_RULE_FILES", 2)
    res = _rules_run(tmp_path, d / "*.yml")
    assert res.exit_code == 4 and "too many rule files" in res.output and len(res.output.strip().splitlines()) == 1
    monkeypatch.setattr("sigmaforge.pipeline.MAX_RULE_FILES", 3)
    assert "too many rule files" not in _rules_run(tmp_path, d / "*.yml").output


def test_total_rule_bytes_are_capped(tmp_path, monkeypatch):
    d = tmp_path / "rules"
    d.mkdir()
    body = "title: t\nlevel: low\n"
    for i in range(3):
        (d / f"r{i}.yml").write_text(body)
    monkeypatch.setattr("sigmaforge.pipeline.RULES_MAX_TOTAL_BYTES", len(body) * 3 - 1)
    res = _rules_run(tmp_path, d / "*.yml")
    assert res.exit_code == 4 and "too large in total" in res.output
    monkeypatch.setattr("sigmaforge.pipeline.RULES_MAX_TOTAL_BYTES", len(body) * 3)
    assert "too large in total" not in _rules_run(tmp_path, d / "*.yml").output


@pytest.mark.parametrize("text", ["- just\n- a list\n", "just a scalar\n"])
def test_rule_document_that_is_not_a_mapping_names_its_file(tmp_path, text):
    d = tmp_path / HOSTILE
    d.mkdir()
    (d / "a.yml").write_text(text)
    res = _rules_run(tmp_path, d / "*.yml")  # a glob: the message must name the FILE, not the glob
    assert res.exit_code == 4 and "malformed rule structure" in res.output
    assert "a.yml" in res.output and "*" not in res.output and len(res.output.strip().splitlines()) == 1


def test_rule_caps_are_pinned():
    from sigmaforge import pipeline

    assert pipeline.MAX_RULE_FILES == 20_000
    assert pipeline.RULES_MAX_TOTAL_BYTES == 64 * 1024 * 1024
    assert pipeline.RULE_FILE_MAX_NODES == 100_000
    assert pipeline.RULES_MAX_TOTAL_NODES == 2_000_000
    assert pipeline.BENIGN_LINE_MAX_BYTES == 1024 * 1024


def test_benign_sample_line_over_the_line_cap_is_refused(tmp_path, monkeypatch):
    ins = _inputs(tmp_path)
    line = b'{"_source": {"a": 1}}\n'
    ins["bs"].write_bytes(line + line)
    monkeypatch.setattr("sigmaforge.pipeline.BENIGN_LINE_MAX_BYTES", len(line))
    assert "Cannot load" not in _backtest(tmp_path, ins).output
    monkeypatch.setattr("sigmaforge.pipeline.BENIGN_LINE_MAX_BYTES", len(line) - 1)
    _assert_clean(_backtest(tmp_path, ins), 4, "line too long")


def test_iter_lines_line_cap_unit(monkeypatch):
    fake = _Fake(b"ab\ncdefg\n")
    sr = _patch_open(monkeypatch, fake)
    with pytest.raises(sr.ReadRefused, match="line too long"):
        list(sr.iter_lines_capped("p", 100, line_cap=4))
    assert fake.asked[0] == 5  # min(budget 101, line_cap + 1)
    fake2 = _Fake(b"ab\ncd\n")
    sr = _patch_open(monkeypatch, fake2)
    assert list(sr.iter_lines_capped("p", 100, line_cap=3)) == [b"ab\n", b"cd\n"]


def test_undefined_alias_is_also_refused_as_an_alias(tmp_path):
    f = tmp_path / "a.yml"
    f.write_text("title: t\nlevel: high\nx: *nope\n")
    res = _rules_run(tmp_path, f)
    assert res.exit_code == 4 and "aliases are not allowed" in res.output


def test_json_ruleset_holding_yaml_is_refused_fast_and_not_retried_as_yaml(tmp_path):
    import time

    f = tmp_path / "compiled.json"
    f.write_text("title: t\nlevel: high\n")  # valid YAML, not JSON
    t0 = time.monotonic()
    res = _rules_run(tmp_path, f)
    assert res.exit_code == 4 and "invalid JSON" in res.output and len(res.output.strip().splitlines()) == 1
    assert time.monotonic() - t0 < 10


@pytest.mark.parametrize("body,reason", [("[" * 100_000, "too deeply nested"), ("[1, 2]", "malformed rule structure")])
def test_json_ruleset_depth_and_shape_are_refused(tmp_path, body, reason):
    f = tmp_path / "compiled.json"
    f.write_text(body)
    res = _rules_run(tmp_path, f)
    assert res.exit_code == 4 and reason in res.output and len(res.output.strip().splitlines()) == 1


def test_large_real_shaped_json_ruleset_loads_within_a_time_bound(tmp_path):
    import time

    from sigmaforge import pipeline

    rules = [
        {
            "title": f"Rule {i}",
            "id": f"00000000-0000-0000-0000-{i:012d}",
            "level": "high",
            "description": "d" * 200,
            "tags": ["attack.execution", "attack.t1059"],
            "filename": f"rule_{i}.yml",
            "rule": [f"SELECT * FROM logs WHERE a{j} LIKE '%x%'" for j in range(8)],
            "detection": {"condition": "selection", "selection": {"Image|endswith": "\\\\cmd.exe"}},
        }
        for i in range(12_000)
    ]
    f = tmp_path / "sigmaforge_loaded.json"
    f.write_text(json.dumps(rules))
    assert f.stat().st_size > 8_000_000
    t0 = time.monotonic()
    loaded = pipeline._load_loaded_rules(str(f))
    assert len(loaded) == 12_000 and time.monotonic() - t0 < 10


def test_json_ruleset_with_a_single_rule_object_loads(tmp_path):
    from sigmaforge import pipeline

    f = tmp_path / "one.json"
    f.write_text(json.dumps({"title": "t", "level": "high", "detection": {"condition": "selection"}}))
    assert [r["title"] for r in pipeline._load_loaded_rules(str(f))] == ["t"]


# --- fix round 6: any loader failure is one clean line; rule fields validated; JSON node budget --


def _one_clean_line_no_secret(res, code):
    assert res.exit_code == code, (res.exit_code, res.output, repr(res.exception))
    assert "Traceback" not in res.output and "secretval" not in res.output.lower()
    assert len(res.output.strip().splitlines()) == 1, res.output


def test_safe_yaml_converts_construction_errors_to_a_value_free_yaml_error():
    import yaml

    from sigmaforge import safe_yaml

    for fn in (safe_yaml.load, lambda t: safe_yaml.load_all(t)[0]):
        with pytest.raises(yaml.YAMLError) as ei:
            fn("x: !!bool SECRETVAL\n")
        assert "secretval" not in str(ei.value).lower() and not isinstance(ei.value, KeyError)
    with pytest.raises(RecursionError):  # limits keep their own, more specific, handlers
        safe_yaml.load("[" * 100_000)


def test_bool_tag_junk_in_config_is_one_clean_line(tmp_path):
    ins = _inputs(tmp_path)
    cfg = _cfg(tmp_path, b"x: !!bool SECRETVAL\n")
    _one_clean_line_no_secret(_backtest(tmp_path, ins, config=cfg), 2)


def test_bool_tag_junk_in_comiset_mapping_is_one_clean_line(tmp_path):
    ins = _inputs(tmp_path)
    ins["cm"].write_text("x: !!bool SECRETVAL\n")
    _one_clean_line_no_secret(_backtest(tmp_path, ins), 4)


def test_bool_tag_junk_in_a_rule_is_one_clean_line(tmp_path):
    f = tmp_path / "a.yml"
    f.write_text("title: t\nlevel: high\nx: !!bool SECRETVAL\n")
    _one_clean_line_no_secret(_rules_run(tmp_path, f), 4)


class _Boom(Exception):
    pass


def _boom(*a, **k):
    raise _Boom("SECRETVAL")


def test_any_exception_in_the_config_loader_is_one_clean_line(tmp_path, monkeypatch):
    ins = _inputs(tmp_path)
    monkeypatch.setattr("sigmaforge.safe_yaml.load", _boom)
    _one_clean_line_no_secret(_backtest(tmp_path, ins, config=_cfg(tmp_path, b"a: 1\n")), 2)


def test_any_exception_in_the_comiset_loader_is_one_clean_line(tmp_path, monkeypatch):
    ins = _inputs(tmp_path)
    monkeypatch.setattr("sigmaforge.safe_yaml.load", _boom)
    _one_clean_line_no_secret(_backtest(tmp_path, ins), 4)


def test_any_exception_in_the_rule_loader_is_one_clean_line(tmp_path, monkeypatch):
    f = tmp_path / "a.yml"
    f.write_text("title: t\nlevel: high\n")
    monkeypatch.setattr("sigmaforge.safe_yaml.load_all", _boom)
    _one_clean_line_no_secret(_rules_run(tmp_path, f), 4)


def test_any_exception_in_the_json_rule_loader_is_one_clean_line(tmp_path, monkeypatch):
    f = tmp_path / "c.json"
    f.write_text("{}")
    monkeypatch.setattr("sigmaforge.pipeline.json.loads", _boom)
    _one_clean_line_no_secret(_rules_run(tmp_path, f), 4)


def test_any_exception_in_the_rule_partition_is_one_clean_line(tmp_path, monkeypatch):
    f = tmp_path / "a.yml"
    f.write_text("title: t\nlevel: high\n")
    monkeypatch.setattr("sigmaforge.pipeline.partition_rules", _boom)
    _one_clean_line_no_secret(_rules_run(tmp_path, f), 4)


def test_any_exception_in_the_technique_map_loader_is_one_clean_line(tmp_path, monkeypatch):
    ins = _inputs(tmp_path)
    monkeypatch.setattr("sigmaforge.pipeline._tmap_ok", _boom)
    _one_clean_line_no_secret(_backtest(tmp_path, ins), 4)


def test_any_exception_in_the_benign_sample_loader_is_one_clean_line(tmp_path, monkeypatch):
    ins = _inputs(tmp_path)
    monkeypatch.setattr("sigmaforge.pipeline._project_event", _boom)
    _one_clean_line_no_secret(_backtest(tmp_path, ins), 4)


def test_any_exception_in_the_config_validator_is_one_clean_line(tmp_path, monkeypatch):
    ins = _inputs(tmp_path)
    monkeypatch.setattr("sigmaforge.config.AppConfig.model_validate", _boom)
    _one_clean_line_no_secret(_backtest(tmp_path, ins, config=_cfg(tmp_path, b"a: 1\n")), 2)


# F2: rule field validation (in-scope rules: level high/critical)

BAD_RULES = {
    "missing_title": {"level": "high"},
    "empty_title": {"title": "", "level": "high"},
    "list_title": {"title": ["x"], "level": "high"},
    "dict_title": {"title": {"a": 1}, "level": "high"},
    "int_tags": {"title": "t", "level": "high", "tags": 5},
    "tags_with_non_str": {"title": "t", "level": "high", "tags": ["attack.t1059", 5]},
    "dict_tags": {"title": "t", "level": "high", "tags": {"a": 1}},
    "int_detection": {"title": "t", "level": "critical", "detection": 5},
    "list_detection": {"title": "t", "level": "high", "detection": ["x"]},
}


def _write_rule(tmp_path, rule, form):
    if form == "yaml":
        import yaml

        f = tmp_path / "a.yml"
        f.write_text(yaml.safe_dump(rule))
    else:
        f = tmp_path / "a.json"
        f.write_text(json.dumps([rule]))
    return f


@pytest.mark.parametrize("form", ["yaml", "json"])
@pytest.mark.parametrize("name", sorted(BAD_RULES))
def test_malformed_rule_fields_are_one_clean_line(tmp_path, name, form):
    f = _write_rule(tmp_path, BAD_RULES[name], form)
    res = _rules_run(tmp_path, tmp_path / ("*" + f.suffix))  # a glob: the message must name the FILE
    assert res.exit_code == 4 and "malformed rule structure" in res.output, res.output
    assert "Traceback" not in res.output and len(res.output.strip().splitlines()) == 1
    assert "a." in res.output and "*" not in res.output


@pytest.mark.parametrize("form", ["yaml", "json"])
def test_well_formed_rule_fields_are_accepted(tmp_path, form):
    rule = {
        "title": "t",
        "level": "high",
        "tags": ["attack.t1059"],
        "detection": {"selection": {"a": 1}, "condition": "selection"},
    }
    res = _rules_run(tmp_path, _write_rule(tmp_path, rule, form))
    assert "malformed rule structure" not in res.output and "Traceback" not in res.output


@pytest.mark.parametrize("form", ["yaml", "json"])
def test_out_of_scope_rules_with_odd_fields_are_not_rejected(tmp_path, form):
    rule = {"level": "low", "tags": 5}
    res = _rules_run(tmp_path, _write_rule(tmp_path, rule, form))
    assert "malformed rule structure" not in res.output


# LOW-1: JSON rulesets share the node budget


def _json_rules(tmp_path, name="c.json"):
    f = tmp_path / name
    f.write_text(json.dumps([{"title": "t", "level": "low"}]))  # list + dict + 2 keys + 2 values = 6 nodes
    return f


def test_json_ruleset_node_budget_exact_count(tmp_path, monkeypatch):
    f = _json_rules(tmp_path)
    monkeypatch.setattr("sigmaforge.pipeline.RULES_MAX_TOTAL_NODES", 6)
    assert "too many JSON nodes" not in _rules_run(tmp_path, f).output
    monkeypatch.setattr("sigmaforge.pipeline.RULES_MAX_TOTAL_NODES", 5)
    res = _rules_run(tmp_path, f)
    assert res.exit_code == 4 and "too many JSON nodes" in res.output


def test_json_ruleset_prescan_refuses_before_parsing(tmp_path, monkeypatch):
    f = tmp_path / "c.json"
    f.write_text("[" + "[]," * 50 + "[]]")
    monkeypatch.setattr("sigmaforge.pipeline.RULES_MAX_TOTAL_NODES", 10)

    def no_parse(*a, **k):
        raise AssertionError("parsed")

    monkeypatch.setattr("sigmaforge.pipeline.json.loads", no_parse)
    res = _rules_run(tmp_path, f)
    assert res.exit_code == 4 and "too many JSON nodes" in res.output


def test_json_ruleset_total_node_budget_spans_files(tmp_path, monkeypatch):
    d = tmp_path / "rs"
    d.mkdir()
    for i in range(2):
        (d / f"c{i}.json").write_text(json.dumps([{"title": "t", "level": "low"}]))
    monkeypatch.setattr("sigmaforge.pipeline.RULES_MAX_TOTAL_NODES", 11)
    res = _rules_run(tmp_path, d / "*.json")
    assert res.exit_code == 4 and "too many JSON nodes" in res.output
    monkeypatch.setattr("sigmaforge.pipeline.RULES_MAX_TOTAL_NODES", 12)
    assert "too many JSON nodes" not in _rules_run(tmp_path, d / "*.json").output


def test_json_node_walk_is_iterative_not_recursive():
    from sigmaforge import pipeline

    deep = []
    cur = deep
    for _ in range(5000):  # deeper than the recursion limit
        nxt = []
        cur.append(nxt)
        cur = nxt
    assert pipeline._count_json_nodes(deep, 10**9) == 5001
    assert pipeline._count_json_nodes({"a": [1, {"b": None}]}, 10**9) == 7


def test_any_exception_in_the_technique_map_parser_is_one_clean_line(tmp_path, monkeypatch):
    ins = _inputs(tmp_path)
    rules = tmp_path / "ok-rules.yml"
    rules.write_text("title: t\nlevel: low\n")
    monkeypatch.setattr("sigmaforge.pipeline.json.loads", _boom)  # first JSON user in a run: the technique map
    res = _rules_run(tmp_path, rules)
    assert ins and "Cannot load technique map" in res.output
    _one_clean_line_no_secret(res, 4)


def test_json_node_walk_stops_just_past_the_limit():
    from sigmaforge import pipeline

    assert pipeline._count_json_nodes(list(range(1000)), 3) == 4


# --- follow-up: surrogate text, compiled ruleset cap, pre-scan thresholds -----------------------


@pytest.mark.parametrize("form", ["yaml", "json"])
@pytest.mark.parametrize(
    "rule",
    [
        {"title": "\ud800x", "level": "high"},
        {"title": "t", "level": "high", "tags": ["attack.t1059", "\udfffz"]},
    ],
)
def test_rule_text_with_a_lone_surrogate_is_refused_at_load(tmp_path, rule, form):
    if form == "yaml":
        f = tmp_path / "a.yml"
        f.write_text(
            "title: " + json.dumps(rule["title"]) + "\nlevel: high\ntags: " + json.dumps(rule.get("tags", [])) + "\n"
        )
    else:
        f = tmp_path / "a.json"
        f.write_text(json.dumps([rule]))
    res = _rules_run(tmp_path, tmp_path / ("*" + f.suffix))
    assert res.exit_code == 4 and "malformed rule structure" in res.output, res.output
    assert "Traceback" not in res.output and len(res.output.strip().splitlines()) == 1


@pytest.mark.parametrize(
    "tm",
    [
        {"technique_event_counts": {"\ud800": 1}, "file_technique": {}, "total_pc": 0},
        {"technique_event_counts": {}, "file_technique": {"\ud800": "T1"}, "total_pc": 0},
        {"technique_event_counts": {}, "file_technique": {"f": "\ud800"}, "total_pc": 0},
    ],
)
def test_technique_map_text_with_a_lone_surrogate_is_refused(tmp_path, tm):
    ins = _inputs(tmp_path)
    ins["tm"].write_text(json.dumps(tm))  # ensure_ascii writes the lone surrogate as a \ud800 escape
    _assert_clean(_backtest(tmp_path, ins), 4, "malformed")


def test_a_surrogate_in_the_report_text_does_not_crash_the_write(tmp_path, monkeypatch):
    from sigmaforge import pipeline

    res_obj = pipeline.BacktestResult(
        rows=[], funnel={}, manifest={"k": "\ud800"}, report_md="# report \ud800 end\n", run_hash="h",
        acceptance_gate=[], n_attack_events=0, technique_event_counts={}, rules_recall_measurable=0,
        rules_precision_measurable=0, loaded_rule_count=0,
    )  # fmt: skip
    monkeypatch.setattr("sigmaforge.pipeline.run_backtest_pipeline", lambda cfg: res_obj)
    ins = _inputs(tmp_path)
    out = tmp_path / "report.md"
    res = _backtest(tmp_path, ins, "--out", str(out))
    assert res.exit_code == 0 and "Traceback" not in res.output, (res.output, repr(res.exception))
    assert out.read_bytes() == b"# report \\ud800 end\n"
    assert b"ud800" in out.with_suffix(".manifest.json").read_bytes()


def test_compiled_ruleset_cap_is_sixteen_mib_and_enforced(tmp_path):
    from sigmaforge import pipeline

    cap = pipeline.RULESET_HASH_MAX_BYTES
    ok = tmp_path / "ok.json"
    ok.write_bytes(b"{}" + b" " * (cap - 2))
    assert "too large" not in _rules_run(tmp_path, ok).output
    big = tmp_path / "big.json"
    big.write_bytes(b"{}" + b" " * (cap - 1))
    res = _rules_run(tmp_path, big)
    assert res.exit_code == 4 and "too large" in res.output


def _prescan_run(tmp_path, monkeypatch, text, budget):
    f = tmp_path / "c.json"
    f.write_text(text)
    monkeypatch.setattr("sigmaforge.pipeline.RULES_MAX_TOTAL_NODES", budget)
    calls = []
    real = json.loads

    def spy(*a, **k):
        calls.append(1)
        return real(*a, **k)

    monkeypatch.setattr("sigmaforge.pipeline.json.loads", spy)
    res = _rules_run(tmp_path, f)
    return res, calls


@pytest.mark.parametrize("text", ["[{},{},{}]", "[[],[],[]]"])  # 4 containers: 1 outer + 3 inner
def test_json_prescan_threshold_is_exact_for_both_bracket_kinds(tmp_path, monkeypatch, text):
    res, calls = _prescan_run(tmp_path, monkeypatch, text, 4)
    assert calls and "too many JSON nodes" not in res.output  # exactly at the budget: parsed
    res, calls = _prescan_run(tmp_path, monkeypatch, text, 3)
    assert not calls and res.exit_code == 4 and "too many JSON nodes" in res.output  # one over: not parsed


# --- #33 round 1: the output location is checked before the run; write failures are one line ------


def _result_obj():
    from sigmaforge import pipeline

    return pipeline.BacktestResult(
        rows=[], funnel={}, manifest={}, report_md="# r\n", run_hash="h", acceptance_gate=[],
        n_attack_events=0, technique_event_counts={}, rules_recall_measurable=0,
        rules_precision_measurable=0, loaded_rule_count=0,
    )  # fmt: skip


@pytest.fixture
def engine_calls(monkeypatch):
    calls = []

    def fake(cfg):
        calls.append(1)
        return _result_obj()

    monkeypatch.setattr("sigmaforge.pipeline.run_backtest_pipeline", fake)
    return calls


def _bt_out(tmp_path, out):
    ins = _inputs(tmp_path)
    return _backtest(tmp_path, ins, "--out", str(out))


def _assert_out_refused(res, calls, reason=None):
    assert res.exit_code == 2, (res.exit_code, res.output, repr(res.exception))
    assert "Traceback" not in res.output and "Cannot write output" in res.output
    assert len(res.output.strip().splitlines()) == 1, res.output
    assert "\x1b" not in res.output and len(res.output) < 1500
    assert not calls, "the engine must not run when the output location is unusable"
    if reason:
        assert reason in res.output


def _out_shapes(tmp_path):
    d = tmp_path / "adir"
    d.mkdir()
    ro = tmp_path / "rodir"
    ro.mkdir()
    ro.chmod(0o555)
    f = tmp_path / "afile"
    f.write_text("x")
    rof = tmp_path / "ro-report.md"
    rof.write_text("old")
    rof.chmod(0o444)
    return {
        "directory": (d, "is a directory"),
        "readonly_dir": (ro / "r.md", "not writable"),
        "under_a_file": (f / "sub" / "r.md", "not writable"),
        "long_name": (tmp_path / ("n" * 5000), "name too long"),
        "readonly_existing_report": (rof, "not writable"),
        "manifest_sibling_is_dir": (tmp_path / "m.md", "is a directory"),
    }


from pathlib import Path  # noqa: E402


@pytest.mark.skipif(os.geteuid() == 0 if hasattr(os, "geteuid") else True, reason="needs a non-root POSIX user")
@pytest.mark.parametrize(
    "shape",
    ["directory", "readonly_dir", "under_a_file", "long_name", "readonly_existing_report", "manifest_sibling_is_dir"],
)  # fmt: skip
def test_unusable_backtest_out_is_refused_before_the_run(tmp_path, engine_calls, shape):
    (tmp_path / "m.manifest.json").mkdir()
    out, reason = _out_shapes(tmp_path)[shape]
    try:
        res = _bt_out(tmp_path, out)
    finally:
        (tmp_path / "rodir").chmod(0o755)
    _assert_out_refused(res, engine_calls, reason)


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0, reason="needs a non-root POSIX user")
def test_unusable_out_is_a_clean_line_in_a_real_subprocess(tmp_path):
    ins = _inputs(tmp_path)
    d = tmp_path / "adir"
    d.mkdir()
    r = _cli_subprocess(tmp_path, ins)  # sanity: the helper itself runs
    args = [
        sys.executable, "-m", "sigmaforge.main", "backtest", "--rules", str(tmp_path / "ok-rules.yml"),
        "--attack-corpus", str(tmp_path), "--technique-map", str(ins["tm"]), "--benign-sample", str(ins["bs"]),
        "--comiset-mapping", str(ins["cm"]), "--engine-home", str(_engine(tmp_path)), "--out", str(d),
    ]  # fmt: skip
    (tmp_path / "ok-rules.yml").write_text("title: t\nlevel: low\n")
    env = {**os.environ, "HOME": str(tmp_path / "home"), "COLUMNS": "300"}
    p = subprocess.run(args, capture_output=True, text=True, timeout=60, env=env)
    assert r is not None and p.returncode == 2, (p.stdout, p.stderr)
    assert "Cannot write output" in p.stdout and "Traceback" not in p.stdout + p.stderr


def _fail_open_for(monkeypatch, predicate):
    """os.open fails with a disk-full error (carrying a secret) for the paths the predicate selects."""
    real = os.open

    def flaky(path, *a, **k):
        if predicate(os.fspath(path)):
            raise OSError(28, "No space left on device: SECRETVAL")
        return real(path, *a, **k)

    monkeypatch.setattr("os.open", flaky)


def test_a_write_failure_after_the_run_is_one_clean_line(tmp_path, engine_calls, monkeypatch):
    _fail_open_for(monkeypatch, lambda p: p.endswith("late.md"))
    res = _bt_out(tmp_path, tmp_path / "late.md")
    assert engine_calls  # the run happened; only the write failed
    assert res.exit_code == 2 and "Cannot write output" in res.output and "Traceback" not in res.output
    assert "secretval" not in res.output.lower() and len(res.output.strip().splitlines()) == 1


def test_a_manifest_write_failure_after_the_run_is_one_clean_line(tmp_path, engine_calls, monkeypatch):
    _fail_open_for(monkeypatch, lambda p: p.endswith("ok.manifest.json"))
    res = _bt_out(tmp_path, tmp_path / "ok.md")
    assert res.exit_code == 2 and "Cannot write output" in res.output and "secretval" not in res.output.lower()
    assert len(res.output.strip().splitlines()) == 1


def test_a_good_out_path_still_writes_both_files_and_leaves_no_probe_behind(tmp_path, engine_calls):
    out = tmp_path / "sub" / "dir" / "r.md"
    res = _bt_out(tmp_path, out)
    assert res.exit_code == 0, res.output
    assert sorted(p.name for p in out.parent.iterdir()) == ["r.manifest.json", "r.md"]


# hunt


def _hunt(tmp_path, out, monkeypatch):
    calls = []
    monkeypatch.setattr(
        "sigmaforge.ingest.compile.compile_ruleset", lambda files, engine_home: (calls.append(1) or [], 0)
    )
    monkeypatch.setattr("sigmaforge.ingest.zircolite_runner.run_shard", lambda *a, **k: [])
    rules = tmp_path / "r.yml"
    rules.write_text("title: t\n")
    res = CliRunner().invoke(
        app,
        [
            "hunt",
            "--rules",
            str(rules),
            "--logs",
            str(tmp_path),
            "--out",
            str(out),
            "--engine-home",
            str(_engine(tmp_path)),
        ],
        env={"COLUMNS": "300"},
    )
    return res, calls


def test_hunt_out_that_is_a_directory_is_refused_before_the_engine(tmp_path, monkeypatch):
    d = tmp_path / "adir"
    d.mkdir()
    res, calls = _hunt(tmp_path, d, monkeypatch)
    _assert_out_refused(res, calls, "is a directory")


def test_hunt_out_under_a_file_is_refused_before_the_engine(tmp_path, monkeypatch):
    f = tmp_path / "afile"
    f.write_text("x")
    res, calls = _hunt(tmp_path, f / "h.json", monkeypatch)
    _assert_out_refused(res, calls, "not writable")


def test_hunt_write_failure_after_the_run_is_one_clean_line(tmp_path, monkeypatch):
    _fail_open_for(monkeypatch, lambda p: p.endswith("late.json"))
    res, calls = _hunt(tmp_path, tmp_path / "late.json", monkeypatch)
    assert calls and res.exit_code == 2 and "Cannot write output" in res.output
    assert "secretval" not in res.output.lower() and len(res.output.strip().splitlines()) == 1


def test_hunt_good_out_writes_and_leaves_no_probe(tmp_path, monkeypatch):
    out = tmp_path / "o" / "h.json"
    res, _ = _hunt(tmp_path, out, monkeypatch)
    assert res.exit_code == 0, res.output
    assert [p.name for p in out.parent.iterdir()] == ["h.json"]


def test_plain_safe_shows_lone_surrogates_as_an_escape():
    from sigmaforge.safe_text import plain_safe, plain_safe_capped

    assert plain_safe("a\udcffb") == "a\\udcffb"
    assert plain_safe_capped("a\udcffb") == "a\\udcffb"
    plain_safe("a\udcffb").encode("utf-8")


def test_out_with_an_invalid_utf8_name_never_crashes_the_message(tmp_path, engine_calls):
    """macOS refuses such a name (clean exit-2 line); Linux accepts it (the run succeeds). Either way the
    output must be printable text, never a traceback."""
    out = Path(os.fsdecode(bytes(tmp_path) + b"/bad\xff\xfe.md"))
    res = _bt_out(tmp_path, out)
    assert res.exception is None or isinstance(res.exception, SystemExit), repr(res.exception)
    assert res.exit_code in (0, 2) and "Traceback" not in res.output
    res.output.encode("utf-8")  # no lone surrogate reached the terminal
    if res.exit_code == 2:
        assert "Cannot write output" in res.output and len(res.output.strip().splitlines()) == 1


# --- #33 round 2: non-regular output targets, empty names, name-length boundary -------------------


def _tool_subprocess(tmp_path, tool, out, timeout=30):
    """backtest or hunt in a child process (a hang fails the test instead of the suite)."""
    ins = _inputs(tmp_path)
    rules = tmp_path / "ok-rules.yml"
    rules.write_text("title: t\nlevel: low\n")
    if tool == "backtest":
        args = [
            sys.executable, "-m", "sigmaforge.main", "backtest", "--rules", str(rules),
            "--attack-corpus", str(tmp_path), "--technique-map", str(ins["tm"]), "--benign-sample", str(ins["bs"]),
            "--comiset-mapping", str(ins["cm"]), "--engine-home", str(_engine(tmp_path)), "--out", str(out),
        ]  # fmt: skip
    else:
        args = [
            sys.executable, "-m", "sigmaforge.main", "hunt", "--rules", str(rules), "--logs", str(tmp_path),
            "--engine-home", str(_engine(tmp_path)), "--out", str(out),
        ]  # fmt: skip
    env = {**os.environ, "HOME": str(tmp_path / "home"), "COLUMNS": "300"}
    env.pop("SIGMAFORGE_HOME", None)
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)


def _assert_refused_proc(p, reason):
    assert p.returncode == 2, (p.returncode, p.stdout[:400], p.stderr[:400])
    assert "Cannot write output" in p.stdout and reason in p.stdout and "Traceback" not in p.stdout + p.stderr
    assert len(p.stdout.strip().splitlines()) == 1


@posix_only
@pytest.mark.parametrize("tool", ["backtest", "hunt"])
def test_fifo_as_out_is_refused_before_the_run(tmp_path, tool):
    fifo = tmp_path / "out-fifo"
    os.mkfifo(fifo)
    _assert_refused_proc(_tool_subprocess(tmp_path, tool, fifo), "not a regular file")


@posix_only
def test_fifo_as_the_manifest_sibling_is_refused_before_the_run(tmp_path):
    os.mkfifo(tmp_path / "rep.manifest.json")
    _assert_refused_proc(_tool_subprocess(tmp_path, "backtest", tmp_path / "rep.md"), "not a regular file")


@posix_only
def test_symlink_to_a_fifo_is_refused_and_dangling_symlink_is_refused(tmp_path):
    os.mkfifo(tmp_path / "real-fifo")
    os.symlink(tmp_path / "real-fifo", tmp_path / "link-fifo")
    _assert_refused_proc(_tool_subprocess(tmp_path, "hunt", tmp_path / "link-fifo"), "not a regular file")
    os.symlink(tmp_path / "nowhere", tmp_path / "dangling")
    _assert_refused_proc(_tool_subprocess(tmp_path, "hunt", tmp_path / "dangling"), "not a regular file")


def test_symlink_to_a_regular_file_is_followed_and_written(tmp_path, engine_calls):
    target = tmp_path / "target.md"
    target.write_text("old")
    link = tmp_path / "link.md"
    os.symlink(target, link)
    res = _bt_out(tmp_path, link)
    assert res.exit_code == 0 and target.read_text() == "# r\n", res.output
    assert link.is_symlink()


@posix_only
def test_write_output_never_blocks_on_a_fifo_swapped_in_after_the_preflight(tmp_path):
    fifo = tmp_path / "late-fifo"
    os.mkfifo(fifo)
    code = (
        "import sys, typer\nfrom pathlib import Path\nfrom sigmaforge.main import _write_output\n"
        "try:\n    _write_output(Path(sys.argv[1]), 'x')\nexcept (typer.Exit, SystemExit) as e:\n    print('refused')\n"
    )
    p = subprocess.run([sys.executable, "-c", code, str(fifo)], capture_output=True, text=True, timeout=20)
    assert "refused" in p.stdout and "Cannot write output" in p.stdout, (p.stdout, p.stderr)


def test_write_output_writes_exact_bytes_and_truncates_a_longer_old_file(tmp_path):
    from sigmaforge.main import _write_output

    f = tmp_path / "w.txt"
    f.write_text("a long old content that must vanish")
    _write_output(f, "new \ud800 text", encoding="utf-8", errors="backslashreplace")
    assert f.read_bytes() == b"new \\ud800 text"
    g = tmp_path / "sub-new.txt"
    _write_output(g, "é")
    assert g.read_bytes() == "é".encode()


@pytest.mark.parametrize("tool", ["backtest", "hunt"])
@pytest.mark.parametrize("out", ["", ".", "/", ".."])
def test_empty_or_root_out_names_are_one_clean_line(tmp_path, tool, out):
    _assert_refused_proc(_tool_subprocess(tmp_path, tool, out), "no file name")


def _name_ok(tmp_path, tool, stem_len, ext):
    return _tool_subprocess(tmp_path, tool, tmp_path / ("s" * stem_len + ext))


def test_name_length_boundary_backtest_counts_the_manifest_sibling(tmp_path, monkeypatch):
    nm = os.pathconf(tmp_path, "PC_NAME_MAX")
    manifest_extra = len(".manifest.json") - len(".md")
    p = _name_ok(tmp_path, "backtest", nm - len(".manifest.json"), ".md")
    assert "Cannot write output" not in p.stdout, (p.stdout, p.stderr)  # both real names fit exactly
    p = _name_ok(tmp_path, "backtest", nm - len(".manifest.json") + 1, ".md")
    _assert_refused_proc(p, "name too long")
    assert manifest_extra > 0


def test_name_length_boundary_hunt(tmp_path):
    nm = os.pathconf(tmp_path, "PC_NAME_MAX")
    p = _tool_subprocess(tmp_path, "hunt", tmp_path / ("n" * (nm - len(".json")) + ".json"))
    assert "Cannot write output" not in p.stdout, (p.stdout, p.stderr)
    p = _tool_subprocess(tmp_path, "hunt", tmp_path / ("n" * (nm - len(".json") + 1) + ".json"))
    _assert_refused_proc(p, "name too long")


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0, reason="needs a non-root POSIX user")
def test_existing_writable_files_in_a_readonly_dir_skip_the_directory_probe(tmp_path, engine_calls):
    d = tmp_path / "rodir2"
    d.mkdir()
    (d / "r.md").write_text("old")
    (d / "r.manifest.json").write_text("old")
    d.chmod(0o555)
    try:
        res = _bt_out(tmp_path, d / "r.md")
    finally:
        d.chmod(0o755)
    assert res.exit_code == 0, res.output
    assert (d / "r.md").read_text() == "# r\n"


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0, reason="needs a non-root POSIX user")
def test_a_missing_manifest_sibling_in_a_readonly_dir_is_still_refused(tmp_path, engine_calls):
    d = tmp_path / "rodir3"
    d.mkdir()
    (d / "r.md").write_text("old")  # report exists and is writable, but the manifest would need a new file
    d.chmod(0o555)
    try:
        res = _bt_out(tmp_path, d / "r.md")
    finally:
        d.chmod(0o755)
    _assert_out_refused(res, engine_calls, "not writable")


def test_only_the_manifest_sibling_name_too_long_is_refused_in_process(tmp_path, engine_calls):
    nm = os.pathconf(tmp_path, "PC_NAME_MAX")
    out = tmp_path / ("s" * (nm - len(".manifest.json") + 1) + ".md")  # report fits, sibling does not
    assert len(out.name) <= nm
    _assert_out_refused(_bt_out(tmp_path, out), engine_calls, "name too long")


@posix_only
def test_write_output_refuses_a_fifo_that_has_a_reader_by_its_type(tmp_path):
    from sigmaforge.main import _write_output

    fifo = tmp_path / "rd-fifo"
    os.mkfifo(fifo)
    rfd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)  # a reader exists, so the open for writing succeeds
    try:
        with pytest.raises(BaseException) as ei:
            _write_output(fifo, "data")
        assert "Exit" in type(ei.value).__name__
        assert os.read(rfd, 100) == b""  # nothing was written into the pipe
    finally:
        os.close(rfd)


def test_write_output_loops_over_short_writes(tmp_path, monkeypatch):
    from sigmaforge.main import _write_output

    real = os.write
    monkeypatch.setattr("os.write", lambda fd, data: real(fd, bytes(data[:3])))
    f = tmp_path / "short.txt"
    _write_output(f, "0123456789abcdef")
    assert f.read_bytes() == b"0123456789abcdef"


def test_write_output_writes_a_large_varied_payload_exactly(tmp_path):
    from sigmaforge.main import _write_output

    text = "".join(f"line {i} é€漢字 {i * 7919 % 10007}\n" for i in range(12_000))
    assert len(text.encode("utf-8")) > 200_000
    f = tmp_path / "big.txt"
    f.write_text("old " * 100_000)  # a longer old file must be fully replaced
    _write_output(f, text)
    assert f.read_bytes() == text.encode("utf-8")
    g = tmp_path / "big-new.txt"
    _write_output(g, text)
    assert g.read_bytes() == text.encode("utf-8")


def test_the_cli_report_and_manifest_are_written_in_full(tmp_path, monkeypatch):
    from sigmaforge import pipeline

    report = "".join(f"| rule {i} | é€漢字 | {i}\n" for i in range(15_000))
    manifest = {f"k{i}": "v" * 20 for i in range(5_000)}
    assert len(report.encode("utf-8")) > 200_000
    res_obj = pipeline.BacktestResult(
        rows=[], funnel={}, manifest=manifest, report_md=report, run_hash="h", acceptance_gate=[],
        n_attack_events=0, technique_event_counts={}, rules_recall_measurable=0,
        rules_precision_measurable=0, loaded_rule_count=0,
    )  # fmt: skip
    monkeypatch.setattr("sigmaforge.pipeline.run_backtest_pipeline", lambda cfg: res_obj)
    out = tmp_path / "full.md"
    res = _bt_out(tmp_path, out)
    assert res.exit_code == 0, res.output
    assert out.read_bytes() == report.encode("utf-8")
    assert json.loads(out.with_suffix(".manifest.json").read_text()) == manifest
