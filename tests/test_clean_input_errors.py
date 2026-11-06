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

    assert pipeline.RULESET_HASH_MAX_BYTES == 64 * 1024 * 1024


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
