"""F7 (CWE-427): the engine that runs is the one named by --engine-home / SIGMAFORGE_HOME,
never one found in the current directory. Fake engines only, so these run in CI (no real
Zircolite there); the real-engine tests stay skipped."""

import json
import os
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sigmaforge.main import app

# A fake engine: records which one ran (MARKER), what it was handed (ARGV_LOG) and writes
# an empty detections list to --outfile, like a real run with no hits.
_FAKE_ENGINE = """
import json, os, sys
TAG = "{tag}"
argv = sys.argv
def arg(name):
    return argv[argv.index(name) + 1] if name in argv else None
with open(os.environ["MARKER"], "w") as fh:
    fh.write(TAG)
if os.environ.get("ARGV_LOG"):
    with open(os.environ["ARGV_LOG"], "w") as fh:
        json.dump(
            {{
                "events_exists": os.path.exists(arg("--events")),
                "ruleset_exists": os.path.exists(arg("--ruleset")),
                "config_exists": os.path.exists(arg("--config")) if arg("--config") else None,
                "outfile_abs": os.path.isabs(arg("--outfile")),
            }},
            fh,
        )
with open(arg("--outfile"), "w") as fh:
    fh.write("[]")
"""


def _fake_engine(root: Path, tag: str) -> Path:
    z = root / "Zircolite"
    z.mkdir(parents=True)
    (z / "zircolite.py").write_text(_FAKE_ENGINE.format(tag=tag))
    return root


@pytest.fixture
def rig(tmp_path, monkeypatch):
    """good engine, evil engine (made the CWD), marker path; SIGMAFORGE_* unset."""
    good = _fake_engine(tmp_path / "good", "GOOD")
    evil = _fake_engine(tmp_path / "evil", "EVIL")
    marker = tmp_path / "marker"
    monkeypatch.setenv("MARKER", str(marker))
    monkeypatch.delenv("SIGMAFORGE_HOME", raising=False)
    monkeypatch.delenv("SIGMAFORGE_ZIRCOLITE", raising=False)
    monkeypatch.chdir(evil)
    return good, evil, marker


def test_run_shard_executes_engine_home_not_cwd(rig):
    from sigmaforge.ingest.zircolite_runner import run_shard

    good, _evil, marker = rig
    run_shard("e.jsonl", "r.json", engine_home=good)
    assert marker.read_text() == "GOOD"


def test_run_shard_without_engine_home_never_executes_cwd_engine(rig):
    from sigmaforge.engine import EngineNotFoundError
    from sigmaforge.ingest.zircolite_runner import run_shard

    _good, _evil, marker = rig
    with pytest.raises(EngineNotFoundError):
        run_shard("e.jsonl", "r.json")
    assert not marker.exists()


def test_sigmaforge_home_env_selects_engine(rig, monkeypatch):
    from sigmaforge.ingest.zircolite_runner import run_shard

    good, _evil, marker = rig
    monkeypatch.setenv("SIGMAFORGE_HOME", str(good))
    run_shard("e.jsonl", "r.json")
    assert marker.read_text() == "GOOD"


def test_run_shard_absolutizes_caller_paths_for_the_engine_cwd(rig, tmp_path, monkeypatch):
    # the engine runs with cwd=<engine home>; caller-relative inputs must still resolve.
    from sigmaforge.ingest.zircolite_runner import run_shard

    good, _evil, _marker = rig
    work = tmp_path / "work"
    work.mkdir()
    for name in ("e.jsonl", "r.json", "m.yaml"):
        (work / name).write_text("{}")
    log = tmp_path / "argv.json"
    monkeypatch.setenv("ARGV_LOG", str(log))
    monkeypatch.chdir(work)
    run_shard("e.jsonl", "r.json", mapping_path="m.yaml", engine_home=good)
    seen = json.loads(log.read_text())
    assert seen == {"events_exists": True, "ruleset_exists": True, "config_exists": True, "outfile_abs": True}


def test_engine_command_is_sys_executable_plus_absolute_script(rig, monkeypatch):
    # B2: no `uv run` (it re-discovers a project, and its .venv, from the CWD).
    from sigmaforge.engine import engine_script
    from sigmaforge.ingest import zircolite_runner

    good, _evil, _marker = rig
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"], seen["kwargs"] = cmd, kwargs
        Path(cmd[cmd.index("--outfile") + 1]).write_text("[]")

    monkeypatch.setattr(zircolite_runner.subprocess, "run", fake_run)
    zircolite_runner.run_shard("e.jsonl", "r.json", engine_home=good)
    cmd = seen["cmd"]
    assert cmd[0] == sys.executable
    assert "uv" not in [os.path.basename(c) for c in cmd]
    assert cmd[1] == str(engine_script(good))
    assert seen["kwargs"]["cwd"] == str(good)


def test_sigmaforge_zircolite_env_replaces_only_the_interpreter_prefix(rig, monkeypatch):
    from sigmaforge.engine import engine_script
    from sigmaforge.ingest import zircolite_runner

    good, _evil, _marker = rig
    monkeypatch.setenv("SIGMAFORGE_ZIRCOLITE", "/opt/py -u")
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        Path(cmd[cmd.index("--outfile") + 1]).write_text("[]")

    monkeypatch.setattr(zircolite_runner.subprocess, "run", fake_run)
    zircolite_runner.run_shard("e.jsonl", "r.json", engine_home=good)
    assert seen["cmd"][:3] == ["/opt/py", "-u", str(engine_script(good))]


def test_planted_cwd_project_venv_is_not_executed(rig):
    # regression (the argv test above is the discriminating proof): a planted pyproject +
    # .venv/bin/python shim in the CWD must not run.
    from sigmaforge.ingest.zircolite_runner import run_shard

    good, evil, marker = rig
    (evil / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "0"\n')
    shim = evil / ".venv" / "bin" / "python"
    shim.parent.mkdir(parents=True)
    shim.write_text('#!/bin/sh\necho SHIM > "$MARKER"\n')
    shim.chmod(0o755)
    run_shard("e.jsonl", "r.json", engine_home=good)
    assert marker.read_text() == "GOOD"


def test_run_shard_validates_inputs_before_resolving_engine(rig):
    from sigmaforge.ingest.zircolite_runner import run_shard

    with pytest.raises(ValueError):
        run_shard("x", "y", json_input=True, xml_input=True)


# --- compile_ruleset ------------------------------------------------------------------


def _fake_zircolite_pkg(root: Path, origin: str) -> None:
    pkg = root / "Zircolite" / "zircolite"
    pkg.mkdir(parents=True)
    (root / "Zircolite" / "zircolite.py").write_text("")
    (pkg / "__init__.py").write_text("")
    (pkg / "config.py").write_text(
        f"ORIGIN = {origin!r}\n"
        "import os\n"
        "if os.environ.get('EVIL_MARKER') and ORIGIN == 'EVIL':\n"
        "    open(os.environ['EVIL_MARKER'], 'w').write('x')\n"
        "class RulesetConfig:\n"
        "    def __init__(self, ruleset, pipeline, save_ruleset):\n"
        "        self.ruleset = ruleset\n"
    )
    (pkg / "rules.py").write_text(
        "class RulesetHandler:\n"
        "    def __init__(self, ruleset_config, logger):\n"
        "        self.rulesets = [{'title': 't'}]\n"
    )


@pytest.fixture
def pkg_rig(tmp_path, monkeypatch):
    good = tmp_path / "good"
    evil = tmp_path / "evil"
    _fake_zircolite_pkg(good, "GOOD")
    _fake_zircolite_pkg(evil, "EVIL")
    monkeypatch.setenv("EVIL_MARKER", str(tmp_path / "evil_marker"))
    monkeypatch.delenv("SIGMAFORGE_HOME", raising=False)
    monkeypatch.chdir(evil / "Zircolite")
    monkeypatch.setattr(sys, "path", list(sys.path))
    for name in [n for n in sys.modules if n == "zircolite" or n.startswith("zircolite.")]:
        monkeypatch.delitem(sys.modules, name)
    yield good, evil, tmp_path / "evil_marker"
    for name in [n for n in sys.modules if n == "zircolite" or n.startswith("zircolite.")]:
        sys.modules.pop(name)


def test_compile_ruleset_imports_from_engine_home_not_cwd(pkg_rig, tmp_path):
    from sigmaforge.ingest.compile import compile_ruleset

    good, _evil, evil_marker = pkg_rig
    rule = tmp_path / "a.yml"
    rule.write_text("title: a\n")
    ruleset, n = compile_ruleset([rule], engine_home=good)
    assert (n, ruleset) == (1, [{"title": "t"}])
    assert sys.modules["zircolite.config"].ORIGIN == "GOOD"
    assert not evil_marker.exists()


def test_compile_ruleset_rejects_a_preimported_foreign_zircolite(pkg_rig, tmp_path):
    import types

    from sigmaforge.engine import EngineNotFoundError
    from sigmaforge.ingest.compile import compile_ruleset

    good, evil, _marker = pkg_rig
    foreign = types.ModuleType("zircolite")
    foreign.__path__ = [str(evil / "Zircolite" / "zircolite")]
    cfg = types.ModuleType("zircolite.config")
    cfg.__file__ = str(evil / "Zircolite" / "zircolite" / "config.py")
    cfg.RulesetConfig = object
    sys.modules["zircolite"] = foreign
    sys.modules["zircolite.config"] = cfg
    with pytest.raises(EngineNotFoundError):
        compile_ruleset([tmp_path / "a.yml"], engine_home=good)


# --- pipeline + CLI threading ---------------------------------------------------------


def test_backtest_threads_engine_home_to_every_exec_site(tmp_path, monkeypatch):
    from sigmaforge import pipeline

    good = _fake_engine(tmp_path / "good", "GOOD")
    (tmp_path / "tm.json").write_text(json.dumps({"technique_event_counts": {}, "file_technique": {}, "total_pc": 0}))
    (tmp_path / "b.jsonl").write_text(json.dumps({"_source": {}}) + "\n")
    (tmp_path / "m.yaml").write_text("mappings: {}\n")
    (tmp_path / "r.json").write_text("[]")
    seen = {"run_shard": [], "provenance": []}

    def fake_run_shard(*args, **kwargs):
        seen["run_shard"].append(kwargs.get("engine_home"))
        return []

    def fake_provenance(*args, **kwargs):
        seen["provenance"].append(kwargs.get("engine_home"))
        return {}

    monkeypatch.setattr(pipeline, "run_shard", fake_run_shard)
    monkeypatch.setattr(pipeline, "provenance", fake_provenance)
    cfg = pipeline.PipelineConfig(
        compiled_ruleset=str(tmp_path / "r.json"),
        loaded_rules_glob=str(tmp_path / "none" / "*.yml"),
        attack_corpus=str(tmp_path),
        technique_map=str(tmp_path / "tm.json"),
        benign_sample=str(tmp_path / "b.jsonl"),
        comiset_mapping=str(tmp_path / "m.yaml"),
        evtx_cfg=str(tmp_path / "m.yaml"),
        engine_home=str(good),
    )
    pipeline.run_backtest_pipeline(cfg)
    assert seen["run_shard"] == [str(good), str(good)]
    assert seen["provenance"] == [str(good)]


def test_hunt_has_engine_home_flag_and_threads_it(tmp_path, monkeypatch):
    import sigmaforge.ingest.compile as compile_mod
    import sigmaforge.ingest.zircolite_runner as runner_mod

    res = CliRunner().invoke(app, ["hunt", "--help"], env={"COLUMNS": "200"})
    assert "--engine-home" in " ".join(res.output.split())

    good = _fake_engine(tmp_path / "good", "GOOD").resolve()
    rules = tmp_path / "r.yml"
    rules.write_text("title: x\n")
    logs = tmp_path / "l.jsonl"
    logs.write_text("{}\n")
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("{}\n")
    seen = {}

    def fake_compile(paths, engine_home=None):
        seen["compile"] = engine_home
        return [], 0

    def fake_run_shard(*args, **kwargs):
        seen["run_shard"] = kwargs.get("engine_home")
        return []

    monkeypatch.setattr(compile_mod, "compile_ruleset", fake_compile)
    monkeypatch.setattr(runner_mod, "run_shard", fake_run_shard)
    monkeypatch.delenv("SIGMAFORGE_HOME", raising=False)
    res = CliRunner().invoke(
        app,
        [
            "hunt",
            "--rules",
            str(rules),
            "--logs",
            str(logs),
            "--out",
            str(tmp_path / "hits.json"),
            "--config",
            str(cfg),
            "--engine-home",
            str(good),
        ],
    )
    assert res.exit_code == 0, res.output
    assert seen == {"compile": str(good), "run_shard": str(good)}


# --- config ---------------------------------------------------------------------------


def test_cwd_config_yaml_is_not_a_config_source(tmp_path, monkeypatch):
    from sigmaforge import config

    empty = tmp_path / "home"
    empty.mkdir()
    planted = tmp_path / "planted"
    planted.mkdir()
    (planted / "config.yaml").write_text("backtest:\n  engine_home: /evil\n")
    monkeypatch.setattr("sigmaforge.config._APP_DIR", empty)
    monkeypatch.chdir(planted)
    assert config.load().backtest.engine_home is None


def test_relative_engine_home_in_config_resolves_against_config_dir(tmp_path, monkeypatch):
    from sigmaforge import config

    cfgdir = tmp_path / "cfg"
    cfgdir.mkdir()
    (cfgdir / "c.yaml").write_text("backtest:\n  engine_home: ../eng\n")
    monkeypatch.setattr("sigmaforge.config._APP_DIR", tmp_path / "nohome")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    got = config.load(cfgdir / "c.yaml").backtest.engine_home
    assert Path(got) == (tmp_path / "eng").resolve()
