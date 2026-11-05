"""F7 (CWE-427): the engine that runs is the one named by --engine-home / SIGMAFORGE_HOME,
never one found in the current directory. Fake engines only, so these run in CI (no real
Zircolite there); the real-engine tests stay skipped."""

import json
import os
import re
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
    # strip ANSI (CI colors the help) before looking for the option name
    assert "--engine-home" in re.sub(r"\x1b\[[0-9;]*m", "", res.output)

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


def test_relative_paths_in_config_resolve_against_config_dir(tmp_path, monkeypatch):
    from sigmaforge import config

    cfgdir = tmp_path / "cfg"
    cfgdir.mkdir()
    keys = ("engine_home", "rules", "attack_corpus", "technique_map", "benign_sample", "comiset_mapping")
    (cfgdir / "c.yaml").write_text("backtest:\n" + "".join(f"  {k}: ../{k}\n" for k in keys))
    monkeypatch.setattr("sigmaforge.config._APP_DIR", tmp_path / "nohome")
    deep = tmp_path / "x" / "y"
    deep.mkdir(parents=True)
    monkeypatch.chdir(deep)
    bt = config.load(cfgdir / "c.yaml").backtest
    for k in keys:
        want = (tmp_path / k).resolve()
        # fixture self-check: resolving against the CWD instead would give another answer
        assert (deep / ".." / k).resolve() != want
        assert Path(getattr(bt, k)) == want, k


def test_config_expands_tilde_in_path_values(tmp_path, monkeypatch):
    from sigmaforge import config

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("sigmaforge.config._APP_DIR", tmp_path / "nohome")
    (tmp_path / "c.yaml").write_text("backtest:\n  engine_home: ~/eng\n  rules: ~/r\n")
    bt = config.load(tmp_path / "c.yaml").backtest
    assert Path(bt.engine_home) == (tmp_path / "eng").resolve()
    assert Path(bt.rules) == (tmp_path / "r").resolve()


def test_non_mapping_config_is_a_clear_error(tmp_path, monkeypatch):
    from sigmaforge import config

    monkeypatch.setattr("sigmaforge.config._APP_DIR", tmp_path / "nohome")
    (tmp_path / "c.yaml").write_text("- just\n- a list\n")
    with pytest.raises(ValueError, match="mapping"):
        config.load(tmp_path / "c.yaml")


# --- review round: import order, symlinks, explicit values, CLI threading ---------------


def test_namespace_package_planted_on_path_is_not_executed(pkg_rig, tmp_path, monkeypatch):
    # `import zircolite` first resolves a namespace package (no __init__.py) from a planted
    # dir; compile_ruleset must refuse BEFORE importing zircolite.config from it.
    from sigmaforge.engine import EngineNotFoundError
    from sigmaforge.ingest.compile import compile_ruleset

    good, _evil, _marker = pkg_rig
    plant = tmp_path / "plant"
    (plant / "zircolite").mkdir(parents=True)
    ran = tmp_path / "ns_marker"
    (plant / "zircolite" / "config.py").write_text(f"open({str(ran)!r}, 'w').write('x')\n")
    monkeypatch.syspath_prepend(str(plant))
    import zircolite  # noqa: F401  (namespace package from the planted dir)

    with pytest.raises(EngineNotFoundError):
        compile_ruleset([tmp_path / "a.yml"], engine_home=good)
    assert not ran.exists()


@pytest.mark.parametrize("entry", ["evil-dir", ""])
def test_engine_dir_wins_over_planted_sys_path_entry(pkg_rig, tmp_path, monkeypatch, entry):
    from sigmaforge.ingest.compile import compile_ruleset

    good, evil, evil_marker = pkg_rig
    monkeypatch.syspath_prepend(str(evil / "Zircolite") if entry else "")
    if not entry:
        sys.path.insert(0, "")  # cwd (= evil/Zircolite) entry, as `python -c` / `-m` have
    rule = tmp_path / "a.yml"
    rule.write_text("title: a\n")
    compile_ruleset([rule], engine_home=good)
    assert sys.modules["zircolite.config"].ORIGIN == "GOOD"
    assert not evil_marker.exists()


def test_symlinked_zircolite_dir_works(pkg_rig, tmp_path):
    from sigmaforge.ingest.compile import compile_ruleset

    good, _evil, _marker = pkg_rig
    home = tmp_path / "linkhome"
    home.mkdir()
    os.symlink(good / "Zircolite", home / "Zircolite")
    rule = tmp_path / "a.yml"
    rule.write_text("title: a\n")
    ruleset, n = compile_ruleset([rule], engine_home=home)
    assert (n, ruleset) == (1, [{"title": "t"}])
    assert sys.modules["zircolite.config"].ORIGIN == "GOOD"


def test_resolve_engine_home_explicit_forms(tmp_path, monkeypatch):
    from sigmaforge.engine import resolve_engine_home

    good = _fake_engine(tmp_path / "x", "GOOD")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("SIGMAFORGE_HOME", raising=False)
    assert resolve_engine_home("~/x") == good.resolve()  # ~ expanded
    monkeypatch.chdir(tmp_path)
    assert resolve_engine_home("x") == good.resolve()  # relative -> absolute
    monkeypatch.chdir(good)  # "" must NOT mean "the current directory"
    assert resolve_engine_home("") is None
    monkeypatch.setenv("SIGMAFORGE_HOME", str(good))
    assert resolve_engine_home("") is None  # explicit-but-empty does not fall through to the env


@pytest.fixture
def cli_rig(tmp_path, monkeypatch):
    good = _fake_engine(tmp_path / "good", "GOOD").resolve()
    other = _fake_engine(tmp_path / "other", "OTHER").resolve()
    cfg = tmp_path / "empty.yaml"
    cfg.write_text("{}\n")
    monkeypatch.setattr("sigmaforge.config._APP_DIR", tmp_path / "nohome")
    monkeypatch.delenv("SIGMAFORGE_HOME", raising=False)
    (tmp_path / "r.yml").write_text("title: x\n")
    (tmp_path / "l.jsonl").write_text("{}\n")
    return good, other, cfg


def _backtest_args(tmp_path, *extra):
    return [
        "backtest",
        "--rules",
        str(tmp_path / "r.yml"),
        "--attack-corpus",
        str(tmp_path),
        "--technique-map",
        str(tmp_path / "tm.json"),
        "--benign-sample",
        str(tmp_path / "b.jsonl"),
        *extra,
    ]


def _capture_backtest(monkeypatch):
    seen = {}

    def fake_pipeline(pcfg):
        seen["engine_home"] = pcfg.engine_home
        raise AssertionError("stop here")

    monkeypatch.setattr("sigmaforge.pipeline.run_backtest_pipeline", fake_pipeline)
    return seen


def test_backtest_engine_home_from_flag_config_and_env(cli_rig, tmp_path, monkeypatch):
    good, other, cfg = cli_rig
    seen = _capture_backtest(monkeypatch)
    # flag beats env
    monkeypatch.setenv("SIGMAFORGE_HOME", str(other))
    res = CliRunner().invoke(app, _backtest_args(tmp_path, "--config", str(cfg), "--engine-home", str(good)))
    assert res.exit_code == 5 and seen["engine_home"] == str(good)
    # env alone
    res = CliRunner().invoke(app, _backtest_args(tmp_path, "--config", str(cfg)))
    assert res.exit_code == 5 and seen["engine_home"] == str(other)
    # config beats env
    monkeypatch.delenv("SIGMAFORGE_HOME")
    cfg2 = tmp_path / "c2.yaml"
    cfg2.write_text(f"backtest:\n  engine_home: {good}\n")
    res = CliRunner().invoke(app, _backtest_args(tmp_path, "--config", str(cfg2)))
    assert res.exit_code == 5 and seen["engine_home"] == str(good)


def _hunt(tmp_path, cfg, *extra):
    return CliRunner().invoke(
        app,
        ["hunt", "--rules", str(tmp_path / "r.yml"), "--logs", str(tmp_path / "l.jsonl")]
        + ["--out", str(tmp_path / "hits.json"), "--config", str(cfg), *extra],
    )


def test_hunt_engine_home_from_config_and_env(cli_rig, tmp_path, monkeypatch):
    import sigmaforge.ingest.compile as compile_mod
    import sigmaforge.ingest.zircolite_runner as runner_mod

    good, other, cfg = cli_rig
    seen = {}

    def fake_compile(paths, engine_home=None):
        seen["compile"] = engine_home
        return [], 0

    def fake_run_shard(*args, **kwargs):
        seen["run_shard"] = kwargs.get("engine_home")
        return []

    monkeypatch.setattr(compile_mod, "compile_ruleset", fake_compile)
    monkeypatch.setattr(runner_mod, "run_shard", fake_run_shard)
    cfg2 = tmp_path / "c2.yaml"
    cfg2.write_text(f"backtest:\n  engine_home: {good}\n")
    assert _hunt(tmp_path, cfg2).exit_code == 0
    assert seen == {"compile": str(good), "run_shard": str(good)}
    monkeypatch.setenv("SIGMAFORGE_HOME", str(other))
    assert _hunt(tmp_path, cfg).exit_code == 0
    assert seen == {"compile": str(other), "run_shard": str(other)}


def test_empty_engine_home_flag_is_invalid_not_unset(cli_rig, tmp_path, monkeypatch):
    good, _other, cfg = cli_rig
    monkeypatch.setenv("SIGMAFORGE_HOME", str(good))
    monkeypatch.chdir(good)
    res = _hunt(tmp_path, cfg, "--engine-home", "")
    assert res.exit_code == 3 and "Traceback" not in res.output
    res = CliRunner().invoke(app, _backtest_args(tmp_path, "--config", str(cfg), "--engine-home", ""))
    assert res.exit_code == 3 and "Traceback" not in res.output


def test_engine_refusal_during_compile_is_a_teaching_exit_3(cli_rig, tmp_path, monkeypatch):
    import sigmaforge.ingest.compile as compile_mod
    from sigmaforge.engine import EngineNotFoundError

    good, _other, cfg = cli_rig

    def refuse(paths, engine_home=None):
        raise EngineNotFoundError("zircolite was already imported from [elsewhere]")

    monkeypatch.setattr(compile_mod, "compile_ruleset", refuse)
    res = _hunt(tmp_path, cfg, "--engine-home", str(good))
    assert res.exit_code == 3 and "Traceback" not in res.output
    assert "already imported" in " ".join(res.output.split())


def test_backtest_engine_refusal_is_exit_3(cli_rig, tmp_path, monkeypatch):
    from sigmaforge.engine import EngineNotFoundError

    good, _other, cfg = cli_rig

    def refuse(pcfg):
        raise EngineNotFoundError("engine refused")

    monkeypatch.setattr("sigmaforge.pipeline.run_backtest_pipeline", refuse)
    res = CliRunner().invoke(app, _backtest_args(tmp_path, "--config", str(cfg), "--engine-home", str(good)))
    assert res.exit_code == 3 and "Traceback" not in res.output


def test_provenance_uses_explicit_then_env_engine_home(tmp_path, monkeypatch):
    from sigmaforge import provenance as prov

    good = _fake_engine(tmp_path / "good", "GOOD").resolve()
    other = tmp_path / "other"
    seen = []
    monkeypatch.setattr(prov, "_git", lambda repo, *a: seen.append(Path(repo)) or "sha")
    monkeypatch.delenv("SIGMAFORGE_HOME", raising=False)
    prov.engine_provenance(engine_home=other)
    assert set(seen) == {other / "Zircolite"}
    seen.clear()
    monkeypatch.setenv("SIGMAFORGE_HOME", str(good))
    prov.engine_provenance()
    assert set(seen) == {good / "Zircolite"}
    seen.clear()
    monkeypatch.delenv("SIGMAFORGE_HOME")
    out = prov.engine_provenance()
    assert seen == [] and "unavailable" in out["zircolite_commit_sha"]
