"""Repo scripts name their engine explicitly (inside main), never at import time."""

from __future__ import annotations

import ast
import importlib
import os
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
ENGINE_SCRIPTS = [
    "run_first_backtest",
    "run2_backtest",
    "run3_backtest",
    "run4_backtest",
    "run5_backtest",
    "run6_backtest",
    "run7_backtest",
    "compile_loaded_ruleset",
]


@pytest.mark.parametrize("name", ENGINE_SCRIPTS)
def test_importing_a_script_does_not_mutate_environ(name, monkeypatch):
    monkeypatch.delenv("SIGMAFORGE_HOME", raising=False)
    before = dict(os.environ)
    importlib.import_module(f"scripts.{name}")
    assert dict(os.environ) == before


@pytest.mark.parametrize("name", ENGINE_SCRIPTS)
def test_main_defaults_sigmaforge_home_to_the_repo(name):
    tree = ast.parse((SCRIPTS / f"{name}.py").read_text())
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    src = "\n".join(ast.unparse(s) for s in main.body[:2])
    assert "os.environ.setdefault('SIGMAFORGE_HOME', str(REPO))" in src
    # and never at module level (would leak into tests importing the module)
    top = "\n".join(ast.unparse(s) for s in tree.body if not isinstance(s, ast.FunctionDef))
    assert "SIGMAFORGE_HOME" not in top
