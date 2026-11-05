"""sigmaforge configuration: ~/.sigmaforge/config.yaml + env > defaults."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel
from shipwright_kit.config import app_dir, load_config

_APP_DIR = app_dir("sigmaforge")


class OutputConfig(BaseModel):
    default_format: str = "rich"


class BacktestConfig(BaseModel):
    """Resolved corpus/mapping/engine inputs for the `backtest` command.

    Defaults are ``None`` (NOT repo-relative paths): a fresh ``pip install`` ships
    no labeled corpora, so the CLI raises a teaching error when these are unset
    outside the repo rather than silently pointing at a non-existent ``data/`` tree.
    """

    rules: Optional[str] = None
    attack_corpus: Optional[str] = None
    technique_map: Optional[str] = None
    benign_sample: Optional[str] = None
    comiset_mapping: Optional[str] = None
    engine_home: Optional[str] = None
    floor: int = 1000


class AppConfig(BaseModel):
    output: OutputConfig = OutputConfig()
    backtest: BacktestConfig = BacktestConfig()


def _load_yaml(path: Path) -> dict:
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    # A relative engine_home in a config file means "relative to THAT file", not the cwd.
    bt = data.get("backtest")
    if isinstance(bt, dict) and bt.get("engine_home"):
        bt["engine_home"] = str((Path(path).parent / Path(str(bt["engine_home"])).expanduser()).resolve())
    return data


def load(config_path: Optional[Path] = None) -> AppConfig:
    """Resolve config: explicit > ~/.sigmaforge/config.yaml > defaults.

    The current directory is deliberately NOT a config source: a planted ./config.yaml
    could otherwise redirect ``backtest.engine_home`` to attacker code."""
    return load_config(
        [config_path, _APP_DIR / "config.yaml"],
        loader=_load_yaml,
        validator=AppConfig.model_validate,
    )
