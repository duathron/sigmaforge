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
        return yaml.safe_load(f) or {}


def load(config_path: Optional[Path] = None) -> AppConfig:
    """Resolve config: explicit > ~/.sigmaforge/config.yaml > ./config.yaml > defaults."""
    return load_config(
        [config_path, _APP_DIR / "config.yaml", Path("config.yaml")],
        loader=_load_yaml,
        validator=AppConfig.model_validate,
    )
