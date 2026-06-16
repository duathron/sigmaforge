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


class AppConfig(BaseModel):
    output: OutputConfig = OutputConfig()


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
