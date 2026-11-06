"""sigmaforge configuration: --config file > ~/.sigmaforge/config.yaml > defaults.

The current directory is not a config source. Every path-valued ``backtest`` key in a
config file resolves relative to that file's directory (``~`` expanded)."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, ValidationError
from shipwright_kit.config import app_dir, load_config, resolve_config_file

from sigmaforge.safe_read import ReadRefused, read_capped

#: A config file larger than this is refused as "too large".
CONFIG_MAX_BYTES = 1024 * 1024

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


#: Every path-valued ``backtest`` key. Relative values mean "relative to the config file".
_PATH_KEYS = ("rules", "attack_corpus", "technique_map", "benign_sample", "comiset_mapping", "engine_home")


class ConfigError(ValueError):
    """A config file could not be used. `path` is the offending file (untrusted text: sanitize at
    the sink); the message is value-free: no YAML snippet, no config value, only field names."""

    def __init__(self, path: object, reason: str):
        super().__init__(reason)
        self.path = path


def _load_yaml(path: Path) -> dict:
    try:
        data = yaml.safe_load(read_capped(path, CONFIG_MAX_BYTES).decode("utf-8")) or {}
    except ReadRefused as e:
        raise ConfigError(path, e.reason) from None
    except yaml.YAMLError:
        raise ConfigError(path, "invalid YAML") from None
    except UnicodeDecodeError:
        raise ConfigError(path, "undecodable text (not UTF-8)") from None
    except RecursionError:
        raise ConfigError(path, "too deeply nested") from None
    except ValueError:  # e.g. the int-conversion digit limit
        raise ConfigError(path, "value out of range") from None
    if not isinstance(data, dict):
        raise ConfigError(path, "config must be a YAML mapping")
    bt = data.get("backtest")
    if isinstance(bt, dict):
        base = Path(path).parent
        for key in _PATH_KEYS:
            if isinstance(bt.get(key), str) and bt[key]:
                try:
                    bt[key] = str((base / Path(bt[key]).expanduser()).resolve())
                except (OSError, ValueError, RuntimeError):
                    raise ConfigError(path, f"invalid path value for backtest.{key}") from None
    return data


def _validate(data: dict, path: object) -> AppConfig:
    """`AppConfig.model_validate`, with a schema error reduced to field names (never values)."""
    try:
        return AppConfig.model_validate(data)
    except ValidationError as e:
        fields = sorted({".".join(str(p) for p in err["loc"]) or "<root>" for err in e.errors()})
        raise ConfigError(path, "invalid field(s): " + ", ".join(fields)) from None


def load(config_path: Optional[Path] = None) -> AppConfig:
    """Resolve config: explicit > ~/.sigmaforge/config.yaml > defaults.

    The current directory is deliberately NOT a config source: a planted ./config.yaml
    could otherwise redirect ``backtest.engine_home`` to attacker code."""
    if config_path is not None:
        # an explicit --config that is not there is a typo to report, not a silent fall-back
        try:
            found = config_path.exists()
        except (OSError, ValueError):
            raise ConfigError(config_path, "unreadable") from None
        if not found:
            raise ConfigError(config_path, "file not found")
    path = resolve_config_file([config_path, _APP_DIR / "config.yaml"])
    return load_config(
        [path],
        loader=_load_yaml,
        validator=lambda data: _validate(data, path),
    )
