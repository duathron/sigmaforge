"""Importable compile path: native Sigma YAML -> Zircolite ruleset, ONE source.

`compile_ruleset` converts a set of `.yml` rule files through Zircolite's OWN
pySigma sqlite backend — the identical converter that produced the bundled
`rules_windows_sysmon.json` snapshot. Lifting it out of
`scripts/compile_loaded_ruleset.py` into the package means both the loaded-ruleset
script (backtest) and the `hunt` command compile rules through ONE source, so the
engine always fires the same rule bodies that get scored.

Engine dependency: the conversion needs the vendored Zircolite (`Zircolite/` under the
`engine_home` argument or SIGMAFORGE_HOME — never the cwd) and its pySigma requirements. Importing THIS module is
cheap and engine-free; the heavy `zircolite.*` imports happen inside the function
so callers (and tests) can import `compile_ruleset` even when the engine is absent.
"""

from __future__ import annotations

import json
import logging
import shutil
import sys
import tempfile
from pathlib import Path

from sigmaforge.engine import EngineNotFoundError, require_engine_home
from sigmaforge.safe_text import plain_safe

#: Zircolite pySigma pipeline name (matches the bundled snapshot's conversion).
PIPELINE = "sysmon"


def _ensure_engine_on_path(home: Path) -> None:
    """Put the engine's `Zircolite/` dir FIRST on sys.path so `import zircolite.*` resolves
    there (absolute path, resolved from the caller-named engine home)."""
    engine = str(home / "Zircolite")
    if not sys.path or sys.path[0] != engine:
        sys.path.insert(0, engine)


def _refuse_foreign_zircolite(engine: Path) -> None:
    """Raise if any already-imported `zircolite` / `zircolite.*` module (including a
    namespace package) lives outside the engine dir — BEFORE anything is imported from it.
    Both sides are compared resolved, so a symlinked `Zircolite/` is fine."""
    for name, mod in list(sys.modules.items()):
        if name != "zircolite" and not name.startswith("zircolite."):
            continue
        locations = [getattr(mod, "__file__", None), *list(getattr(mod, "__path__", None) or [])]
        for loc in filter(None, locations):
            if not Path(loc).resolve().is_relative_to(engine):
                raise EngineNotFoundError(f"{name} was already imported from {loc}, not from {engine}")


# Logger namespaces that can carry rule text. pySigma/Zircolite are not installed where this was
# written, so the sigma names are the documented-convention set, not measured: keep it generous.
ENGINE_LOGGERS = ("zircolite", "sigma", "pysigma", "pySigma", "compile_loaded_ruleset")


class _SanitizingFormatter(logging.Formatter):
    """Engine log lines carry rule-derived (attacker) text: flatten + strip before stderr."""

    def format(self, record: logging.LogRecord) -> str:
        return plain_safe(record.getMessage())


def _engine_logger() -> logging.Logger:
    """The engine's loggers write to stderr through a sanitizing handler; the root logger is
    never configured (no global side effect, no raw `basicConfig` handler)."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_SanitizingFormatter())
    for name in ENGINE_LOGGERS:
        lg = logging.getLogger(name)
        lg.handlers = [handler]
        lg.setLevel(logging.INFO)
        lg.propagate = False
    return logging.getLogger("compile_loaded_ruleset")


def compile_ruleset(paths: list[Path], engine_home: str | Path | None = None) -> tuple[list[dict], int]:
    """Convert exactly `paths` through Zircolite's pySigma sqlite backend.

    Returns (converted_ruleset, n_staged). n_staged is how many .yml files were
    handed to the converter; len(converted_ruleset) is how many compiled OK.
    The engine comes from `engine_home` (else $SIGMAFORGE_HOME); a `zircolite` package
    already imported from anywhere else is refused (EngineNotFoundError).
    """
    home = require_engine_home(engine_home)
    engine = (home / "Zircolite").resolve()
    _refuse_foreign_zircolite(engine)
    _ensure_engine_on_path(home)
    from zircolite import config as zconfig
    from zircolite.config import RulesetConfig
    from zircolite.rules import RulesetHandler

    if not Path(zconfig.__file__).resolve().is_relative_to(engine):
        raise EngineNotFoundError(f"zircolite was imported from {zconfig.__file__}, not from {engine}")

    logger = _engine_logger()

    with tempfile.TemporaryDirectory(prefix="sigmaforge_loaded_") as tmp:
        stage = Path(tmp)
        for p in paths:
            # flat-stage with a unique name so rglob('*.yml') in the converter
            # picks up exactly these and nothing else.
            shutil.copy2(p, stage / p.name)
        n_staged = len(list(stage.glob("*.yml")))

        cfg = RulesetConfig(
            ruleset=[str(stage)],
            pipeline=[[PIPELINE]],
            save_ruleset=False,
        )
        handler = RulesetHandler(ruleset_config=cfg, logger=logger)
        # .rulesets IS the converted Zircolite-format list (same shape as
        # rules_windows_sysmon.json). Deep-copy by re-serialising to be safe.
        ruleset = json.loads(json.dumps(handler.rulesets))
    return ruleset, n_staged
