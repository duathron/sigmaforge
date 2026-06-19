"""Importable compile path: native Sigma YAML -> Zircolite ruleset, ONE source.

`compile_ruleset` converts a set of `.yml` rule files through Zircolite's OWN
pySigma sqlite backend — the identical converter that produced the bundled
`rules_windows_sysmon.json` snapshot. Lifting it out of
`scripts/compile_loaded_ruleset.py` into the package means both the loaded-ruleset
script (backtest) and the `hunt` command compile rules through ONE source, so the
engine always fires the same rule bodies that get scored.

Engine dependency: the conversion needs the vendored Zircolite (`Zircolite/` under
SIGMAFORGE_HOME or the cwd) and its pySigma requirements. Importing THIS module is
cheap and engine-free; the heavy `zircolite.*` imports happen inside the function
so callers (and tests) can import `compile_ruleset` even when the engine is absent.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

#: Zircolite pySigma pipeline name (matches the bundled snapshot's conversion).
PIPELINE = "sysmon"


def _ensure_engine_on_path() -> None:
    """Put the vendored Zircolite dir on sys.path so `import zircolite.*` resolves.

    Mirrors the engine-home convention of `ingest.zircolite_runner` (SIGMAFORGE_HOME
    or the cwd contains the `Zircolite/` checkout) — no hardcoded absolute path.
    """
    home = Path(os.environ.get("SIGMAFORGE_HOME", os.getcwd()))
    engine = home / "Zircolite"
    if str(engine) not in sys.path:
        sys.path.insert(0, str(engine))


def compile_ruleset(paths: list[Path]) -> tuple[list[dict], int]:
    """Convert exactly `paths` through Zircolite's pySigma sqlite backend.

    Returns (converted_ruleset, n_staged). n_staged is how many .yml files were
    handed to the converter; len(converted_ruleset) is how many compiled OK.
    """
    _ensure_engine_on_path()
    from zircolite.config import RulesetConfig
    from zircolite.rules import RulesetHandler

    logger = logging.getLogger("compile_loaded_ruleset")
    logging.basicConfig(level=logging.INFO, format="%(message)s")

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
