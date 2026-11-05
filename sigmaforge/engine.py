"""Where the Zircolite engine lives: ONE resolution rule for every exec/import site.

The engine is third-party code that sigmaforge executes and imports, so it must come
from a location the user NAMED: an explicit path (``--engine-home`` / ``backtest.engine_home``
in a config file) or ``$SIGMAFORGE_HOME``. It is never taken from the current directory:
a ``Zircolite/zircolite.py`` that merely happens to sit under the CWD (a cloned repo, an
unpacked archive) would otherwise run with the user's privileges (CWE-427).
"""

from __future__ import annotations

import os
from pathlib import Path


class EngineNotFoundError(RuntimeError):
    """No usable Zircolite engine at the explicit path / $SIGMAFORGE_HOME."""


def engine_script(home: Path) -> Path:
    """The engine entry point under an engine root."""
    return home / "Zircolite" / "zircolite.py"


def resolve_engine_home(explicit: str | Path | None = None) -> Path | None:
    """Absolute engine root containing ``Zircolite/zircolite.py``, or None.

    Precedence: ``explicit`` (CLI flag, else config value) > ``$SIGMAFORGE_HOME`` > None.
    An explicit wrong path is NOT retried elsewhere (it must fail, not fall back)."""
    if explicit:
        root = Path(explicit)
    else:
        env = os.environ.get("SIGMAFORGE_HOME")
        if not env:
            return None
        root = Path(env)
    root = root.expanduser().resolve()
    return root if engine_script(root).is_file() else None


def require_engine_home(explicit: str | Path | None = None) -> Path:
    """Like :func:`resolve_engine_home` but raises a teaching error instead of None."""
    home = resolve_engine_home(explicit)
    if home is None:
        raise EngineNotFoundError(
            "Detection engine not found: sigmaforge needs the vendored Zircolite engine "
            "(Zircolite/zircolite.py), which is not bundled in the pip package. Fetch it with "
            "`bash scripts/setup_engine.sh`, then pass --engine-home or set SIGMAFORGE_HOME to "
            "the directory that CONTAINS Zircolite/. The current directory is never searched."
        )
    return home
