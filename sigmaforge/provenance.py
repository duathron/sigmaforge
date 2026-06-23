"""Run provenance for cross-system comparability.

A run's numbers depend on more than the rules + corpora: the engine source, its
Python dependency closure, the interpreter, the OS, and sqlite all affect which
events fire. We do NOT try to force identical output across machines (that needs a
container) — instead we RECORD every axis in the manifest so that, when two machines
disagree, `run_hash` flags it and the provenance block says WHICH axis differs. Same
provenance + same corpus SHAs => same run_hash. None of this feeds `run_hash`; it is
pure metadata.
"""

from __future__ import annotations

import importlib.metadata
import platform
import sqlite3
import subprocess
from pathlib import Path

from sigmaforge.ingest.zircolite_runner import _zircolite_home

# Engine deps whose version changes how a rule compiles or fires (pySigma backend +
# the JSON/XML parsers Zircolite uses). Diffing these across machines localizes a
# divergence that the engine commit SHA alone would not explain.
_ENGINE_DEPS = (
    "pysigma",
    "pysigma-pipeline-sysmon",
    "pysigma-pipeline-windows",
    "pysigma-backend-sqlite",
    "orjson",
    "lxml",
    "xxhash",
)


def _git(repo: Path, *args: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return out.stdout.strip() or None
    except Exception:
        return None


def engine_provenance(engine_home: str | None = None) -> dict:
    """The vendored Zircolite engine's exact source: commit SHA + tag if it is a git
    checkout (as `scripts/setup_engine.sh` produces), else flagged unavailable. The
    version STRING a human typed is not enough — two builds of "3.7.6" can differ."""
    home = Path(engine_home) if engine_home else Path(_zircolite_home())
    zdir = home / "Zircolite"
    sha = _git(zdir, "rev-parse", "HEAD")
    return {
        "zircolite_commit_sha": sha or "unavailable (engine not a git checkout)",
        "zircolite_tag": _git(zdir, "describe", "--tags", "--always") or "unavailable",
    }


def _dep_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "absent"


def environment_block() -> dict:
    """The interpreter / OS / sqlite / engine-dep closure that can shift fires across
    systems. Recorded so a `run_hash` mismatch is attributable, not mysterious."""
    return {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "sqlite_version": sqlite3.sqlite_version,
        "engine_deps": {name: _dep_version(name) for name in _ENGINE_DEPS},
    }


def provenance(engine_home: str | None = None) -> dict:
    """Full provenance block for the manifest: engine source + environment closure."""
    return {**engine_provenance(engine_home), "environment": environment_block()}
