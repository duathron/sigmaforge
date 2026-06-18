#!/usr/bin/env bash
# Fetch the Zircolite detection engine (pinned 3.7.6) + install its runtime deps.
# The engine is a large third-party tool, so it is NOT bundled in this repo or the pip
# package — this script reproduces it on any machine. Run from the repo root:
#   bash scripts/setup_engine.sh
# After this + `uv sync --group backtest`, the run scripts in scripts/ are runnable.
set -euo pipefail

ZIRCOLITE_VERSION="v3.7.6"
ZIRCOLITE_REPO="https://github.com/wagga40/Zircolite.git"
DEST="Zircolite"

if [ -d "$DEST/.git" ] || [ -f "$DEST/zircolite.py" ]; then
    echo "[setup] $DEST already present — skipping clone (delete it to re-fetch)."
else
    echo "[setup] cloning Zircolite $ZIRCOLITE_VERSION ..."
    git clone --depth 1 --branch "$ZIRCOLITE_VERSION" "$ZIRCOLITE_REPO" "$DEST"
fi

echo "[setup] installing Zircolite runtime requirements into the uv env ..."
uv pip install -r "$DEST/requirements.txt"

echo "[setup] done. Engine at ./$DEST (run scripts from the repo root, or set SIGMAFORGE_HOME)."
echo "[setup] smoke test: uv run python -c 'import orjson, lxml, evtx; print(\"engine deps OK\")'"
