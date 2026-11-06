#!/usr/bin/env bash
# Fetch the Zircolite detection engine (pinned to v3.7.6, commit below) + install its runtime deps.
# The engine is a large third-party tool, so it is NOT bundled in this repo or the pip
# package — this script reproduces it on any machine. Run from the repo root:
#   bash scripts/setup_engine.sh
# After this + `uv sync --group backtest`, the run scripts in scripts/ are runnable.
#
# Supply chain: the checkout must be EXACTLY the pinned commit (a moved tag or a stale checkout
# fails), and the dependencies are installed from scripts/zircolite-requirements.lock with
# `--require-hashes`. The lock records the sha256 of the engine's requirements.txt; if that file
# differs, regenerate the lock (command in the lock header) instead of installing unhashed deps.
set -euo pipefail

ZIRCOLITE_VERSION="v3.7.6"
ZIRCOLITE_COMMIT="b37b51eb00c49fc7bfd2f4968f1e5c3fc30da643"
ZIRCOLITE_REPO="https://github.com/wagga40/Zircolite.git"
DEST="Zircolite"
LOCK="$(cd "$(dirname "$0")" && pwd)/zircolite-requirements.lock"

verify_head() {
    local head
    head="$(git -C "$DEST" rev-parse HEAD)"
    if [ "$head" != "$ZIRCOLITE_COMMIT" ]; then
        echo "[setup] ERROR: $DEST is at $head, expected the pinned $ZIRCOLITE_COMMIT ($ZIRCOLITE_VERSION)." >&2
        echo "[setup] Delete $DEST and re-run this script to fetch the pinned engine." >&2
        exit 1
    fi
}

if [ -d "$DEST/.git" ]; then
    echo "[setup] $DEST already present — verifying it against the pin."
    verify_head
elif [ -e "$DEST" ]; then
    echo "[setup] ERROR: $DEST exists but is not a git checkout, so it cannot be verified against the pin." >&2
    echo "[setup] Delete $DEST and re-run this script." >&2
    exit 1
else
    echo "[setup] cloning Zircolite $ZIRCOLITE_VERSION ..."
    git clone --depth 1 --branch "$ZIRCOLITE_VERSION" "$ZIRCOLITE_REPO" "$DEST"
    verify_head
fi

want="$(sed -n 's/^# requirements-sha256: \([0-9a-f]\{64\}\)$/\1/p' "$LOCK" | head -n 1)"
have="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$DEST/requirements.txt")"
if [ -z "$want" ] || [ "$want" != "$have" ]; then
    echo "[setup] ERROR: $DEST/requirements.txt (sha256 $have) does not match the lock ($want)." >&2
    echo "[setup] Regenerate scripts/zircolite-requirements.lock (command in its header); nothing was installed." >&2
    exit 1
fi

echo "[setup] installing Zircolite runtime requirements (hash-checked) into the uv env ..."
uv pip install --require-hashes -r "$LOCK"

echo "[setup] done. Engine at $(pwd)/$DEST. Point sigmaforge at it: export SIGMAFORGE_HOME=\"$(pwd)\" (or pass --engine-home)."
echo "[setup] do not run 'uv sync' again afterwards: it uninstalls the engine deps; re-run this script if you do."
echo "[setup] smoke test: uv run python -c 'import orjson, lxml, evtx; print(\"engine deps OK\")'"
