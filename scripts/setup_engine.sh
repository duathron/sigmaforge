#!/usr/bin/env bash
# Fetch the Zircolite detection engine (pinned to v3.7.6, commit + tree below) + install its runtime deps.
# The engine is a large third-party tool, so it is NOT bundled in this repo or the pip
# package — this script reproduces it on any machine. Run from the repo root:
#   bash scripts/setup_engine.sh
# After this + `uv sync --group backtest`, the run scripts in scripts/ are runnable.
#
# Supply chain: an existing Zircolite/ directory is NEVER trusted (its working tree, .git and
# config can all be planted). Every run clones the engine fresh into a new directory next to the
# target, checks the commit AND the tree sha against the pins and the sha256 of its
# requirements.txt against the lock, and only then renames the old directory aside
# (Zircolite.old.<timestamp>, never deleted) and the new one into place. Dependencies are
# installed from scripts/zircolite-requirements.lock with `--require-hashes`.
# sigmaforge does not re-verify the engine at run time: this is a setup-time check only; whoever
# can write to the engine directory afterwards can run code as you.
set -euo pipefail

ZIRCOLITE_VERSION="v3.7.6"
ZIRCOLITE_COMMIT="b37b51eb00c49fc7bfd2f4968f1e5c3fc30da643"
ZIRCOLITE_TREE="e8be4ec9d77b6850730e08d610cfb2b0b2ced2cb"
ZIRCOLITE_REPO="https://github.com/wagga40/Zircolite.git"
DEST="Zircolite"
LOCK="$(cd "$(dirname "$0")" && pwd)/zircolite-requirements.lock"

# git with the ambient repository/config environment removed and no fsmonitor hook.
safe_git() {
    env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE -u GIT_OBJECT_DIRECTORY \
        -u GIT_ALTERNATE_OBJECT_DIRECTORIES -u GIT_CONFIG -u GIT_CONFIG_GLOBAL \
        -u GIT_CONFIG_SYSTEM -u GIT_CONFIG_COUNT -u GIT_CONFIG_PARAMETERS \
        git -c core.fsmonitor=false "$@"
}

NEW="$(mktemp -d "${DEST}.setup.XXXXXX")"
echo "[setup] cloning Zircolite $ZIRCOLITE_VERSION into $NEW ..."
safe_git clone --depth 1 --branch "$ZIRCOLITE_VERSION" "$ZIRCOLITE_REPO" "$NEW"

head="$(safe_git -C "$NEW" rev-parse HEAD)"
tree="$(safe_git -C "$NEW" rev-parse 'HEAD^{tree}')"
if [ "$head" != "$ZIRCOLITE_COMMIT" ] || [ "$tree" != "$ZIRCOLITE_TREE" ]; then
    echo "[setup] ERROR: the clone is at commit $head / tree $tree, expected $ZIRCOLITE_COMMIT / $ZIRCOLITE_TREE." >&2
    echo "[setup] Nothing was installed; the untrusted clone was left at $NEW for inspection." >&2
    exit 1
fi

want="$(sed -n 's/^# requirements-sha256: \([0-9a-f]\{64\}\)$/\1/p' "$LOCK" | head -n 1)"
have="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$NEW/requirements.txt")"
if [ -z "$want" ] || [ "$want" != "$have" ]; then
    echo "[setup] ERROR: $NEW/requirements.txt (sha256 $have) does not match the lock ($want)." >&2
    echo "[setup] Regenerate scripts/zircolite-requirements.lock (command in its header); nothing was installed." >&2
    exit 1
fi

if [ -e "$DEST" ]; then
    ASIDE="$DEST.old.$(date +%Y%m%d%H%M%S).$$"
    mv "$DEST" "$ASIDE"
    echo "[setup] the previous $DEST was NOT trusted and was moved aside to $ASIDE (delete it yourself if you do not need it)."
fi
mv "$NEW" "$DEST"

echo "[setup] installing Zircolite runtime requirements (hash-checked) into the uv env ..."
uv pip install --require-hashes -r "$LOCK"

echo "[setup] done. Engine at $(pwd)/$DEST. Point sigmaforge at it: export SIGMAFORGE_HOME=\"$(pwd)\" (or pass --engine-home)."
echo "[setup] do not run 'uv sync' again afterwards: it uninstalls the engine deps; re-run this script if you do."
echo "[setup] smoke test: uv run python -c 'import orjson, lxml, evtx; print(\"engine deps OK\")'"
