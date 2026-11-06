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
# Leftovers: Zircolite.setup.* after a failed clone/verification, Zircolite.old.* whenever a previous Zircolite/ existed, and
# Zircolite.untrusted.* if the moved-in engine failed the final check (all git-ignored).
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

# verify_dir DIR: succeed only for a real directory (not a symbolic link) that is at the pinned
# commit AND tree and whose requirements.txt matches the lock. Sets VERIFY_ERR on failure.
verify_dir() {
    local d="$1" h t st want have
    VERIFY_ERR=""
    if [ -L "$d" ]; then
        VERIFY_ERR="$d is a symbolic link, not the verified clone"
        return 1
    fi
    h="$(safe_git -C "$d" rev-parse HEAD)"
    t="$(safe_git -C "$d" rev-parse 'HEAD^{tree}')"
    if [ "$h" != "$ZIRCOLITE_COMMIT" ] || [ "$t" != "$ZIRCOLITE_TREE" ]; then
        VERIFY_ERR="$d is at commit $h / tree $t, expected $ZIRCOLITE_COMMIT / $ZIRCOLITE_TREE"
        return 1
    fi
    # A genuine clone with extra or modified files passes the commit/tree checks, so the working tree
    # must be clean too: modified, untracked and ignored files all count (a fresh clone has none).
    if ! st="$(safe_git -C "$d" status --porcelain --untracked-files=all --ignored)" || [ -n "$st" ]; then
        VERIFY_ERR="the working tree of $d is not clean (modified, untracked or ignored files, or git status failed)"
        return 1
    fi
    want="$(sed -n 's/^# requirements-sha256: \([0-9a-f]\{64\}\)$/\1/p' "$LOCK" | head -n 1)"
    have="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$d/requirements.txt")"
    if [ -z "$want" ] || [ "$want" != "$have" ]; then
        VERIFY_ERR="$d/requirements.txt (sha256 $have) does not match the lock ($want); regenerate scripts/zircolite-requirements.lock (command in its header)"
        return 1
    fi
    return 0
}

refuse_if_link() {
    if [ -L "$NEW" ]; then
        echo "[setup] ERROR: $NEW was replaced by a symbolic link after it was verified; nothing was moved or installed." >&2
        exit 1
    fi
}

NEW="$(mktemp -d "${DEST}.setup.XXXXXX")"
echo "[setup] cloning Zircolite $ZIRCOLITE_VERSION into $NEW ..."
safe_git clone --depth 1 --branch "$ZIRCOLITE_VERSION" "$ZIRCOLITE_REPO" "$NEW"

if ! verify_dir "$NEW"; then
    echo "[setup] ERROR: $VERIFY_ERR." >&2
    echo "[setup] Nothing was installed; the untrusted clone was left at $NEW for inspection." >&2
    exit 1
fi

refuse_if_link
chmod 755 "$NEW"  # mktemp creates 0700; the verified engine directory should be readable like a normal checkout
refuse_if_link

if [ -e "$DEST" ] || [ -L "$DEST" ]; then
    ASIDE="$DEST.old.$(date +%Y%m%d%H%M%S).$$"
    mv "$DEST" "$ASIDE"
    echo "[setup] the previous $DEST was NOT trusted and was moved aside to $ASIDE (delete it yourself if you do not need it)."
fi
mv "$NEW" "$DEST" || {
    echo "[setup] ERROR: could not move '$NEW' into place as '$DEST'; your previous engine, if any, is at '${ASIDE:-}' (mv it back to '$DEST')." >&2
    exit 1
}

# Re-verify what is now at $DEST: the clone directory could have been swapped or tampered with between
# the checks and the move. A rejected directory is quarantined (renamed, never deleted) and the
# previous engine, if there was one, is put back.
if ! verify_dir "$DEST"; then
    UNTRUSTED="$DEST.untrusted.$(date +%Y%m%d%H%M%S).$$"
    mv "$DEST" "$UNTRUSTED"
    echo "[setup] ERROR: after the move, $VERIFY_ERR. Nothing was installed." >&2
    echo "[setup] The rejected copy was renamed to '$UNTRUSTED' (inspect it, then remove it yourself)." >&2
    if [ -n "${ASIDE:-}" ]; then
        if mv "$ASIDE" "$DEST"; then
            echo "[setup] Your previous engine was restored to '$DEST' (it had been moved aside to '$ASIDE')." >&2
        else
            echo "[setup] Could NOT restore your previous engine: it is still at '$ASIDE' (mv it back to '$DEST')." >&2
        fi
    else
        echo "[setup] There was no previous engine, so '$DEST' does not exist now." >&2
    fi
    exit 1
fi

echo "[setup] installing Zircolite runtime requirements (hash-checked) into the uv env ..."
uv pip install --require-hashes -r "$LOCK"

echo "[setup] done. Engine at $(pwd)/$DEST. Point sigmaforge at it: export SIGMAFORGE_HOME=\"$(pwd)\" (or pass --engine-home)."
echo "[setup] do not run 'uv sync' again afterwards: it uninstalls the engine deps; re-run this script if you do."
echo "[setup] smoke test: uv run python -c 'import orjson, lxml, evtx; print(\"engine deps OK\")'"
