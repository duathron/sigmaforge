#!/usr/bin/env bash
# Fetch the Zircolite detection engine (pinned to v3.7.6, commit + tree below) + install its runtime deps.
# The engine is a large third-party tool, so it is NOT bundled in this repo or the pip
# package — this script reproduces it on any machine. Run from the repo root:
#   bash scripts/setup_engine.sh
# After this + `uv sync --group backtest`, the run scripts in scripts/ are runnable.
#
# Supply chain: an existing Zircolite/ directory is NEVER trusted (its working tree, .git and
# config can all be planted). Every run clones the engine fresh into a new directory next to the
# target and verifies it BY CONTENT: the commit and tree sha against the pins, every tracked file
# against its blob id in the pinned tree (`git ls-tree` + `git hash-object --no-filters`, which
# never consult the index, attributes, filters or hooks), the working tree to contain exactly the
# tracked paths (plus .git/), and the sha256 of requirements.txt against the lock. Only then is
# the old directory moved aside and the new one moved into place, and the result is verified
# again. Nothing is ever deleted: the old engine goes into a private mktemp container
# (Zircolite.old.XXXXXX/Zircolite), a rejected engine into Zircolite.untrusted.XXXXXX/Zircolite.
# Dependencies are installed from scripts/zircolite-requirements.lock with `--require-hashes`.
# Leftovers (all git-ignored): Zircolite.setup.* after a failed clone/verification, Zircolite.old.*
# whenever a previous Zircolite/ existed, Zircolite.untrusted.* if the moved-in engine failed the
# final check.
# sigmaforge does not re-verify the engine at run time: this is a setup-time check only; whoever
# can write to the engine directory afterwards can run code as you.
set -euo pipefail

ZIRCOLITE_VERSION="v3.7.6"
ZIRCOLITE_COMMIT="b37b51eb00c49fc7bfd2f4968f1e5c3fc30da643"
ZIRCOLITE_TREE="e8be4ec9d77b6850730e08d610cfb2b0b2ced2cb"
ZIRCOLITE_REPO="https://github.com/wagga40/Zircolite.git"
DEST="Zircolite"
LOCK="$(cd "$(dirname "$0")" && pwd)/zircolite-requirements.lock"

# git with the ambient repository/config environment removed, no fsmonitor and no hooks.
safe_git() {
    env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE -u GIT_OBJECT_DIRECTORY \
        -u GIT_ALTERNATE_OBJECT_DIRECTORIES -u GIT_CONFIG -u GIT_CONFIG_GLOBAL \
        -u GIT_CONFIG_SYSTEM -u GIT_CONFIG_COUNT -u GIT_CONFIG_PARAMETERS \
        git -c core.fsmonitor=false -c core.hooksPath=/dev/null "$@"
}

# check_content DIR: every tracked file matches its blob id and mode in the pinned tree, and the
# directory holds exactly those paths (and their parent directories) plus .git. Reads only the
# object database and the files themselves: never the index, attributes, filters or hooks.
check_content() {
    python3 - "$1" <<'PY'
import os
import subprocess
import sys

d = sys.argv[1]
env = {
    k: v
    for k, v in os.environ.items()
    if k not in {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                 "GIT_ALTERNATE_OBJECT_DIRECTORIES"} and not k.startswith("GIT_CONFIG")
}


def git(*args, data=None):
    cmd = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", d, *args]
    return subprocess.run(cmd, env=env, capture_output=True, check=True, input=data).stdout


def fail(msg):
    print(msg)
    sys.exit(1)


if os.path.islink(os.path.join(d, ".git")) or not os.path.isdir(os.path.join(d, ".git")):
    fail(".git is not a real directory")
expected = set()
try:
    listing = git("ls-tree", "-r", "-z", "HEAD")
except subprocess.CalledProcessError:
    fail("git ls-tree failed")
for rec in listing.split(b"\0"):
    if not rec:
        continue
    meta, path = rec.split(b"\t", 1)
    mode, typ, sha = meta.split(b" ")
    rel = os.fsdecode(path)
    full = os.path.join(d, rel)
    if typ != b"blob" or mode not in (b"100644", b"100755", b"120000"):
        fail("unexpected tree entry " + repr(rel))
    try:
        if mode == b"120000":
            if not os.path.islink(full):
                fail("tracked symlink missing: " + repr(rel))
            got = git("hash-object", "--no-filters", "--stdin", data=os.fsencode(os.readlink(full)))
        else:
            if os.path.islink(full) or not os.path.isfile(full):
                fail("tracked file missing or replaced: " + repr(rel))
            if bool(os.stat(full).st_mode & 0o100) != (mode == b"100755"):
                fail("mode differs for " + repr(rel))
            got = git("hash-object", "--no-filters", "--", rel)
    except subprocess.CalledProcessError:
        fail("git hash-object failed for " + repr(rel))
    if got.strip() != sha:
        fail("content differs for " + repr(rel))
    parts = rel.split("/")
    for n in range(1, len(parts) + 1):
        expected.add("/".join(parts[:n]))
actual = set()
for root, dirs, files in os.walk(d, followlinks=False):
    rel_root = os.path.relpath(root, d)
    if rel_root == ".":
        dirs[:] = [x for x in dirs if x != ".git"]
        files = [x for x in files if x != ".git"]
    for name in dirs + files:
        actual.add(name if rel_root == "." else rel_root + "/" + name)
if actual != expected:
    extra = sorted(actual - expected)[:3]
    missing = sorted(expected - actual)[:3]
    fail("working tree differs from the pinned tree (extra: %r, missing: %r)" % (extra, missing))
PY
}

# verify_dir DIR: succeed only for a real directory (not a symbolic link) that is at the pinned
# commit AND tree, whose content matches the tree, and whose requirements.txt matches the lock.
# Sets VERIFY_ERR on failure.
verify_dir() {
    local d="$1" h t what want have
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
    if ! what="$(check_content "$d" 2>&1)"; then
        VERIFY_ERR="the content of $d is not the pinned tree: $what"
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

# refuse_if_present PATH: a destination must not exist (not even as a dangling link) before a move.
refuse_if_present() {
    if [ -e "$1" ] || [ -L "$1" ]; then
        echo "[setup] ERROR: '$1' already exists; refusing to move anything onto it." >&2
        exit 1
    fi
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

ASIDE_DIR=""
if [ -e "$DEST" ] || [ -L "$DEST" ]; then
    ASIDE_DIR="$(mktemp -d "$DEST.old.XXXXXX")"
    refuse_if_present "$ASIDE_DIR/$DEST"
    mv "$DEST" "$ASIDE_DIR/$DEST"
    echo "[setup] the previous $DEST was NOT trusted and was moved aside to '$ASIDE_DIR/$DEST' (delete it yourself if you do not need it)."
fi
refuse_if_present "$DEST"
mv "$NEW" "$DEST" || {
    echo "[setup] ERROR: could not move '$NEW' into place as '$DEST'; your previous engine, if any, is at '${ASIDE_DIR:+$ASIDE_DIR/$DEST}' (mv it back to '$DEST')." >&2
    exit 1
}

# Re-verify what is now at $DEST: the clone directory could have been swapped or tampered with between
# the checks and the move. A rejected directory is quarantined (renamed into a private container,
# never deleted) and the previous engine, if there was one, is put back.
if ! verify_dir "$DEST"; then
    UNTRUSTED_DIR="$(mktemp -d "$DEST.untrusted.XXXXXX")"
    refuse_if_present "$UNTRUSTED_DIR/$DEST"
    mv "$DEST" "$UNTRUSTED_DIR/$DEST" || {
        echo "[setup] ERROR: after the move, $VERIFY_ERR, and it could not be quarantined: '$DEST' is still the REJECTED engine; your previous engine, if any, is at '${ASIDE_DIR:+$ASIDE_DIR/$DEST}'. Do not use '$DEST'." >&2
        exit 1
    }
    echo "[setup] ERROR: after the move, $VERIFY_ERR. Nothing was installed." >&2
    echo "[setup] The rejected copy was quarantined at '$UNTRUSTED_DIR/$DEST' (inspect it, then remove it yourself)." >&2
    if [ -n "$ASIDE_DIR" ]; then
        if [ -e "$DEST" ] || [ -L "$DEST" ]; then
            echo "[setup] Could NOT restore your previous engine: '$DEST' exists again. It is still at '$ASIDE_DIR/$DEST'." >&2
        elif mv "$ASIDE_DIR/$DEST" "$DEST"; then
            echo "[setup] Your previous engine was restored to '$DEST' (it had been moved aside to '$ASIDE_DIR/$DEST')." >&2
        else
            echo "[setup] Could NOT restore your previous engine: it is still at '$ASIDE_DIR/$DEST' (mv it back to '$DEST')." >&2
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
