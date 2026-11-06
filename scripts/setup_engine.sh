#!/usr/bin/env bash
# Fetch the Zircolite detection engine (pinned to v3.7.6, commit + tree below) + install its runtime deps.
# The engine is a large third-party tool, so it is NOT bundled in this repo or the pip
# package — this script reproduces it on any machine. Run from the repo root:
#   bash scripts/setup_engine.sh
# After this + `uv sync --group backtest`, the run scripts in scripts/ are runnable.
#
# Supply chain: an existing Zircolite/ directory is NEVER trusted (its working tree, .git and
# config can all be planted). Every run clones the engine fresh into a new directory next to the
# target and verifies it against a PINNED FILE MANIFEST committed next to the lock
# (scripts/zircolite-manifest.sha256: mode + sha256 of every tracked file of the pinned tag; the
# manifest's own sha256 is pinned in this script). The working tree must contain exactly those
# paths (plus .git/), with the listed content and exec bit, no symlinks anywhere, and no hardlinked
# files; the clone's git object database is NOT trusted for this. The commit/tree sha are checked
# as an extra sanity check, and requirements.txt against the lock. Only then is the old directory
# moved aside and the new one moved into place, and the result is verified again. Nothing is ever
# deleted: the old engine goes into a private mktemp container (Zircolite.old.XXXXXX/Zircolite), a
# rejected engine into Zircolite.untrusted.XXXXXX/Zircolite.
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
ZIRCOLITE_MANIFEST_SHA256="e6d7e30bdfd42c2c93cdcc2458a3cab592b83201544e66d71817ad79928975f6"
DEST="Zircolite"
LOCK="$(cd "$(dirname "$0")" && pwd)/zircolite-requirements.lock"
MANIFEST="$(cd "$(dirname "$0")" && pwd)/zircolite-manifest.sha256"

# git with the ambient repository/config environment removed, no fsmonitor, no hooks, no replace refs.
safe_git() {
    env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE -u GIT_OBJECT_DIRECTORY \
        -u GIT_ALTERNATE_OBJECT_DIRECTORIES -u GIT_CONFIG -u GIT_CONFIG_GLOBAL \
        -u GIT_CONFIG_SYSTEM -u GIT_CONFIG_COUNT -u GIT_CONFIG_PARAMETERS \
        GIT_NO_REPLACE_OBJECTS=1 git -c core.fsmonitor=false -c core.hooksPath=/dev/null "$@"
}

# check_content DIR: the working tree matches the pinned manifest exactly. Reads only the files
# themselves and the manifest: never git (object database, index, attributes, filters, hooks).
check_content() {
    python3 - "$1" "$MANIFEST" <<'PY'
import hashlib
import os
import stat
import sys

d, manifest = sys.argv[1], sys.argv[2]


def fail(msg):
    print(msg)
    sys.exit(1)


expected = {}
dirs = set()
with open(manifest, encoding="utf-8") as fh:
    for line in fh:
        if line.startswith("#") or not line.strip():
            continue
        mode, digest, rel = line.rstrip("\n").split(" ", 2)
        expected[rel] = (mode, digest)
        parts = rel.split("/")
        for n in range(1, len(parts)):
            dirs.add("/".join(parts[:n]))
if not expected:
    fail("the manifest is empty")
git_dir = os.path.join(d, ".git")
if os.path.islink(git_dir) or not os.path.isdir(git_dir):
    fail(".git is not a real directory")
for rel, (mode, digest) in expected.items():
    full = os.path.join(d, rel)
    try:
        st = os.lstat(full)
    except OSError:
        fail("missing file " + repr(rel))
    if not stat.S_ISREG(st.st_mode):
        fail("not a regular file (symlink or other): " + repr(rel))
    if st.st_nlink != 1:
        fail("hardlinked file: " + repr(rel))
    if bool(st.st_mode & 0o100) != (mode == "100755"):
        fail("mode differs for " + repr(rel))
    with open(full, "rb") as fh:
        if hashlib.sha256(fh.read()).hexdigest() != digest:
            fail("content differs for " + repr(rel))
actual = set()
for root, dnames, fnames in os.walk(d, followlinks=False):
    rel_root = os.path.relpath(root, d)
    if rel_root == ".":
        dnames[:] = [x for x in dnames if x != ".git"]
        fnames = [x for x in fnames if x != ".git"]
    for name in dnames + fnames:
        rel = name if rel_root == "." else rel_root + "/" + name
        actual.add(rel)
        if os.path.islink(os.path.join(root, name)):
            fail("symbolic link in the tree: " + repr(rel))
want = set(expected) | dirs
if actual != want:
    fail("working tree differs from the manifest (extra: %r, missing: %r)" % (sorted(actual - want)[:3], sorted(want - actual)[:3]))
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
    # Extra sanity check (the clone's object database is not trusted for the content above).
    h="$(safe_git -C "$d" rev-parse HEAD)"
    t="$(safe_git -C "$d" rev-parse 'HEAD^{tree}')"
    if [ "$h" != "$ZIRCOLITE_COMMIT" ] || [ "$t" != "$ZIRCOLITE_TREE" ]; then
        VERIFY_ERR="$d is at commit $h / tree $t, expected $ZIRCOLITE_COMMIT / $ZIRCOLITE_TREE"
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

manifest_have="$(python3 -c 'import hashlib,sys;print(hashlib.sha256("".join(l for l in open(sys.argv[1], encoding="utf-8") if not l.startswith("#")).encode()).hexdigest())' "$MANIFEST")"
if [ "$manifest_have" != "$ZIRCOLITE_MANIFEST_SHA256" ]; then
    echo "[setup] ERROR: $MANIFEST (body sha256 $manifest_have) does not match the pinned $ZIRCOLITE_MANIFEST_SHA256; nothing was cloned or installed." >&2
    exit 1
fi

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
