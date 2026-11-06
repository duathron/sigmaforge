#!/usr/bin/env python3
"""Print the pinned file manifest of a GENUINE Zircolite checkout (run it on a fresh clone of the pin).

    python3 scripts/make_zircolite_manifest.py Zircolite > scripts/zircolite-manifest.sha256

One line per tracked file: `<mode> <sha256 of the content> <path>`, sorted by path. The header carries
`# manifest-sha256:` (sha256 of the body); copy that value into ZIRCOLITE_MANIFEST_SHA256 in
scripts/setup_engine.sh. Refuses a checkout that is not exactly the pinned commit and tree, is dirty,
or has anything but regular files (no symlinks) with a space in no path.
"""

import hashlib
import os
import subprocess
import sys

COMMIT = "b37b51eb00c49fc7bfd2f4968f1e5c3fc30da643"
TREE = "e8be4ec9d77b6850730e08d610cfb2b0b2ced2cb"


def git(engine, *args):
    return subprocess.run(["git", "-C", engine, *args], capture_output=True, check=True).stdout


def main(engine: str) -> int:
    head = git(engine, "rev-parse", "HEAD").decode().strip()
    tree = git(engine, "rev-parse", "HEAD^{tree}").decode().strip()
    if (head, tree) != (COMMIT, TREE):
        print(f"not the pinned engine: {head} / {tree}", file=sys.stderr)
        return 1
    if git(engine, "status", "--porcelain", "--untracked-files=all", "--ignored").strip():
        print("the checkout is not clean", file=sys.stderr)
        return 1
    rows = []
    for rec in git(engine, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
        if not rec:
            continue
        meta, path = rec.split(b"\t", 1)
        mode, typ, _sha = meta.split(b" ")
        rel = os.fsdecode(path)
        if typ != b"blob" or mode not in (b"100644", b"100755") or " " in rel or "\n" in rel:
            print(f"unsupported entry {rel!r} ({mode!r})", file=sys.stderr)
            return 1
        with open(os.path.join(engine, rel), "rb") as fh:
            rows.append((rel, mode.decode(), hashlib.sha256(fh.read()).hexdigest()))
    rows.sort()
    body = "".join(f"{mode} {digest} {rel}\n" for rel, mode, digest in rows)
    print(
        f"# Pinned file manifest of the Zircolite engine v3.7.6 (commit {COMMIT}, tree {TREE}).\n"
        f"# Format: <mode> <sha256 of the file content> <path>, sorted by path. {len(rows)} tracked files.\n"
        f"# manifest-sha256: {hashlib.sha256(body.encode()).hexdigest()}\n"
        "# setup_engine.sh pins this manifest-sha256 as ZIRCOLITE_MANIFEST_SHA256 and checks the working tree\n"
        "# against THIS file only. Regenerate from a genuine clone of the pinned tag, then update the constant:\n"
        "#   python3 scripts/make_zircolite_manifest.py Zircolite > scripts/zircolite-manifest.sha256\n" + body,
        end="",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]) if len(sys.argv) == 2 else 2)
