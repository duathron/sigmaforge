"""setup_engine.sh: pinned commit, verified checkout, hashed install. Behavioural, shims on PATH, no network."""

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "setup_engine.sh"
LOCK = ROOT / "scripts" / "zircolite-requirements.lock"
GOOD_SHA = "b37b51eb00c49fc7bfd2f4968f1e5c3fc30da643"
GOOD_TREE = "e8be4ec9d77b6850730e08d610cfb2b0b2ced2cb"
REQ = b"orjson>=3.9.15\n"

GIT_SHIM = """#!/bin/bash
echo "git[GIT_DIR=${GIT_DIR-unset} WT=${GIT_WORK_TREE-unset}] $*" >> "$SHIM_LOG"
case "$*" in
  *'HEAD^{tree}'*) echo "$SHIM_TREE"; exit 0 ;;
  *rev-parse*) echo "$SHIM_HEAD"; exit 0 ;;
  *clone*)
    dest="${@: -1}"
    mkdir -p "$dest/.git"
    printf 'orjson>=3.9.15\\n' > "$dest/requirements.txt"
    : > "$dest/zircolite.py"
    exit 0 ;;
esac
exit 0
"""
UV_SHIM = '#!/bin/bash\necho "uv $*" >> "$SHIM_LOG"\nexit 0\n'


def _setup(tmp_path, lock_sha=None):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in (("git", GIT_SHIM), ("uv", UV_SHIM)):
        f = bindir / name
        f.write_text(body)
        f.chmod(0o755)
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    shutil.copy(SCRIPT, scripts / "setup_engine.sh")
    sha = lock_sha or hashlib.sha256(REQ).hexdigest()
    (scripts / "zircolite-requirements.lock").write_text(
        f"# requirements-sha256: {sha}\norjson==3.10.0 \\\n    --hash=sha256:{'0' * 64}\n"
    )
    work = tmp_path / "work"
    work.mkdir()
    return bindir, scripts, work


def _run(
    tmp_path,
    head=GOOD_SHA,
    tree=GOOD_TREE,
    lock_sha=None,
    uv_exit=0,
    extra_env=None,
    existing=None,
    pre=None,
    bin_hook=None,
):
    """Run the script in tmp/work. `existing(dir)` populates a pre-existing Zircolite/."""
    bindir, scripts, work = _setup(tmp_path, lock_sha)
    if uv_exit:
        (bindir / "uv").write_text(f'#!/bin/bash\necho "uv $*" >> "$SHIM_LOG"\nexit {uv_exit}\n')
    if bin_hook:
        bin_hook(bindir)
    if pre:
        pre(work)
    if existing:
        (work / "Zircolite").mkdir()
        existing(work / "Zircolite")
    log = tmp_path / "log"
    log.write_text("")
    env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "SHIM_LOG": str(log),
        "SHIM_HEAD": head,
        "SHIM_TREE": tree,
        **(extra_env or {}),
    }
    res = subprocess.run(["bash", str(scripts / "setup_engine.sh")], cwd=work, env=env, capture_output=True, text=True)
    return res, log.read_text(), work


def _uv_installs(log):
    return [ln for ln in log.splitlines() if ln.startswith("uv ") and "install" in ln]


def test_setup_engine_installs_with_hashes_only(tmp_path):
    res, log, work = _run(tmp_path)
    assert res.returncode == 0, res.stderr + res.stdout
    installs = _uv_installs(log)
    assert len(installs) == 1 and "--require-hashes" in installs[0] and "zircolite-requirements.lock" in installs[0]
    assert "requirements.txt" not in installs[0].replace("zircolite-requirements.lock", "")
    assert (work / "Zircolite" / "zircolite.py").exists()


def test_setup_engine_refuses_wrong_head_after_clone(tmp_path):
    res, log, work = _run(tmp_path, head="0" * 40)
    assert res.returncode != 0 and not _uv_installs(log)
    assert not (work / "Zircolite").exists()


def test_setup_engine_refuses_wrong_tree_even_when_head_matches(tmp_path):
    res, log, work = _run(tmp_path, tree="1" * 40)
    assert res.returncode != 0 and not _uv_installs(log)
    assert not (work / "Zircolite").exists()


def test_setup_engine_refuses_when_requirements_hash_differs_from_the_lock(tmp_path):
    res, log, work = _run(tmp_path, lock_sha="f" * 64)
    assert res.returncode != 0 and not _uv_installs(log)
    assert not (work / "Zircolite").exists()


def _dirty(d):
    (d / ".git").mkdir()
    (d / "zircolite.py").write_text("print('modified tracked file')\n")
    (d / "evil.py").write_text("print('untracked')\n")
    (d / "requirements.txt").write_bytes(REQ)


def test_setup_engine_never_trusts_an_existing_checkout_and_moves_it_aside(tmp_path):
    res, log, work = _run(tmp_path, existing=_dirty)
    assert res.returncode == 0, res.stderr
    assert not (work / "Zircolite" / "evil.py").exists()
    assert (work / "Zircolite" / "zircolite.py").read_text() == ""
    aside = [p for p in work.iterdir() if p.name.startswith("Zircolite.old.")]
    assert len(aside) == 1 and (aside[0] / "evil.py").exists()  # renamed, never deleted
    assert aside[0].name in res.stdout
    assert not any(re.search(r"-C Zircolite( |$)", ln) or "Zircolite.old" in ln for ln in log.splitlines())


def test_setup_engine_replaces_a_forged_git_dir_with_empty_objects(tmp_path):
    def forged(d):
        (d / ".git" / "objects").mkdir(parents=True)
        (d / ".git" / "HEAD").write_text(GOOD_SHA + "\n")
        (d / "requirements.txt").write_bytes(REQ)
        (d / "zircolite.py").write_text("import os\n")

    res, log, work = _run(tmp_path, existing=forged)
    assert res.returncode == 0, res.stderr
    assert (work / "Zircolite" / "zircolite.py").read_text() == ""
    assert any((work / n).is_dir() for n in os.listdir(work) if n.startswith("Zircolite.old."))


def test_setup_engine_replaces_an_existing_non_git_directory(tmp_path):
    res, log, work = _run(tmp_path, existing=lambda d: (d / "zircolite.py").write_text("old"))
    assert res.returncode == 0, res.stderr
    assert (work / "Zircolite" / "zircolite.py").read_text() == ""


def test_setup_engine_never_runs_git_inside_the_hostile_old_checkout(tmp_path):
    marker = tmp_path / "MARKER"

    def hostile(d):
        (d / ".git").mkdir()
        (d / ".git" / "config").write_text(f"[core]\n\tfsmonitor = touch {marker}\n")
        (d / "requirements.txt").write_bytes(REQ)

    res, log, work = _run(tmp_path, existing=hostile)
    assert res.returncode == 0, res.stderr
    assert not marker.exists()
    assert not any("old" in ln and "-C" in ln for ln in log.splitlines())


def test_setup_engine_git_calls_ignore_ambient_git_environment(tmp_path):
    env = {"GIT_DIR": "/nonexistent/evil", "GIT_WORK_TREE": "/nonexistent/wt", "GIT_CONFIG_COUNT": "1"}
    res, log, work = _run(tmp_path, extra_env=env)
    assert res.returncode == 0, res.stderr
    git_lines = [ln for ln in log.splitlines() if ln.startswith("git[")]
    assert git_lines and all("GIT_DIR=unset" in ln and "WT=unset" in ln for ln in git_lines), git_lines
    assert all("core.fsmonitor=false" in ln for ln in git_lines)


def test_setup_engine_exits_nonzero_and_does_not_claim_done_when_uv_fails(tmp_path):
    res, log, work = _run(tmp_path, uv_exit=1)
    assert res.returncode != 0
    assert "done" not in res.stdout


def test_setup_script_never_deletes_anything():
    text = SCRIPT.read_text()
    assert not re.search(r"(^|[\s;&|(])(rm|rmdir|unlink|shred)\b", text, re.M)
    assert "does not re-verify" in text


def test_setup_engine_pin_is_a_full_sha():
    text = SCRIPT.read_text()
    assert re.search(r'^ZIRCOLITE_COMMIT="[0-9a-f]{40}"$', text, re.M)
    assert GOOD_SHA in text


def test_lock_every_requirement_carries_hashes():
    assert LOCK.exists()
    lines = LOCK.read_text().splitlines()
    assert any(re.fullmatch(r"# requirements-sha256: [0-9a-f]{64}", ln) for ln in lines[:12])
    blocks, cur = [], None
    for ln in lines:
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        if not ln.startswith(" "):
            cur = {"req": ln, "hashes": 0}
            blocks.append(cur)
        elif "--hash=sha256:" in ln:
            cur["hashes"] += 1
    assert blocks and all(b["hashes"] >= 1 for b in blocks), [b["req"] for b in blocks if b["hashes"] < 1]


def test_setup_engine_replaces_a_dangling_symlink(tmp_path):
    res, log, work = _run(tmp_path, existing=None, pre=lambda w: (w / "Zircolite").symlink_to(w / "nonexistent"))
    assert res.returncode == 0, res.stderr + res.stdout
    assert (work / "Zircolite").is_dir() and not (work / "Zircolite").is_symlink()
    aside = [p for p in work.iterdir() if p.name.startswith("Zircolite.old.")]
    assert len(aside) == 1 and aside[0].is_symlink()  # the link itself was moved aside, not followed


def test_setup_engine_failed_swap_names_both_paths_and_does_not_claim_done(tmp_path):
    def failing_second_mv(bindir):
        (bindir / "mv").write_text(
            '#!/bin/bash\nn=$(cat "$SHIM_LOG.mv" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$SHIM_LOG.mv"\n'
            '[ "$n" -ge 2 ] && exit 1\nexec /bin/mv "$@"\n'
        )
        (bindir / "mv").chmod(0o755)

    res, log, work = _run(tmp_path, existing=lambda d: (d / "keep.txt").write_text("mine"), bin_hook=failing_second_mv)
    assert res.returncode != 0 and "done" not in res.stdout
    aside = [p for p in work.iterdir() if p.name.startswith("Zircolite.old.")]
    assert len(aside) == 1 and (aside[0] / "keep.txt").exists()
    msg = res.stderr
    assert "could not move" in msg and str(aside[0].name) in msg and "Zircolite.setup." in msg
    assert not _uv_installs(log)


def test_setup_engine_installed_directory_is_world_readable(tmp_path):
    res, log, work = _run(tmp_path)
    assert res.returncode == 0
    assert (work / "Zircolite").stat().st_mode & 0o777 == 0o755


def test_setup_leftovers_are_gitignored_and_documented():
    ignored = (ROOT / ".gitignore").read_text().splitlines()
    assert "/Zircolite.old.*" in ignored and "/Zircolite.setup.*" in ignored
    for doc in ("README.md", "sigmaforge/MANUAL.md"):
        text = (ROOT / doc).read_text()
        assert "Zircolite.setup." in text and "network" in text and "0755" in text, doc
