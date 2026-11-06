"""setup_engine.sh: pinned commit, verified checkout, hashed install. Behavioural, shims on PATH, no network."""

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "setup_engine.sh"
LOCK = ROOT / "scripts" / "zircolite-requirements.lock"
GOOD_SHA = "b37b51eb00c49fc7bfd2f4968f1e5c3fc30da643"
GOOD_TREE = "e8be4ec9d77b6850730e08d610cfb2b0b2ced2cb"
REQ = b"orjson>=3.9.15\n"
# what the git shim's clone contains (sorted): path, mode, content
FIXTURE_FILES = [
    ("lib/sub/data.txt", "100644", b"data\n"),
    ("requirements.txt", "100644", REQ),
    ("zircolite.py", "100644", b""),
]

GIT_SHIM = """#!/bin/bash
echo "git[GIT_DIR=${GIT_DIR-unset} WT=${GIT_WORK_TREE-unset} NR=${GIT_NO_REPLACE_OBJECTS-unset}] $*" >> "$SHIM_LOG"
cdir=""
prev=""
for a in "$@"; do [ "$prev" = "-C" ] && cdir="$a"; prev="$a"; done
sub=""
skip=0
for a in "$@"; do
  if [ "$skip" = 1 ]; then skip=0; continue; fi
  case "$a" in -C|-c) skip=1 ;; -*) ;; *) sub="$a"; break ;; esac
done
case "$*" in
  *'HEAD^{tree}'*)
    echo "$SHIM_TREE"
    # the last check of a verification: swap the whole clone for a symlink right after it
    if [ -n "${SHIM_SWAP_TO:-}" ] && [ "$cdir" != "Zircolite" ]; then
      /bin/mv "$cdir" "$cdir.real" && ln -s "$SHIM_SWAP_TO" "$cdir"
    fi
    exit 0 ;;
  *rev-parse*)
    if [ "$cdir" = "Zircolite" ] && [ -n "${SHIM_HEAD_AFTER:-}" ]; then
      echo "$SHIM_HEAD_AFTER"
    else
      echo "$SHIM_HEAD"
    fi
    exit 0 ;;
  *clone*)
    dest="${@: -1}"
    printf 'orjson>=3.9.15\\n' > "$dest/requirements.txt"
    : > "$dest/zircolite.py"
    chmod 600 "$dest/zircolite.py"
    mkdir -p "$dest/lib/sub"
    echo data > "$dest/lib/sub/data.txt"
    [ -n "${SHIM_NO_REPO:-}" ] && exit 0
    "$SHIM_REAL_GIT" -C "$dest" init -q
    "$SHIM_REAL_GIT" -C "$dest" add -A
    "$SHIM_REAL_GIT" -C "$dest" -c user.name=t -c user.email=t@t commit -q -m c
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
    body = "".join(f"{m} {hashlib.sha256(c).hexdigest()} {p}\n" for p, m, c in FIXTURE_FILES)
    manifest_hash = hashlib.sha256(body.encode()).hexdigest()
    (scripts / "zircolite-manifest.sha256").write_text("# synthetic manifest for the shim clone\n" + body)
    text = re.sub(
        r'ZIRCOLITE_MANIFEST_SHA256="[0-9a-f]{64}"', f'ZIRCOLITE_MANIFEST_SHA256="{manifest_hash}"', SCRIPT.read_text()
    )
    (scripts / "setup_engine.sh").write_text(text)
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
    timeout=120,
    umask=None,
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
        "SHIM_REAL_GIT": shutil.which("git"),
        **(extra_env or {}),
    }
    cmd = ["bash", str(scripts / "setup_engine.sh")]
    if umask:
        cmd = ["bash", "-c", f'umask {umask}; exec bash "$0"', str(scripts / "setup_engine.sh")]
    res = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout)
    return res, log.read_text(), work


def _assert_git_never_touches_the_old_dir(log):
    lines = log.splitlines()
    assert not any("Zircolite.old" in ln for ln in lines)
    setup_calls = [i for i, ln in enumerate(lines) if "Zircolite.setup." in ln]
    final_calls = [i for i, ln in enumerate(lines) if re.search(r"-C Zircolite( |$)", ln)]
    # git only ever runs in the fresh clone, and in the final directory strictly after the swap
    assert setup_calls and all(i > max(setup_calls) for i in final_calls)


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
    assert len(aside) == 1 and (aside[0] / "Zircolite" / "evil.py").exists()  # renamed, never deleted
    assert aside[0].name in res.stdout
    _assert_git_never_touches_the_old_dir(log)


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
    _assert_git_never_touches_the_old_dir(log)


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
    assert len(aside) == 1 and (aside[0] / "Zircolite").is_symlink()  # the link itself, not followed


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
    assert len(aside) == 1 and (aside[0] / "Zircolite" / "keep.txt").exists()
    msg = res.stderr
    assert "could not move" in msg and str(aside[0].name) in msg and "Zircolite.setup." in msg
    assert not _uv_installs(log)


def test_setup_engine_installed_directory_is_world_readable(tmp_path):
    res, log, work = _run(tmp_path)
    assert res.returncode == 0
    assert (work / "Zircolite").stat().st_mode & 0o777 == 0o755


def test_setup_leftovers_are_gitignored_and_documented():
    ignored = (ROOT / ".gitignore").read_text().splitlines()
    assert {"/Zircolite.old.*", "/Zircolite.setup.*", "/Zircolite.untrusted.*"} <= set(ignored)
    for doc in ("README.md", "sigmaforge/MANUAL.md"):
        text = (ROOT / doc).read_text()
        assert "Zircolite.setup." in text and "network" in text and "0755" in text, doc
        assert "whenever a previous" in text and "git-ignored" in text, doc
        assert "Zircolite.untrusted." in text, doc


def _mode(path):
    return path.stat().st_mode & 0o777


def test_chmod_touches_only_the_fresh_clone_not_the_old_directory_or_its_files(tmp_path):
    def old(d):
        (d / "f").write_text("x")
        (d / "f").chmod(0o640)
        d.chmod(0o700)

    res, log, work = _run(tmp_path, existing=old)
    assert res.returncode == 0, res.stderr
    aside = next(p for p in work.iterdir() if p.name.startswith("Zircolite.old."))
    assert _mode(aside) == 0o700 and _mode(aside / "Zircolite") == 0o700 and _mode(aside / "Zircolite" / "f") == 0o640
    assert _mode(work / "Zircolite") == 0o755
    assert _mode(work / "Zircolite" / "zircolite.py") == 0o600  # not recursive


def _victim(tmp_path):
    victim = tmp_path / "victim"
    victim.mkdir()
    victim.chmod(0o700)
    (victim / "requirements.txt").write_bytes(REQ)  # PoC shape: matches the lock hash
    (victim / "zircolite.py").write_text("")
    (victim / "lib" / "sub").mkdir(parents=True)
    (victim / "lib" / "sub" / "data.txt").write_text(
        "data\n"
    )  # and holds every tracked path, so only the link check can refuse
    return victim


def test_clone_swapped_for_a_symlink_after_the_checks_is_refused(tmp_path):
    victim = _victim(tmp_path)
    res, log, work = _run(
        tmp_path, existing=lambda d: (d / "keep").write_text("mine"), extra_env={"SHIM_SWAP_TO": str(victim)}
    )
    assert res.returncode != 0 and "symbolic link" in res.stderr
    assert _mode(victim) == 0o700  # chmod never followed the link
    assert not _uv_installs(log)
    assert (work / "Zircolite" / "keep").exists()  # nothing was moved aside or in


def test_clone_swapped_for_a_symlink_during_the_move_is_caught_by_the_reverification(tmp_path):
    victim = _victim(tmp_path)

    def swapping_mv(bindir):
        (bindir / "mv").write_text(
            "#!/bin/bash\n"
            '/bin/mv "$@" || exit 1\n'
            'n=$(cat "$SHIM_LOG.mv" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$SHIM_LOG.mv"\n'
            f'if [ "$n" = 1 ]; then d=$(ls -d Zircolite.setup.*); /bin/mv "$d" "$d.real"; ln -s {victim} "$d"; fi\n'
        )
        (bindir / "mv").chmod(0o755)

    res, log, work = _run(tmp_path, existing=lambda d: (d / "keep").write_text("mine"), bin_hook=swapping_mv)
    assert res.returncode != 0 and "after the move" in res.stderr and "Zircolite.old." in res.stderr
    assert not _uv_installs(log) and "done" not in res.stdout


def test_wrong_head_at_the_final_location_is_refused_and_names_the_previous_engine(tmp_path):
    res, log, work = _run(
        tmp_path, existing=lambda d: (d / "keep").write_text("mine"), extra_env={"SHIM_HEAD_AFTER": "9" * 40}
    )
    assert res.returncode != 0 and "after the move" in res.stderr and "Zircolite.old." in res.stderr
    assert not _uv_installs(log)


def test_clone_swapped_for_a_symlink_between_chmod_and_move_is_refused_before_anything_moves(tmp_path):
    victim = _victim(tmp_path)

    def swapping_chmod(bindir):
        (bindir / "chmod").write_text(
            f'#!/bin/bash\n/bin/chmod "$@" || exit 1\n'
            f'case "$2" in Zircolite.setup.??????) /bin/mv "$2" "$2.real" && ln -s {victim} "$2" ;; esac\n'
        )
        (bindir / "chmod").chmod(0o755)

    res, log, work = _run(tmp_path, existing=lambda d: (d / "keep").write_text("mine"), bin_hook=swapping_chmod)
    assert res.returncode != 0 and "symbolic link" in res.stderr
    assert (work / "Zircolite" / "keep").exists() and not _uv_installs(log)
    assert not any(p.name.startswith("Zircolite.old.") for p in work.iterdir())  # nothing moved aside


# --- round 4: quarantine a rejected engine, require a clean working tree -----------------------


def _content_rejected(res):
    return "is not the pinned tree" in res.stderr


def _untrusted(work):
    return [p for p in work.iterdir() if p.name.startswith("Zircolite.untrusted.")]


def _old(d):
    (d / "keep").write_text("mine")


def test_rejected_final_engine_is_quarantined_and_the_previous_one_restored(tmp_path):
    res, log, work = _run(tmp_path, existing=_old, extra_env={"SHIM_HEAD_AFTER": "9" * 40})
    assert res.returncode != 0 and "after the move" in res.stderr and not _uv_installs(log)
    assert (work / "Zircolite" / "keep").exists() and not (work / "Zircolite" / "zircolite.py").exists()
    q = _untrusted(work)
    assert len(q) == 1 and (q[0] / "Zircolite" / "zircolite.py").exists() and q[0].name in res.stderr
    assert "restored" in res.stderr
    assert not any((p / "Zircolite").exists() for p in work.iterdir() if p.name.startswith("Zircolite.old."))


def test_rejected_final_engine_without_a_previous_one_leaves_no_zircolite(tmp_path):
    res, log, work = _run(tmp_path, extra_env={"SHIM_HEAD_AFTER": "9" * 40})
    assert res.returncode != 0 and not _uv_installs(log)
    assert not (work / "Zircolite").exists() and len(_untrusted(work)) == 1
    assert "no previous engine" in res.stderr


def test_symlink_swapped_in_during_the_move_is_quarantined_and_the_victim_untouched(tmp_path):
    victim = _victim(tmp_path)

    def swapping_mv(bindir):
        (bindir / "mv").write_text(
            "#!/bin/bash\n"
            '/bin/mv "$@" || exit 1\n'
            'n=$(cat "$SHIM_LOG.mv" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$SHIM_LOG.mv"\n'
            f'if [ "$n" = 1 ]; then d=$(ls -d Zircolite.setup.*); /bin/mv "$d" "$d.real"; ln -s {victim} "$d"; fi\n'
        )
        (bindir / "mv").chmod(0o755)

    res, log, work = _run(tmp_path, existing=_old, bin_hook=swapping_mv)
    assert res.returncode != 0 and not _uv_installs(log) and "done" not in res.stdout
    assert (work / "Zircolite" / "keep").exists() and not (work / "Zircolite").is_symlink()
    q = _untrusted(work)
    assert len(q) == 1 and (q[0] / "Zircolite").is_symlink()
    assert _mode(victim) == 0o700 and (victim / "requirements.txt").exists()


def _tamper_after_first_mv(tmp_path, tamper):
    def hook(bindir):
        (bindir / "mv").write_text(
            "#!/bin/bash\n"
            '/bin/mv "$@" || exit 1\n'
            'n=$(cat "$SHIM_LOG.mv" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$SHIM_LOG.mv"\n'
            f'if [ "$n" = 1 ]; then d=$(ls -d Zircolite.setup.* | head -1); {tamper}; fi\n'
        )
        (bindir / "mv").chmod(0o755)

    return _run(tmp_path, existing=_old, bin_hook=hook)


def test_modified_tracked_file_in_the_moved_clone_is_refused(tmp_path):
    res, log, work = _tamper_after_first_mv(tmp_path, 'echo evil > "$d/zircolite.py"')
    assert res.returncode != 0 and not _uv_installs(log) and _content_rejected(res)
    assert (work / "Zircolite" / "keep").exists() and len(_untrusted(work)) == 1


def test_untracked_file_in_the_moved_clone_is_refused(tmp_path):
    res, log, work = _tamper_after_first_mv(tmp_path, 'echo evil > "$d/evil.py"')
    assert res.returncode != 0 and not _uv_installs(log) and _content_rejected(res)
    assert (work / "Zircolite" / "keep").exists() and len(_untrusted(work)) == 1


def test_ignored_file_in_the_moved_clone_is_refused(tmp_path):
    res, log, work = _tamper_after_first_mv(tmp_path, 'echo "*.pyc" > "$d/.git/info/exclude"; echo y > "$d/hidden.pyc"')
    assert res.returncode != 0 and not _uv_installs(log)


def test_a_clean_clone_passes_and_git_is_never_used_for_the_content(tmp_path):
    res, log, work = _run(tmp_path)
    assert res.returncode == 0, res.stderr
    lines = [ln for ln in log.splitlines() if ln.startswith("git[")]
    for sub in ("ls-tree", "hash-object", " status", "cat-file", "diff"):
        assert not any(sub in ln for ln in lines), sub  # the object database/index are not consulted
    assert all("core.hooksPath=/dev/null" in ln and "NR=1" in ln for ln in lines), lines


def test_a_clone_without_a_git_dir_is_a_refusal_not_a_pass(tmp_path):
    res, log, work = _run(tmp_path, extra_env={"SHIM_NO_REPO": "1"})
    assert res.returncode != 0 and not _uv_installs(log) and ".git is not a real directory" in res.stderr


# --- round 5: content verification, private containers, guarded quarantine ----------------------


def _refused_by_content(tmp_path, tamper):
    res, log, work = _tamper_after_first_mv(tmp_path, tamper)
    assert res.returncode != 0 and not _uv_installs(log) and _content_rejected(res), res.stderr
    assert (work / "Zircolite" / "keep").exists() and len(_untrusted(work)) == 1


def test_assume_unchanged_does_not_hide_a_modified_tracked_file(tmp_path):
    _refused_by_content(
        tmp_path,
        '"$SHIM_REAL_GIT" -C "$d" update-index --assume-unchanged zircolite.py; echo evil > "$d/zircolite.py"',
    )


def test_skip_worktree_does_not_hide_a_modified_tracked_file(tmp_path):
    _refused_by_content(
        tmp_path,
        '"$SHIM_REAL_GIT" -C "$d" update-index --skip-worktree zircolite.py; echo evil > "$d/zircolite.py"',
    )


def test_extra_empty_directory_is_refused(tmp_path):
    _refused_by_content(tmp_path, 'mkdir "$d/emptydir"')


def test_tracked_file_replaced_by_a_symlink_is_refused(tmp_path):
    _refused_by_content(tmp_path, '/bin/mv "$d/zircolite.py" "$d/../moved.py"; ln -s /etc/hostname "$d/zircolite.py"')


def test_changed_exec_bit_is_refused(tmp_path):
    _refused_by_content(tmp_path, 'chmod 755 "$d/zircolite.py"')


def test_forged_filter_and_attributes_are_never_executed(tmp_path):
    marker = tmp_path / "FILTER_MARKER"
    tamper = (
        "printf '* filter=evil\\n' >> \"$d/.git/info/attributes\"; "
        f"printf '[filter \"evil\"]\\n\\tclean = touch {marker}\\n[core]\\n\\tfsmonitor = touch {marker}\\n' "
        '>> "$d/.git/config"; '
        f"printf '#!/bin/sh\\ntouch {marker}\\n' > \"$d/.git/hooks/post-index-change\"; "
        'chmod 755 "$d/.git/hooks/post-index-change"'
    )
    res, log, work = _tamper_after_first_mv(tmp_path, tamper)
    assert res.returncode == 0, res.stderr  # the content is the pinned tree; .git internals are not executed
    assert not marker.exists()


def test_old_engine_container_is_private_fresh_and_unpredictable(tmp_path):
    res, log, work = _run(tmp_path, existing=_old)
    assert res.returncode == 0, res.stderr
    containers = [p for p in work.iterdir() if p.name.startswith("Zircolite.old.")]
    assert len(containers) == 1 and _mode(containers[0]) == 0o700
    assert not re.fullmatch(r"Zircolite\.old\.\d{14}\.\d+", containers[0].name)  # not <timestamp>.<pid>
    assert (containers[0] / "Zircolite" / "keep").exists()


def test_a_planted_dir_at_a_timestamped_name_cannot_capture_the_old_engine(tmp_path):
    def plant(work):
        for n in ("Zircolite.old.20260101000000.1", "Zircolite.untrusted.20260101000000.1"):
            (work / n).mkdir()

    res, log, work = _run(tmp_path, existing=_old, pre=plant)
    assert res.returncode == 0, res.stderr
    assert not (work / "Zircolite.old.20260101000000.1" / "Zircolite").exists()
    assert len(list(work.glob("Zircolite.old.??????"))) == 1


def _mv_failing_on(n_fail, then=""):
    def hook(bindir):
        (bindir / "mv").write_text(
            "#!/bin/bash\n"
            'n=$(cat "$SHIM_LOG.mv" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$SHIM_LOG.mv"\n'
            f'if [ "$n" = {n_fail} ]; then exit 1; fi\n'
            '/bin/mv "$@" || exit 1\n'
            f"{then}\n"
        )
        (bindir / "mv").chmod(0o755)

    return hook


def test_a_failing_quarantine_rename_names_both_paths_and_exits_1(tmp_path):
    # calls: 1 aside, 2 move in, 3 quarantine (fails)
    def hook(bindir):
        _mv_failing_on(3)(bindir)

    res, log, work = _run(tmp_path, existing=_old, extra_env={"SHIM_HEAD_AFTER": "9" * 40}, bin_hook=hook)
    assert res.returncode != 0 and not _uv_installs(log) and "done" not in res.stdout
    assert "could not be quarantined" in res.stderr and "REJECTED" in res.stderr
    assert "Zircolite.old." in res.stderr and "Do not use" in res.stderr


def test_a_failing_restore_says_so_and_names_the_container(tmp_path):
    # calls: 1 aside, 2 move in, 3 quarantine, 4 restore (fails)
    res, log, work = _run(tmp_path, existing=_old, extra_env={"SHIM_HEAD_AFTER": "9" * 40}, bin_hook=_mv_failing_on(4))
    assert res.returncode != 0 and not _uv_installs(log)
    assert "Could NOT restore" in res.stderr and "Zircolite.old." in res.stderr
    container = next(p for p in work.iterdir() if p.name.startswith("Zircolite.old."))
    assert (container / "Zircolite" / "keep").exists() and container.name in res.stderr


def test_restore_aborts_instead_of_nesting_when_the_destination_exists_again(tmp_path):
    # after the quarantine rename (call 3) an attacker re-creates Zircolite/
    res, log, work = _run(
        tmp_path,
        existing=_old,
        extra_env={"SHIM_HEAD_AFTER": "9" * 40},
        bin_hook=_mv_failing_on(99, then='if [ "$n" = 3 ]; then mkdir Zircolite; fi'),
    )
    assert res.returncode != 0 and not _uv_installs(log)
    assert "Could NOT restore" in res.stderr and "exists again" in res.stderr
    container = next(p for p in work.iterdir() if p.name.startswith("Zircolite.old."))
    assert (container / "Zircolite" / "keep").exists()  # the old engine was not moved onto the new dir
    assert not (work / "Zircolite" / "Zircolite").exists()


def test_tracked_file_replaced_by_a_symlink_to_identical_content_is_refused(tmp_path):
    # git hash-object follows the link and would see the same blob: only the explicit link check catches it
    _refused_by_content(
        tmp_path, ': > "$d/../same.py"; /bin/mv "$d/zircolite.py" "$d/../orig.py"; ln -s ../same.py "$d/zircolite.py"'
    )


def test_a_nested_extra_directory_is_refused(tmp_path):
    _refused_by_content(tmp_path, 'mkdir "$d/lib/extra"')


def test_a_missing_nested_file_is_refused(tmp_path):
    _refused_by_content(tmp_path, '/bin/mv "$d/lib/sub/data.txt" "$d/../data.bak"')


def test_a_git_dir_that_is_a_symlink_is_refused(tmp_path):
    res, log, work = _tamper_after_first_mv(tmp_path, '/bin/mv "$d/.git" "$d/../realgit"; ln -s ../realgit "$d/.git"')
    assert res.returncode != 0 and not _uv_installs(log) and ".git is not a real directory" in res.stderr


def test_quarantine_container_is_private_and_unpredictable(tmp_path):
    res, log, work = _run(tmp_path, existing=_old, extra_env={"SHIM_HEAD_AFTER": "9" * 40})
    q = _untrusted(work)
    assert len(q) == 1 and _mode(q[0]) == 0o700
    assert not re.fullmatch(r"Zircolite\.untrusted\.\d{14}\.\d+", q[0].name)


# --- round 6: pinned file manifest ------------------------------------------------------------


def test_tampered_manifest_is_refused_before_cloning(tmp_path):
    def tamper(bindir):  # change the manifest after the script's constant was derived from the original
        manifest = bindir.parent / "scripts" / "zircolite-manifest.sha256"
        manifest.write_text(manifest.read_text() + f"100644 {'0' * 64} evil.py\n")

    res, log, work = _run(tmp_path, bin_hook=tamper)
    assert res.returncode != 0 and "does not match the pinned" in res.stderr
    assert "clone" not in log and not _uv_installs(log) and not (work / "Zircolite").exists()


def test_consistent_but_forged_object_database_cannot_launder_a_modified_file(tmp_path):
    # the clone's own git database is rewritten to agree with the evil file: only the pinned manifest can tell
    tamper = (
        'echo evil > "$d/zircolite.py"; "$SHIM_REAL_GIT" -C "$d" add -A; '
        '"$SHIM_REAL_GIT" -C "$d" -c user.name=t -c user.email=t@t commit -q --amend -m forged'
    )
    _refused_by_content(tmp_path, tamper)


def test_hardlinked_tracked_file_is_refused(tmp_path):
    _refused_by_content(tmp_path, 'ln "$d/zircolite.py" "$d/../hardlink-to-zircolite"')


def test_symlink_inside_the_tree_is_refused_even_when_untracked(tmp_path):
    _refused_by_content(tmp_path, 'ln -s /etc "$d/lib/sub/link"')


def test_generated_manifest_matches_the_pinned_constant_and_shape():
    lines = (ROOT / "scripts" / "zircolite-manifest.sha256").read_text().splitlines()
    body = [ln for ln in lines if not ln.startswith("#")]
    header = {ln.split(": ")[0]: ln.split(": ")[1] for ln in lines if ln.startswith("# manifest-sha256: ")}
    digest = hashlib.sha256(("\n".join(body) + "\n").encode()).hexdigest()
    assert digest == header["# manifest-sha256"]
    assert f'ZIRCOLITE_MANIFEST_SHA256="{digest}"' in SCRIPT.read_text()
    rows = [ln.split(" ", 2) for ln in body]
    assert len(rows) == 171 and [r[2] for r in rows] == sorted(r[2] for r in rows)
    assert sum(r[0] == "100755" for r in rows) == 1 and sum(r[0] == "100644" for r in rows) == 170
    assert all(re.fullmatch(r"[0-9a-f]{64}", r[1]) for r in rows) and len({r[2] for r in rows}) == 171
    assert GOOD_SHA in lines[0] and GOOD_TREE in lines[0]


@pytest.mark.network
@pytest.mark.skipif(os.environ.get("SIGMAFORGE_NETWORK_TESTS") != "1", reason="opt-in: clones the real Zircolite tag")
def test_committed_manifest_matches_a_genuine_checkout_of_the_pin(tmp_path):
    clone = tmp_path / "Zircolite"
    subprocess.run(
        [
            "git",
            "clone",
            "-q",
            "--depth",
            "1",
            "--branch",
            "v3.7.6",
            "https://github.com/wagga40/Zircolite.git",
            str(clone),
        ],
        check=True,
    )
    out = subprocess.run(
        ["python3", str(ROOT / "scripts" / "make_zircolite_manifest.py"), str(clone)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert out == (ROOT / "scripts" / "zircolite-manifest.sha256").read_text()


# --- follow-up: loose modes, planted modules, special files, manifest read once ------------------


def _helper_source():
    text = SCRIPT.read_text()
    m = re.search(r"python3 -I - \"\$1\" <<'PY'\n(.*?)\nPY\n", text, re.S)
    assert m, "check_content helper not found"
    return m.group(1)


def _manifest_text(files):
    return "".join(f"{m} {hashlib.sha256(c).hexdigest()} {p}\n" for p, m, c in files)


def _make_tree(root, files=FIXTURE_FILES):
    (root / ".git").mkdir(parents=True)
    root.chmod(0o755)
    for rel, mode, content in files:
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.parent.chmod(0o755)
        f.write_bytes(content)
        f.chmod(0o755 if mode == "100755" else 0o644)
    return root


def _run_helper(tree, files=FIXTURE_FILES, patch=None):
    """Execute the shipped check_content helper in-process; return (exit code, message)."""
    import contextlib
    import io
    import sys

    out = io.StringIO()
    old_env, old_argv = os.environ.get("ZM"), sys.argv
    os.environ["ZM"] = _manifest_text(files)
    sys.argv = ["helper", str(tree)]
    code = 0
    try:
        with contextlib.redirect_stdout(out):
            try:
                if patch:
                    patch()
                exec(compile(_helper_source(), "check_content", "exec"), {"__name__": "__main__"})
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else 1
    finally:
        sys.argv = old_argv
        if old_env is None:
            os.environ.pop("ZM", None)
        else:
            os.environ["ZM"] = old_env
    return code, out.getvalue()


def test_helper_accepts_a_clean_tree(tmp_path):
    assert _run_helper(_make_tree(tmp_path / "t")) == (0, "")


@pytest.mark.parametrize("mode", [0o666, 0o664, 0o646, 0o4644, 0o2644, 0o1644])
def test_helper_rejects_loose_or_special_file_modes(tmp_path, mode):
    t = _make_tree(tmp_path / "t")
    (t / "zircolite.py").chmod(mode)
    code, msg = _run_helper(t)
    assert code == 1 and "zircolite.py" in msg and ("writable" in msg or "setuid" in msg), msg


@pytest.mark.parametrize("mode", [0o777, 0o775, 0o757, 0o2755, 0o1755])
def test_helper_rejects_loose_or_special_directory_modes(tmp_path, mode):
    t = _make_tree(tmp_path / "t")
    (t / "lib").chmod(mode)
    code, msg = _run_helper(t)
    assert code == 1 and "lib" in msg, msg


def test_helper_rejects_a_loose_clone_root(tmp_path):
    t = _make_tree(tmp_path / "t")
    t.chmod(0o777)
    code, msg = _run_helper(t)
    assert code == 1 and "clone directory" in msg


def test_a_fifo_at_a_manifest_path_is_refused_without_hanging(tmp_path):
    t = _make_tree(tmp_path / "t")
    os.rename(t / "zircolite.py", tmp_path / "moved.py")
    os.mkfifo(t / "zircolite.py", 0o644)
    import signal

    def on_alarm(*_):
        raise AssertionError("opening the FIFO blocked")

    old = signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(10)
    try:
        code, msg = _run_helper(t)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)
    assert code == 1 and "zircolite.py" in msg


def test_symlink_swapped_in_after_the_walk_is_refused_by_nofollow(tmp_path):
    t = _make_tree(tmp_path / "t")
    same = tmp_path / "same.py"
    same.write_bytes(b"")
    same.chmod(0o644)

    def swap_after_walk():
        real_walk = os.walk

        def walk(*a, **k):
            yield from real_walk(*a, **k)
            os.rename(t / "zircolite.py", tmp_path / "orig.py")
            os.symlink(same, t / "zircolite.py")  # identical content, regular target

        os.walk = walk

    real = os.walk
    try:
        code, msg = _run_helper(t, patch=swap_after_walk)
    finally:
        os.walk = real
    assert code == 1 and "cannot open" in msg, msg


def test_a_planted_hashlib_in_the_cwd_is_never_imported(tmp_path):
    marker = tmp_path / "HASHLIB_MARKER"

    def plant(work):
        for name in ("hashlib.py", "stat.py", "os.py", "sys.py"):
            (work / name).write_text(f"open({str(marker)!r}, 'w').write('x')\n")

    res, log, work = _run(tmp_path, pre=plant)
    assert res.returncode == 0, res.stderr + res.stdout
    assert not marker.exists()


def test_every_python_invocation_in_the_script_uses_isolated_mode():
    calls = re.findall(r"python3 [^\n]*", SCRIPT.read_text())
    assert calls and all(c.startswith("python3 -I") for c in calls), calls


def test_manifest_is_read_once_so_pin_and_parse_cannot_disagree(tmp_path):
    # a `cat` shim hands out the genuine manifest, then rewrites the file on disk: a script that re-read
    # the file for the content check would now see an extra entry and refuse
    def cat_shim(bindir):
        manifest = bindir.parent / "scripts" / "zircolite-manifest.sha256"
        (bindir / "cat").write_text(
            '#!/bin/bash\n/bin/cat "$@"\n'
            f'case "$*" in *zircolite-manifest.sha256*) echo "100644 {"0" * 64} evil.py" >> {manifest} ;; esac\n'
        )
        (bindir / "cat").chmod(0o755)

    res, log, work = _run(tmp_path, bin_hook=cat_shim)
    assert res.returncode == 0, res.stderr
    assert sum(ln.startswith("uv ") and "install" in ln for ln in log.splitlines()) == 1


def test_setup_works_under_a_group_writable_umask(tmp_path):
    res, log, work = _run(tmp_path, umask="002")
    assert res.returncode == 0, res.stderr


def test_provenance_sha_is_documented_as_unverified():
    text = (ROOT / "sigmaforge" / "MANUAL.md").read_text()
    assert "not verified" in text and "zircolite_commit_sha" in text


def test_file_made_writable_after_the_walk_is_refused_by_the_fd_check(tmp_path):
    t = _make_tree(tmp_path / "t")

    def loosen_after_walk():
        real_walk = os.walk

        def walk(*a, **k):
            yield from real_walk(*a, **k)
            (t / "zircolite.py").chmod(0o666)

        os.walk = walk

    real = os.walk
    try:
        code, msg = _run_helper(t, patch=loosen_after_walk)
    finally:
        os.walk = real
    assert code == 1 and "zircolite.py" in msg and "writable" in msg, msg
