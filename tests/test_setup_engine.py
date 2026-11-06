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
cdir=""
prev=""
for a in "$@"; do [ "$prev" = "-C" ] && cdir="$a"; prev="$a"; done
sub=""
skip=0
for a in "$@"; do
  if [ "$skip" = 1 ]; then skip=0; continue; fi
  case "$a" in -C|-c) skip=1 ;; -*) ;; *) sub="$a"; break ;; esac
done
if [ "$sub" = "ls-tree" ]; then exec "$SHIM_REAL_GIT" "$@"; fi
if [ "$sub" = "hash-object" ]; then
  out="$("$SHIM_REAL_GIT" "$@")"; rc=$?
  echo "$out"
  # the last tracked file hashed: swap the whole clone for a symlink right after the content check
  if [ -n "${SHIM_SWAP_TO:-}" ] && [ "${@: -1}" = "zircolite.py" ] && [ "$cdir" != "Zircolite" ]; then
    /bin/mv "$cdir" "$cdir.real" && ln -s "$SHIM_SWAP_TO" "$cdir"
  fi
  exit $rc
fi
if [ "$sub" = "status" ]; then
  out="$("$SHIM_REAL_GIT" "$@")"; rc=$?
  [ -n "$out" ] && echo "$out"
  if [ -n "${SHIM_SWAP_TO:-}" ] && [ "$cdir" != "Zircolite" ]; then
    /bin/mv "$cdir" "$cdir.real" && ln -s "$SHIM_SWAP_TO" "$cdir"
  fi
  exit $rc
fi
case "$*" in
  *'HEAD^{tree}'*)
    echo "$SHIM_TREE"
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
        "SHIM_REAL_GIT": shutil.which("git"),
        **(extra_env or {}),
    }
    res = subprocess.run(["bash", str(scripts / "setup_engine.sh")], cwd=work, env=env, capture_output=True, text=True)
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
            f'#!/bin/bash\n/bin/chmod "$@" || exit 1\n/bin/mv "$2" "$2.real" && ln -s {victim} "$2"\n'
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


def test_a_clean_real_git_clone_passes_the_content_check(tmp_path):
    res, log, work = _run(tmp_path)
    assert res.returncode == 0, res.stderr
    lines = log.splitlines()
    assert any("ls-tree -r -z HEAD" in ln for ln in lines)
    assert any("hash-object --no-filters -- " in ln for ln in lines)
    assert not any(" status" in ln for ln in lines)  # the index is never consulted
    assert all("core.hooksPath=/dev/null" in ln for ln in lines if ln.startswith("git["))


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
