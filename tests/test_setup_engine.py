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
REQ = b"orjson>=3.9.15\n"

GIT_SHIM = """#!/bin/bash
echo "git $*" >> "$SHIM_LOG"
case "$*" in
  *rev-parse*) echo "$SHIM_HEAD"; exit 0 ;;
  clone*)
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


def _run(tmp_path, head=GOOD_SHA, lock_sha=None, preexisting=False):
    bindir, scripts, work = _setup(tmp_path, lock_sha)
    if preexisting:
        (work / "Zircolite" / ".git").mkdir(parents=True)
        (work / "Zircolite" / "requirements.txt").write_bytes(REQ)
    log = tmp_path / "log"
    log.write_text("")
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "SHIM_LOG": str(log), "SHIM_HEAD": head}
    res = subprocess.run(["bash", str(scripts / "setup_engine.sh")], cwd=work, env=env, capture_output=True, text=True)
    return res, log.read_text()


def test_setup_engine_installs_with_hashes_only(tmp_path):
    res, log = _run(tmp_path)
    assert res.returncode == 0, res.stderr + res.stdout
    installs = [ln for ln in log.splitlines() if ln.startswith("uv ") and "install" in ln]
    assert len(installs) == 1 and "--require-hashes" in installs[0] and "zircolite-requirements.lock" in installs[0]
    assert "requirements.txt" not in installs[0].replace("zircolite-requirements.lock", "")


def test_setup_engine_refuses_wrong_head_after_clone(tmp_path):
    res, log = _run(tmp_path, head="0" * 40)
    assert res.returncode != 0
    assert not any("install" in ln for ln in log.splitlines() if ln.startswith("uv "))


def test_setup_engine_refuses_existing_checkout_at_the_wrong_commit(tmp_path):
    res, log = _run(tmp_path, head="1" * 40, preexisting=True)
    assert res.returncode != 0 and "clone" not in log
    assert not any(ln.startswith("uv ") for ln in log.splitlines())
    assert "delete" in (res.stderr + res.stdout).lower()


def test_setup_engine_accepts_existing_checkout_at_the_pin(tmp_path):
    res, log = _run(tmp_path, preexisting=True)
    assert res.returncode == 0, res.stderr
    assert "clone" not in log and any("--require-hashes" in ln for ln in log.splitlines())


def test_setup_engine_refuses_when_requirements_hash_differs_from_the_lock(tmp_path):
    res, log = _run(tmp_path, lock_sha="f" * 64)
    assert res.returncode != 0
    assert not any("install" in ln for ln in log.splitlines() if ln.startswith("uv "))


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


def test_setup_engine_refuses_an_existing_non_git_directory(tmp_path):
    bindir, scripts, work = _setup(tmp_path)
    (work / "Zircolite").mkdir()
    (work / "Zircolite" / "zircolite.py").write_text("")
    log = tmp_path / "log"
    log.write_text("")
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "SHIM_LOG": str(log), "SHIM_HEAD": GOOD_SHA}
    res = subprocess.run(["bash", str(scripts / "setup_engine.sh")], cwd=work, env=env, capture_output=True, text=True)
    assert res.returncode != 0 and "not a git checkout" in res.stderr
    assert not any(ln.startswith("uv ") for ln in log.read_text().splitlines())
