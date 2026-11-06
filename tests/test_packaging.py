import tomllib
from pathlib import Path


def test_pyyaml_is_a_runtime_dependency():
    # shipped sigmaforge/config.py + main.py `import yaml`; it must be a direct
    # runtime dep (NOT transitively provided — shipwright-kit 0.8.0 has no runtime deps),
    # else `pip install sigmaforge` + `sigmaforge backtest` => ModuleNotFoundError.
    pp = tomllib.loads(Path("pyproject.toml").read_text())
    deps = " ".join(pp["project"]["dependencies"])
    assert "pyyaml" in deps.lower() or "PyYAML" in deps


def test_project_urls_declared():
    pp = tomllib.loads(Path("pyproject.toml").read_text())
    urls = pp["project"]["urls"]
    assert {"Homepage", "Repository", "Issues", "Changelog"} <= set(urls)
    assert all(v.startswith("https://github.com/duathron/sigmaforge") for v in urls.values())


def test_tracked_files_have_no_home_paths():
    import re
    import subprocess

    import pytest

    try:
        files = subprocess.run(
            ["git", "ls-files"], check=True, capture_output=True, text=True, cwd=Path(__file__).parent.parent
        ).stdout.splitlines()
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    # concatenated so this test never contains the literal it scans for
    home = re.compile("/" + "Users" + r"/[A-Za-z0-9._-]+/|/" + "home" + r"/[A-Za-z0-9._-]+/")
    # known-open: recorded provenance in these data files is kept stable (recall_technique_map_sha)
    allow = {"data/comiset/technique_map.json", "data/comiset/attack_data_technique_map.json"}
    root = Path(__file__).parent.parent
    bad = []
    for f in files:
        if f in allow or not (root / f).is_file():
            continue
        try:
            text = (root / f).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if home.search(text):
            bad.append(f)
    assert not bad, f"personal home paths in tracked files: {bad}"
