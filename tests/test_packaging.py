import tomllib
from pathlib import Path


def test_pyyaml_is_a_runtime_dependency():
    # shipped sigmaforge/config.py + main.py `import yaml`; it must be a direct
    # runtime dep (NOT transitively provided — shipwright-kit 0.8.0 has no runtime deps),
    # else `pip install sigmaforge` + `sigmaforge backtest` => ModuleNotFoundError.
    pp = tomllib.loads(Path("pyproject.toml").read_text())
    deps = " ".join(pp["project"]["dependencies"])
    assert "pyyaml" in deps.lower() or "PyYAML" in deps
