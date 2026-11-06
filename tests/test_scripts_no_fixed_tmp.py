"""F11: scripts must not hardcode world-writable /tmp paths (symlink/plant vector).

The AST test locks the absence of the literal in scripts/; it does not prove the symlink
behaviour of the replacement paths (those are repo-relative, under reports/ or a CLI argument).
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = sorted((ROOT / "scripts").rglob("*.py"))


def _string_constants(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node


def test_scripts_do_not_hardcode_tmp_paths():
    assert SCRIPTS
    hits = [
        f"{p.relative_to(ROOT)}:{n.lineno}"
        for p in SCRIPTS
        for n in _string_constants(ast.parse(p.read_text(encoding="utf-8")))
        if "/tmp" in n.value
    ]
    assert hits == []


def _has_flag(script, flag):
    tree = ast.parse((ROOT / "scripts" / script).read_text(encoding="utf-8"))
    return any(n.value == flag for n in _string_constants(tree))


def test_former_tmp_readers_take_arguments():
    assert _has_flag("run_first_backtest.py", "--n-attack-events")
    assert _has_flag("pull_optc_fullweek.py", "--targets")


def test_summary_files_are_gitignored():
    assert "reports/_*_summary.json" in (ROOT / ".gitignore").read_text().splitlines()


def test_pull_optc_missing_targets_is_a_clean_one_line_exit_2(tmp_path, monkeypatch, capsys):
    import importlib
    import sys
    import types

    monkeypatch.setitem(sys.modules, "gdown", types.ModuleType("gdown"))
    monkeypatch.syspath_prepend(str(ROOT))
    mod = importlib.import_module("scripts.pull_optc_fullweek")
    missing = tmp_path / "no\x1b[31m-such.json"
    monkeypatch.setattr(sys, "argv", ["pull_optc_fullweek.py", "--targets", str(missing)])
    assert mod.main() == 2
    out = capsys.readouterr().out
    assert len(out.strip().splitlines()) == 1 and "--targets file missing" in out and "\x1b" not in out
