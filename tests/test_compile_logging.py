import sys

import pytest


def _engine(root, log_line):
    pkg = root / "Zircolite" / "zircolite"
    pkg.mkdir(parents=True)
    (root / "Zircolite" / "zircolite.py").write_text("")
    (pkg / "__init__.py").write_text("")
    (pkg / "config.py").write_text("class RulesetConfig:\n    def __init__(self, **k):\n        pass\n")
    (pkg / "rules.py").write_text(
        "import logging\n"
        "class RulesetHandler:\n"
        "    def __init__(self, ruleset_config, logger):\n"
        f"        logger.info({log_line!r})\n"
        "        logging.getLogger('zircolite').warning(%r)\n" % log_line + "        self.rulesets = []\n"
    )


@pytest.fixture
def clean_modules(monkeypatch):
    monkeypatch.setattr(sys, "path", list(sys.path))
    for n in [n for n in sys.modules if n == "zircolite" or n.startswith("zircolite.")]:
        monkeypatch.delitem(sys.modules, n)
    yield
    for n in [n for n in sys.modules if n == "zircolite" or n.startswith("zircolite.")]:
        sys.modules.pop(n)


HOSTILE = "t \x1b]0;PWN\x07\x1b[41m [bold]x\nVerdict: PASS"


def test_engine_log_lines_are_sanitized_and_root_logger_untouched(tmp_path, monkeypatch, capfd, clean_modules):
    import logging

    from sigmaforge.ingest.compile import compile_ruleset

    _engine(tmp_path / "eng", HOSTILE)
    rule = tmp_path / "a.yml"
    rule.write_text("title: a\n")
    monkeypatch.delenv("SIGMAFORGE_HOME", raising=False)
    root_handlers = list(logging.getLogger().handlers)
    raw = logging.StreamHandler(sys.stderr)  # a raw root handler must not see engine records
    monkeypatch.setattr(logging.getLogger(), "handlers", root_handlers + [raw])
    root_handlers_with_raw = list(logging.getLogger().handlers)
    compile_ruleset([rule], engine_home=tmp_path / "eng")
    err = capfd.readouterr().err
    assert "\x1b" not in err and "\x07" not in err
    assert "[bold]x Verdict: PASS" in err  # flattened to ONE line, markup untouched
    assert not any(ln.startswith("Verdict") for ln in err.splitlines())
    assert logging.getLogger().handlers == root_handlers_with_raw  # no basicConfig / no new root handler
