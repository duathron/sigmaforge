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


def _run(tmp_path, monkeypatch):
    from sigmaforge.ingest.compile import compile_ruleset

    _engine(tmp_path / "eng", HOSTILE)
    rule = tmp_path / "a.yml"
    rule.write_text("title: a\n")
    monkeypatch.delenv("SIGMAFORGE_HOME", raising=False)
    compile_ruleset([rule], engine_home=tmp_path / "eng")


def test_compile_does_not_configure_the_root_logger(tmp_path, monkeypatch, clean_modules):
    import logging

    monkeypatch.setattr(logging.getLogger(), "handlers", [])
    _run(tmp_path, monkeypatch)
    assert logging.getLogger().handlers == []


def test_engine_log_lines_are_sanitized_even_with_a_raw_root_handler(tmp_path, monkeypatch, capfd, clean_modules):
    import logging

    raw = logging.StreamHandler(sys.stderr)  # a raw root handler must not see engine records
    monkeypatch.setattr(logging.getLogger(), "handlers", [raw])
    _run(tmp_path, monkeypatch)
    err = capfd.readouterr().err
    assert "\x1b" not in err and "\x07" not in err
    assert "[bold]x Verdict: PASS" in err  # flattened to ONE line, markup untouched
    assert not any(ln.startswith("Verdict") for ln in err.splitlines())


@pytest.mark.parametrize("name", ["sigma", "sigma.backends.sqlite", "pysigma.x", "pySigma", "zircolite.rules"])
def test_other_engine_namespaces_are_sanitized_not_lastresort(tmp_path, monkeypatch, capfd, clean_modules, name):
    import logging

    monkeypatch.setattr(logging.getLogger(), "handlers", [])
    _run(tmp_path, monkeypatch)
    capfd.readouterr()
    logging.getLogger(name).warning("w \x1b]0;PWN\x07\nVerdict: PASS %s", "\x1b[41m")
    err = capfd.readouterr().err
    assert "\x1b" not in err and "\x07" not in err
    assert err.splitlines() == ["w  Verdict: PASS "], err
    assert logging.getLogger().handlers == []


# --- every other in-process channel (lastResort, root logging, warnings, print) ---------------

EVIL = "e \x1b]0;PWN\x07\x1b[41m\x9b31m\nPASS forged"
CHANNELS = {
    "C_lastresort": "logging.getLogger('some.other.lib').warning(%r)",
    "C2_lastresort_no_propagate": (
        "lg = logging.getLogger('np.' + uuid.uuid4().hex); lg.propagate = False; lg.warning(%r)"
    ),
    "D_root": "logging.warning(%r)",
    "E_warnings": "warnings.warn(%r)",
    "F_print": "print(%r)",
    "G_print_stderr": "print(%r, file=sys.stderr)",
}


def _channel_engine(root, body, then=""):
    pkg = root / "Zircolite" / "zircolite"
    pkg.mkdir(parents=True)
    (root / "Zircolite" / "zircolite.py").write_text("")
    (pkg / "__init__.py").write_text("")
    (pkg / "config.py").write_text("class RulesetConfig:\n    def __init__(self, **k):\n        pass\n")
    (pkg / "rules.py").write_text(
        "import logging, sys, uuid, warnings\n"
        "class RulesetHandler:\n"
        "    def __init__(self, ruleset_config, logger):\n"
        f"        {body}\n"
        f"        {then}\n"
        "        self.rulesets = []\n"
    )


def _compile(tmp_path, monkeypatch, body, then=""):
    from sigmaforge.ingest.compile import compile_ruleset

    _channel_engine(tmp_path / "eng", body, then)
    rule = tmp_path / "a.yml"
    rule.write_text("title: a\n")
    monkeypatch.delenv("SIGMAFORGE_HOME", raising=False)
    return compile_ruleset([rule], engine_home=tmp_path / "eng")


def _assert_clean(cap):
    for text in (cap.out, cap.err):
        assert "\x1b" not in text and "\x07" not in text
        assert not any(0x80 <= ord(c) <= 0x9F for c in text)
        assert not any(ln.startswith("PASS") for ln in text.splitlines())


@pytest.mark.parametrize("channel", sorted(CHANNELS))
def test_every_in_process_channel_is_clean_on_success(tmp_path, monkeypatch, capfd, clean_modules, channel):
    import logging

    root_handlers, last_resort = list(logging.getLogger().handlers), logging.lastResort
    _compile(tmp_path, monkeypatch, CHANNELS[channel] % EVIL)
    _assert_clean(capfd.readouterr())
    assert logging.getLogger().handlers == root_handlers and logging.lastResort is last_resort


def test_logging_channels_still_surface_sanitized_text(tmp_path, monkeypatch, capfd, clean_modules):
    _compile(tmp_path, monkeypatch, CHANNELS["C_lastresort"] % EVIL, CHANNELS["D_root"] % EVIL)
    err = capfd.readouterr().err
    assert err.splitlines() == ["e 31m PASS forged"] * 2


@pytest.mark.parametrize("channel", sorted(CHANNELS))
def test_failure_reemits_a_sanitized_tail_and_restores_state(tmp_path, monkeypatch, capfd, clean_modules, channel):
    import logging

    root_handlers, last_resort = list(logging.getLogger().handlers), logging.lastResort
    with pytest.raises(RuntimeError):
        _compile(tmp_path, monkeypatch, CHANNELS[channel] % EVIL, "raise RuntimeError('boom')")
    cap = capfd.readouterr()
    _assert_clean(cap)
    assert "PASS forged" in cap.err
    assert logging.getLogger().handlers == root_handlers and logging.lastResort is last_resort


def test_failure_tail_is_bounded(tmp_path, monkeypatch, capfd, clean_modules):
    body = "print(*[f'LINE{i:02d}' + 'q' * 300 for i in range(20)], sep='\\n', file=sys.stderr)"
    with pytest.raises(RuntimeError):
        _compile(tmp_path, monkeypatch, body, "raise RuntimeError('x')")
    err = capfd.readouterr().err
    assert len(err.splitlines()) <= 5 and err.count("q") <= 600 and "LINE19" in err


def test_failure_tail_prefers_stderr_over_stdout(tmp_path, monkeypatch, capfd, clean_modules):
    with pytest.raises(RuntimeError):
        _compile(
            tmp_path, monkeypatch, "print('FROM_OUT'); print('FROM_ERR', file=sys.stderr)", "raise RuntimeError('x')"
        )
    err = capfd.readouterr().err
    assert "FROM_ERR" in err and "FROM_OUT" not in err


def test_compile_loaded_ruleset_logger_is_sanitized_at_warning(tmp_path, monkeypatch, capfd, clean_modules):
    _compile(tmp_path, monkeypatch, "pass")
    import logging

    capfd.readouterr()
    logging.getLogger("compile_loaded_ruleset").warning("w \x1b]0;PWN\x07\nPASS forged")
    assert capfd.readouterr().err.splitlines() == ["w  PASS forged"]


def test_basicconfig_is_not_re_added_after_the_engine_logger(tmp_path, monkeypatch, clean_modules):
    import logging

    monkeypatch.setattr(logging.getLogger(), "handlers", [])
    _compile(tmp_path, monkeypatch, "logging.warning('x')")
    assert logging.getLogger().handlers == []


def test_lastresort_records_surface_sanitized(tmp_path, monkeypatch, capfd, clean_modules):
    _compile(tmp_path, monkeypatch, CHANNELS["C2_lastresort_no_propagate"] % EVIL)
    assert capfd.readouterr().err.splitlines() == ["e 31m PASS forged"]
