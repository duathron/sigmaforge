"""Contract between sigmaforge and the shipwright-kit window it supports."""

import importlib
from importlib.metadata import version

import pytest


def test_locked_kit_is_in_supported_window():
    v = tuple(int(x) for x in version("shipwright-kit").split(".")[:3])
    assert (0, 12, 1) <= v < (0, 13, 0)


@pytest.mark.parametrize(
    ("module", "name"),
    [
        ("shipwright_kit.config", "app_dir"),
        ("shipwright_kit.config", "load_config"),
        ("shipwright_kit.design.banner", "make_banner"),
        ("shipwright_kit.cli", "build_typer"),
        ("shipwright_kit.eval", "EvalResult"),
        ("shipwright_kit.security.render", "safe_render"),
    ],
)
def test_kit_symbols_sigmaforge_uses_exist(module, name):
    assert hasattr(importlib.import_module(module), name)


def test_safe_render_neutralizes_markup():
    render = importlib.import_module("shipwright_kit.security.render")
    assert render.safe_render("[red]x[/red]") != "[red]x[/red]"
