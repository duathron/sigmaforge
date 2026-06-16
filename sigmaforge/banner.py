"""sigmaforge banner — uses the Shipwright design system."""

from __future__ import annotations

import sys

from shipwright_kit.design.banner import make_banner

from sigmaforge import __version__


def show_banner(*, quiet: bool = False) -> None:
    if quiet or not sys.stderr.isatty():
        return
    print(make_banner("sigmaforge", __version__, "Honest Sigma-rule backtest harness"), file=sys.stderr)
