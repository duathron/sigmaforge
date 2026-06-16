"""sigmaforge — CLI entry point."""

from __future__ import annotations

from rich.console import Console
from shipwright_kit.cli import build_typer

from sigmaforge import __version__
from sigmaforge.detect import classify as classify_input

app = build_typer("sigmaforge", "Honest Sigma-rule backtest harness", version=__version__)
console = Console()


@app.command()
def classify(value: str) -> None:
    """Classify an input string (example parse boundary)."""
    console.print(classify_input(value))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
