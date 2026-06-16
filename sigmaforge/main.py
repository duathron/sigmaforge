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


@app.command()
def backtest(
    rules: str,
    attack: str,
    benign: str,
    out: str,
    mapping: str = "data/mappings/comiset.yaml",
    workers: int = 4,
    min_events: int = 1000,
    attack_events: int = 0,
) -> None:
    """Backtest Sigma rules: recall on the native-EVTX attack corpus, precision@COMISET on
    the benign corpus. Writes the FP-tuning report to OUT. (Live end-to-end run; meaningful
    precision numbers require the COMISET benign sample.)"""
    import json
    from pathlib import Path

    import yaml

    from sigmaforge.ingest.ruleload import partition_rules
    from sigmaforge.ingest.zircolite_runner import run_shard
    from sigmaforge.orchestrate import run_backtest

    rule_docs = [
        doc
        for p in Path(rules).rglob("*.yml")
        for doc in [yaml.safe_load(p.read_text())]
        if isinstance(doc, dict) and doc.get("title")
    ]
    loaded, _excluded = partition_rules(rule_docs)
    benign_events = [json.loads(line) for line in Path(benign).read_text().splitlines()]
    attack_fires = set(run_shard(attack, rules, json_input=False, corpus_label="malicious"))
    benign_fires = set(run_shard(benign, rules, mapping_path=mapping, json_input=True))
    pc_fired = any(f.event_label == "malicious" for f in benign_fires)
    _rows, _funnel, md = run_backtest(
        loaded,
        attack_fires,
        benign_fires,
        benign_events,
        n_attack_events=attack_events,  # attack-corpus event count = recall denominator (provide via --attack-events)
        positive_control_fired=pc_fired,
        min_events=min_events,
    )
    Path(out).write_text(md)
    console.print(f"report written: {out}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
