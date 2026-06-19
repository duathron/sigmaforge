"""sigmaforge — CLI entry point.

Exit-code table (canonical, owned here):
  0 ok · 2 usage · 3 no-engine · 4 no-corpus/missing-inputs · 5 gate-FAIL.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from shipwright_kit.cli import build_typer

from sigmaforge import __version__

app = build_typer("sigmaforge", "Honest Sigma-rule backtest harness", version=__version__)
console = Console()


def _resolve_engine_home(engine_home: Optional[str]) -> Optional[Path]:
    """Locate the vendored Zircolite engine and return the root containing
    ``Zircolite/zircolite.py``, or None if unresolvable.

    If ``engine_home`` is given explicitly it is the ONLY candidate (an explicit
    wrong path must fail, not silently fall back). Otherwise: SIGMAFORGE_HOME > cwd."""
    if engine_home:
        candidates = [Path(engine_home)]
    else:
        candidates = []
        if os.environ.get("SIGMAFORGE_HOME"):
            candidates.append(Path(os.environ["SIGMAFORGE_HOME"]))
        candidates.append(Path.cwd())
    for root in candidates:
        if (root / "Zircolite" / "zircolite.py").exists():
            return root
    return None


@app.command()
def backtest(
    rules: Optional[str] = typer.Option(None, help="Source Sigma rules (.yml file OR dir). Default from config."),
    attack_corpus: Optional[str] = typer.Option(None, help="Native-EVTX attack corpus dir (recall)."),
    technique_map: Optional[str] = typer.Option(None, help="attack_data technique map JSON."),
    benign_sample: Optional[str] = typer.Option(None, help="Benign corpus JSONL (precision)."),
    comiset_mapping: Optional[str] = typer.Option(None, help="COMISET _source -> Sigma field mapping YAML."),
    engine_home: Optional[str] = typer.Option(None, help="Engine root containing Zircolite/zircolite.py."),
    config: Optional[str] = typer.Option(None, help="Path to a sigmaforge config YAML."),
    out: str = typer.Option("reports/run.md", help="Report output path."),
    floor: Optional[int] = typer.Option(None, help="Override the precision scoring floor."),
) -> None:
    """Backtest Sigma rules against LABELED corpora: per-technique recall + label-aware
    precision@COMISET + honesty gates + report + manifest (run7-equivalent).

    Requires the vendored engine AND labeled corpora. With nothing configured this
    teaches what to run (exit 4) and points you at `sigmaforge hunt` (which needs no
    corpora). Never silently pooled-recall: a run without per-technique inputs is refused.
    """
    import json

    from sigmaforge.config import load as load_config
    from sigmaforge.pipeline import PipelineConfig, run_backtest_pipeline

    cfg = load_config(Path(config) if config else None)
    bt = cfg.backtest

    # Resolve effective inputs: flags > config > None.
    r_rules = rules or bt.rules
    r_attack = attack_corpus or bt.attack_corpus
    r_technique_map = technique_map or bt.technique_map
    r_benign = benign_sample or bt.benign_sample
    r_mapping = comiset_mapping or bt.comiset_mapping
    r_engine_home = engine_home or bt.engine_home
    r_floor = floor if floor is not None else bt.floor

    # --- Preflight: corpus/inputs FIRST (no corpus -> go to hunt, regardless of engine) ---
    missing = [
        name
        for name, val in (
            ("--rules", r_rules),
            ("--attack-corpus", r_attack),
            ("--technique-map", r_technique_map),
            ("--benign-sample", r_benign),
        )
        if not val
    ]
    if missing:
        console.print(
            "[red]No labeled corpus configured[/red] — `backtest` measures rules against a "
            "LABELED attack + benign corpus, and these inputs are unset: " + ", ".join(missing) + "."
        )
        console.print(
            "To build the corpora: run the corpus-build scripts (e.g. "
            "`scripts/build_attack_data_corpus.py`, `scripts/build_optc_benign.py`) and the engine "
            "via `scripts/setup_engine.sh`, or set them in your config / pass the flags above."
        )
        console.print(
            "If you just want to run rules against arbitrary (unlabeled) logs — no corpus needed — "
            "use [bold]`sigmaforge hunt`[/bold] instead."
        )
        raise typer.Exit(4)

    # --- Preflight: engine resolvable? ---
    engine_root = _resolve_engine_home(r_engine_home)
    if engine_root is None:
        console.print(
            "[red]Detection engine not found[/red] — `backtest` needs the vendored Zircolite "
            "engine (Zircolite/zircolite.py) which is not bundled in the pip package."
        )
        console.print(
            "Fetch + install it with [bold]`bash scripts/setup_engine.sh`[/bold] (run from the repo "
            "root), or point --engine-home / SIGMAFORGE_HOME at the engine root."
        )
        raise typer.Exit(3)

    evtx_cfg = str(engine_root / "Zircolite" / "config" / "fieldMappings.yaml")
    # The engine consumes a COMPILED ruleset JSON. C3.1 lifts an in-process compiler;
    # until then resolve a pre-compiled ruleset: a .json `rules` IS the compiled ruleset,
    # otherwise treat `rules` as the loaded-source glob and reuse it (the pipeline globs .yml).
    compiled_ruleset = r_rules
    loaded_rules_glob = r_rules

    pcfg = PipelineConfig(
        compiled_ruleset=compiled_ruleset,
        loaded_rules_glob=loaded_rules_glob,
        attack_corpus=r_attack,
        technique_map=r_technique_map,
        benign_sample=r_benign,
        comiset_mapping=r_mapping or evtx_cfg,
        evtx_cfg=evtx_cfg,
        min_events=r_floor,
    )

    try:
        res = run_backtest_pipeline(pcfg)
    except AssertionError as e:
        # FIX H acceptance gate FAILED — a real engine/scored discrepancy. Surface as the
        # canonical gate-FAIL exit code, not a traceback.
        console.print(f"[red]Acceptance gate FAILED[/red]: {e}")
        raise typer.Exit(5) from None

    # Never silently pooled-recall: refuse a run that fell back to the pooled denominator.
    if res.funnel.get("recall_mode") == "pooled":
        console.print(
            "[red]Refusing a pooled-recall backtest[/red] — per-technique inputs (technique map + "
            "event-technique join) were absent, so recall would be pooled over the whole corpus "
            "(a recall-side tautology). Provide a technique map to measure per-technique recall."
        )
        raise typer.Exit(4)

    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(res.report_md)
    manifest_path = out_path.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(res.manifest, indent=2, sort_keys=True))
    console.print(f"report written: {out_path}")
    console.print(f"manifest written: {manifest_path}")
    console.print(
        f"loaded={res.loaded_rule_count} recall-measurable={res.rules_recall_measurable} "
        f"precision-measurable={res.rules_precision_measurable} run_hash={res.run_hash}"
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
