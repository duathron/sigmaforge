"""sigmaforge — CLI entry point.

Exit-code table (canonical, owned here):
  0 ok · 1 engine-failed · 2 usage/unusable-config · 3 no-engine · 4 no-corpus/missing-inputs · 5 gate-FAIL.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from typing import NoReturn, Optional

import typer
from rich.console import Console
from shipwright_kit.cli import build_typer

from sigmaforge import __version__
from sigmaforge.config import ConfigError
from sigmaforge.engine import EngineNotFoundError, resolve_engine_home
from sigmaforge.ingest.ruleload import RuleLoadError
from sigmaforge.ingest.zircolite_runner import EngineRunError
from sigmaforge.pipeline import InputLoadError
from sigmaforge.safe_text import markup_escape, plain_safe, plain_safe_capped

app = build_typer("sigmaforge", "Honest Sigma-rule backtest harness", version=__version__)
app.pretty_exceptions_show_locals = False  # a traceback must never dump locals (rule text, paths)
console = Console(emoji=False)


def _rich_safe(x: object) -> str:
    """Untrusted single-line text for a Rich markup sink: line breaks and tabs flattened to a
    space (no forged output lines), control/ANSI/bidi stripped, then markup escaped.
    Not `safe_render(x)` alone: that doubles backslashes (Windows paths) on the console.
    Print the result with `soft_wrap=True` so Rich cannot re-wrap it into a new line start."""
    return markup_escape(plain_safe(x))


@app.command()
def manual() -> None:
    """Show the sigmaforge manual (bundled CLI reference)."""
    from importlib.resources import files

    from rich.markdown import Markdown

    text = files("sigmaforge").joinpath("MANUAL.md").read_text(encoding="utf-8")
    console.print(Markdown(text))


def _err_safe(x: object) -> str:
    """An untrusted ERROR message for a Rich sink: single line, sanitized, capped at 600 characters
    (a multi-megabyte message must not hang the console)."""
    return markup_escape(plain_safe_capped(x))


def _output_refused(path: object, reason: str) -> NoReturn:
    """The output location cannot be written. A bad `--out` is a usage error (exit 2)."""
    console.print(f"[red]Cannot write output[/red] {_err_safe(path)}: {reason}", soft_wrap=True, highlight=False)
    raise typer.Exit(2) from None


def _name_max(parent: Path) -> int:
    try:
        return os.pathconf(parent, "PC_NAME_MAX")
    except (OSError, ValueError, AttributeError):
        return 255


def _target_state(t: Path) -> str:
    """'ok' (a regular file, or absent and creatable), or the reason it is refused. Symlinks are
    FOLLOWED: the final target must be a regular file or must not exist (a dangling link is refused)."""
    try:
        st = os.stat(t)
    except FileNotFoundError:
        return "not a regular file" if os.path.islink(t) else "ok"
    if stat.S_ISDIR(st.st_mode):
        return "is a directory"
    if not stat.S_ISREG(st.st_mode):  # FIFO, device (/dev/null), socket
        return "not a regular file"
    return "ok" if os.access(t, os.W_OK) else "not writable"


def _check_output(out: str, sibling_suffix: str | None = None) -> Path:
    """Verify the output location BEFORE the (long) run: refuse an empty/root name, a non-regular
    target (directory, FIFO, device, socket, dangling link), an unwritable parent or file, and a name
    longer than the filesystem allows. A short probe file proves the directory is writable (the
    stdlib removes it on close). Returns the output path."""
    path = Path(out)
    try:
        if path.name in ("", ".."):  # Path(".") and Path("/") have the name ""
            _output_refused(out, "no file name")
        targets = [path] + ([path.with_suffix(sibling_suffix)] if sibling_suffix else [])
        parent = path.parent if str(path.parent) else Path(".")
        parent.mkdir(parents=True, exist_ok=True)
        limit = _name_max(parent)
        if any(len(os.fsencode(t.name)) > limit for t in targets):
            _output_refused(out, "name too long")
        states = [_target_state(t) for t in targets]
        for state in states:
            if state != "ok":
                _output_refused(out, state)
        if not all(os.path.exists(t) for t in targets):
            # a file still to be created needs a writable directory; when every target already exists
            # (and passed the regular-file and writable checks above) the directory itself may be read-only
            with tempfile.NamedTemporaryFile(dir=parent, prefix=".sigmaforge-probe-"):
                pass
    except (OSError, ValueError):
        _output_refused(out, "not writable")
    return path


def _write_output(path: Path, text: str, encoding: str = "utf-8", errors: str = "strict") -> None:
    """Write one output file; a failure is one value-free line (exit 2), never a traceback or a hang.
    The file is opened non-blocking and checked with fstat BEFORE it is truncated, so a FIFO swapped in
    after the preflight is refused instead of blocking. Symlinks are followed (as in the preflight)."""
    try:
        data = text.encode(encoding, errors)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0), 0o644)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                _output_refused(path, "not a regular file")
            os.ftruncate(fd, 0)
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
        finally:
            os.close(fd)
    except (OSError, ValueError):
        _output_refused(path, "not writable")


def _engine_refused(err: Exception) -> NoReturn:
    """The engine could not be used safely (e.g. a foreign `zircolite` already imported)."""
    console.print(f"[red]Detection engine refused[/red]: {_err_safe(err)}", soft_wrap=True, highlight=False)
    console.print("Point --engine-home / SIGMAFORGE_HOME at the engine root, in a fresh process.")
    raise typer.Exit(3) from None


def _engine_failed(err: Exception) -> NoReturn:
    """The engine ran but failed. Its output is captured, never streamed; show a short tail."""
    console.print(f"[red]Detection engine failed[/red]: {_err_safe(err)}", soft_wrap=True, highlight=False)
    raise typer.Exit(1) from None


def _load_cfg(config: Optional[str]):
    """Resolve the config; a broken config file is ONE clean line (exit 2), never a traceback."""
    from sigmaforge.config import load as load_config

    try:
        return load_config(Path(config) if config else None)
    except ConfigError as e:
        console.print(
            f"[red]Cannot load config file[/red] {_rich_safe(e.path)}: {_err_safe(e)}", soft_wrap=True, highlight=False
        )
        raise typer.Exit(2) from None


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

    from sigmaforge.pipeline import PipelineConfig, run_backtest_pipeline

    cfg = _load_cfg(config)
    bt = cfg.backtest

    # Resolve effective inputs: flags > config > None.
    r_rules = rules or bt.rules
    r_attack = attack_corpus or bt.attack_corpus
    r_technique_map = technique_map or bt.technique_map
    r_benign = benign_sample or bt.benign_sample
    r_mapping = comiset_mapping or bt.comiset_mapping
    r_engine_home = engine_home if engine_home is not None else bt.engine_home
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
    engine_root = resolve_engine_home(r_engine_home)
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

    out_path = _check_output(out, ".manifest.json")

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
        engine_home=str(engine_root),
    )

    try:
        res = run_backtest_pipeline(pcfg)
    except EngineNotFoundError as e:
        _engine_refused(e)
    except EngineRunError as e:
        _engine_failed(e)
    except RuleLoadError as e:
        console.print(
            f"[red]Cannot load rule file[/red] {_rich_safe(e.path)}: {_err_safe(e)}", soft_wrap=True, highlight=False
        )
        raise typer.Exit(4) from None
    except InputLoadError as e:
        console.print(
            f"[red]Cannot load {e.what}[/red] {_rich_safe(e.path)}: {_err_safe(e)}", soft_wrap=True, highlight=False
        )
        raise typer.Exit(4) from None
    except AssertionError as e:
        # FIX H acceptance gate FAILED — a real engine/scored discrepancy. Surface as the
        # canonical gate-FAIL exit code, not a traceback.
        console.print(f"[red]Acceptance gate FAILED[/red]: {_err_safe(e)}", soft_wrap=True, highlight=False)
        raise typer.Exit(5) from None

    # Never silently pooled-recall: refuse a run that fell back to the pooled denominator.
    if res.funnel.get("recall_mode") == "pooled":
        console.print(
            "[red]Refusing a pooled-recall backtest[/red] — per-technique inputs (technique map + "
            "event-technique join) were absent, so recall would be pooled over the whole corpus "
            "(a recall-side tautology). Provide a technique map to measure per-technique recall."
        )
        raise typer.Exit(4)

    # backslashreplace: text that cannot be encoded (a lone surrogate) is written as an escape instead of
    # crashing after the whole engine run, and the report stays complete (no new exit code, no lost run)
    _write_output(out_path, res.report_md, encoding="utf-8", errors="backslashreplace")
    manifest_path = out_path.with_suffix(".manifest.json")
    _write_output(manifest_path, json.dumps(res.manifest, indent=2, sort_keys=True))
    console.print(f"report written: {_rich_safe(out_path)}", soft_wrap=True)
    console.print(f"manifest written: {_rich_safe(manifest_path)}", soft_wrap=True)
    console.print(
        f"loaded={res.loaded_rule_count} recall-measurable={res.rules_recall_measurable} "
        f"precision-measurable={res.rules_precision_measurable} run_hash={res.run_hash}"
    )


_HUNT_BANNER = "hits only — NOT a quality measurement (logs are unlabeled)"
_HUNT_UNMEASURED = "unmeasured — unlabeled corpus"


def _is_evtx_logs(logs: Path) -> bool:
    """Detect whether `logs` is EVTX (-> xml/evtx input) or JSON.

    EVTX when the path (or, for a dir, any file under it) is a .evtx/.xml file;
    otherwise JSON (.json/.jsonl). A dir wins on its first EVTX file."""
    suffixes = {".evtx", ".xml"}
    if logs.is_dir():
        return any(p.suffix.lower() in suffixes for p in logs.rglob("*") if p.is_file())
    return logs.suffix.lower() in suffixes


@app.command()
def hunt(
    rules: str = typer.Option(..., help="Source Sigma rules (.yml file OR dir)."),
    logs: str = typer.Option(..., help="Logs to hunt over (EVTX/XML or JSON, file OR dir)."),
    out: str = typer.Option("hits.json", help="Hits output path."),
    engine_home: Optional[str] = typer.Option(None, help="Engine root containing Zircolite/zircolite.py."),
    config: Optional[str] = typer.Option(None, help="Path to a sigmaforge config YAML (engine override)."),
) -> None:
    """Run Sigma rules against ARBITRARY (unlabeled) logs and report HITS ONLY.

    The pip-only path: needs the vendored engine but NO labeled corpora. Because the
    logs are unlabeled, precision/recall are structurally UNMEASURED — the output is a
    hit list, NOT a quality measurement. For measured recall/precision use
    `sigmaforge backtest` against labeled corpora.
    """
    import json
    import tempfile
    from collections import Counter

    from sigmaforge.ingest.compile import compile_ruleset
    from sigmaforge.ingest.zircolite_runner import run_shard

    cfg = _load_cfg(config)

    # --- Preflight: engine resolvable? (no corpora required — this is the pip path) ---
    engine_root = resolve_engine_home(engine_home if engine_home is not None else cfg.backtest.engine_home)
    if engine_root is None:
        console.print(
            "[red]Detection engine not found[/red] — `hunt` needs the vendored Zircolite "
            "engine (Zircolite/zircolite.py) which is not bundled in the pip package."
        )
        console.print(
            "Fetch + install it with [bold]`bash scripts/setup_engine.sh`[/bold] (run from the repo "
            "root), or point --engine-home / SIGMAFORGE_HOME at the engine root."
        )
        raise typer.Exit(3)

    out_path = _check_output(out)

    rules_path = Path(rules)
    rule_files = sorted(rules_path.rglob("*.yml")) if rules_path.is_dir() else [rules_path]

    # compile_ruleset returns an IN-MEMORY list[dict]; run_shard needs a ruleset FILE.
    try:
        compiled, _n_staged = compile_ruleset(rule_files, engine_home=str(engine_root))
    except EngineNotFoundError as e:
        _engine_refused(e)
    except EngineRunError as e:  # EngineCompileError: the in-process compile raised
        _engine_failed(e)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(compiled, fh)
        ruleset_path = fh.name

    # Engine field-mapping config: the `--config` file's `backtest.comiset_mapping`
    # override (e.g. a COMISET _source->Sigma map for ES-shaped JSON), else the
    # engine's own bundled field-mapping config so the engine always has one.
    mapping_path = cfg.backtest.comiset_mapping or str(engine_root / "Zircolite" / "config" / "fieldMappings.yaml")

    logs_path = Path(logs)
    evtx = _is_evtx_logs(logs_path)
    try:
        matches = run_shard(
            str(logs_path),
            ruleset_path,
            mapping_path=mapping_path,
            json_input=not evtx,
            xml_input=evtx,
            engine_home=str(engine_root),
        )
    except EngineRunError as e:
        _engine_failed(e)

    counts = Counter((m.rule_id, m.event_id) for m in matches)
    hits = [{"rule_id": rid, "event_id": eid, "count": n} for (rid, eid), n in sorted(counts.items())]

    result = {
        "banner": _HUNT_BANNER,
        "precision": _HUNT_UNMEASURED,
        "recall": _HUNT_UNMEASURED,
        "rules_compiled": len(compiled),
        "hit_count": len(hits),
        "hits": hits,
    }
    _write_output(out_path, json.dumps(result, indent=2, sort_keys=True))

    console.print(f"[yellow]{_HUNT_BANNER}[/yellow]")
    console.print(
        f"hits written: {_rich_safe(out_path)} ({len(hits)} hit(s), {len(compiled)} rule(s) compiled)",
        soft_wrap=True,
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
