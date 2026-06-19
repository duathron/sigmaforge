"""The extracted, reusable backtest pipeline.

`run_backtest_pipeline(cfg)` is the corpus-AGNOSTIC glue lifted from
`scripts/run7_backtest.py::main`: compile/load the ruleset, run the engine over
the attack corpus (recall) and the benign corpus (precision), run the acceptance
gate, score via `orchestrate.run_backtest`, build the generic manifest body, and
render the generic report body. It computes everything a caller needs to rebuild
a run-specific header (the acceptance-gate rows, event counts, measurable counts,
the run hash, the firing rows) WITHOUT inlining any run-specific prose: any
run7/OpTC-specific caveat (e.g. the OpTC Image path-form split) is computed by the
CALLER from the corpus it owns and injected via the report renderer / manifest
merge.

`PipelineConfig` is the pipeline's resolved input dataclass — distinct from the
user-facing `config.BacktestConfig` YAML block; the CLI resolves the latter into
the former.
"""

from __future__ import annotations

import glob
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import yaml

from sigmaforge.ingest.ruleload import partition_rules
from sigmaforge.ingest.zircolite_runner import run_shard
from sigmaforge.orchestrate import run_backtest
from sigmaforge.records import MatchRecord
from sigmaforge.runmanifest import build_manifest, run_hash
from sigmaforge.score.acceptance import GateResult, assert_one_source
from sigmaforge.score.recall import rule_techniques


@dataclass(frozen=True)
class PipelineConfig:
    """Resolved inputs for one backtest run. Module constants the run7 script used
    to hardcode become these fields; the CLI resolves `config.BacktestConfig` into
    this."""

    compiled_ruleset: str  # path to the compiled-from-loaded ruleset JSON
    loaded_rules_glob: str  # glob of the loaded source .yml rules (recall titles)
    attack_corpus: str  # native-EVTX attack corpus dir (recall)
    technique_map: str  # attack_data technique map JSON
    benign_sample: str  # benign corpus JSONL (precision)
    comiset_mapping: str  # COMISET _source -> Sigma field mapping YAML
    evtx_cfg: str  # Zircolite EVTX field-mapping config
    min_events: int = 1000
    source: str = "COMISET"


@dataclass
class BacktestResult:
    """Everything a caller needs to rebuild a run-specific header WITHOUT the
    pipeline inlining prose. `funnel` carries `recall_mode`."""

    rows: list[dict]
    funnel: dict
    manifest: dict
    report_md: str
    run_hash: str
    # COMPUTED provenance the run7 header embeds today:
    acceptance_gate: list[GateResult]  # attack/benign engine/scored/dropped/ok rows
    n_attack_events: int
    technique_event_counts: dict[str, int]
    rules_recall_measurable: int
    rules_precision_measurable: int
    loaded_rule_count: int


def _sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_comiset_field_map(comiset_mapping: str) -> dict[str, str]:
    with open(comiset_mapping) as fh:
        cfg = yaml.safe_load(fh)
    out = {}
    for raw, sigma in (cfg.get("mappings") or {}).items():
        if raw.startswith("_source."):
            out[raw[len("_source.") :]] = sigma
    return out


def _project_event(src: dict, field_map: dict[str, str]) -> dict:
    ev = {}
    for k, v in src.items():
        ev[field_map.get(k, k)] = v
    return ev


def _load_loaded_rules(loaded_rules_glob: str) -> list[dict]:
    rules = []
    for f in glob.glob(loaded_rules_glob):
        with open(f) as fh:
            for doc in yaml.safe_load_all(fh):
                if doc:
                    rules.append(doc)
    loaded, _ = partition_rules(rules)
    return loaded


def run_backtest_pipeline(cfg: PipelineConfig) -> BacktestResult:
    """The lifted body of run7_backtest.main, corpus-agnostic, module constants
    replaced by cfg.*."""
    loaded = _load_loaded_rules(cfg.loaded_rules_glob)
    loaded_titles = {r["title"] for r in loaded}
    n_tagged = sum(1 for r in loaded if rule_techniques(r))

    tmap = json.loads(Path(cfg.technique_map).read_text())
    technique_event_counts = tmap["technique_event_counts"]
    file_technique = tmap["file_technique"]
    n_pc = tmap["total_pc"]

    # --- Recall pass — native-EVTX attack corpus, per-technique ---
    event_technique: dict[str, str] = {}
    attack_fires = run_shard(
        cfg.attack_corpus,
        cfg.compiled_ruleset,
        mapping_path=cfg.evtx_cfg,
        json_input=False,
        xml_input=True,
        corpus_label="malicious",
        file_technique_map=file_technique,
        event_technique_out=event_technique,
    )

    # --- Precision pass — benign corpus, SAME one-source ruleset ---
    benign_fires = run_shard(
        cfg.benign_sample,
        cfg.compiled_ruleset,
        mapping_path=cfg.comiset_mapping,
        json_input=True,
    )

    field_map = _load_comiset_field_map(cfg.comiset_mapping)
    benign_events: list[dict] = []
    with open(cfg.benign_sample) as fh:
        for line in fh:
            doc = json.loads(line)
            src = doc.get("_source", {})
            ev = _project_event(src, field_map)
            ev["sigmaforge_label"] = src.get("sigmaforge_label", "benign")
            benign_events.append(ev)

    n_mal = sum(1 for e in benign_events if e.get("sigmaforge_label") == "malicious")
    n_ben = len(benign_events) - n_mal

    pc_fired = any(f.event_label == "malicious" for f in benign_fires)

    set_attack: set[MatchRecord] = set(attack_fires)
    set_benign: set[MatchRecord] = set(benign_fires)
    gate = assert_one_source(loaded_titles, set_attack, set_benign)

    rows, funnel, report_md = run_backtest(
        loaded_rules=loaded,
        attack_fires=set_attack,
        benign_fires=set_benign,
        benign_events=benign_events,
        n_attack_events=n_pc,
        positive_control_fired=pc_fired,
        min_events=cfg.min_events,
        source=cfg.source,
        event_technique=event_technique,
        technique_event_counts=technique_event_counts,
    )

    n_measurable = sum(1 for r in rows if r["recall_measurable"])
    n_unmeasured = len(rows) - n_measurable
    prec_key = f"precision@{cfg.source}"
    n_prec_measurable = sum(1 for r in rows if isinstance(r.get(prec_key), float))

    rh = run_hash(set_attack | set_benign)

    # Generic, corpus-agnostic manifest body. The caller merges run-specific
    # provenance keys (corpus prose, OpTC slice/path-form provenance, etc.) onto
    # this before writing.
    manifest = build_manifest(
        recommended_precision_floor=max(200, int(0.10 * len(benign_events))),
        ruleset_path=str(cfg.compiled_ruleset),
        ruleset_sha=_sha256_file(cfg.compiled_ruleset),
        loaded_rule_count=len(loaded),
        mapping_path=str(cfg.comiset_mapping),
        mapping_hash=_sha256_file(cfg.comiset_mapping),
        precision_floor=cfg.min_events,
        benign_corpus_path=str(cfg.benign_sample),
        benign_corpus_sha=_sha256_file(cfg.benign_sample),
        benign_eid1_total=len(benign_events),
        benign_label_split={"benign": n_ben, "malicious": n_mal},
        attack_process_creation_events=n_pc,
        recall_technique_map=str(cfg.technique_map),
        recall_technique_map_sha=_sha256_file(cfg.technique_map),
        rules_with_technique_tag=n_tagged,
        rules_recall_measurable=n_measurable,
        rules_recall_unmeasured=n_unmeasured,
        rules_precision_measurable=n_prec_measurable,
        attack_fires=len(set_attack),
        benign_fires=len(set_benign),
        positive_control_fired=pc_fired,
        run_hash=rh,
    )

    return BacktestResult(
        rows=rows,
        funnel=funnel,
        manifest=manifest,
        report_md=report_md,
        run_hash=rh,
        acceptance_gate=gate,
        n_attack_events=n_pc,
        technique_event_counts=technique_event_counts,
        rules_recall_measurable=n_measurable,
        rules_precision_measurable=n_prec_measurable,
        loaded_rule_count=len(loaded),
    )
