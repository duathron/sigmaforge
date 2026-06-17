#!/usr/bin/env python3
"""run6 backtest -> reports/run6.md — PRECISION corpus AUGMENTED with DARPA OpTC benign.

Builds on run5 (FIX B3 sub-technique recall; run5.md/run5_manifest.json PRESERVED).
The RECALL pass is byte-for-byte identical to run5. The ONLY change is the PRECISION
(benign) corpus: run5's `combined_benign_sample.jsonl` (COMISET real slice +
NextronSystems/evtx-baseline) is EXTENDED with DARPA OpTC benign-week process-creation
telemetry (scripts/build_optc_benign.py) for VOLUME + real enterprise diversity, so
MORE loaded rules clear the precision floor and become precision-measurable.

OpTC (FiveDirections/OpTC-data, public domain / Distribution A) has a dedicated benign
collection period (Sept 17-23 2019) across ~1000 real enterprise hosts BEFORE any
red-team activity — every process-creation record there is benign BY CONSTRUCTION. The
eCAR JSON is reshaped into the SAME COMISET _source envelope the rest of the benign
corpus uses, so the single comiset.yaml mapping + project_event path handle it uniformly.

PRECONDITION: the augmented corpus must exist at BENIGN_SAMPLE (see below). Build it with:
  python scripts/build_optc_benign.py \
      --ecar ~/sigmaforge-v0/optc/AIA-201-225.ecar-last.json.gz \
      --append data/comiset/combined_benign_sample.jsonl \
      --out  data/comiset/combined_optc_benign_sample.jsonl \
      --max-eid1 0

Engine: vendored Zircolite 3.7.6, SAME compiled-from-loaded ruleset both passes.
"""

from __future__ import annotations

import glob
import hashlib
import json
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from sigmaforge.ingest.ruleload import partition_rules  # noqa: E402
from sigmaforge.ingest.zircolite_runner import run_shard  # noqa: E402
from sigmaforge.orchestrate import run_backtest  # noqa: E402
from sigmaforge.runmanifest import build_manifest, run_hash  # noqa: E402
from sigmaforge.score.acceptance import assert_one_source  # noqa: E402
from sigmaforge.score.recall import rule_techniques  # noqa: E402

COMPILED_RULESET = str(REPO / "data" / "rulesets" / "sigmaforge_loaded.json")
COMISET_MAPPING = str(REPO / "data" / "mappings" / "comiset.yaml")
EVTX_DEFAULT_CFG = str(REPO / "Zircolite" / "config" / "fieldMappings.yaml")
# recall corpus + technique map: UNCHANGED from run5 (FIX B3)
RECALL_CORPUS = str(Path.home() / "sigmaforge-v0" / "attack_data_corpus")
TECHNIQUE_MAP = REPO / "data" / "comiset" / "attack_data_technique_map.json"
# PRECISION corpus: run5 combined corpus EXTENDED with OpTC benign-week telemetry.
BENIGN_SAMPLE = str(REPO / "data" / "comiset" / "combined_optc_benign_sample.jsonl")
# run5's precision corpus, for the before/after comparison.
BENIGN_BASELINE = str(REPO / "data" / "comiset" / "combined_benign_sample.jsonl")
REPORT_OUT = REPO / "reports" / "run6.md"
MANIFEST_OUT = REPO / "reports" / "run6_manifest.json"
MIN_EVENTS = 1000
ZIRCOLITE_VERSION = "3.7.6"
LEVELS = ("high", "critical")


def _sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_comiset_field_map() -> dict[str, str]:
    with open(COMISET_MAPPING) as fh:
        cfg = yaml.safe_load(fh)
    out = {}
    for raw, sigma in (cfg.get("mappings") or {}).items():
        if raw.startswith("_source."):
            out[raw[len("_source.") :]] = sigma
    return out


def project_event(src: dict, field_map: dict[str, str]) -> dict:
    ev = {}
    for k, v in src.items():
        ev[field_map.get(k, k)] = v
    return ev


def load_loaded_rules() -> list[dict]:
    rules = []
    for f in glob.glob(str(REPO / "sigma/rules/windows/process_creation/*.yml")):
        with open(f) as fh:
            for doc in yaml.safe_load_all(fh):
                if doc:
                    rules.append(doc)
    loaded, _ = partition_rules(rules)
    return loaded


def _count_eid1(path: str) -> int:
    if not Path(path).exists():
        return 0
    n = 0
    with open(path) as fh:
        for line in fh:
            if line.strip():
                n += 1
    return n


def main() -> int:
    if not Path(COMPILED_RULESET).exists():
        print(f"[FATAL] {COMPILED_RULESET} missing. Run scripts/compile_loaded_ruleset.py first.", flush=True)
        return 2
    if not TECHNIQUE_MAP.exists():
        print(f"[FATAL] {TECHNIQUE_MAP} missing. Run scripts/build_attack_data_corpus.py first.", flush=True)
        return 2
    if not Path(BENIGN_SAMPLE).exists():
        print(
            f"[FATAL] {BENIGN_SAMPLE} missing. Build it with scripts/build_optc_benign.py "
            "(see this script's docstring).",
            flush=True,
        )
        return 2

    loaded = load_loaded_rules()
    loaded_titles = {r["title"] for r in loaded}
    print(f"[loaded] {len(loaded)} high+critical stateless process_creation rules", flush=True)

    n_tagged = sum(1 for r in loaded if rule_techniques(r))
    print(f"[rule->technique] {n_tagged}/{len(loaded)} rules carry a usable ATT&CK technique tag", flush=True)

    tmap = json.loads(TECHNIQUE_MAP.read_text())
    technique_event_counts = tmap["technique_event_counts"]
    file_technique = tmap["file_technique"]
    n_pc = tmap["total_pc"]

    base_eid1 = _count_eid1(BENIGN_BASELINE)
    aug_eid1 = _count_eid1(BENIGN_SAMPLE)
    print(
        f"[precision] benign corpus: run5 baseline={base_eid1} -> run6 OpTC-augmented={aug_eid1} "
        f"(+{aug_eid1 - base_eid1} OpTC EID-1)",
        flush=True,
    )

    # --- Recall pass — IDENTICAL to run5 (FIX B3) ---
    print("[recall] running Zircolite on the sub-technique attack_data corpus (loaded ruleset) ...", flush=True)
    event_technique: dict[str, str] = {}
    attack_fires = run_shard(
        RECALL_CORPUS,
        COMPILED_RULESET,
        mapping_path=EVTX_DEFAULT_CFG,
        json_input=False,
        xml_input=True,
        corpus_label="malicious",
        file_technique_map=file_technique,
        event_technique_out=event_technique,
    )
    print(
        f"[recall] attack_fires={len(attack_fires)}; fired events with a technique={len(event_technique)}",
        flush=True,
    )

    # --- Precision pass — OpTC-AUGMENTED benign corpus, SAME one-source ruleset ---
    print("[precision] running Zircolite on OpTC-augmented benign corpus (loaded ruleset) ...", flush=True)
    benign_fires = run_shard(BENIGN_SAMPLE, COMPILED_RULESET, mapping_path=COMISET_MAPPING, json_input=True)
    print(f"[precision] benign_fires={len(benign_fires)}", flush=True)

    field_map = load_comiset_field_map()
    benign_events = []
    with open(BENIGN_SAMPLE) as fh:
        for line in fh:
            doc = json.loads(line)
            src = doc.get("_source", {})
            ev = project_event(src, field_map)
            ev["sigmaforge_label"] = src.get("sigmaforge_label", "benign")
            benign_events.append(ev)

    n_mal = sum(1 for e in benign_events if e.get("sigmaforge_label") == "malicious")
    n_ben = len(benign_events) - n_mal
    print(f"[precision] benign_events={len(benign_events)} malicious={n_mal} benign={n_ben}", flush=True)

    pc_fired = any(f.event_label == "malicious" for f in benign_fires)
    print(f"[positive-control] fired={pc_fired}", flush=True)

    set_attack, set_benign = set(attack_fires), set(benign_fires)
    gate = assert_one_source(loaded_titles, set_attack, set_benign)
    for g in gate:
        print(f"[gate] {g.reason()}", flush=True)

    rows, funnel, report_md = run_backtest(
        loaded_rules=loaded,
        attack_fires=set_attack,
        benign_fires=set_benign,
        benign_events=benign_events,
        n_attack_events=n_pc,
        positive_control_fired=pc_fired,
        min_events=MIN_EVENTS,
        source="COMISET",
        event_technique=event_technique,
        technique_event_counts=technique_event_counts,
    )

    n_measurable = sum(1 for r in rows if r["recall_measurable"])
    n_unmeasured = len(rows) - n_measurable
    # precision-measurable = the precision floor was cleared (precision is a float, not "unmeasured")
    prec_key = "precision@COMISET"
    n_prec_measurable = sum(1 for r in rows if isinstance(r.get(prec_key), float))
    print(
        f"[recall] measurable={n_measurable} unmeasured={n_unmeasured}; "
        f"[precision] precision-measurable rules={n_prec_measurable}",
        flush=True,
    )

    attack_gate = next(g for g in gate if g.corpus == "attack")
    benign_gate = next(g for g in gate if g.corpus == "benign")

    rh = run_hash(set_attack | set_benign)
    manifest = build_manifest(
        recommended_precision_floor=max(200, int(0.10 * len(benign_events))),
        zircolite_version=ZIRCOLITE_VERSION,
        ruleset_path=str(Path(COMPILED_RULESET).relative_to(REPO)),
        ruleset_sha=_sha256_file(COMPILED_RULESET),
        loaded_rule_count=len(loaded),
        level=LEVELS,
        mapping_path=str(Path(COMISET_MAPPING).relative_to(REPO)),
        mapping_hash=_sha256_file(COMISET_MAPPING),
        precision_floor=MIN_EVENTS,
        benign_corpus=(
            "run6: combined (COMISET real slice + NextronSystems/evtx-baseline) "
            "+ DARPA OpTC benign-week eCAR (FiveDirections/OpTC-data, Distribution A)"
        ),
        benign_corpus_path=str(Path(BENIGN_SAMPLE).relative_to(REPO)),
        benign_corpus_sha=_sha256_file(BENIGN_SAMPLE),
        benign_eid1_total=len(benign_events),
        benign_eid1_baseline_run5=base_eid1,
        benign_eid1_optc_added=aug_eid1 - base_eid1,
        benign_label_split={"benign": n_ben, "malicious": n_mal},
        attack_corpus="splunk/attack_data (sub-technique-foldered, Apache-2.0) — UNCHANGED from run5 (FIX B3)",
        attack_process_creation_events=n_pc,
        recall_method="per-sub-technique (FIX B3, unchanged)",
        recall_technique_map=str(TECHNIQUE_MAP.relative_to(REPO)),
        recall_technique_map_sha=_sha256_file(TECHNIQUE_MAP),
        rules_with_technique_tag=n_tagged,
        rules_recall_measurable=n_measurable,
        rules_recall_unmeasured=n_unmeasured,
        rules_precision_measurable=n_prec_measurable,
        attack_fires=len(set_attack),
        benign_fires=len(set_benign),
        positive_control_fired=pc_fired,
        run_hash=rh,
    )
    MANIFEST_OUT.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_OUT.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"[manifest] -> {MANIFEST_OUT}", flush=True)

    header = (
        "# Sigmaforge backtest — run6 (PRECISION corpus augmented with DARPA OpTC benign)\n\n"
        "## What changed vs run5\n\n"
        "The **recall** pass is byte-for-byte identical to run5 (FIX B3 sub-technique recall). The "
        "ONLY change is the **precision (benign) corpus**: run5's combined corpus (COMISET real "
        "slice + NextronSystems/evtx-baseline) is EXTENDED with **DARPA OpTC** benign-week "
        "process-creation telemetry for VOLUME + real enterprise diversity, so more loaded rules "
        "clear the precision floor.\n\n"
        "OpTC (**FiveDirections/OpTC-data**, public domain / Distribution A) has a dedicated benign "
        "collection period (**Sept 17-23 2019**) across ~1000 real enterprise hosts BEFORE any "
        "red-team activity — every process-creation record there is benign BY CONSTRUCTION. The "
        "eCAR JSON (`object=PROCESS action=CREATE/START`) is reshaped by "
        "`scripts/build_optc_benign.py` into the SAME COMISET `_source` envelope the rest of the "
        "benign corpus uses, so the single `comiset.yaml` mapping + `project_event` path handle it "
        "uniformly.\n\n"
        f"- precision corpus: run5 baseline **{base_eid1}** EID-1 -> run6 OpTC-augmented "
        f"**{aug_eid1}** EID-1 (**+{aug_eid1 - base_eid1}** OpTC benign-by-construction events).\n"
        f"- precision-measurable rules: **{n_prec_measurable}** / {len(loaded)} loaded "
        "(cleared the precision floor on the augmented corpus).\n\n"
        "### Acceptance gate (engine == scored, both corpora)\n\n"
        "| corpus | engine fires | scored fires | title-drop | gate |\n"
        "|---|---|---|---|---|\n"
        f"| attack | {attack_gate.engine_fires} | {attack_gate.scored_fires} | "
        f"{len(attack_gate.dropped_titles)} | {'PASS' if attack_gate.ok else 'FAIL'} |\n"
        f"| benign | {benign_gate.engine_fires} | {benign_gate.scored_fires} | "
        f"{len(benign_gate.dropped_titles)} | {'PASS' if benign_gate.ok else 'FAIL'} |\n\n"
        "---\n\n"
    )
    report_md = header + report_md

    REPORT_OUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT_OUT.write_text(report_md)
    print(f"[report] -> {REPORT_OUT}", flush=True)

    summary = {
        "loaded_rules": len(loaded),
        "benign_eid1_baseline_run5": base_eid1,
        "benign_eid1_optc_augmented": aug_eid1,
        "benign_eid1_optc_added": aug_eid1 - base_eid1,
        "rules_precision_measurable": n_prec_measurable,
        "recall_measurable": n_measurable,
        "attack_fires_distinct": len(set_attack),
        "benign_fires_distinct": len(set_benign),
        "positive_control_fired": pc_fired,
        "run_hash": rh,
    }
    Path("/tmp/_run6_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
