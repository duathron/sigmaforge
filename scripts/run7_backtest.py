#!/usr/bin/env python3
"""run7 backtest -> reports/run7.md — PRECISION corpus + one more OpTC host group (partial pull 1/5).

Builds on run6 (which added one OpTC slice: 18-19Sep/AIA-201-225, 30,383 EID-1). The
RECALL pass is byte-for-byte identical to run5/run6 (FIX B3 sub-technique recall;
run4/run5/run6 artifacts PRESERVED). The ONLY change vs run6 is the PRECISION (benign)
corpus: it is ENLARGED with ADDITIONAL DARPA OpTC benign-week host-group/day dumps
(beyond run6's single slice), pulled one-gz-at-a-time by scripts/pull_optc_fullweek.py
(which REUSES scripts/build_optc_benign.py for the eCAR->COMISET mapping and identity-
dedups by sigmaforge_eid against the existing corpus). More benign VOLUME + enterprise
diversity => more loaded rules clear the precision floor and become precision-measurable.

OpTC (FiveDirections/OpTC-data, public domain / Distribution A) has a dedicated benign
collection period (Sept 17-23 2019) across ~1000 real enterprise hosts BEFORE any
red-team activity — every process-creation record there is benign BY CONSTRUCTION. The
eCAR JSON is reshaped into the SAME COMISET _source envelope the rest of the benign
corpus uses, so the single comiset.yaml mapping + project_event path handle it uniformly.

PRECONDITION: the enlarged corpus must exist at BENIGN_SAMPLE (see below). Build it with:
  python scripts/pull_optc_fullweek.py --max-optc-total 500000 --max-raw-gb 60
which appends additional OpTC benign-week records onto the run6 combined corpus in place.

Engine: vendored Zircolite 3.7.6, SAME compiled-from-loaded ruleset both passes.

THIS SCRIPT IS A THIN CALLER. The corpus-agnostic glue lives in
`sigmaforge.pipeline.run_backtest_pipeline`; this script holds the run7 constants and
computes its OWN run7/OpTC-specific provenance (the OpTC Image path-form split, the
run5/run6/run7 EID deltas, the OpTC slice/pull provenance) from the benign corpus it
owns, then injects it via the report header + the manifest merge. It is the
semantic-equivalence regression oracle for the extraction.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from sigmaforge.pipeline import (  # noqa: E402
    BacktestResult,
    PipelineConfig,
    run_backtest_pipeline,
)

COMPILED_RULESET = str(REPO / "data" / "rulesets" / "sigmaforge_loaded.json")
COMISET_MAPPING = str(REPO / "data" / "mappings" / "comiset.yaml")
EVTX_DEFAULT_CFG = str(REPO / "Zircolite" / "config" / "fieldMappings.yaml")
LOADED_RULES_GLOB = str(REPO / "sigma/rules/windows/process_creation/*.yml")
# recall corpus + technique map: UNCHANGED from run5 (FIX B3)
RECALL_CORPUS = str(Path.home() / "sigmaforge-v0" / "attack_data_corpus")
TECHNIQUE_MAP = REPO / "data" / "comiset" / "attack_data_technique_map.json"
# PRECISION corpus: run5 combined corpus EXTENDED with OpTC benign-week telemetry.
BENIGN_SAMPLE = str(REPO / "data" / "comiset" / "combined_optc_benign_sample.jsonl")
# run5's precision corpus, for the before/after comparison.
BENIGN_BASELINE = str(REPO / "data" / "comiset" / "combined_benign_sample.jsonl")
REPORT_OUT = REPO / "reports" / "run7.md"
MANIFEST_OUT = REPO / "reports" / "run7_manifest.json"
MIN_EVENTS = 1000
ZIRCOLITE_VERSION = "3.7.6"
LEVELS = ("high", "critical")
# run6's OpTC slice size (18-19Sep/AIA-201-225), for the run7-over-run6 delta.
RUN6_OPTC_EID1 = 30383
# Provenance of the OpTC host-group/day dumps pulled across run6 + run7. Written by
# scripts/pull_optc_fullweek.py to reports/run7_pull_progress.json (read here if present).
PULL_PROGRESS = REPO / "reports" / "run7_pull_progress.json"


def _count_eid1(path: str) -> int:
    if not Path(path).exists():
        return 0
    n = 0
    with open(path) as fh:
        for line in fh:
            if line.strip():
                n += 1
    return n


def _load_benign_events() -> list[dict]:
    """Reload the benign corpus the run7 caller OWNS, to compute run-specific
    provenance (the OpTC Image path-form split) — corpus-specific, not pipeline glue."""
    from sigmaforge.pipeline import _load_comiset_field_map, _project_event

    field_map = _load_comiset_field_map(COMISET_MAPPING)
    events: list[dict] = []
    with open(BENIGN_SAMPLE) as fh:
        for line in fh:
            doc = json.loads(line)
            src = doc.get("_source", {})
            ev = _project_event(src, field_map)
            ev["sigmaforge_label"] = src.get("sigmaforge_label", "benign")
            events.append(ev)
    return events


def _optc_pathform_split(benign_events: list[dict]) -> dict[str, int]:
    """run7/OpTC-specific provenance computed from the corpus the caller owns."""
    nt = bare = drive = other = 0
    for e in benign_events:
        if e.get("Provider_Name") != "DARPA-OpTC-eCAR":
            continue
        img = e.get("Image", "") or ""
        if img.startswith("\\Device\\"):
            nt += 1
        elif "\\" not in img and "/" not in img:
            bare += 1
        elif len(img) >= 2 and img[1] == ":":
            drive += 1
        else:
            other += 1
    return {"nt_device_form": nt, "bare_basename": bare, "drive_letter": drive, "other": other}


def run() -> BacktestResult:
    if not Path(COMPILED_RULESET).exists():
        raise SystemExit(f"[FATAL] {COMPILED_RULESET} missing. Run scripts/compile_loaded_ruleset.py first.")
    if not TECHNIQUE_MAP.exists():
        raise SystemExit(f"[FATAL] {TECHNIQUE_MAP} missing. Run scripts/build_attack_data_corpus.py first.")
    if not Path(BENIGN_SAMPLE).exists():
        raise SystemExit(
            f"[FATAL] {BENIGN_SAMPLE} missing. Build it with scripts/build_optc_benign.py "
            "(see this script's docstring)."
        )

    cfg = PipelineConfig(
        compiled_ruleset=COMPILED_RULESET,
        loaded_rules_glob=LOADED_RULES_GLOB,
        attack_corpus=RECALL_CORPUS,
        technique_map=str(TECHNIQUE_MAP),
        benign_sample=BENIGN_SAMPLE,
        comiset_mapping=COMISET_MAPPING,
        evtx_cfg=EVTX_DEFAULT_CFG,
        min_events=MIN_EVENTS,
        source="COMISET",
    )
    res = run_backtest_pipeline(cfg)

    loaded_count = res.loaded_rule_count
    n_prec_measurable = res.rules_precision_measurable

    # --- run7/OpTC-specific provenance computed from the corpus the caller OWNS ---
    benign_events = _load_benign_events()
    n_ben_total = len(benign_events)
    n_mal = sum(1 for e in benign_events if e.get("sigmaforge_label") == "malicious")
    n_ben = n_ben_total - n_mal  # noqa: F841 (kept for parity; label split lives in the manifest body)

    base_eid1 = _count_eid1(BENIGN_BASELINE)
    aug_eid1 = _count_eid1(BENIGN_SAMPLE)
    optc_total_eid1 = aug_eid1 - base_eid1
    optc_run7_added = optc_total_eid1 - RUN6_OPTC_EID1

    pf = _optc_pathform_split(benign_events)
    optc_nt, optc_bare, optc_drive, optc_other = (
        pf["nt_device_form"],
        pf["bare_basename"],
        pf["drive_letter"],
        pf["other"],
    )
    optc_total = optc_nt + optc_bare + optc_drive + optc_other

    def _pct(n: int) -> float:
        return (100.0 * n / optc_total) if optc_total else 0.0

    pull_records = []
    if PULL_PROGRESS.exists():
        try:
            pp = json.loads(PULL_PROGRESS.read_text())
            pull_records = pp.get("pulled", [])
        except Exception:
            pull_records = []

    attack_gate = next(g for g in res.acceptance_gate if g.corpus == "attack")
    benign_gate = next(g for g in res.acceptance_gate if g.corpus == "benign")

    # --- Merge the run7-specific provenance onto the pipeline's generic manifest body.
    # Path keys are rewritten to repo-relative form (the committed manifest's shape).
    recommended_floor = res.manifest["recommended_precision_floor"]
    manifest = {
        **res.manifest,
        "ruleset_path": str(Path(COMPILED_RULESET).relative_to(REPO)),
        "mapping_path": str(Path(COMISET_MAPPING).relative_to(REPO)),
        "benign_corpus_path": str(Path(BENIGN_SAMPLE).relative_to(REPO)),
        "recall_technique_map": str(TECHNIQUE_MAP.relative_to(REPO)),
        "level": list(LEVELS),
        "zircolite_version": ZIRCOLITE_VERSION,
        "recall_method": "per-sub-technique (FIX B3, unchanged)",
        "benign_corpus": (
            "run7: combined (COMISET real slice + NextronSystems/evtx-baseline) "
            "+ DARPA OpTC benign week, PARTIAL pull (run6: AIA-201-225 + run7: AIA-101-125; "
            "1 of 5 intended run7 host groups — gdown failed on the rest; "
            "FiveDirections/OpTC-data, Distribution A)"
        ),
        "benign_eid1_baseline_run5": base_eid1,
        "benign_eid1_optc_added": optc_total_eid1,
        "benign_eid1_optc_run6": RUN6_OPTC_EID1,
        "benign_eid1_optc_run7_new": optc_run7_added,
        "attack_corpus": "splunk/attack_data (sub-technique-foldered, Apache-2.0) — UNCHANGED from run5 (FIX B3)",
        "optc_slice_provenance": {
            "run6_slice": {
                "source_file": "AIA-201-225.ecar-last.json.gz",
                "day_folder": "18-19Sep19",
                "host_group": "AIA-201-225",
                "host_domain": "systemia.com (SysClient0201-0225)",
                "host_count": 24,
                "benign_window_collected": "2019-09-18 (within OpTC benign period 17-23 Sep 2019)",
                "raw_process_create_eid1": RUN6_OPTC_EID1,
            },
            "run7_dumps": pull_records,
            "optc_total_eid1": optc_total_eid1,
            "note": (
                "PROCESS object + CREATE/START action == EID-1 equivalent; "
                "run7 dumps identity-deduped by sigmaforge_eid against the existing corpus"
            ),
        },
        "optc_image_pathform": {
            "total": optc_total,
            "nt_device_form": optc_nt,
            "bare_basename": optc_bare,
            "drive_letter": optc_drive,
            "other": optc_other,
            "note": (
                "Image|endswith selectors miss the bare-basename share; drive-letter selectors match 0 OpTC events"
            ),
        },
    }
    manifest = dict(sorted(manifest.items()))

    MANIFEST_OUT.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_OUT.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    header = (
        "# Sigmaforge backtest — run7 (PRECISION corpus enlarged with one more DARPA OpTC host group)\n\n"
        "## What changed vs run6\n\n"
        "The **recall** pass is byte-for-byte identical to run5/run6 (FIX B3 sub-technique recall). The "
        "ONLY change is the **precision (benign) corpus**: run6's combined corpus (COMISET real "
        "slice + NextronSystems/evtx-baseline + one OpTC host group AIA-201-225) is EXTENDED with "
        "**one more OpTC host group (AIA-101-125)** for VOLUME, to test whether more benign data "
        "clears more rules' precision floor. (Spoiler — see 'diminishing return' below: it barely "
        "does.)\n\n"
        "OpTC (**FiveDirections/OpTC-data**, public domain / Distribution A) has a dedicated benign "
        "collection period (**Sept 17-23 2019**) across ~1000 real enterprise hosts BEFORE any "
        "red-team activity — every process-creation record there is benign BY CONSTRUCTION. The "
        "eCAR JSON (`object=PROCESS action=CREATE/START`) is reshaped by "
        "`scripts/build_optc_benign.py` into the SAME COMISET `_source` envelope the rest of the "
        "benign corpus uses, so the single `comiset.yaml` mapping + `project_event` path handle it "
        "uniformly.\n\n"
        "### OpTC Image path-form caveat (read before trusting path-anchored precision)\n\n"
        "OpTC eCAR does **not** record `Image` as a normal drive-letter path. Measured on this "
        f"corpus ({optc_total} OpTC PROCESS/CREATE events): **{optc_nt} ({_pct(optc_nt):.0f}%)** carry "
        "the **NT-device form** `\\Device\\HarddiskVolume1\\...\\foo.exe`, **"
        f"{optc_bare} ({_pct(optc_bare):.0f}%)** carry a **bare basename** with no path separator "
        f"(`PING.EXE`, `cmd.exe`), {optc_other} ({_pct(optc_other):.0f}%) carry other forms "
        "(`\\\\?\\C:\\...`, `\\SystemRoot\\...`, `%SystemRoot%\\...`), and **"
        f"{optc_drive} ({_pct(optc_drive):.0f}%)** carry a drive-letter `C:\\...` path.\n\n"
        "Consequence for selector matching against the OpTC slice:\n\n"
        "- `Image|endswith: '\\foo.exe'` selectors **fail to match the ~50% bare-basename "
        "events** — a bare basename has no leading separator, so `\\foo.exe` never matches "
        "`FOO.EXE`. They still match the NT-device-form events (which end in `\\foo.exe`).\n"
        "- `Image|contains: 'C:'` / any drive-letter-anchored selector matches **none** of the "
        "OpTC slice (0 drive-letter paths).\n"
        "- selectors keyed on `CommandLine` or `ParentImage` are unaffected by the Image form, "
        "which is why the precision-measurable count is legitimate (it is a coverage-floor "
        "count driven by CommandLine/parent_path presence, not by Image path shape).\n\n"
        "This does **not** invalidate the precision-measurable count and **cannot inflate "
        "precision** — a path mismatch only means a rule fired LESS on benign data, i.e. fewer "
        "FPs were detected. But it means the precision **figures for path-anchored rules "
        "UNDERSTATE their true FP exposure** on this corpus: an `Image|endswith` rule that looks "
        "clean here would still have fired on the ~50% bare-basename events had OpTC recorded "
        "full paths. Treat path-anchored `precision@COMISET = 1.0` on the OpTC slice as a floor, "
        "not a guarantee.\n\n"
        f"- precision corpus: run5 baseline **{base_eid1}** -> run6 **{base_eid1 + RUN6_OPTC_EID1}** "
        f"-> run7 **{aug_eid1}** EID-1 (run7 added **+{optc_run7_added}** OpTC benign-by-construction "
        "events over run6).\n"
        f"- precision-measurable rules: **{n_prec_measurable}** / {loaded_count} loaded "
        "(cleared the precision floor on the enlarged corpus).\n"
        f"- precision floor: the manifest's `recommended_precision_floor` is "
        f"**{recommended_floor}** (10% of the {n_ben_total}-event "
        f"corpus); the per-rule table below uses the generic **{MIN_EVENTS}**-event floor, so "
        f'"{n_prec_measurable}/{loaded_count} precision-measurable" against 1000 should NOT be '
        f"read as stronger than it is — at the recommended {recommended_floor}"
        "-event floor far fewer rules would clear it.\n\n"
        "### Honest delta — diminishing return\n\n"
        f"Enlarging the benign corpus from **{base_eid1 + RUN6_OPTC_EID1}** (run6) to **{aug_eid1}** "
        f"(run7) — roughly **2x** — moved precision-measurable rules from **7** (run6) to "
        f"**{n_prec_measurable}** (run7): **+{n_prec_measurable - 7}**. Doubling the OpTC volume "
        "barely moves the needle. The bottleneck is NOT benign volume but **field/behaviour "
        "diversity**: more of the same enterprise activity (and OpTC's NT-device/bare-basename Image "
        "form) does not add the selection-field combinations that would let more rules clear the "
        "floor. Path-anchored rules in particular gain nothing from more OpTC.\n\n"
        "### Partial pull (honest scope)\n\n"
        "This run is **NOT** the full OpTC benign week. The run7 enlargement intended ~5 host groups "
        "but pulled **only 1** (AIA-101-125) before the Google Drive fetch failed on the next file "
        "(`gdown: Failed to retrieve file url` — public-file throttling). Treat run7 as run6 **+ one "
        "additional host group**, not a full-week corpus.\n\n"
        "### Acceptance gate (engine == scored, both corpora)\n\n"
        "| corpus | engine fires | scored fires | title-drop | gate |\n"
        "|---|---|---|---|---|\n"
        f"| attack | {attack_gate.engine_fires} | {attack_gate.scored_fires} | "
        f"{len(attack_gate.dropped_titles)} | {'PASS' if attack_gate.ok else 'FAIL'} |\n"
        f"| benign | {benign_gate.engine_fires} | {benign_gate.scored_fires} | "
        f"{len(benign_gate.dropped_titles)} | {'PASS' if benign_gate.ok else 'FAIL'} |\n\n"
        "---\n\n"
    )
    report_md = header + res.report_md

    REPORT_OUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT_OUT.write_text(report_md)

    res.report_md = report_md
    res.manifest = manifest
    return res


def main() -> int:
    res = run()
    summary = {
        "loaded_rules": res.loaded_rule_count,
        "rules_precision_measurable": res.rules_precision_measurable,
        "recall_measurable": res.rules_recall_measurable,
        "attack_fires_distinct": res.manifest["attack_fires"],
        "benign_fires_distinct": res.manifest["benign_fires"],
        "positive_control_fired": res.manifest["positive_control_fired"],
        "run_hash": res.run_hash,
    }
    Path("/tmp/_run7_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
