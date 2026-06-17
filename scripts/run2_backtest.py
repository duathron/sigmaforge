#!/usr/bin/env python3
"""Corrected end-to-end Sigmaforge backtest (Skeptic round 2) -> reports/run2.md.

Fixes vs first_run.md:
- BLOCKER-1: recall denominator = the count of PROCESS-CREATION attack events
  (Sysmon EID 1 + Security 4688) in EVTX-ATTACK-SAMPLES, computed for real and
  pinned in reports/run_manifest.json + data/comiset/attack_pc_count.json.
  (The first run used 34990 = ALL EVTX events across all channels, deflating
  recall ~23x for a 100% process_creation ruleset.)
- BLOCKER-2: per-rule `no_benign_exemplars` flag + report caveat so precision=1.0
  with fp=0 is NOT presented as FP-resistance when no benign exemplar existed.
- MAJOR-1: runmanifest.build_manifest is wired here and written to disk.
- SCALE: benign corpus = COMISET real slice + NextronSystems/evtx-baseline
  (Apache-2.0 goodware, native EVTX, benign-by-construction).

Engine: vendored Zircolite 3.7.6, SAME compiled ruleset for both passes.
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
from sigmaforge.score.coverage import events_evaluated_for_rule, selection_fields  # noqa: E402

COMPILED_RULESET = str(REPO / "Zircolite" / "rules" / "rules_windows_sysmon.json")
COMISET_MAPPING = str(REPO / "data" / "mappings" / "comiset.yaml")
EVTX_DEFAULT_CFG = str(REPO / "Zircolite" / "config" / "fieldMappings.yaml")
EVTX_DIR = str(Path.home() / "sigmaforge-v0" / "EVTX-ATTACK-SAMPLES")
BENIGN_SAMPLE = str(REPO / "data" / "comiset" / "combined_benign_sample.jsonl")
ATTACK_PC_COUNT = REPO / "data" / "comiset" / "attack_pc_count.json"
REPORT_OUT = REPO / "reports" / "run2.md"
MANIFEST_OUT = REPO / "reports" / "run_manifest.json"
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


def attack_process_creation_count() -> int:
    """BLOCKER-1: pinned process-creation attack-event count (recall denominator)."""
    return int(json.loads(ATTACK_PC_COUNT.read_text())["pc"])


def main() -> int:
    loaded = load_loaded_rules()
    print(f"[loaded] {len(loaded)} high+critical stateless process_creation rules", flush=True)

    # --- BLOCKER-1: recall denominator = process-creation attack events ---
    n_attack_events = attack_process_creation_count()
    print(f"[recall] n_attack_events (process_creation only) = {n_attack_events}", flush=True)

    # --- Recall pass (EVTX attack corpus, all-malicious) ---
    print("[recall] running Zircolite on EVTX-ATTACK-SAMPLES ...", flush=True)
    attack_fires = run_shard(
        EVTX_DIR,
        COMPILED_RULESET,
        mapping_path=EVTX_DEFAULT_CFG,
        json_input=False,
        corpus_label="malicious",
    )
    print(f"[recall] attack_fires={len(attack_fires)}", flush=True)

    # --- Precision pass (combined benign corpus) ---
    print("[precision] running Zircolite on combined benign corpus ...", flush=True)
    benign_fires = run_shard(
        BENIGN_SAMPLE,
        COMPILED_RULESET,
        mapping_path=COMISET_MAPPING,
        json_input=True,
    )
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

    rows, funnel, report_md = run_backtest(
        loaded_rules=loaded,
        attack_fires=set(attack_fires),
        benign_fires=set(benign_fires),
        benign_events=benign_events,
        n_attack_events=n_attack_events,
        positive_control_fired=pc_fired,
        min_events=MIN_EVENTS,
        source="COMISET",
    )

    # --- A12: recompute the precision-floor recommendation from the NEW coverage distribution ---
    n_be = len(benign_events)
    covs = sorted((events_evaluated_for_rule(benign_events, selection_fields(r)) for r in loaded), reverse=True)
    nonzero = [c for c in covs if c > 0]
    zero_cov = len(covs) - len(nonzero)
    cover_ge_floor = sum(1 for c in covs if c >= MIN_EVENTS)
    recommended_floor = max(200, int(0.10 * n_be))
    saturated = zero_cov == 0 and (min(nonzero) if nonzero else 0) >= MIN_EVENTS

    # --- MAJOR-1: build + write the run manifest ---
    rh = run_hash(set(attack_fires) | set(benign_fires))
    manifest = build_manifest(
        recommended_precision_floor=recommended_floor,
        zircolite_version=ZIRCOLITE_VERSION,
        ruleset_path=str(Path(COMPILED_RULESET).relative_to(REPO)),
        ruleset_sha=_sha256_file(COMPILED_RULESET),
        loaded_rule_count=len(loaded),
        level=LEVELS,
        mapping_path=str(Path(COMISET_MAPPING).relative_to(REPO)),
        mapping_hash=_sha256_file(COMISET_MAPPING),
        precision_floor=MIN_EVENTS,
        benign_corpus="combined: COMISET real slice + NextronSystems/evtx-baseline v0.8.4 all-evtx",
        benign_corpus_path=str(Path(BENIGN_SAMPLE).relative_to(REPO)),
        benign_corpus_sha=_sha256_file(BENIGN_SAMPLE),
        benign_eid1_total=len(benign_events),
        benign_label_split={"benign": n_ben, "malicious": n_mal},
        attack_corpus="EVTX-ATTACK-SAMPLES (native EVTX, all-malicious)",
        attack_process_creation_events=n_attack_events,
        attack_pc_breakdown=json.loads(ATTACK_PC_COUNT.read_text()),
        attack_fires=len(attack_fires),
        benign_fires=len(benign_fires),
        positive_control_fired=pc_fired,
        run_hash=rh,
    )
    MANIFEST_OUT.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_OUT.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"[manifest] -> {MANIFEST_OUT}", flush=True)

    # --- A12: render the recomputed floor recommendation into the report ---
    report_md += (
        "\n\n## A12 floor recommendation (recomputed on the scaled corpus)\n\n"
        f"- benign corpus size: **{n_be}** EID-1 events\n"
        f"- rules with zero field-coverage: **{zero_cov}** / {len(loaded)}\n"
        f"- rules clearing the current floor ({MIN_EVENTS}): **{cover_ge_floor}** / {len(loaded)}\n"
        f"- min non-zero coverage: **{min(nonzero) if nonzero else 0}**, "
        f"median non-zero coverage: **{nonzero[len(nonzero) // 2] if nonzero else 0}**\n"
        f"- recommended floor (10% of corpus, min 200): **{recommended_floor}**\n\n"
    )
    if saturated:
        report_md += (
            "> **HONEST CAVEAT — coverage is now saturated.** Because process_creation rules key on "
            "fields (Image/CommandLine/ParentImage) that EVERY Sysmon EID-1 event carries, all loaded "
            "rules clear any field-presence floor on this corpus. The field-presence floor no longer "
            "separates 'ran' from 'didn't run' — it is satisfied trivially. The true discriminator is "
            "now whether a rule's VALUE-level selection (contains/endswith patterns) matched, which the "
            "current `events_evaluated` counter (field-presence only) does not measure. Recommendation: "
            f"keep the floor at {recommended_floor} as a corpus-size sanity gate, but treat precision as "
            "trustworthy ONLY for rules that actually FIRED on the benign corpus (here: 2). Precision for "
            "rules that never fired is 'no FP observed at this corpus size', NOT measured FP-resistance.\n"
        )

    # reference the manifest from the report
    report_md += (
        f"\n\n## Run manifest\n\n"
        f"Reproducibility inputs pinned in [`reports/run_manifest.json`](run_manifest.json): "
        f"benign corpus {len(benign_events)} EID-1 ({n_ben} benign / {n_mal} malicious), "
        f"ruleset `{Path(COMPILED_RULESET).name}` ({len(loaded)} loaded high+critical "
        f"process_creation rules), COMISET mapping hash `{manifest['mapping_hash'][:12]}…`, "
        f"precision floor {MIN_EVENTS}, recall denominator (process-creation attack events) "
        f"{n_attack_events}, run hash `{rh[:12]}…`.\n"
    )
    REPORT_OUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT_OUT.write_text(report_md)
    print(f"[report] -> {REPORT_OUT}", flush=True)

    measured = [r for r in rows if isinstance(r.get("precision@COMISET"), float)]
    real_signal = [r for r in measured if not r.get("no_benign_exemplars")]
    tautology = [r for r in measured if r.get("no_benign_exemplars")]
    real_fps = [r for r in rows if isinstance(r.get("fp"), int) and r["fp"] > 0]
    summary = {
        "loaded_rules": len(loaded),
        "rules_with_measured_precision": len(measured),
        "rules_with_real_precision_signal": len(real_signal),
        "rules_precision_tautology": len(tautology),
        "rules_with_real_fps": len(real_fps),
        "funnel": funnel,
        "n_benign_events": len(benign_events),
        "n_benign_malicious": n_mal,
        "n_benign_benign": n_ben,
        "n_attack_events_process_creation": n_attack_events,
        "attack_fires": len(attack_fires),
        "benign_fires": len(benign_fires),
        "positive_control_fired": pc_fired,
        "run_hash": rh,
    }
    Path("/tmp/_run2_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
