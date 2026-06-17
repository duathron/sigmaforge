#!/usr/bin/env python3
"""First real end-to-end Sigmaforge backtest -> reports/first_run.md.

Engine: vendored Zircolite 3.7.6. SAME compiled ruleset for both passes
(Zircolite/rules/rules_windows_sysmon.json, 2680 rules) so recall (EVTX) and
precision (COMISET) are measured by the identical engine. Only the loaded
high+critical, stateless process_creation rules are SCORED (others ignored).

Recall   : Zircolite on native EVTX (EVTX-ATTACK-SAMPLES, all-malicious) with
           the default Zircolite fieldMappings; corpus_label="malicious".
Precision: Zircolite on the streamed COMISET benign EID-1 sample, with the
           COMISET mapping (data/mappings/comiset.yaml); per-event label from
           injected _source.sigmaforge_label.
"""

from __future__ import annotations

import glob
import json
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from sigmaforge.ingest.ruleload import partition_rules  # noqa: E402
from sigmaforge.ingest.zircolite_runner import run_shard  # noqa: E402
from sigmaforge.orchestrate import run_backtest  # noqa: E402

COMPILED_RULESET = str(REPO / "Zircolite" / "rules" / "rules_windows_sysmon.json")
COMISET_MAPPING = str(REPO / "data" / "mappings" / "comiset.yaml")
EVTX_DEFAULT_CFG = str(REPO / "Zircolite" / "config" / "fieldMappings.yaml")
EVTX_DIR = str(Path.home() / "sigmaforge-v0" / "EVTX-ATTACK-SAMPLES")
BENIGN_SAMPLE = str(REPO / "data" / "comiset" / "real_benign_sample.jsonl")
REPORT_OUT = REPO / "reports" / "first_run.md"
MIN_EVENTS = 1000


def load_comiset_field_map() -> dict[str, str]:
    """Read the `_source.<raw> -> <Sigma>` mappings from comiset.yaml so we can
    project the benign events into the Sigma field namespace the ENGINE sees.
    Coverage (events_evaluated_for_rule) checks Sigma field names; if we hand it
    raw _source (process_path, not Image), every Image-based rule wrongly reads
    coverage 0. We mirror exactly the engine's rename here."""
    with open(COMISET_MAPPING) as fh:
        cfg = yaml.safe_load(fh)
    out = {}
    for raw, sigma in (cfg.get("mappings") or {}).items():
        if raw.startswith("_source."):
            out[raw[len("_source.") :]] = sigma
    return out


def project_event(src: dict, field_map: dict[str, str]) -> dict:
    """Apply the COMISET rename to a single _source dict -> Sigma-named event.
    Unmapped keys are kept verbatim (Zircolite would normalize them, but only
    mapped Sigma fields drive rule coverage, so verbatim is harmless here)."""
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


def main() -> int:
    loaded = load_loaded_rules()
    print(f"[loaded] {len(loaded)} high+critical stateless process_creation rules", flush=True)

    # --- Recall pass (EVTX attack corpus, all-malicious) ---
    print("[recall] running Zircolite on EVTX-ATTACK-SAMPLES ...", flush=True)
    attack_fires = run_shard(
        EVTX_DIR,
        COMPILED_RULESET,
        mapping_path=EVTX_DEFAULT_CFG,
        json_input=False,
        corpus_label="malicious",
    )
    n_attack_events = (
        int(Path("/tmp/_n_attack_events").read_text().strip()) if Path("/tmp/_n_attack_events").exists() else 0
    )
    print(f"[recall] attack_fires={len(attack_fires)} n_attack_events={n_attack_events}", flush=True)

    # --- Precision pass (COMISET benign sample) ---
    print("[precision] running Zircolite on COMISET benign sample ...", flush=True)
    benign_fires = run_shard(
        BENIGN_SAMPLE,
        COMPILED_RULESET,
        mapping_path=COMISET_MAPPING,
        json_input=True,
    )
    print(f"[precision] benign_fires={len(benign_fires)}", flush=True)

    # benign events: project _source into the Sigma field namespace (Image, etc.)
    # so coverage matches what the engine evaluated. Carry sigmaforge_label.
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
    print(
        f"[precision] benign_events={len(benign_events)} malicious={n_mal} benign={len(benign_events) - n_mal}",
        flush=True,
    )

    # --- Positive control: any malicious-labelled benign-corpus hit ---
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

    REPORT_OUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT_OUT.write_text(report_md)
    print(f"[report] -> {REPORT_OUT}", flush=True)

    # headline stats to stderr (real numbers)
    measured = [r for r in rows if isinstance(r.get("precision@COMISET"), float)]
    unmeasured = [r for r in rows if r.get("precision@COMISET") == "unmeasured"]
    fired = [r for r in rows if r.get("recall", 0) > 0 or r.get("fp", 0) > 0 or r.get("tp", 0) > 0]
    summary = {
        "loaded_rules": len(loaded),
        "rules_with_measured_precision": len(measured),
        "rules_unmeasured": len(unmeasured),
        "rules_with_recall_or_fire": len(fired),
        "funnel": funnel,
        "n_benign_events": len(benign_events),
        "n_benign_malicious": n_mal,
        "n_attack_events": n_attack_events,
        "attack_fires": len(attack_fires),
        "benign_fires": len(benign_fires),
        "positive_control_fired": pc_fired,
    }
    Path("/tmp/_backtest_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
