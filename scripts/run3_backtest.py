#!/usr/bin/env python3
"""FIX H end-to-end Sigmaforge backtest -> reports/run3.md.

ONE source of truth (vs run2):
- run2 fired Zircolite's BUNDLED 2680-rule snapshot (rules_windows_sysmon.json)
  while the scorer filtered the ~609 loaded SigmaHQ titles -> version skew +
  silent benign-side title-drop (benign_fires=767 -> funnel fires=2).
- run3 fires `data/rulesets/sigmaforge_loaded.json`, compiled from EXACTLY the
  609 loaded rules (scripts/compile_loaded_ruleset.py). Engine and scorer now
  share one ruleset, so engine fires == scored fires by construction — enforced
  by the FIX H acceptance gate (sigmaforge.score.acceptance.assert_one_source),
  which is also invoked inside run_backtest and raises on any discrepancy.

OUT OF SCOPE here: per-technique recall (fix B). Recall stays pooled; the
existing pooled-recall caveat is preserved.

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
from sigmaforge.score.coverage import events_evaluated_for_rule, selection_fields  # noqa: E402

# FIX H: ONE source — the ruleset compiled from exactly the loaded set.
COMPILED_RULESET = str(REPO / "data" / "rulesets" / "sigmaforge_loaded.json")
COMISET_MAPPING = str(REPO / "data" / "mappings" / "comiset.yaml")
EVTX_DEFAULT_CFG = str(REPO / "Zircolite" / "config" / "fieldMappings.yaml")
EVTX_DIR = str(Path.home() / "sigmaforge-v0" / "EVTX-ATTACK-SAMPLES")
BENIGN_SAMPLE = str(REPO / "data" / "comiset" / "combined_benign_sample.jsonl")
ATTACK_PC_COUNT = REPO / "data" / "comiset" / "attack_pc_count.json"
REPORT_OUT = REPO / "reports" / "run3.md"
MANIFEST_OUT = REPO / "reports" / "run3_manifest.json"
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
    return int(json.loads(ATTACK_PC_COUNT.read_text())["pc"])


def main() -> int:
    if not Path(COMPILED_RULESET).exists():
        print(
            f"[FATAL] {COMPILED_RULESET} missing. Run scripts/compile_loaded_ruleset.py first.",
            flush=True,
        )
        return 2

    loaded = load_loaded_rules()
    loaded_titles = {r["title"] for r in loaded}
    print(f"[loaded] {len(loaded)} high+critical stateless process_creation rules", flush=True)

    n_attack_events = attack_process_creation_count()
    print(f"[recall] n_attack_events (process_creation only) = {n_attack_events}", flush=True)

    # --- Recall pass (EVTX attack corpus) — ONE-source ruleset ---
    print("[recall] running Zircolite on EVTX-ATTACK-SAMPLES (loaded ruleset) ...", flush=True)
    attack_fires = run_shard(
        EVTX_DIR,
        COMPILED_RULESET,
        mapping_path=EVTX_DEFAULT_CFG,
        json_input=False,
        corpus_label="malicious",
    )
    print(f"[recall] attack_fires={len(attack_fires)}", flush=True)

    # --- Precision pass (benign corpus) — SAME one-source ruleset ---
    print("[precision] running Zircolite on combined benign corpus (loaded ruleset) ...", flush=True)
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

    # --- FIX H acceptance gate (BOTH corpora) BEFORE scoring ---
    set_attack, set_benign = set(attack_fires), set(benign_fires)
    gate = assert_one_source(loaded_titles, set_attack, set_benign)
    for g in gate:
        print(f"[gate] {g.reason()}", flush=True)

    rows, funnel, report_md = run_backtest(
        loaded_rules=loaded,
        attack_fires=set_attack,
        benign_fires=set_benign,
        benign_events=benign_events,
        n_attack_events=n_attack_events,
        positive_control_fired=pc_fired,
        min_events=MIN_EVENTS,
        source="COMISET",
    )

    # engine==scored, surfaced numerically from the gate
    attack_gate = next(g for g in gate if g.corpus == "attack")
    benign_gate = next(g for g in gate if g.corpus == "benign")

    # --- floor recommendation (unchanged methodology) ---
    n_be = len(benign_events)
    covs = sorted((events_evaluated_for_rule(benign_events, selection_fields(r)) for r in loaded), reverse=True)
    nonzero = [c for c in covs if c > 0]
    zero_cov = len(covs) - len(nonzero)
    cover_ge_floor = sum(1 for c in covs if c >= MIN_EVENTS)
    recommended_floor = max(200, int(0.10 * n_be))
    saturated = zero_cov == 0 and (min(nonzero) if nonzero else 0) >= MIN_EVENTS

    rh = run_hash(set_attack | set_benign)
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
        attack_fires=len(set_attack),
        benign_fires=len(set_benign),
        positive_control_fired=pc_fired,
        run_hash=rh,
    )
    MANIFEST_OUT.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_OUT.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"[manifest] -> {MANIFEST_OUT}", flush=True)

    # --- FIX H header prepended to the report ---
    fixh_md = (
        "# Sigmaforge backtest — run3 (FIX H: one-source ruleset)\n\n"
        "## FIX H — engine and scorer now share ONE ruleset\n\n"
        "run2 fired Zircolite's bundled 2680-rule snapshot (`rules_windows_sysmon.json`) "
        "but scored only the ~609 loaded SigmaHQ titles. That two-source join by title "
        "caused version skew and silently dropped engine fires outside the 609 set "
        "(manifest: `benign_fires=767` collapsing to funnel `fires=2`).\n\n"
        f"run3 fires `data/rulesets/sigmaforge_loaded.json`, compiled from EXACTLY the "
        f"{len(loaded)} loaded rules via Zircolite's pySigma sqlite backend "
        "(`scripts/compile_loaded_ruleset.py`, pipeline `sysmon`).\n\n"
        "### Acceptance gate (reconcile-not-relabel) — engine == scored, both corpora\n\n"
        "| corpus | engine fires (distinct rule×event) | scored fires | title-drop | gate |\n"
        "|---|---|---|---|---|\n"
        f"| attack | {attack_gate.engine_fires} | {attack_gate.scored_fires} | "
        f"{len(attack_gate.dropped_titles)} | {'PASS' if attack_gate.ok else 'FAIL'} |\n"
        f"| benign | {benign_gate.engine_fires} | {benign_gate.scored_fires} | "
        f"{len(benign_gate.dropped_titles)} | {'PASS' if benign_gate.ok else 'FAIL'} |\n\n"
        f"Raw runner fires: attack={len(attack_fires)} ({len(set_attack)} distinct), "
        f"benign={len(benign_fires)} ({len(set_benign)} distinct).\n\n"
        "> The 767-vs-2 contradiction is resolved by construction: the engine can only "
        "fire rules that exist in the loaded set, so there is nothing left to title-drop. "
        "The gate asserts engine==scored on BOTH corpora and raises on any divergence.\n\n"
        "---\n\n"
    )
    report_md = fixh_md + report_md

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
            "> **HONEST CAVEAT — coverage is saturated.** process_creation rules key on "
            "fields (Image/CommandLine/ParentImage) every Sysmon EID-1 event carries, so all "
            "loaded rules clear any field-presence floor. The field-presence floor no longer "
            "separates 'ran' from 'didn't run'. Treat precision as trustworthy ONLY for rules "
            "that actually FIRED on the benign corpus.\n"
        )

    report_md += (
        "\n\n## Pooled-recall caveat (UNCHANGED — fix B out of scope)\n\n"
        "> Recall here is **pooled** over the whole process-creation attack corpus "
        f"(tp / {n_attack_events}), NOT per-technique. A pooled denominator caps every "
        "single-technique rule near zero by construction. FIX H only unifies the ruleset; "
        "per-technique recall (fix B) is a separate, still-open item.\n"
    )

    report_md += (
        f"\n\n## Run manifest\n\n"
        f"Reproducibility inputs pinned in [`reports/run3_manifest.json`](run3_manifest.json): "
        f"benign corpus {len(benign_events)} EID-1 ({n_ben} benign / {n_mal} malicious), "
        f"ruleset `{Path(COMPILED_RULESET).name}` ({len(loaded)} loaded high+critical "
        f"process_creation rules, compiled-from-loaded), COMISET mapping hash "
        f"`{manifest['mapping_hash'][:12]}…`, precision floor {MIN_EVENTS}, recall denominator "
        f"{n_attack_events}, run hash `{rh[:12]}…`.\n"
    )
    REPORT_OUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT_OUT.write_text(report_md)
    print(f"[report] -> {REPORT_OUT}", flush=True)

    summary = {
        "loaded_rules": len(loaded),
        "ruleset": str(Path(COMPILED_RULESET).relative_to(REPO)),
        "attack_fires_raw": len(attack_fires),
        "attack_fires_distinct": len(set_attack),
        "benign_fires_raw": len(benign_fires),
        "benign_fires_distinct": len(set_benign),
        "gate_attack_engine": attack_gate.engine_fires,
        "gate_attack_scored": attack_gate.scored_fires,
        "gate_attack_pass": attack_gate.ok,
        "gate_benign_engine": benign_gate.engine_fires,
        "gate_benign_scored": benign_gate.scored_fires,
        "gate_benign_pass": benign_gate.ok,
        "funnel": funnel,
        "positive_control_fired": pc_fired,
        "run_hash": rh,
    }
    Path("/tmp/_run3_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
