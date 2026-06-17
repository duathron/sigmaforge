#!/usr/bin/env python3
"""FIX B end-to-end Sigmaforge backtest -> reports/run4.md (per-technique recall).

Builds on run3 (FIX H one-source ruleset; run3.md preserved). The ONLY change is the
recall denominator:

- run3: POOLED recall = tp / 1533 over the WHOLE sbousseaden process-creation corpus.
  A single-technique rule's recall ceiling is ~1.6% by construction -> meaningless.
- run4: PER-TECHNIQUE recall = (unique attack events OF THE RULE'S TECHNIQUE the rule
  fired on) / (total attack events OF THAT TECHNIQUE). Rules with no technique tag, or
  whose technique has zero attack events, are "unmeasured" (not 0, not pooled).

CORPUS SWITCH (honestly disclosed): per-event TECHNIQUE labels require a
technique-foldered corpus. sbousseaden/EVTX-ATTACK-SAMPLES is foldered by TACTIC only
and embeds a technique ID in just 3/278 filenames, so it cannot be mapped to per-event
technique granularity. The recall corpus is therefore switched to
mdecrevoisier/EVTX-to-MITRE-Attack (CC0), foldered TAxxxx/Txxxx -> each source EVTX
file's parent folder is an unambiguous ATT&CK technique. Precision (benign corpus) is
UNCHANGED. The per-event technique is keyed on _stable_event_id (fix C identity), joined
via each fire's OriginalLogfile (EVTX basename) -> technique (scripts/build_technique_map.py).

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
# FIX B recall corpus: technique-foldered (TAxxxx/Txxxx). Switched from sbousseaden.
RECALL_CORPUS = str(Path.home() / "sigmaforge-v0" / "EVTX-to-MITRE-Attack")
TECHNIQUE_MAP = REPO / "data" / "comiset" / "technique_map.json"
BENIGN_SAMPLE = str(REPO / "data" / "comiset" / "combined_benign_sample.jsonl")
REPORT_OUT = REPO / "reports" / "run4.md"
MANIFEST_OUT = REPO / "reports" / "run4_manifest.json"
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


def main() -> int:
    if not Path(COMPILED_RULESET).exists():
        print(f"[FATAL] {COMPILED_RULESET} missing. Run scripts/compile_loaded_ruleset.py first.", flush=True)
        return 2
    if not TECHNIQUE_MAP.exists():
        print(f"[FATAL] {TECHNIQUE_MAP} missing. Run scripts/build_technique_map.py first.", flush=True)
        return 2

    loaded = load_loaded_rules()
    loaded_titles = {r["title"] for r in loaded}
    print(f"[loaded] {len(loaded)} high+critical stateless process_creation rules", flush=True)

    # rule -> technique coverage (FIX B step 1)
    n_tagged = sum(1 for r in loaded if rule_techniques(r))
    print(f"[rule->technique] {n_tagged}/{len(loaded)} rules carry a usable ATT&CK technique tag", flush=True)

    tmap = json.loads(TECHNIQUE_MAP.read_text())
    technique_event_counts = tmap["technique_event_counts"]
    file_technique = tmap["file_technique"]
    n_pc = tmap["total_pc"]
    n_subtech = sum(1 for t in technique_event_counts if "." in t)
    n_baretech = sum(1 for t in technique_event_counts if "." not in t)
    print(
        f"[recall] per-technique corpus={Path(RECALL_CORPUS).name}: {n_pc} PC events across "
        f"{tmap['techniques_with_pc']} techniques; {tmap['files_mapped']} files mapped, "
        f"{len(tmap['files_unmappable'])} unmappable",
        flush=True,
    )

    # --- Recall pass (technique-foldered attack corpus) — ONE-source ruleset ---
    print("[recall] running Zircolite on the technique-foldered attack corpus (loaded ruleset) ...", flush=True)
    event_technique: dict[str, str] = {}
    attack_fires = run_shard(
        RECALL_CORPUS,
        COMPILED_RULESET,
        mapping_path=EVTX_DEFAULT_CFG,
        json_input=False,
        corpus_label="malicious",
        file_technique_map=file_technique,
        event_technique_out=event_technique,
    )
    print(
        f"[recall] attack_fires={len(attack_fires)}; fired events with a technique={len(event_technique)}",
        flush=True,
    )

    # --- Precision pass (benign corpus) — UNCHANGED, SAME one-source ruleset ---
    print("[precision] running Zircolite on combined benign corpus (loaded ruleset) ...", flush=True)
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
        n_attack_events=n_pc,  # retained for the (now-superseded) pooled comparison
        positive_control_fired=pc_fired,
        min_events=MIN_EVENTS,
        source="COMISET",
        event_technique=event_technique,
        technique_event_counts=technique_event_counts,
    )

    n_measurable = sum(1 for r in rows if r["recall_measurable"])
    n_unmeasured = len(rows) - n_measurable
    n_fired_recall = sum(1 for r in rows if isinstance(r["recall"], float) and r["recall"] > 0)
    print(f"[recall] measurable={n_measurable} unmeasured={n_unmeasured} firing(recall>0)={n_fired_recall}", flush=True)

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
        benign_corpus="combined: COMISET real slice + NextronSystems/evtx-baseline v0.8.4 all-evtx",
        benign_corpus_path=str(Path(BENIGN_SAMPLE).relative_to(REPO)),
        benign_corpus_sha=_sha256_file(BENIGN_SAMPLE),
        benign_eid1_total=len(benign_events),
        benign_label_split={"benign": n_ben, "malicious": n_mal},
        attack_corpus="mdecrevoisier/EVTX-to-MITRE-Attack (technique-foldered, CC0) — FIX B recall corpus",
        attack_process_creation_events=n_pc,
        recall_method="per-technique (FIX B)",
        recall_technique_map=str(TECHNIQUE_MAP.relative_to(REPO)),
        recall_technique_map_sha=_sha256_file(TECHNIQUE_MAP),
        rules_with_technique_tag=n_tagged,
        rules_recall_measurable=n_measurable,
        rules_recall_unmeasured=n_unmeasured,
        attack_fires=len(set_attack),
        benign_fires=len(set_benign),
        positive_control_fired=pc_fired,
        run_hash=rh,
    )
    MANIFEST_OUT.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_OUT.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"[manifest] -> {MANIFEST_OUT}", flush=True)

    # --- FIX B header ---
    top_tech = sorted(technique_event_counts.items(), key=lambda x: -x[1])[:5]
    header = (
        "# Sigmaforge backtest — run4 (FIX B: per-technique recall, FIX B2: sub-technique-granular)\n\n"
        "## FIX B / B2 — recall is PER-TECHNIQUE, SUB-TECHNIQUE-GRANULAR\n\n"
        "run3 pooled recall over the whole process-creation attack corpus (`tp / 1533`). A "
        "single-technique rule can match at most the events of its own technique, so a "
        "corpus-wide denominator caps its recall near **1.6%** by construction — a recall-side "
        "tautology that makes the number meaningless.\n\n"
        "run4 measures each rule against **only the attack events of its own ATT&CK "
        "(sub-)technique(s)**: `recall = (unique matching events the rule fired on) / (total "
        "matching events)`.\n\n"
        "**FIX B2 — sub-technique-granular scoping (no sibling dilution).** Technique IDs are kept "
        "at full sub-technique granularity on BOTH sides (rule tag and corpus event); they are NOT "
        "folded to parent. Matching is **asymmetric**: an attack event of technique X counts toward "
        "rule R iff (a) X is exactly one of R's (sub-)technique tags — so a `T1059.001` (PowerShell) "
        "rule is scored against `T1059.001` events ONLY, never its `T1059.003` (Windows Command "
        "Shell) siblings — OR (b) R carries a **bare parent** tag (e.g. `T1059` with no "
        "sub-technique) and X is any child of it (`T1059.*`), since a generic rule legitimately "
        "covers the whole technique. The earlier fold-to-parent merged a `T1059.001` rule against "
        "the whole `T1059` pool (and sibling sub-techniques), inflating the denominator and "
        "deflating recall. Rules with no technique tag, or whose tags match zero attack events in "
        "the corpus, are **`unmeasured`** (NOT 0, NOT pooled).\n\n"
        f"- **rule -> technique coverage:** {n_tagged}/{len(loaded)} loaded rules carry a usable "
        "`attack.tXXXX` tag.\n"
        f"- **recall-measurable rules:** {n_measurable}/{len(loaded)} "
        f"(technique present in the corpus); **unmeasured:** {n_unmeasured}.\n\n"
        "### Corpus switch (honestly disclosed)\n\n"
        "Per-event TECHNIQUE labels require a technique-foldered corpus. sbousseaden "
        "`EVTX-ATTACK-SAMPLES` (run3's recall corpus) is foldered by **tactic** only and embeds a "
        "technique ID in just **3/278** filenames — it cannot be mapped to per-event technique "
        "granularity. The recall corpus is therefore switched to "
        "**mdecrevoisier/EVTX-to-MITRE-Attack** (CC0), foldered `TAxxxx/Txxxx`, so each source "
        "EVTX file's parent folder is an unambiguous ATT&CK technique. **Precision (the benign "
        "corpus) is UNCHANGED.**\n\n"
        f"- per-technique corpus: **{n_pc}** process-creation events across "
        f"**{tmap['techniques_with_pc']}** distinct techniques — **{n_subtech}** at "
        f"sub-technique granularity (e.g. `T1059.001`, `T1059.003`) + **{n_baretech}** bare-parent "
        f"buckets (corpus folder carries no sub-technique, or a `Txxxx.xxx` unknown-sub "
        f"placeholder). **{tmap['files_mapped']}** EVTX files mapped to a technique, "
        f"**{len(tmap['files_unmappable'])}** unmappable (non-`TAxxxx`-foldered helper dirs — "
        "excluded, NOT silently counted).\n"
        f"- technique skew (HONEST): the corpus is dominated by "
        + ", ".join(f"`{t}`={c}" for t, c in top_tech)
        + " — recall for low-population (sub-)techniques rests on very few events.\n"
        "- worked example (the sibling-dilution bug, fixed): **HackTool - CrackMapExec PowerShell "
        "Obfuscation** is tagged `attack.t1059.001` + `attack.t1027.005`. Under the old "
        "fold-to-parent it scored **1/940** (denom = T1027=742 + T1059=198, merging both parents "
        "and every sibling sub-technique). Sub-technique-granular: `T1059.001`=58 matching events "
        "(sibling `T1059.003`=140 excluded), and `T1027.005` has **no** corpus bucket (the corpus "
        "holds only bare `T1027`, which a sub-technique tag does NOT match) — so its denom is "
        "**58**, recall **0/58 = 0.0** (the lone old 'hit' was a fire on an off-technique sibling "
        "event that never should have counted).\n"
        "- event identity: per-event technique is keyed on `_stable_event_id` (fix C); a fire is "
        "joined to its technique via `OriginalLogfile` (EVTX basename) -> technique "
        "(`scripts/build_technique_map.py`, `data/comiset/technique_map.json`).\n\n"
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

    # --- per-technique recall detail for the rules that actually fired ---
    fired_rows = sorted(
        (r for r in rows if isinstance(r["recall"], float) and r["recall"] > 0),
        key=lambda r: -r["recall"],
    )
    report_md += "\n\n## Per-technique recall — rules with recall > 0\n\n"
    report_md += "| rule | technique(s) | recall | numer/denom |\n|---|---|---|---|\n"
    for r in fired_rows:
        techs = ",".join(r["recall_measured_techniques"]) or "—"
        report_md += f"| {r['rule']} | {techs} | {r['recall']:.4f} | {r['recall_numer']}/{r['recall_denom']} |\n"
    if not fired_rows:
        report_md += "| _(none fired on its own technique's events)_ | | | |\n"

    REPORT_OUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT_OUT.write_text(report_md)
    print(f"[report] -> {REPORT_OUT}", flush=True)

    summary = {
        "loaded_rules": len(loaded),
        "rules_with_technique_tag": n_tagged,
        "recall_measurable": n_measurable,
        "recall_unmeasured": n_unmeasured,
        "attack_fires_distinct": len(set_attack),
        "benign_fires_distinct": len(set_benign),
        "fired_recall_rows": [
            {"rule": r["rule"], "recall": r["recall"], "numer": r["recall_numer"], "denom": r["recall_denom"]}
            for r in fired_rows
        ],
        "positive_control_fired": pc_fired,
        "run_hash": rh,
    }
    Path("/tmp/_run4_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
