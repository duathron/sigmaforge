#!/usr/bin/env python3
"""FIX B3 end-to-end Sigmaforge backtest -> reports/run5.md (SUB-technique recall).

Builds on run4 (FIX B per-technique recall; run4.md preserved). The ONLY change is the
RECALL CORPUS — precision (the benign corpus) is byte-for-byte UNCHANGED.

THE run4 GAP this fixes: run4's recall corpus (mdecrevoisier/EVTX-to-MITRE-Attack) is
foldered ``TAxxxx/Txxxx`` — bare-PARENT technique only. The asymmetric matcher in
``sigmaforge.score.recall`` lets a SUB-technique-tagged rule (e.g. ``attack.t1059.001``)
score ONLY against an EXACT sub-technique corpus bucket, of which mdecrevoisier has none.
So every sub-technique-tagged rule came back ``unmeasured`` — no recall credit at all.

run5 swaps in a SUB-technique-labeled recall corpus sourced from splunk/attack_data
(Apache-2.0), foldered ``datasets/attack_techniques/<TECH>/<source>/windows-sysmon.log``
where the folder name IS the ATT&CK (sub-)technique (e.g. ``T1059.001``). The line-XML
Sysmon logs are converted (scripts/build_attack_data_corpus.py) into wrapped ``<Events>``
XML documents Zircolite ingests via ``--xml-input``; each fired event's ``OriginalLogfile``
(the .xml basename) joins to its sub-technique via the file_technique map — the SAME
recall join as run4, keyed on ``_stable_event_id`` (fix C identity).

Per-technique recall is otherwise identical to run4/FIX B2: a ``T1059.001`` rule is
measured against ``T1059.001`` events ONLY (no sibling dilution); a bare-parent rule
covers all its children. Rules whose tags match zero corpus events are ``unmeasured``.

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
# FIX B3 recall corpus: SUB-technique-foldered, converted from splunk/attack_data line-XML
# into wrapped <Events> XML (scripts/build_attack_data_corpus.py) -> Zircolite --xml-input.
RECALL_CORPUS = str(Path.home() / "sigmaforge-v0" / "attack_data_corpus")
TECHNIQUE_MAP = REPO / "data" / "comiset" / "attack_data_technique_map.json"
BENIGN_SAMPLE = str(REPO / "data" / "comiset" / "combined_benign_sample.jsonl")
REPORT_OUT = REPO / "reports" / "run5.md"
MANIFEST_OUT = REPO / "reports" / "run5_manifest.json"
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
        print(f"[FATAL] {TECHNIQUE_MAP} missing. Run scripts/build_attack_data_corpus.py first.", flush=True)
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
    n_skipped_no_eid1 = len(tmap.get("skipped_no_eid1", []))
    print(
        f"[recall] sub-technique corpus={Path(RECALL_CORPUS).name}: {n_pc} PC events across "
        f"{tmap['techniques_with_pc']} sub-techniques; {tmap['files_mapped']} files mapped, "
        f"{n_skipped_no_eid1} source logs skipped (no EID-1)",
        flush=True,
    )

    # --- Recall pass (SUB-technique-foldered attack_data corpus) — ONE-source ruleset ---
    print("[recall] running Zircolite on the sub-technique attack_data corpus (loaded ruleset) ...", flush=True)
    event_technique: dict[str, str] = {}
    attack_fires = run_shard(
        RECALL_CORPUS,
        COMPILED_RULESET,
        mapping_path=EVTX_DEFAULT_CFG,
        json_input=False,
        xml_input=True,  # FIX B3: attack_data line-XML -> wrapped <Events> XML
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
        attack_corpus=(
            "splunk/attack_data (sub-technique-foldered, Apache-2.0) — FIX B3 recall corpus; "
            "line-XML windows-sysmon.log -> wrapped <Events> XML (--xml-input)"
        ),
        attack_process_creation_events=n_pc,
        recall_method="per-sub-technique (FIX B3)",
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

    # --- FIX B3 header ---
    top_tech = sorted(technique_event_counts.items(), key=lambda x: -x[1])[:5]
    header = (
        "# Sigmaforge backtest — run5 (FIX B3: SUB-technique recall corpus)\n\n"
        "## FIX B3 — recall corpus is labeled at SUB-technique granularity\n\n"
        "run4 introduced per-(sub-)technique recall (FIX B/B2) but ran it against "
        "**mdecrevoisier/EVTX-to-MITRE-Attack**, which is foldered at **bare-parent** technique "
        "(`TAxxxx/Txxxx`) only. The asymmetric matcher scores a SUB-technique-tagged rule "
        "(e.g. `attack.t1059.001`) ONLY against an **exact** `T1059.001` corpus bucket — and "
        "mdecrevoisier has none. So every sub-technique-tagged rule came back **`unmeasured`**: "
        "no recall credit, the run4 gap this run closes.\n\n"
        "run5 keeps the recall math identical and swaps in a **sub-technique-labeled** recall "
        "corpus from **splunk/attack_data** (Apache-2.0), foldered "
        "`datasets/attack_techniques/<TECH>/<source>/windows-sysmon.log` where the folder name "
        "IS the ATT&CK (sub-)technique (e.g. `T1059.001`). The Sysmon **line-XML** logs (one "
        "`<Event>` per line, no single root) are converted "
        "(`scripts/build_attack_data_corpus.py`) into wrapped `<Events>...</Events>` XML "
        "documents Zircolite ingests via `--xml-input`; each fired event's `OriginalLogfile` "
        "(the .xml basename) joins to its sub-technique via the file_technique map — the SAME "
        "recall join as run4, keyed on `_stable_event_id` (fix C). **Precision (the benign "
        "corpus) is byte-for-byte UNCHANGED.**\n\n"
        "Recall scoping is unchanged from FIX B2 (asymmetric, no sibling dilution): a "
        "`T1059.001` rule is measured against `T1059.001` events ONLY (never its `T1059.003` "
        "siblings); a bare-parent rule covers all its children. Rules with no usable tag, or "
        "whose tags match zero corpus events, stay **`unmeasured`** (NOT 0, NOT pooled).\n\n"
        f"- **rule -> technique coverage:** {n_tagged}/{len(loaded)} loaded rules carry a usable "
        "`attack.tXXXX` tag.\n"
        f"- **recall-measurable rules:** {n_measurable}/{len(loaded)} "
        f"(technique present in the corpus); **unmeasured:** {n_unmeasured}.\n\n"
        "### Corpus provenance (honestly disclosed)\n\n"
        "**splunk/attack_data** (Apache-2.0). Only the sub-technique folders matching a loaded "
        "rule's `attack.tXXXX.xxx` tag were pulled (via the Git-LFS media API — git-lfs was not "
        "installed for a sparse-checkout), so a few MB-to-GB of relevant Sysmon logs, not the "
        "full ~9 GB repo. Each `windows-sysmon.log` is **line-XML** "
        "(`Microsoft-Windows-Sysmon/Operational`, EID-1). Converted to wrapped-XML and run via "
        "`--xml-input` (the same streaming flattener as native EVTX, so `OriginalLogfile` is "
        "set per event exactly as the run4 join expects).\n\n"
        f"- sub-technique corpus: **{n_pc}** process-creation (EID-1) events across "
        f"**{tmap['techniques_with_pc']}** distinct **sub-techniques** ({n_subtech} sub-technique "
        f"+ {n_baretech} bare-parent buckets). **{tmap['files_mapped']}** wrapped-XML files "
        f"mapped to a sub-technique; **{n_skipped_no_eid1}** source logs skipped (no EID-1 "
        "event — excluded, NOT silently counted).\n"
        f"- technique skew (HONEST): the corpus is dominated by "
        + ", ".join(f"`{t}`={c}" for t, c in top_tech)
        + " — recall for low-population sub-techniques rests on very few events.\n"
        "- event identity: per-event sub-technique is keyed on `_stable_event_id` (fix C); a "
        "fire is joined to its sub-technique via `OriginalLogfile` (the .xml basename) -> "
        "sub-technique (`scripts/build_attack_data_corpus.py`, "
        "`data/comiset/attack_data_technique_map.json`).\n\n"
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
    Path("/tmp/_run5_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
