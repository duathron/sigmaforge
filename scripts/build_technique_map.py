"""FIX B: build the per-technique recall denominators + file->technique map.

The recall corpus for per-technique recall is mdecrevoisier/EVTX-to-MITRE-Attack
(CC0), which is foldered ``TAxxxx-Tactic/Txxxx-Technique/IDnn-....evtx`` — so each
source EVTX file's PARENT FOLDER carries an unambiguous ATT&CK technique. sbousseaden
(EVTX-ATTACK-SAMPLES) is foldered by TACTIC only and embeds a technique ID in just
3/278 filenames, so it cannot be mapped to per-event TECHNIQUE granularity — hence
the corpus switch (documented in reports/run4.md).

Outputs (committed for reproducibility, like data/comiset/attack_pc_count.json):
- ``technique_event_counts``: parent technique -> total process-creation events (Sysmon
  EID 1 + Security 4688) of that technique. This is the per-technique recall denominator.
- ``file_technique``: source EVTX basename -> parent technique. The orchestrator joins
  fired events (whose OriginalLogfile == this basename) to a technique.

Sub-techniques are folded to parent (T1543.003 -> T1543); the ``.xxx`` placeholder
folders (e.g. T1098.xxx) fold to T1098.

Usage: uv run python scripts/build_technique_map.py <CORPUS_DIR> [out.json]
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path

from evtx import PyEvtxParser

_TECH_DIR = re.compile(r"^(T\d{4})")


def _technique_of(path: Path, root: Path) -> str | None:
    """Parent ATT&CK technique from the file's folder path (Txxxx... folder segment)."""
    for seg in path.relative_to(root).parts:
        m = _TECH_DIR.match(seg)
        if m:
            return m.group(1)
    return None


def _is_process_creation(rec_json: str) -> bool:
    try:
        data = json.loads(rec_json)
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    ev = data.get("Event")
    ev = ev if isinstance(ev, dict) else {}
    system = ev.get("System")
    system = system if isinstance(system, dict) else {}
    eidv = system.get("EventID", "")
    eid = str(eidv.get("#text", "") if isinstance(eidv, dict) else eidv)
    channel = system.get("Channel", "")
    return (channel == "Microsoft-Windows-Sysmon/Operational" and eid == "1") or (
        channel == "Security" and eid == "4688"
    )


def build(corpus_dir: str) -> dict:
    root = Path(corpus_dir)
    pc_by_tech: Counter[str] = Counter()
    file_technique: dict[str, str] = {}
    files_by_tech: Counter[str] = Counter()
    total_pc = 0
    unmappable_files: list[str] = []
    open_errors: list[list[str]] = []
    for p in sorted(root.rglob("*.evtx")):
        tech = _technique_of(p, root)
        if not tech:
            unmappable_files.append(str(p.relative_to(root)))
            continue
        file_technique[p.name] = tech
        files_by_tech[tech] += 1
        try:
            parser = PyEvtxParser(str(p))
        except Exception as e:  # noqa: BLE001
            open_errors.append([str(p.relative_to(root)), str(e)])
            continue
        for rec in parser.records_json():
            if _is_process_creation(rec["data"]):
                pc_by_tech[tech] += 1
                total_pc += 1
    return {
        "corpus": str(root),
        "total_pc": total_pc,
        "technique_event_counts": dict(sorted(pc_by_tech.items())),
        "techniques_with_pc": sum(1 for v in pc_by_tech.values() if v > 0),
        "files_mapped": len(file_technique),
        "files_unmappable": unmappable_files,
        "files_by_technique": dict(sorted(files_by_tech.items())),
        "file_technique": dict(sorted(file_technique.items())),
        "open_errors": open_errors,
    }


if __name__ == "__main__":
    result = build(sys.argv[1])
    summary = {k: v for k, v in result.items() if k not in ("file_technique",)}
    print(json.dumps(summary, indent=2))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(json.dumps(result, indent=2))
        print(f"[written] {sys.argv[2]}", flush=True)
