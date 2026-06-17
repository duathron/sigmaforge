"""Count process-creation events (Sysmon EID 1 + Security 4688) in an EVTX attack corpus.

This is the recall denominator (BLOCKER-1). Committed so the pinned count in
reports/run_manifest.json (attack_process_creation_events) is reproducible from tracked code.

Usage: uv run python scripts/count_attack_pc.py <EVTX_DIR> [out.json]
"""

import json
import sys
from pathlib import Path

from evtx import PyEvtxParser  # same parser Zircolite uses


def count_pc(evtx_dir: str) -> dict:
    sysmon1 = sec4688 = total = 0
    for p in Path(evtx_dir).rglob("*.evtx"):
        try:
            parser = PyEvtxParser(str(p))
        except Exception:
            continue
        for rec in parser.records_json():
            total += 1
            data = json.loads(rec["data"])
            system = (data.get("Event", {}) or {}).get("System", {}) or {}
            eid = str((system.get("EventID", {}) or {}).get("#text", system.get("EventID", "")))
            channel = system.get("Channel", "")
            if channel == "Microsoft-Windows-Sysmon/Operational" and eid == "1":
                sysmon1 += 1
            elif channel == "Security" and eid == "4688":
                sec4688 += 1
    return {
        "sysmon_eid1": sysmon1,
        "security_4688": sec4688,
        "process_creation_total": sysmon1 + sec4688,
        "all_events_parsed": total,
    }


if __name__ == "__main__":
    result = count_pc(sys.argv[1])
    print(json.dumps(result, indent=2))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(json.dumps(result, indent=2))
