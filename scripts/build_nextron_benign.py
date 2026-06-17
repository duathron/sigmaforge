#!/usr/bin/env python3
"""Convert NextronSystems/evtx-baseline native EVTX into COMISET-shaped benign
EID-1 JSONL and APPEND to the benign corpus (Skeptic round 2, scale lever).

WHY: the COMISET real slice yielded only 2032 EID-1 -> just 1 rule cleared the
precision floor. evtx-baseline (Apache-2.0) is native-EVTX goodware captured on
clean reference Windows hosts, so EVERY Sysmon process-creation event is benign
BY CONSTRUCTION. We extract those EID-1 events, reshape them into the SAME
"_source"-envelope schema the COMISET sample uses (so the single comiset.yaml
mapping + scripts.run_first_backtest.project_event path handle the whole corpus
uniformly), label them "benign", and stamp identity fields.

Field reshape (native Sysmon EID-1 EventData -> COMISET _source path):
  Image             -> _source.process_path
  CommandLine       -> _source.CommandLine
  ParentImage       -> _source.process_parent_path
  ParentCommandLine -> _source.ParentCommandLine
  ... (see FIELD_MAP). Channel/EventID land under _source.log_name/_source.event_id
  so the event_filter + EventID mapping still match.

Usage:
  python scripts/build_nextron_benign.py \
      --evtx-root ~/sigmaforge-v0/nextron-baseline/extracted \
      --append data/comiset/real_benign_sample.jsonl \
      --out data/comiset/combined_benign_sample.jsonl
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import sys
from pathlib import Path

from evtx import PyEvtxParser

# native Sysmon EID-1 EventData field -> COMISET _source path (no _source. prefix here)
FIELD_MAP = {
    "Image": "process_path",
    "CommandLine": "CommandLine",
    "ParentImage": "process_parent_path",
    "ParentCommandLine": "ParentCommandLine",
    "OriginalFileName": "OriginalFileName",
    "CurrentDirectory": "CurrentDirectory",
    "IntegrityLevel": "IntegrityLevel",
    "ProcessGuid": "process_guid",
    "ProcessId": "process_id",
    "ParentProcessGuid": "process_parent_guid",
    "ParentProcessId": "process_parent_id",
    "ParentUser": "ParentUser",
    "Company": "Company",
    "Description": "Description",
    "Product": "Product",
    "FileVersion": "FileVersion",
    "RuleName": "RuleName",
    "User": "user_account",
    "Hashes": "Hashes",
}


def _eid(system: dict):
    e = system.get("EventID")
    if isinstance(e, dict):
        e = e.get("#text", e.get("Value"))
    try:
        return int(e)
    except Exception:
        return e


def _provider(system: dict) -> str:
    return (system.get("Provider") or {}).get("#attributes", {}).get("Name", "")


def iter_benign_eid1(evtx_root: str):
    files = sorted(glob.glob(str(Path(evtx_root) / "**" / "*.evtx"), recursive=True))
    for f in files:
        try:
            parser = PyEvtxParser(f)
            gen = parser.records_json()
        except Exception:
            continue
        while True:
            try:
                rec = next(gen)
            except StopIteration:
                break
            except Exception:
                continue
            try:
                ev = json.loads(rec["data"])["Event"]
                system = ev.get("System") or {}
            except Exception:
                continue
            if _eid(system) != 1 or "Sysmon" not in _provider(system):
                continue
            data = ev.get("EventData") or {}
            src: dict = {}
            for native, comiset_key in FIELD_MAP.items():
                if native in data and data[native] not in (None, ""):
                    src[comiset_key] = data[native]
            src["log_name"] = system.get("Channel", "Microsoft-Windows-Sysmon/Operational")
            src["event_id"] = "1"
            src["source_name"] = _provider(system)
            # benign BY CONSTRUCTION (goodware capture); identity = sha1 of the record
            raw = rec["data"].encode("utf-8", "replace")
            src["sigmaforge_eid"] = hashlib.sha1(raw).hexdigest()
            src["sigmaforge_label"] = "benign"
            yield {"_source": src}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evtx-root", required=True, help="dir tree with extracted evtx-baseline *.evtx")
    ap.add_argument("--append", default=None, help="existing benign JSONL to carry through unchanged")
    ap.add_argument("--out", required=True, help="combined benign JSONL out")
    ap.add_argument("--max-eid1", type=int, default=0, help="cap Nextron EID-1 captured (0 = unbounded)")
    args = ap.parse_args()

    carried = carried_mal = 0
    with open(args.out, "w") as out:
        if args.append:
            with open(args.append) as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    doc = json.loads(line)
                    out.write(json.dumps(doc) + "\n")
                    carried += 1
                    if doc.get("_source", {}).get("sigmaforge_label") == "malicious":
                        carried_mal += 1

        nextron = 0
        for doc in iter_benign_eid1(args.evtx_root):
            out.write(json.dumps(doc) + "\n")
            nextron += 1
            if args.max_eid1 and nextron >= args.max_eid1:
                break

    total = carried + nextron
    summary = {
        "carried_from_append": carried,
        "carried_malicious": carried_mal,
        "carried_benign": carried - carried_mal,
        "nextron_benign_eid1": nextron,
        "combined_total_eid1": total,
        "combined_malicious": carried_mal,
        "combined_benign": total - carried_mal,
        "out": args.out,
    }
    sys.stderr.write(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
