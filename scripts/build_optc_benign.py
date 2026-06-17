#!/usr/bin/env python3
"""Convert DARPA OpTC eCAR benign-week telemetry into COMISET-shaped benign EID-1
JSONL and APPEND to the benign corpus (precision/false-positive lever).

WHY: the precision side of the backtest needs VOLUME + real enterprise diversity.
DARPA OpTC (FiveDirections/OpTC-data, public domain / Distribution A) has a dedicated
BENIGN collection period (Sept 17-23 2019) recorded across ~1000 real enterprise hosts
BEFORE any red-team activity, so every process-creation record from that window is
benign BY CONSTRUCTION. We extract those records, reshape them into the SAME
"_source"-envelope schema the COMISET / Nextron samples use (so the single
comiset.yaml mapping + scripts.run4_backtest.project_event path handle the whole
corpus uniformly), label them "benign", and stamp identity fields.

FORMAT: OpTC is eCAR JSON (MITRE CAR-based), NOT EVTX. Process-creation records carry
object="PROCESS" action="CREATE" (or "START") with a nested "properties" dict. Field
reshape (eCAR -> COMISET _source path):
  image_path         -> _source.process_path        (-> Sigma Image)
  command_line       -> _source.CommandLine          (-> Sigma CommandLine)
  parent_image_path  -> _source.process_parent_path  (-> Sigma ParentImage)
  principal          -> _source.user_account         (-> Sigma User)
  pid                -> _source.process_id
  ppid               -> _source.process_parent_id
log_name/event_id are stamped to the Sysmon channel/EID-1 so the event_filter +
EventID mapping still match. Identity = sha1 of the raw record line.

Records may be at the eCAR top level OR nested under "properties" (the OpTC ecar
schema puts image_path/command_line/parent_image_path under "properties"); both are
probed. object/action are read case-insensitively.

Usage:
  python scripts/build_optc_benign.py \
      --ecar ~/sigmaforge-v0/optc/AIA-201-225.ecar-last.json.gz \
      --append data/comiset/combined_benign_sample.jsonl \
      --out data/comiset/combined_optc_benign_sample.jsonl \
      --max-eid1 200000

The eCAR input may be plain JSONL (one record per line) or gzipped JSONL (.gz),
auto-detected by magic bytes. Multiple --ecar paths may be passed.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import sys
from typing import IO, Iterator

# eCAR property key -> COMISET _source path (no _source. prefix here). Each maps
# through comiset.yaml to the Sigma field the process_creation rules expect.
FIELD_MAP = {
    "image_path": "process_path",
    "command_line": "CommandLine",
    "parent_image_path": "process_parent_path",
    "principal": "user_account",
    "pid": "process_id",
    "ppid": "process_parent_id",
}

# OpTC benign-week records are process-creation iff object == PROCESS and the action
# is one of these (CREATE in the ecar dumps, START in some errata exports).
PROCESS_OBJECT = "PROCESS"
CREATE_ACTIONS = {"CREATE", "START"}


def _open_maybe_gz(path: str) -> IO[bytes]:
    """Open path as a binary stream, transparently de-gzipping .gz by magic bytes."""
    fh = open(path, "rb")
    head = fh.read(2)
    fh.seek(0)
    if head == b"\x1f\x8b":
        return gzip.GzipFile(fileobj=fh)
    return fh


def _get(rec: dict, key: str):
    """Look up an eCAR field at the top level or under 'properties'."""
    if key in rec and rec[key] not in (None, ""):
        return rec[key]
    props = rec.get("properties")
    if isinstance(props, dict) and props.get(key) not in (None, ""):
        return props[key]
    return None


def _is_process_create(rec: dict) -> bool:
    obj = str(rec.get("object", "")).upper()
    act = str(rec.get("action", "")).upper()
    return obj == PROCESS_OBJECT and act in CREATE_ACTIONS


def reshape_record(rec: dict, raw: bytes) -> dict | None:
    """Reshape one eCAR record into a COMISET _source-envelope doc, or None if it is
    not a process-creation record. Identity = sha1(raw record bytes)."""
    if not _is_process_create(rec):
        return None
    src: dict = {}
    for ecar_key, comiset_key in FIELD_MAP.items():
        val = _get(rec, ecar_key)
        if val not in (None, ""):
            src[comiset_key] = val
    # Drop records that carry no usable process path (nothing for a rule to match).
    if "process_path" not in src:
        return None
    src["log_name"] = "Microsoft-Windows-Sysmon/Operational"
    src["event_id"] = "1"
    src["source_name"] = "DARPA-OpTC-eCAR"
    src["sigmaforge_eid"] = hashlib.sha1(raw).hexdigest()
    src["sigmaforge_label"] = "benign"
    return {"_source": src}


def iter_benign_eid1(ecar_paths: list[str]) -> Iterator[dict]:
    for path in ecar_paths:
        try:
            stream = _open_maybe_gz(path)
        except Exception:
            continue
        with io.TextIOWrapper(stream, encoding="utf-8", errors="replace") as text:
            for line in text:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if not isinstance(rec, dict):
                    continue
                doc = reshape_record(rec, line.encode("utf-8", "replace"))
                if doc is not None:
                    yield doc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ecar", action="append", required=True, help="eCAR JSONL file (.json or .json.gz); repeatable")
    ap.add_argument("--append", default=None, help="existing benign JSONL to carry through unchanged")
    ap.add_argument("--out", required=True, help="combined benign JSONL out")
    ap.add_argument("--max-eid1", type=int, default=0, help="cap OpTC EID-1-equivalent captured (0 = unbounded)")
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

        optc = 0
        for doc in iter_benign_eid1(args.ecar):
            out.write(json.dumps(doc) + "\n")
            optc += 1
            if args.max_eid1 and optc >= args.max_eid1:
                break

    total = carried + optc
    summary = {
        "carried_from_append": carried,
        "carried_malicious": carried_mal,
        "carried_benign": carried - carried_mal,
        "optc_benign_eid1": optc,
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
