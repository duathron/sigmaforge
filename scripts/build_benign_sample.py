#!/usr/bin/env python3
"""Stream the COMISET *Real* dataset zip and build a bounded benign EID-1 sample.

Streams (never fully extracts) the 934 GB JSONL member via `unzip -p ... | this`,
filters to Sysmon process-creation (log_name == Microsoft-Windows-Sysmon/Operational
AND event_id == "1"), injects identity fields UNDER _source so the COMISET mapping
(which maps `_source.sigmaforge_eid`/`_source.sigmaforge_label` identity) surfaces them:

  _source.sigmaforge_eid   = sha1(raw line)
  _source.sigmaforge_label = "malicious" iff _source.rule_technique_id present else "benign"

Bounded by --max-lines (lines scanned) and/or --max-eid1 (EID-1 events captured).
Reads raw lines from stdin (so the caller controls the unzip stream).

Usage:
  unzip -p <zip> <member> | python scripts/build_benign_sample.py \
      --out data/comiset/real_benign_sample.jsonl --max-lines 5000000
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-lines", type=int, default=5_000_000, help="raw lines to scan (0 = unbounded)")
    ap.add_argument("--max-eid1", type=int, default=0, help="stop after capturing this many EID-1 (0 = unbounded)")
    args = ap.parse_args()

    scanned = 0
    captured = 0
    malicious = 0
    parse_err = 0

    with open(args.out, "w") as out:
        for raw in sys.stdin.buffer:
            scanned += 1
            if args.max_lines and scanned > args.max_lines:
                break
            try:
                line = raw.decode("utf-8", "replace")
                doc = json.loads(line)
            except Exception:
                parse_err += 1
                continue
            src = doc.get("_source")
            if not isinstance(src, dict):
                continue
            if src.get("log_name") != "Microsoft-Windows-Sysmon/Operational":
                continue
            if str(src.get("event_id")) != "1":
                continue
            # inject identity fields under _source (mapping surfaces them verbatim)
            eid = hashlib.sha1(raw).hexdigest()
            is_mal = src.get("rule_technique_id") not in (None, "", [])
            src["sigmaforge_eid"] = eid
            src["sigmaforge_label"] = "malicious" if is_mal else "benign"
            out.write(json.dumps(doc) + "\n")
            captured += 1
            if is_mal:
                malicious += 1
            if args.max_eid1 and captured >= args.max_eid1:
                break

    summary = {
        "scanned": scanned,
        "eid1_captured": captured,
        "malicious": malicious,
        "benign": captured - malicious,
        "parse_errors": parse_err,
        "out": args.out,
    }
    sys.stderr.write(json.dumps(summary) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
