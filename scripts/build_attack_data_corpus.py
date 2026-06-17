#!/usr/bin/env python3
"""FIX B3: build a SUB-technique-labeled attack recall corpus from splunk/attack_data.

WHY (the run4 gap): run4's recall corpus (mdecrevoisier/EVTX-to-MITRE-Attack) is
foldered ``TAxxxx/Txxxx`` — bare-PARENT technique only. So a rule tagged at
sub-technique granularity (e.g. ``attack.t1059.001``) gets NO recall credit: the
asymmetric matcher in ``sigmaforge.score.recall`` only lets a sub-technique rule
score against an EXACT sub-technique corpus bucket, and the mdecrevoisier corpus
has none. The result: every sub-technique-tagged rule is ``unmeasured``.

THE FIX: splunk/attack_data (Apache-2.0) is foldered
``datasets/attack_techniques/<TECH>/<source>/windows-sysmon.log`` where ~204 of
the 339 folder names ARE at sub-technique granularity (e.g. ``T1059.001``). The
folder name is the ATT&CK (sub-)technique label. We convert each
``windows-sysmon.log`` (Sysmon LINE-XML: one full ``<Event>...</Event>`` Windows
EventLog XML element per line, channel ``Microsoft-Windows-Sysmon/Operational``)
into a shape Zircolite ingests, preserving per-event -> sub-technique label.

FORMAT CHOICE (justified): the line-XML files have NO single XML root (one
``<Event>`` per line). Zircolite's ``--xml-input`` streaming path uses
``lxml.etree.iterparse``, which stops after the FIRST root element on a multi-root
file. So we WRAP each source file's events in a single ``<Events>...</Events>``
document and emit one ``<TECH>__<source>.xml`` per source. We do NOT synthesize
binary EVTX (no maintained pure-Python EVTX writer is vendored, and the round-trip
would be lossy); ``--xml-input`` runs the SAME streaming flattener
(``_flatten_event``) as native EVTX, so ``OriginalLogfile`` (= the .xml basename)
is set per event exactly as run4's recall join expects.

OUTPUT (mirrors scripts/build_technique_map.py so run5's recall path consumes it
with minimal change):
- a directory of ``<TECH>__<source>.xml`` files (the corpus run5 feeds Zircolite
  with ``xml_input=True``);
- a technique-map JSON with the SAME keys ``build_technique_map.py`` emits:
  ``technique_event_counts`` (sub-technique -> process-creation EID-1 count =
  recall denominator), ``file_technique`` (.xml basename -> sub-technique),
  ``total_pc``, ``techniques_with_pc``, ``files_mapped``, ``files_by_technique``.

The recall join is identical to run4: a fired event's ``OriginalLogfile`` (the
.xml basename) -> sub-technique via ``file_technique``; ``_stable_event_id``
identity; ``per_technique_recall`` scores each rule against ONLY its own
(sub-)technique events.

Usage:
  uv run python scripts/build_attack_data_corpus.py \
      --src ~/sigmaforge-v0/attack_data/datasets/attack_techniques \
      --out-dir ~/sigmaforge-v0/attack_data_corpus \
      --map-out data/comiset/attack_data_technique_map.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

# A line is an EID-1 (Sysmon process-creation) event iff it is a Sysmon-Operational
# <Event> carrying <EventID>1</EventID>. The line-XML uses single-quoted attrs and
# the canonical EventLog namespace. We match on raw text (cheap, robust) and only
# parse the lines we keep.
_EVENTID_RE = re.compile(r"<EventID[^>]*>\s*(\d+)\s*</EventID>")
_CHANNEL_RE = re.compile(r"<Channel>([^<]+)</Channel>")
_SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# Folder name -> ATT&CK (sub-)technique. Keep sub-technique granularity (T1059.001).
# A ``.xxx`` placeholder folder (unknown sub-technique) folds to the bare parent.
_TECH_DIR = re.compile(r"^(T\d{4})(?:\.(\d{3}|xxx))?$")


def technique_of_folder(name: str) -> str | None:
    """ATT&CK (sub-)technique label from a splunk/attack_data folder name.

    ``T1059.001`` -> ``T1059.001``; bare ``T1059`` -> ``T1059``; a ``.xxx``
    placeholder (unknown sub-technique) folds to the bare parent ``T1059``.
    Returns None if the folder is not a technique folder.
    """
    m = _TECH_DIR.match(name)
    if not m:
        return None
    parent, sub = m.group(1), m.group(2)
    if sub and sub != "xxx":
        return f"{parent}.{sub}"
    return parent


def is_process_creation_line(line: str) -> bool:
    """True iff this line-XML <Event> is a Sysmon EID-1 process-creation event."""
    ch = _CHANNEL_RE.search(line)
    if not ch or ch.group(1) != _SYSMON_CHANNEL:
        return False
    eid = _EVENTID_RE.search(line)
    return bool(eid) and eid.group(1) == "1"


def iter_event_lines(text: str):
    """Yield each ``<Event ...>...</Event>`` element from a line-XML document.

    Robust to events split or joined across newlines: we re-segment on the
    ``<Event`` ... ``</Event>`` boundaries rather than trusting one-per-physical-line.
    """
    # Normalize: put each <Event ...> on its own segment, strip stray newlines.
    normalized = text.replace("\r", "").replace("\n", "")
    for chunk in normalized.split("</Event>"):
        chunk = chunk.strip()
        if not chunk:
            continue
        start = chunk.find("<Event")
        if start == -1:
            continue
        yield chunk[start:] + "</Event>"


def convert_log_to_events_xml(log_text: str) -> tuple[str, int]:
    """Convert one windows-sysmon.log (line-XML) -> a single wrapped <Events> doc.

    Keeps ONLY Sysmon EID-1 (process-creation) events — the recall denominator the
    process-creation ruleset is measured against. Returns (xml_document, eid1_count).
    Returns ("", 0) when the file holds no EID-1 events (caller skips it).
    """
    kept: list[str] = []
    for ev in iter_event_lines(log_text):
        if is_process_creation_line(ev):
            kept.append(ev)
    if not kept:
        return "", 0
    body = "\n".join(kept)
    return f"<Events>\n{body}\n</Events>\n", len(kept)


def build(src: str, out_dir: str) -> dict:
    """Convert every windows-sysmon.log under sub-technique folders of src.

    src is the ``datasets/attack_techniques`` directory of a (sparse) splunk/attack_data
    checkout. out_dir receives one ``<TECH>__<source>.xml`` per source folder that has
    EID-1 events. Returns the technique map (same schema as build_technique_map.py).
    """
    src_root = Path(src)
    out_root = Path(out_dir)
    out_root.mkdir(parents=True, exist_ok=True)

    pc_by_tech: Counter[str] = Counter()
    files_by_tech: Counter[str] = Counter()
    file_technique: dict[str, str] = {}
    total_pc = 0
    skipped_no_eid1: list[str] = []
    skipped_not_technique: list[str] = []

    # A source folder may hold several Sysmon logs: the canonical ``windows-sysmon.log``
    # plus prefixed variants (e.g. ``createdump_windows-sysmon.log``). Capture them all;
    # the filename stem is folded into the output basename so they never collide.
    for log in sorted(src_root.rglob("*windows-sysmon.log")):
        # .../attack_techniques/<TECH>/<source>/[<prefix>_]windows-sysmon.log
        rel = log.relative_to(src_root)
        parts = rel.parts
        if len(parts) < 2:
            continue
        tech = technique_of_folder(parts[0])
        if tech is None:
            skipped_not_technique.append(str(rel))
            continue
        source = parts[1] if len(parts) >= 3 else "root"
        xml_doc, eid1 = convert_log_to_events_xml(log.read_text(encoding="utf-8", errors="replace"))
        if eid1 == 0:
            skipped_no_eid1.append(str(rel))
            continue
        # basename = join key; must be unique. <TECH>__<source>__<logstem>.xml
        safe_source = re.sub(r"[^A-Za-z0-9._-]", "_", source)
        stem = log.name[: -len(".log")]
        safe_stem = re.sub(r"[^A-Za-z0-9._-]", "_", stem)
        base = f"{parts[0]}__{safe_source}__{safe_stem}.xml"
        (out_root / base).write_text(xml_doc, encoding="utf-8")
        file_technique[base] = tech
        files_by_tech[tech] += 1
        pc_by_tech[tech] += eid1
        total_pc += eid1

    return {
        "corpus": str(out_root),
        "source": str(src_root),
        "total_pc": total_pc,
        "technique_event_counts": dict(sorted(pc_by_tech.items())),
        "techniques_with_pc": sum(1 for v in pc_by_tech.values() if v > 0),
        "files_mapped": len(file_technique),
        "files_by_technique": dict(sorted(files_by_tech.items())),
        "file_technique": dict(sorted(file_technique.items())),
        "skipped_no_eid1": skipped_no_eid1,
        "skipped_not_technique_folder": skipped_not_technique,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="attack_data datasets/attack_techniques dir")
    ap.add_argument("--out-dir", required=True, help="output dir for <TECH>__<source>.xml corpus")
    ap.add_argument("--map-out", default=None, help="write the technique map JSON here")
    args = ap.parse_args()

    result = build(args.src, args.out_dir)
    summary = {k: v for k, v in result.items() if k not in ("file_technique",)}
    print(json.dumps(summary, indent=2))
    if args.map_out:
        Path(args.map_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.map_out).write_text(json.dumps(result, indent=2))
        print(f"[written] {args.map_out}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
