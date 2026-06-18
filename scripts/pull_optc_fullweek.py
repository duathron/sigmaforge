#!/usr/bin/env python3
"""run7 corpus builder — enlarge the DARPA OpTC benign-week slice for the precision corpus.

Pulls ADDITIONAL OpTC benign-week host-group/day dumps (beyond run6's single
18-19Sep/AIA-201-225 slice) from the public FiveDirections/OpTC-data Google Drive,
converts each via scripts/build_optc_benign.py (REUSED — the eCAR->COMISET mapping is
NOT rewritten), identity-dedups by sigmaforge_eid against the EXISTING combined corpus,
and appends only NEW benign PROCESS/CREATE EID-1 records.

DISK DISCIPLINE: process ONE source gz at a time — download, convert+append, then DELETE
the raw gz before fetching the next, so raw disk usage stays flat.

BUDGETS (stop on first hit):
  --max-optc-total  cumulative OpTC EID-1 cap in the corpus (default 500000)
  --max-raw-gb      cumulative raw download cap (default 60 GB)

The combined corpus (data/comiset/combined_optc_benign_sample.jsonl) already holds
run5 baseline (17,124: COMISET + Nextron) + run6 OpTC (30,383). We APPEND onto it; the
baseline + run6 events are carried through unchanged (identity-dedup guarantees no
double-count).
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import subprocess
import sys
from pathlib import Path

import gdown

REPO = Path(__file__).resolve().parent.parent
COMBINED = REPO / "data" / "comiset" / "combined_optc_benign_sample.jsonl"
TARGETS_JSON = Path("/tmp/optc_targets.json")
OPTC_DIR = Path.home() / "sigmaforge-v0" / "optc"
PROGRESS = REPO / "reports" / "run7_pull_progress.json"

# Same selectors build_optc_benign uses, replicated here only for the dedup pass
# (we re-derive sigmaforge_eid = sha1(raw line) exactly as the build script does).
PROCESS_OBJECT = "PROCESS"
CREATE_ACTIONS = {"CREATE", "START"}


def _open_maybe_gz(path: Path) -> io.BufferedReader:
    fh = open(path, "rb")
    head = fh.read(2)
    fh.seek(0)
    if head == b"\x1f\x8b":
        return gzip.GzipFile(fileobj=fh)  # type: ignore[return-value]
    return fh


def load_existing_eids() -> set[str]:
    eids: set[str] = set()
    if not COMBINED.exists():
        return eids
    with open(COMBINED) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            e = d.get("_source", {}).get("sigmaforge_eid")
            if e:
                eids.add(e)
    return eids


def count_optc_in_corpus() -> int:
    n = 0
    if not COMBINED.exists():
        return 0
    with open(COMBINED) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            if d.get("_source", {}).get("source_name") == "DARPA-OpTC-eCAR":
                n += 1
    return n


def convert_one(gz_path: Path, tmp_out: Path) -> dict:
    """Run build_optc_benign.py on a single gz, NO --append, into tmp_out. Returns the
    script's JSON summary (its stdout last line)."""
    cmd = [
        sys.executable,
        str(REPO / "scripts" / "build_optc_benign.py"),
        "--ecar",
        str(gz_path),
        "--out",
        str(tmp_out),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"build_optc_benign failed: {proc.stderr[-2000:]}")
    last = proc.stdout.strip().splitlines()[-1]
    return json.loads(last)


def append_dedup(tmp_out: Path, existing: set[str], remaining_budget: int) -> tuple[int, int]:
    """Append records from tmp_out into COMBINED, skipping any sigmaforge_eid already in
    `existing`. Stops at remaining_budget new records. Updates `existing` in place.
    Returns (new_appended, duplicates_skipped)."""
    new_appended = 0
    dups = 0
    with open(tmp_out) as src, open(COMBINED, "a") as dst:
        for line in src:
            line = line.strip()
            if not line:
                continue
            if remaining_budget is not None and new_appended >= remaining_budget:
                break
            try:
                d = json.loads(line)
            except Exception:
                continue
            e = d.get("_source", {}).get("sigmaforge_eid")
            if e in existing:
                dups += 1
                continue
            dst.write(json.dumps(d) + "\n")
            existing.add(e)
            new_appended += 1
    return new_appended, dups


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-optc-total", type=int, default=500_000)
    ap.add_argument("--max-raw-gb", type=float, default=60.0)
    args = ap.parse_args()

    if not COMBINED.exists():
        print(f"[FATAL] {COMBINED} missing — run6 corpus required as the append base.", flush=True)
        return 2
    targets = json.loads(TARGETS_JSON.read_text())
    print(f"[targets] {len(targets)} host-group/day ecar-last.json.gz files queued", flush=True)

    existing = load_existing_eids()
    optc_before = count_optc_in_corpus()
    print(f"[corpus] existing lines with eid={len(existing)} OpTC-in-corpus={optc_before}", flush=True)

    raw_gb_used = 0.0
    pulled: list[dict] = []
    OPTC_DIR.mkdir(parents=True, exist_ok=True)
    tmp_out = OPTC_DIR / "_tmp_convert.jsonl"

    for i, t in enumerate(targets):
        optc_now = count_optc_in_corpus()
        if optc_now >= args.max_optc_total:
            print(f"[STOP] OpTC total cap hit ({optc_now} >= {args.max_optc_total})", flush=True)
            break
        if raw_gb_used >= args.max_raw_gb:
            print(f"[STOP] raw download cap hit ({raw_gb_used:.1f} >= {args.max_raw_gb} GB)", flush=True)
            break

        label = f"{t['day']}/{t['host_group']}"
        gz_path = OPTC_DIR / f"_pull_{t['host_group']}_{t['day']}.json.gz"
        print(f"\n[{i + 1}/{len(targets)}] downloading {label} ({t['file_name']}) ...", flush=True)
        try:
            gdown.download(id=t["file_id"], output=str(gz_path), quiet=False, use_cookies=False)
        except Exception as ex:
            print(f"[ERR] download failed for {label}: {ex} — stopping gracefully", flush=True)
            break
        if not gz_path.exists() or gz_path.stat().st_size == 0:
            print(f"[ERR] {label} produced no file — stopping gracefully", flush=True)
            break

        gz_bytes = gz_path.stat().st_size
        gz_gb = gz_bytes / (1024**3)
        raw_gb_used += gz_gb
        print(f"[dl] {label} {gz_gb:.2f} GB (cumulative raw {raw_gb_used:.2f} GB)", flush=True)

        try:
            summary = convert_one(gz_path, tmp_out)
        except Exception as ex:
            print(f"[ERR] convert failed for {label}: {ex}", flush=True)
            gz_path.unlink(missing_ok=True)
            break
        produced = summary.get("optc_benign_eid1", 0)

        remaining = args.max_optc_total - count_optc_in_corpus()
        new_appended, dups = append_dedup(tmp_out, existing, remaining)
        tmp_out.unlink(missing_ok=True)
        gz_path.unlink(missing_ok=True)  # DISK DISCIPLINE: delete raw before next pull

        rec = {
            "day": t["day"],
            "host_group": t["host_group"],
            "file_name": t["file_name"],
            "raw_gb": round(gz_gb, 3),
            "produced_eid1": produced,
            "new_appended": new_appended,
            "duplicates_skipped": dups,
        }
        pulled.append(rec)
        print(
            f"[append] {label}: produced={produced} new={new_appended} dup={dups} "
            f"corpus_optc_now={count_optc_in_corpus()}",
            flush=True,
        )
        PROGRESS.write_text(json.dumps({"raw_gb_used": raw_gb_used, "pulled": pulled}, indent=2))

    optc_after = count_optc_in_corpus()
    out = {
        "optc_before": optc_before,
        "optc_after": optc_after,
        "optc_newly_added": optc_after - optc_before,
        "raw_gb_downloaded": round(raw_gb_used, 2),
        "files_pulled": len(pulled),
        "pulled": pulled,
    }
    PROGRESS.write_text(json.dumps(out, indent=2))
    print("\n" + json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
