#!/usr/bin/env python3
"""
Sigmaforge A1 GATE spike (SPEC §6).

Proves the COMISET -> Zircolite -> Sigma backtest loop end to end on the real
A1 slice, using the vendored Zircolite engine and the real field-mapping config.

It computes four numbers and an overall verdict:

  (a) LOGSOURCE-ONLY probe -> how many events the mapping/logsource admits.
      Want > 0. If 0, the mapping or the logsource filter drops everything and
      A1 FAILs (nothing downstream can ever match).

  (b) NARROW rule + 1 PLANTED positive -> the planted row MUST fire (>= 1).
      We copy a real slice row, rewrite Image/CommandLine so it matches the
      narrow rule, relabel it, append it to a temp slice, and run. This proves
      a true positive is detectable through the full mapping path. The narrow
      rule has ZERO natural hits on the raw slice (verified by (c)), so the only
      possible hit is the plant -- and we additionally assert the matched
      sigmaforge_eid IS the planted eid.

  (c) A labeled-BENIGN event must NOT fire the narrow rule. We confirm the
      narrow rule's hit count over the raw (unplanted) slice is 0 -> no benign
      event trips it.

  (d) A BROAD rule over the raw slice -> FP count must be finite/inspectable
      and the whole ruleset must NOT be FP=0-across-all-rules. We run the full
      SigmaHQ process_creation ruleset and report the broad rule's count plus
      the total hits and number of distinct rules that fired.

PASS iff: (a) > 0  AND  (b) planted fires (and is the plant)  AND  (c) benign
does not fire the narrow rule  AND  (d) total hits across all rules > 0.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

# --- repo-relative paths (run from repo root) -------------------------------
REPO = Path(__file__).resolve().parent.parent
ZIRCOLITE = REPO / "Zircolite" / "zircolite.py"
CONFIG = REPO / "data" / "mappings" / "comiset.yaml"
SLICE = REPO / "data" / "comiset" / "real_slice_ids.jsonl"

LOGSOURCE_PROBE = REPO / "data" / "fixtures" / "rules" / "logsource_only.yml"
LOGSOURCE_TITLE = "A1 Logsource-Only Probe (process_creation admits any event)"

SIGMA_PC = REPO / "sigma" / "rules" / "windows" / "process_creation"
NARROW_RULE = SIGMA_PC / "proc_creation_win_powershell_encode.yml"
NARROW_TITLE = "Suspicious Execution of Powershell with Base64"
BROAD_RULE = SIGMA_PC / "proc_creation_win_powershell_non_interactive_execution.yml"
BROAD_TITLE = "Non Interactive PowerShell Process Spawned"

PLANTED_EID = "a1planted0000000000000000000000000000000"


def run_zircolite(ruleset: Path, events: Path, outfile: Path) -> list[dict]:
    """Run vendored Zircolite with the real mapping; return parsed detections."""
    if outfile.exists():
        outfile.unlink()
    cmd = [
        "uv", "run", "python", str(ZIRCOLITE),
        "--events", str(events),
        "--json-input",
        "--ruleset", str(ruleset),
        "--config", str(CONFIG),
        "--outfile", str(outfile),
    ]
    proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"Zircolite failed (rc={proc.returncode}) for {ruleset}")
    if not outfile.exists():
        return []  # no detections -> Zircolite may not write the file
    text = outfile.read_text().strip()
    return json.loads(text) if text else []


def count_for_title(detections: list[dict], title: str) -> int:
    for r in detections:
        if r.get("title") == title:
            return int(r.get("count", 0))
    return 0


def total_hits(detections: list[dict]) -> int:
    return sum(int(r.get("count", 0)) for r in detections)


def planted_hit_is_plant(detections: list[dict], title: str, planted_eid: str) -> bool:
    """Confirm the narrow rule's matched rows include the planted eid."""
    for r in detections:
        if r.get("title") != title:
            continue
        for row in r.get("matches", []) or []:
            for key in ("sigmaforge_eid", "id", "row_id"):
                if str(row.get(key, "")) == planted_eid:
                    return True
    return False


def build_planted_slice(dst: Path) -> str:
    """Copy the raw slice and append one PLANTED positive crafted to match the
    NARROW rule (Image endswith \\powershell.exe AND CommandLine has ' -enc ').
    Returns the planted event's sigmaforge_eid."""
    with SLICE.open() as src:
        first = json.loads(src.readline())

    planted = json.loads(json.dumps(first))  # deep copy
    s = planted["_source"]
    # Rewrite to match the narrow encoded-PowerShell rule through the mapping:
    #   _source.process_path -> Image ; _source.CommandLine -> CommandLine
    s["process_path"] = "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe"
    s["process_name"] = "powershell.exe"
    s["CommandLine"] = (
        "powershell.exe -nop -w hidden -enc "
        "JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA"
    )
    s["OriginalFileName"] = "PowerShell.EXE"
    s["sigmaforge_label"] = "malicious"
    s["sigmaforge_eid"] = PLANTED_EID
    planted["_id"] = PLANTED_EID

    with dst.open("w") as out:
        with SLICE.open() as src:
            for line in src:
                out.write(line)
        out.write(json.dumps(planted) + "\n")
    return PLANTED_EID


def main() -> int:
    for p in (ZIRCOLITE, CONFIG, SLICE, LOGSOURCE_PROBE, NARROW_RULE, BROAD_RULE):
        if not p.exists():
            raise SystemExit(f"missing prerequisite: {p}")

    print("=" * 72)
    print("Sigmaforge A1 GATE spike  (COMISET -> Zircolite -> Sigma)")
    print("=" * 72)
    print(f"slice          : {SLICE}")
    print(f"mapping config : {CONFIG}")
    print(f"engine         : {ZIRCOLITE}")
    print(f"narrow rule    : {NARROW_TITLE}")
    print(f"broad rule     : {BROAD_TITLE}")
    print("-" * 72)

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        # (a) logsource-only probe -----------------------------------------
        det_a = run_zircolite(LOGSOURCE_PROBE, SLICE, tmp / "a.json")
        a_admitted = count_for_title(det_a, LOGSOURCE_TITLE)
        if a_admitted == 0 and det_a:  # title drift fallback
            a_admitted = total_hits(det_a)

        # (c) narrow rule over RAW slice -> benign must NOT fire it ---------
        det_c = run_zircolite(NARROW_RULE, SLICE, tmp / "c.json")
        c_narrow_raw = count_for_title(det_c, NARROW_TITLE)

        # (b) narrow rule over PLANTED slice -> planted MUST fire -----------
        planted_slice = tmp / "planted.jsonl"
        build_planted_slice(planted_slice)
        det_b = run_zircolite(NARROW_RULE, planted_slice, tmp / "b.json")
        b_narrow_planted = count_for_title(det_b, NARROW_TITLE)
        b_is_plant = planted_hit_is_plant(det_b, NARROW_TITLE, PLANTED_EID)

        # (d) broad rule + whole ruleset over RAW slice --------------------
        det_d = run_zircolite(SIGMA_PC, SLICE, tmp / "d.json")
        d_broad = count_for_title(det_d, BROAD_TITLE)
        d_total_fp = total_hits(det_d)
        d_rules_fired = len(det_d)

    # --- verdict ----------------------------------------------------------
    crit_a = a_admitted > 0
    crit_b = b_narrow_planted >= 1 and b_is_plant
    crit_c = c_narrow_raw == 0
    crit_d = d_total_fp > 0

    print("RESULTS")
    print("-" * 72)
    print(f"(a) logsource-only events admitted         : {a_admitted}"
          f"   [want > 0]          {'OK' if crit_a else 'FAIL'}")
    print(f"(b) narrow rule hits on PLANTED slice      : {b_narrow_planted}"
          f"   [want >= 1]         {'OK' if crit_b else 'FAIL'}")
    print(f"    planted eid is the firing row          : {b_is_plant}")
    print(f"(c) narrow rule hits on RAW (benign) slice : {c_narrow_raw}"
          f"   [want == 0]         {'OK' if crit_c else 'FAIL'}")
    print(f"(d) broad rule hits ('{BROAD_TITLE}'): {d_broad}")
    print(f"    total hits across whole ruleset        : {d_total_fp}"
          f"   [want > 0]          {'OK' if crit_d else 'FAIL'}")
    print(f"    distinct SigmaHQ rules that fired       : {d_rules_fired}")
    print("-" * 72)

    if crit_a and crit_b and crit_c and crit_d:
        print("A1 PASS")
        print("The COMISET -> Zircolite -> Sigma backtest loop is proven. M1 unblocked.")
        return 0

    print("A1 FAIL")
    failed = [n for n, ok in
              (("a", crit_a), ("b", crit_b), ("c", crit_c), ("d", crit_d)) if not ok]
    print(f"failed criteria: {', '.join(failed)}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
