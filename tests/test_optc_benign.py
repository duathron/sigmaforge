"""Tests for scripts/build_optc_benign.py — the DARPA OpTC eCAR benign-corpus converter.

Proves on a tiny synthetic eCAR fixture (no network, no Drive download) that the
converter:
  * keeps ONLY PROCESS object + CREATE/START action records (drops everything else),
  * reshapes eCAR image_path / command_line / parent_image_path / principal into the
    COMISET _source envelope and labels each "benign",
  * stamps a stable sha1 identity,
  * gz round-trips through --append/--out exactly like build_nextron_benign.py, AND
  * each output line survives the run4 precision path (load_comiset_field_map ->
    project_event) into the Sigma fields Image / CommandLine / ParentImage / User.
"""

import gzip
import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

_SPEC = importlib.util.spec_from_file_location(
    "build_optc_benign",
    REPO / "scripts" / "build_optc_benign.py",
)
mod = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(mod)

# Reuse the EXACT run4 precision-pass projection so the test asserts the real
# consumption path, not a re-implementation.
_RUN4_SPEC = importlib.util.spec_from_file_location(
    "run4_backtest",
    REPO / "scripts" / "run4_backtest.py",
)
run4 = importlib.util.module_from_spec(_RUN4_SPEC)
assert _RUN4_SPEC and _RUN4_SPEC.loader
_RUN4_SPEC.loader.exec_module(run4)


# Synthetic eCAR records mirroring the OpTC ecar schema:
#  - rec 1: PROCESS / CREATE with fields under "properties" (the OpTC ecar layout) — KEEP
#  - rec 2: FLOW / MESSAGE (a network record, NOT process-creation) — DROP
#  - rec 3: PROCESS / START with fields at the top level — KEEP (action alias)
_REC_PROCESS_CREATE = {
    "object": "PROCESS",
    "action": "CREATE",
    "pid": 4321,
    "ppid": 1000,
    "principal": "SYSADMIN-201\\bob",
    "timestamp": 1568700000000,
    "properties": {
        "image_path": "C:\\Windows\\System32\\notepad.exe",
        "command_line": "notepad.exe C:\\Users\\bob\\notes.txt",
        "parent_image_path": "C:\\Windows\\explorer.exe",
    },
}
_REC_FLOW = {
    "object": "FLOW",
    "action": "MESSAGE",
    "properties": {"src_ip": "10.0.0.5", "dest_ip": "10.0.0.9"},
}
_REC_PROCESS_START_TOPLEVEL = {
    "object": "PROCESS",
    "action": "START",
    "pid": 9999,
    "ppid": 4321,
    "principal": "SYSADMIN-201\\bob",
    "image_path": "C:\\Windows\\System32\\cmd.exe",
    "command_line": "cmd.exe /c whoami",
    "parent_image_path": "C:\\Windows\\System32\\notepad.exe",
}


def _write_ecar_gz(path: Path, records: list[dict]) -> None:
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")


def test_reshape_keeps_process_create_drops_others():
    raw = json.dumps(_REC_PROCESS_CREATE).encode("utf-8")
    doc = mod.reshape_record(_REC_PROCESS_CREATE, raw)
    assert doc is not None
    src = doc["_source"]
    assert src["process_path"] == "C:\\Windows\\System32\\notepad.exe"
    assert src["CommandLine"] == "notepad.exe C:\\Users\\bob\\notes.txt"
    assert src["process_parent_path"] == "C:\\Windows\\explorer.exe"
    assert src["user_account"] == "SYSADMIN-201\\bob"
    assert src["log_name"] == "Microsoft-Windows-Sysmon/Operational"
    assert src["event_id"] == "1"
    assert src["sigmaforge_label"] == "benign"
    # identity is sha1 of the raw record bytes
    import hashlib

    assert src["sigmaforge_eid"] == hashlib.sha1(raw).hexdigest()


def test_reshape_drops_non_process_record():
    assert mod.reshape_record(_REC_FLOW, b"{}") is None


def test_reshape_accepts_start_action_and_toplevel_fields():
    doc = mod.reshape_record(_REC_PROCESS_START_TOPLEVEL, b"{}")
    assert doc is not None
    assert doc["_source"]["process_path"] == "C:\\Windows\\System32\\cmd.exe"
    assert doc["_source"]["CommandLine"] == "cmd.exe /c whoami"


def test_iter_drops_non_process_records(tmp_path):
    ecar = tmp_path / "AIA-201.ecar.json.gz"
    _write_ecar_gz(ecar, [_REC_PROCESS_CREATE, _REC_FLOW, _REC_PROCESS_START_TOPLEVEL])
    docs = list(mod.iter_benign_eid1([str(ecar)]))
    assert len(docs) == 2  # the FLOW record is dropped
    assert all(d["_source"]["sigmaforge_label"] == "benign" for d in docs)


def test_append_out_merges_like_nextron(tmp_path):
    """--append carries an existing corpus line through unchanged, then OpTC docs
    are appended — exactly the build_nextron_benign.py merge contract."""
    ecar = tmp_path / "AIA-201.ecar.json.gz"
    _write_ecar_gz(ecar, [_REC_PROCESS_CREATE, _REC_FLOW, _REC_PROCESS_START_TOPLEVEL])

    existing = tmp_path / "existing_benign.jsonl"
    carried_doc = {"_source": {"process_path": "C:\\carried.exe", "sigmaforge_label": "benign"}}
    existing.write_text(json.dumps(carried_doc) + "\n")

    out = tmp_path / "combined.jsonl"
    rc = _run_main(["--ecar", str(ecar), "--append", str(existing), "--out", str(out)])
    assert rc == 0

    lines = [json.loads(line) for line in out.read_text().splitlines() if line.strip()]
    assert len(lines) == 3  # 1 carried + 2 OpTC
    assert lines[0] == carried_doc  # carried line is byte-identical
    assert lines[1]["_source"]["process_path"] == "C:\\Windows\\System32\\notepad.exe"


def test_max_eid1_cap(tmp_path):
    ecar = tmp_path / "AIA-201.ecar.json.gz"
    _write_ecar_gz(ecar, [_REC_PROCESS_CREATE, _REC_PROCESS_START_TOPLEVEL])
    out = tmp_path / "capped.jsonl"
    rc = _run_main(["--ecar", str(ecar), "--out", str(out), "--max-eid1", "1"])
    assert rc == 0
    lines = [line for line in out.read_text().splitlines() if line.strip()]
    assert len(lines) == 1


def test_output_roundtrips_through_run4_project_event(tmp_path):
    """The load-bearing assertion: an OpTC output line, read by the run4 precision
    pass (load_comiset_field_map -> project_event), surfaces the Sigma fields the
    process_creation rules match on."""
    ecar = tmp_path / "AIA-201.ecar.json.gz"
    _write_ecar_gz(ecar, [_REC_PROCESS_CREATE])
    out = tmp_path / "combined.jsonl"
    assert _run_main(["--ecar", str(ecar), "--out", str(out)]) == 0

    field_map = run4.load_comiset_field_map()
    doc = json.loads(out.read_text().splitlines()[0])
    src = doc["_source"]
    ev = run4.project_event(src, field_map)

    # COMISET _source.* paths -> Sigma fields, via the real comiset.yaml mapping.
    assert ev["Image"] == "C:\\Windows\\System32\\notepad.exe"
    assert ev["CommandLine"] == "notepad.exe C:\\Users\\bob\\notes.txt"
    assert ev["ParentImage"] == "C:\\Windows\\explorer.exe"
    assert ev["User"] == "SYSADMIN-201\\bob"
    assert ev["Channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert ev["EventID"] == "1"
    # label survives verbatim (mapped to itself in comiset.yaml)
    assert ev["sigmaforge_label"] == "benign"


def _run_main(argv: list[str]) -> int:
    import sys

    old = sys.argv
    sys.argv = ["build_optc_benign.py", *argv]
    try:
        return mod.main()
    finally:
        sys.argv = old
