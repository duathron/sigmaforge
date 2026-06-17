"""FIX B3 tests for scripts/build_attack_data_corpus.py — the splunk/attack_data
sub-technique recall-corpus converter.

Proves on a tiny synthetic windows-sysmon.log fixture that the converter:
  * extracts Sysmon EID-1 process-creation events (and ONLY those),
  * preserves Image / CommandLine through the wrapped <Events> doc,
  * labels each output file with the correct SUB-technique (the folder name),
  * emits the same technique-map schema build_technique_map.py does.
"""

import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "build_attack_data_corpus",
    Path(__file__).resolve().parent.parent / "scripts" / "build_attack_data_corpus.py",
)
mod = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(mod)


# Synthetic windows-sysmon.log: 3 lines mirroring splunk/attack_data line-XML.
# Line 1: EID-1 process-creation (powershell) — KEEP.
# Line 2: EID-3 network-connect (NOT process-creation) — DROP.
# Line 3: EID-1 process-creation (cmd) — KEEP.
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_EID1_PS = (
    f"<Event xmlns='{_NS}'><System><Provider Name='Microsoft-Windows-Sysmon'/>"
    "<EventID>1</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
    "<Computer>host1</Computer></System><EventData>"
    "<Data Name='UtcTime'>2021-03-01 22:52:57.032</Data>"
    "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
    "<Data Name='CommandLine'>powershell.exe -enc ZQBjAGgAbwA=</Data>"
    "</EventData></Event>"
)
_EID3_NET = (
    f"<Event xmlns='{_NS}'><System><Provider Name='Microsoft-Windows-Sysmon'/>"
    "<EventID>3</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
    "<Computer>host1</Computer></System><EventData>"
    "<Data Name='Image'>C:\\Windows\\System32\\svchost.exe</Data>"
    "<Data Name='DestinationIp'>10.0.0.1</Data></EventData></Event>"
)
_EID1_CMD = (
    f"<Event xmlns='{_NS}'><System><Provider Name='Microsoft-Windows-Sysmon'/>"
    "<EventID>1</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
    "<Computer>host1</Computer></System><EventData>"
    "<Data Name='UtcTime'>2021-03-01 22:53:00.000</Data>"
    "<Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data>"
    "<Data Name='CommandLine'>cmd.exe /c whoami</Data>"
    "</EventData></Event>"
)
_SYNTH_LOG = "\n".join([_EID1_PS, _EID3_NET, _EID1_CMD]) + "\n"


def test_technique_of_folder_keeps_subtechnique():
    assert mod.technique_of_folder("T1059.001") == "T1059.001"


def test_technique_of_folder_bare_parent():
    assert mod.technique_of_folder("T1003") == "T1003"


def test_technique_of_folder_xxx_placeholder_folds_to_parent():
    assert mod.technique_of_folder("T1110.xxx") == "T1110"


def test_technique_of_folder_rejects_non_technique():
    assert mod.technique_of_folder("atomic_red_team") is None


def test_is_process_creation_line():
    assert mod.is_process_creation_line(_EID1_PS) is True
    assert mod.is_process_creation_line(_EID3_NET) is False


def test_convert_keeps_only_eid1_and_preserves_fields():
    xml_doc, eid1 = mod.convert_log_to_events_xml(_SYNTH_LOG)
    # Exactly the 2 EID-1 events kept, the EID-3 dropped.
    assert eid1 == 2
    assert xml_doc.startswith("<Events>")
    assert xml_doc.rstrip().endswith("</Events>")
    assert xml_doc.count("<Event ") == 2
    # Image + CommandLine preserved for BOTH kept events.
    assert "powershell.exe" in xml_doc
    assert "cmd.exe /c whoami" in xml_doc
    # The network event's distinctive field is gone (it was dropped).
    assert "DestinationIp" not in xml_doc


def test_convert_empty_when_no_eid1():
    xml_doc, eid1 = mod.convert_log_to_events_xml(_EID3_NET + "\n")
    assert eid1 == 0
    assert xml_doc == ""


def test_build_labels_files_with_subtechnique(tmp_path):
    # Lay out a tiny splunk/attack_data tree:
    #   <src>/T1059.001/atomic_red_team/windows-sysmon.log  (2 EID-1)
    #   <src>/T1003.001/lsass_dump/windows-sysmon.log       (1 EID-1)
    src = tmp_path / "attack_techniques"
    f1 = src / "T1059.001" / "atomic_red_team" / "windows-sysmon.log"
    f1.parent.mkdir(parents=True)
    f1.write_text(_SYNTH_LOG, encoding="utf-8")

    f2 = src / "T1003.001" / "lsass_dump" / "windows-sysmon.log"
    f2.parent.mkdir(parents=True)
    f2.write_text(_EID1_PS + "\n", encoding="utf-8")

    out_dir = tmp_path / "corpus"
    result = mod.build(str(src), str(out_dir))

    # Same schema as build_technique_map.py.
    assert result["total_pc"] == 3
    assert result["technique_event_counts"] == {"T1003.001": 1, "T1059.001": 2}
    assert result["techniques_with_pc"] == 2
    assert result["files_mapped"] == 2

    # file_technique join key (.xml basename) -> sub-technique.
    ft = result["file_technique"]
    assert ft == {
        "T1003.001__lsass_dump__windows-sysmon.xml": "T1003.001",
        "T1059.001__atomic_red_team__windows-sysmon.xml": "T1059.001",
    }
    # The wrapped .xml files were actually written.
    assert (out_dir / "T1059.001__atomic_red_team__windows-sysmon.xml").exists()
    assert (out_dir / "T1003.001__lsass_dump__windows-sysmon.xml").exists()


def test_build_prefixed_variants_in_same_source_do_not_collide(tmp_path):
    # A source folder can hold windows-sysmon.log AND createdump_windows-sysmon.log.
    # Both must be captured under distinct join keys (basenames).
    src = tmp_path / "attack_techniques"
    d = src / "T1003.001" / "atomic_red_team"
    d.mkdir(parents=True)
    (d / "windows-sysmon.log").write_text(_EID1_PS + "\n", encoding="utf-8")
    (d / "createdump_windows-sysmon.log").write_text(_EID1_CMD + "\n", encoding="utf-8")

    result = mod.build(str(src), str(tmp_path / "corpus"))
    assert result["files_mapped"] == 2
    assert set(result["file_technique"]) == {
        "T1003.001__atomic_red_team__windows-sysmon.xml",
        "T1003.001__atomic_red_team__createdump_windows-sysmon.xml",
    }
    assert result["technique_event_counts"] == {"T1003.001": 2}


def test_build_skips_non_technique_and_no_eid1(tmp_path):
    src = tmp_path / "attack_techniques"
    # non-technique-named folder -> skipped
    bad = src / "apt_simulations" / "src" / "windows-sysmon.log"
    bad.parent.mkdir(parents=True)
    bad.write_text(_EID1_PS + "\n", encoding="utf-8")
    # technique folder but no EID-1 -> skipped (recorded)
    noev = src / "T1071.001" / "beacon" / "windows-sysmon.log"
    noev.parent.mkdir(parents=True)
    noev.write_text(_EID3_NET + "\n", encoding="utf-8")

    result = mod.build(str(src), str(tmp_path / "corpus"))
    assert result["files_mapped"] == 0
    assert "apt_simulations/src/windows-sysmon.log" in result["skipped_not_technique_folder"]
    assert "T1071.001/beacon/windows-sysmon.log" in result["skipped_no_eid1"]
