import os

import pytest

from sigmaforge.ingest.zircolite_runner import _zircolite_home, parse_detections, run_shard


def test_zircolite_home_is_portable_not_hardcoded(monkeypatch):
    # reproducibility: the engine working dir must NOT be a hardcoded absolute path
    # (the shipped 0.1.0 had cwd="/Users/christianhuhn/..."). Defaults to the current
    # working directory; overridable via SIGMAFORGE_HOME.
    monkeypatch.delenv("SIGMAFORGE_HOME", raising=False)
    assert _zircolite_home() == os.getcwd()
    monkeypatch.setenv("SIGMAFORGE_HOME", "/tmp/some/engine/dir")
    assert _zircolite_home() == "/tmp/some/engine/dir"


def test_parse_reads_passthrough_id_and_label():
    out = [
        {
            "title": "RuleA",
            "matches": [
                {"Image": "x", "sigmaforge_eid": "e1", "sigmaforge_label": "malicious"},
                {"Image": "y", "sigmaforge_eid": "e2", "sigmaforge_label": "benign"},
            ],
        },
        {"title": "RuleB", "matches": []},
    ]
    recs = parse_detections(out)
    assert {(r.rule_id, r.event_id, r.event_label) for r in recs} == {
        ("RuleA", "e1", "malicious"),
        ("RuleA", "e2", "benign"),
    }


def test_parse_evtx_fallback_uses_stable_hash_not_bare_recordid():
    # EVTX rows have no sigmaforge_eid -> event_id is a stable hash of the row (NOT bare EventRecordID),
    # and the corpus_label is applied.
    out = [{"title": "R", "matches": [{"EventRecordID": 42, "Image": "m.exe"}]}]
    recs = parse_detections(out, corpus_label="malicious")
    assert recs[0].event_label == "malicious"
    assert recs[0].event_id != "42"  # not the bare per-file counter
    assert len(recs[0].event_id) == 40  # sha1 hex


def test_eventrecordid_cross_file_collision_does_not_deflate_recall():
    # FIX C regression: same EventRecordID=42 in two different files (different Image/Computer)
    # must yield TWO distinct events, not collapse to one (which would silently deflate recall).
    out = [
        {
            "title": "R",
            "matches": [
                {"EventRecordID": 42, "Image": "a.exe", "Computer": "HOST-A"},
                {"EventRecordID": 42, "Image": "b.exe", "Computer": "HOST-B"},
            ],
        }
    ]
    recs = parse_detections(out, corpus_label="malicious")
    assert len({r.event_id for r in recs}) == 2  # NOT collapsed to 1


def test_truly_identical_events_still_dedupe():
    # contrast: two byte-identical rows are the same event -> hash-collapse is correct dedup.
    out = [{"title": "R", "matches": [{"EventRecordID": 7, "Image": "x.exe"}, {"EventRecordID": 7, "Image": "x.exe"}]}]
    recs = parse_detections(out, corpus_label="malicious")
    assert len({r.event_id for r in recs}) == 1


def test_json_and_xml_input_mutually_exclusive():
    # FIX B3: xml_input (attack_data corpus) and json_input (benign corpus) cannot both be set.
    with pytest.raises(ValueError):
        run_shard("x", "y", json_input=True, xml_input=True)


def test_technique_passthrough_keyed_on_stable_event_id():
    # FIX B: event->technique map keyed on the SAME identity (_stable_event_id),
    # technique resolved from the source EVTX basename via OriginalLogfile.
    out = [
        {
            "title": "R",
            "matches": [
                {"Image": "a.exe", "OriginalLogfile": "ID4688-foo.evtx"},
                {"Image": "b.exe", "OriginalLogfile": "ID1-bar.evtx"},
                {"Image": "c.exe", "OriginalLogfile": "unmapped.evtx"},  # not in map -> skipped
            ],
        }
    ]
    ev_tech: dict[str, str] = {}
    recs = parse_detections(
        out,
        corpus_label="malicious",
        file_technique_map={"ID4688-foo.evtx": "T1059", "ID1-bar.evtx": "T1003"},
        event_technique_out=ev_tech,
    )
    by_image = {m["Image"]: r.event_id for m, r in zip(out[0]["matches"], recs)}
    assert ev_tech[by_image["a.exe"]] == "T1059"
    assert ev_tech[by_image["b.exe"]] == "T1003"
    assert by_image["c.exe"] not in ev_tech  # unmapped source file -> no technique
