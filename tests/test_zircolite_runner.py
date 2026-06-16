from sigmaforge.ingest.zircolite_runner import parse_detections


def test_parse_reads_passthrough_id_and_label():
    out = [
        {"title": "RuleA", "matches": [
            {"Image": "x", "sigmaforge_eid": "e1", "sigmaforge_label": "malicious"},
            {"Image": "y", "sigmaforge_eid": "e2", "sigmaforge_label": "benign"}]},
        {"title": "RuleB", "matches": []},
    ]
    recs = parse_detections(out)
    assert {(r.rule_id, r.event_id, r.event_label) for r in recs} == {
        ("RuleA", "e1", "malicious"), ("RuleA", "e2", "benign")}


def test_parse_evtx_fallback_id_and_corpus_label():
    out = [{"title": "R", "matches": [{"EventRecordID": 42, "Image": "m.exe"}]}]
    recs = parse_detections(out, corpus_label="malicious")
    assert (recs[0].event_id, recs[0].event_label) == ("42", "malicious")
