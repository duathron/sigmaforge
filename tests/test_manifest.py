from sigmaforge.records import MatchRecord
from sigmaforge.runmanifest import build_manifest, run_hash


def test_manifest_pins_inputs():
    m = build_manifest(
        zircolite_version="3.7.6", ruleset_sha="abc", mapping_hash="def",
        corpus_hashes={"comiset": "h1"}, level=("high", "critical"),
        shard_size=20, workers=4,
    )
    assert m["ruleset_sha"] == "abc" and m["level"] == ["high", "critical"]


def test_run_hash_stable_across_worker_count():
    agg = {MatchRecord("r1", "e1", "malicious"), MatchRecord("r1", "e2", "benign")}
    assert run_hash(agg, workers=1) == run_hash(agg, workers=8)


def test_run_hash_order_independent():
    a = {("r1", "e1"), ("r1", "e2")}
    b = {("r1", "e2"), ("r1", "e1")}
    assert run_hash(a) == run_hash(b)
