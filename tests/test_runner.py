from sigmaforge.records import MatchRecord
from sigmaforge.backtest.runner import aggregate, backtest


def test_aggregate_is_set_union_dedup():
    a = [MatchRecord("r1", "e1", "malicious")]
    b = [MatchRecord("r1", "e2", "benign"), MatchRecord("r1", "e1", "malicious")]
    agg = aggregate([a, b])
    assert {(r.rule_id, r.event_id) for r in agg} == {("r1", "e1"), ("r1", "e2")}


def _fake_shard_fn(shard):
    # deterministic stand-in for a Zircolite run: fire r1 on every event id ending in 0
    return [MatchRecord("r1", e, "benign") for e in shard if e.endswith("0")]


def test_worker_count_invariance():
    items = [f"e{i}" for i in range(50)]
    r1 = backtest(items, shard_size=10, workers=1, shard_fn=_fake_shard_fn)
    r8 = backtest(items, shard_size=10, workers=8, shard_fn=_fake_shard_fn)
    assert r1 == r8                      # byte-identical aggregated set regardless of worker count
    assert r1 == {MatchRecord("r1", e, "benign") for e in items if e.endswith("0")}
