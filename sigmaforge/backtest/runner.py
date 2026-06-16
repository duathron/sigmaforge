from concurrent.futures import ProcessPoolExecutor

from sigmaforge.ingest.chunker import chunk_lines
from sigmaforge.records import MatchRecord


def aggregate(shard_results: list[list[MatchRecord]]) -> set[MatchRecord]:
    merged: set[MatchRecord] = set()
    for s in shard_results:
        merged.update(s)  # set union = order-independent, dedup across shard boundaries
    return merged


def backtest(items, shard_size, workers, shard_fn) -> set[MatchRecord]:
    shards = list(chunk_lines(items, shard_size))
    if workers == 1:
        results = [shard_fn(s) for s in shards]
    else:
        with ProcessPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(shard_fn, shards))
    return aggregate(results)
