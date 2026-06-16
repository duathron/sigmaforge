from sigmaforge.ingest.chunker import chunk_lines


def test_chunk_is_true_partition():
    items = [f"line{i}" for i in range(105)]
    shards = list(chunk_lines(items, shard_size=20))
    flat = [x for s in shards for x in s]
    assert flat == items
    assert len(shards) == 6
    assert sum(len(s) for s in shards) == 105


def test_chunk_size_must_be_positive():
    import pytest
    with pytest.raises(ValueError):
        list(chunk_lines(["a"], shard_size=0))
