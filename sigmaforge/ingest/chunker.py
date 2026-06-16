from typing import Iterator, Sequence, TypeVar

T = TypeVar("T")


def chunk_lines(items: Sequence[T], shard_size: int) -> Iterator[list[T]]:
    """Partition items into chunks of shard_size.

    Args:
        items: Sequence to partition
        shard_size: Size of each chunk (must be >= 1)

    Yields:
        Lists of items, each of size shard_size (except possibly the last chunk)

    Raises:
        ValueError: If shard_size < 1
    """
    if shard_size < 1:
        raise ValueError("shard_size must be >= 1")
    for i in range(0, len(items), shard_size):
        yield list(items[i : i + shard_size])
