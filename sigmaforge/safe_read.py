"""Bounded, non-blocking reads of user-supplied input files.

A path is never `open()`ed blindly: a FIFO would block forever and `/dev/zero` would be read until
memory is gone. The file is opened with ``O_NONBLOCK`` (a FIFO opens at once), checked with
``fstat`` on the open descriptor (so a path swapped after a check cannot slip through), refused
unless it is a regular file, and read through at most ``cap + 1`` bytes. Failures carry a fixed,
value-free reason; callers wrap it in their own error type (config -> exit 2, backtest input -> 4).
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from typing import BinaryIO


class ReadRefused(Exception):
    """The file was not read. ``reason`` is a fixed value-free phrase."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@contextmanager
def open_regular(path: object, cap: int) -> Iterator[BinaryIO]:
    """Yield a binary file object for a regular file of at most ``cap`` bytes (by ``fstat``)."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(os.fspath(path), flags)
    except FileNotFoundError:
        raise ReadRefused("file not found") from None
    except (OSError, ValueError):  # permission, ELOOP, embedded NUL, ...
        raise ReadRefused("unreadable") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ReadRefused("not a regular file")
        if st.st_size > cap:
            raise ReadRefused("too large")
        fh = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with fh:
        yield fh


def read_capped(path: object, cap: int) -> bytes:
    """The whole file, refusing one larger than ``cap`` bytes (reads at most ``cap + 1``)."""
    with open_regular(path, cap) as fh:
        try:
            data = fh.read(cap + 1)
        except OSError:
            raise ReadRefused("unreadable") from None
    if len(data) > cap:
        raise ReadRefused("too large")
    return data


def iter_lines_capped(path: object, cap: int) -> Iterator[bytes]:
    """Lines of a regular file, refusing one that grows past ``cap`` bytes in total."""
    with open_regular(path, cap) as fh:
        seen = 0
        while True:
            try:
                line = fh.readline(cap + 1 - seen)
            except OSError:
                raise ReadRefused("unreadable") from None
            if not line:
                return
            seen += len(line)
            if seen > cap:
                raise ReadRefused("too large")
            yield line
