"""Provide verified snapshot bytes in a caller-owned temporary data directory."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory

from repo_sentinel_reader import ReaderLimits, Snapshot, read_snapshot


class MaterializationRefused(ValueError):
    """Materialization failed; the message is a fixed code, without local paths."""


@dataclass(frozen=True)
class MaterializedSnapshot:
    snapshot: Snapshot
    root: Path = field(repr=False)


def _regular_path(path: Path, *, directory: bool = False) -> None:
    info = path.lstat()
    reparse = getattr(info, "st_file_attributes", 0) & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
    )
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if reparse or not expected(info.st_mode):
        raise MaterializationRefused("unsafe_filesystem_entry")


def _write_verified(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        if output.write(data) != len(data):
            raise MaterializationRefused("short_write")
    _regular_path(path)
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as output:
        info = os.fstat(output.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != len(data):
            raise MaterializationRefused("written_bytes_mismatch")
        if output.read(len(data) + 1) != data:
            raise MaterializationRefused("written_bytes_mismatch")


@contextmanager
def materialized_snapshot(
    repository: Path,
    commit_oid: str,
    scratch_root: Path,
    *,
    limits: ReaderLimits = ReaderLimits(),
) -> Iterator[MaterializedSnapshot]:
    """Yield only complete verified files, and remove them when the context exits.

    The caller owns stable scratch_root and ancestors, and must not allow other
    processes or the consumer to mutate this private directory during use.
    Source modes stay in snapshot metadata; POSIX files request mode 0600 subject
    to umask. The reader's deadline does not bound filesystem I/O or consumer use.
    """
    snapshot = read_snapshot(repository, commit_oid, limits=limits)
    temporary: TemporaryDirectory[str] | None = None
    try:
        try:
            # Inspect before resolve, so a supplied symlink/junction is refused.
            _regular_path(scratch_root, directory=True)
            temporary = TemporaryDirectory(prefix="repo-sentinel-data-",
                                           dir=scratch_root.resolve())
            root = Path(temporary.name) / "data"
            root.mkdir(mode=0o700)
            directories = {root}
            for item in snapshot.files:
                directory = root
                for component in item.path.split("/")[:-1]:
                    directory = directory / component
                    if directory not in directories:
                        directory.mkdir(mode=0o700)
                        directories.add(directory)
                    _regular_path(directory, directory=True)
                _regular_path(root, directory=True)
                _write_verified(root / item.path, item.data)
        except OSError:
            raise MaterializationRefused("filesystem_io_failed") from None
        yield MaterializedSnapshot(snapshot, root)
    finally:
        if temporary is not None:
            try:
                temporary.cleanup()
            except OSError:
                raise MaterializationRefused("cleanup_failed") from None
