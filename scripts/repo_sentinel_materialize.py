"""Provide verified snapshot bytes in a caller-owned temporary data directory."""

from __future__ import annotations

import ntpath
import os
import stat
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory

from repo_sentinel_reader import ReaderLimits, Snapshot, SnapshotFile, read_snapshot


class MaterializationRefused(ValueError):
    """Materialization failed; the message is a fixed code, without local paths."""


@dataclass(frozen=True)
class MaterializedSnapshot:
    snapshot: Snapshot
    root: Path = field(repr=False)


@dataclass(frozen=True)
class _MaterializationPlan:
    files: tuple[tuple[SnapshotFile, tuple[str, ...]], ...]
    directories: tuple[tuple[str, ...], ...]


_WINDOWS_FORBIDDEN = frozenset('<>:"\\|?*')
_WINDOWS_DEVICES = frozenset({"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"})
_WINDOWS_PORT_DEVICE_SUFFIXES = frozenset("123456789¹²³")
_ASCII_CASE_TRANSLATION = {
    codepoint: codepoint + (ord("a") - ord("A"))
    for codepoint in range(ord("A"), ord("Z") + 1)
}


def _has_control_characters(value: str) -> bool:
    return any(ord(character) < 0x20 or 0x7f <= ord(character) <= 0x9f
               for character in value)


def _logical_components(path: str, limits: ReaderLimits) -> tuple[str, ...]:
    if type(path) is not str or ntpath.splitdrive(path)[0] or ntpath.isabs(path):
        raise MaterializationRefused("unsupported_host_path")
    components = tuple(path.split("/"))
    if (not components or len(components) > limits.max_depth + 1
            or any(not component or component in (".", "..")
                   or _has_control_characters(component) for component in components)):
        raise MaterializationRefused("unsupported_host_path")
    for component in components:
        try:
            encoded = component.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise MaterializationRefused("unsupported_host_path") from None
        if len(encoded) > 255:
            raise MaterializationRefused("path_limit")
    return components


def _validate_portable_component(component: str) -> None:
    stem = component.split(".", 1)[0].rstrip(" ").upper()
    if (any(character in _WINDOWS_FORBIDDEN for character in component)
            or component.endswith((".", " "))
            or (component.isascii() and component.lower() == ".git")
            or stem in _WINDOWS_DEVICES
            or (len(stem) == 4 and stem[:3] in ("COM", "LPT")
                and stem[3] in _WINDOWS_PORT_DEVICE_SUFFIXES)):
        raise MaterializationRefused("unsupported_host_path")


def _path_key(
    components: tuple[str, ...], normalization: str | None
) -> tuple[str, ...]:
    if normalization is not None:
        return tuple(
            unicodedata.normalize(normalization, component) for component in components
        )
    return tuple(component.translate(_ASCII_CASE_TRANSLATION) for component in components)


def _pathconf(root: Path, name: str) -> int | None:
    try:
        value = os.pathconf(root, name)
    except (AttributeError, OSError, ValueError):
        return None
    return value if type(value) is int and value > 0 else None


def _validate_host_lengths(root: Path, paths: tuple[tuple[str, ...], ...]) -> None:
    if os.name == "nt":
        for components in paths:
            for component in components:
                if len(component.encode("utf-16-le")) // 2 > 255:
                    raise MaterializationRefused("path_limit")
            target = root.joinpath(*components)
            if len(str(target).encode("utf-16-le")) // 2 >= 260:
                raise MaterializationRefused("path_limit")
        return
    if os.name != "posix":
        raise MaterializationRefused("unsupported_host_path")
    name_limit = _pathconf(root, "PC_NAME_MAX")
    path_limit = _pathconf(root, "PC_PATH_MAX")
    if name_limit is None or path_limit is None:
        raise MaterializationRefused("unsupported_host_path")
    for components in paths:
        try:
            if name_limit is not None and any(
                len(os.fsencode(component)) > name_limit for component in components
            ):
                raise MaterializationRefused("path_limit")
            target = root.joinpath(*components)
            if path_limit is not None and len(os.fsencode(target)) >= path_limit:
                raise MaterializationRefused("path_limit")
        except UnicodeEncodeError:
            raise MaterializationRefused("unsupported_host_path") from None


def _preflight_snapshot(
    snapshot: Snapshot, root: Path, limits: ReaderLimits
) -> _MaterializationPlan:
    files: list[tuple[SnapshotFile, tuple[str, ...]]] = []
    logical_nodes: dict[tuple[str, ...], str] = {}
    for item in snapshot.files:
        components = _logical_components(item.path, limits)
        for component in components:
            _validate_portable_component(component)
        for depth in range(1, len(components)):
            directory = components[:depth]
            if logical_nodes.get(directory) == "file":
                raise MaterializationRefused("path_collision")
            logical_nodes.setdefault(directory, "directory")
        if components in logical_nodes:
            raise MaterializationRefused("path_collision")
        logical_nodes[components] = "file"
        files.append((item, components))

    for normalization in (None, "NFC", "NFD"):
        aliases: dict[tuple[str, ...], tuple[str, ...]] = {}
        for logical_path in logical_nodes:
            key = _path_key(logical_path, normalization)
            previous = aliases.get(key)
            if previous is not None and previous != logical_path:
                raise MaterializationRefused("host_path_collision")
            aliases[key] = logical_path

    all_paths = tuple(logical_nodes)
    _validate_host_lengths(root, all_paths)
    directories = tuple(
        sorted(
            (path for path, kind in logical_nodes.items() if kind == "directory"),
            key=lambda path: (len(path), path),
        )
    )
    return _MaterializationPlan(tuple(files), directories)


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
            _regular_path(root, directory=True)
            plan = _preflight_snapshot(snapshot, root, limits)
            for components in plan.directories:
                directory = root.joinpath(*components)
                directory.mkdir(mode=0o700)
                _regular_path(directory, directory=True)
            _regular_path(root, directory=True)
            for item, components in plan.files:
                _write_verified(root.joinpath(*components), item.data)
        except OSError:
            raise MaterializationRefused("filesystem_io_failed") from None
        yield MaterializedSnapshot(snapshot, root)
    finally:
        if temporary is not None:
            try:
                temporary.cleanup()
            except OSError:
                raise MaterializationRefused("cleanup_failed") from None
