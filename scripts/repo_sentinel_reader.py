"""Read bounded raw snapshots from a caller-owned, stable Git object database."""

from __future__ import annotations

import hashlib
import math
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path


class ReaderRefused(ValueError):
    """A complete snapshot could not be established; message contains only a code."""


@dataclass(frozen=True)
class ReaderLimits:
    max_files: int = 4096
    max_objects: int = 8192
    max_bytes: int = 16 * 1024 * 1024
    max_blob_bytes: int = 2 * 1024 * 1024
    max_depth: int = 32
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        for value in (self.max_files, self.max_objects, self.max_bytes,
                      self.max_blob_bytes, self.max_depth):
            if type(value) is not int or value <= 0:
                raise ReaderRefused("invalid_limits")
        if (type(self.timeout_seconds) not in (int, float)
                or not math.isfinite(self.timeout_seconds)
                or self.timeout_seconds <= 0):
            raise ReaderRefused("invalid_limits")
        if self.max_depth > 64:
            raise ReaderRefused("invalid_limits")


@dataclass(frozen=True)
class SnapshotFile:
    path: str
    mode: str
    oid: str
    data: bytes = field(repr=False)


@dataclass(frozen=True)
class Snapshot:
    commit_oid: str
    tree_oid: str
    files: tuple[SnapshotFile, ...]


def _git(repository: Path, arguments: list[str], cap: int, deadline: float) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ReaderRefused("time_limit")
    environment = {key: value for key, value in os.environ.items()
                   if not key.upper().startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")
    try:
        with subprocess.Popen(
            ["git", "--no-replace-objects", *arguments], cwd=repository,
            env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ) as process:
            timer = threading.Timer(remaining, process.kill)
            timer.start()
            try:
                assert process.stdout is not None
                output = process.stdout.read(cap + 1)
                if len(output) > cap:
                    process.kill()
                    raise ReaderRefused("byte_limit")
                status = process.wait()
                if time.monotonic() >= deadline:
                    raise ReaderRefused("time_limit")
                if status:
                    raise ReaderRefused("object_unavailable")
                return output
            finally:
                timer.cancel()
                timer.join()
    except OSError:
        raise ReaderRefused("git_unavailable") from None


def _component(raw: bytes) -> str:
    # A deliberately portable subset, before any future filesystem writes.
    if not re.fullmatch(rb"[A-Za-z0-9._ -]{1,255}", raw):
        raise ReaderRefused("unsupported_path")
    name = raw.decode("ascii")
    stem = name.split(".", 1)[0].rstrip(" ").upper()
    if (name in (".", "..") or name.lower() == ".git"
            or name.endswith((".", " "))
            or stem in {"CON", "PRN", "AUX", "NUL"}
            or re.fullmatch(r"(?:COM|LPT)[1-9]", stem)):
        raise ReaderRefused("unsupported_path")
    return name


def read_snapshot(
    repository: Path, commit_oid: str, *, limits: ReaderLimits = ReaderLimits(),
) -> Snapshot:
    """Return all admitted files or raise ReaderRefused without partial output.

    The caller owns Git, repository configuration and object storage, and must
    keep them stable during this call. No checkout, fetch or target execution.
    """
    deadline = time.monotonic() + limits.timeout_seconds
    repository = repository.resolve()
    object_format = _git(repository, ["rev-parse", "--show-object-format"], 16,
                         deadline).strip()
    if object_format not in (b"sha1", b"sha256"):
        raise ReaderRefused("unsupported_object_format")
    algorithm = object_format.decode("ascii")
    oid_bytes = hashlib.new(algorithm).digest_size
    if not re.fullmatch(r"[0-9a-f]{%d}" % (oid_bytes * 2), commit_oid):
        raise ReaderRefused("invalid_commit_oid")
    remaining_bytes = limits.max_bytes
    object_count = 0

    def read_object(kind: str, oid: str) -> bytes:
        nonlocal remaining_bytes, object_count
        object_count += 1
        if object_count > limits.max_objects:
            raise ReaderRefused("object_limit")
        cap = min(remaining_bytes, limits.max_blob_bytes) if kind == "blob" else remaining_bytes
        body = _git(repository, ["cat-file", kind, oid], cap, deadline)
        framed = kind.encode() + b" " + str(len(body)).encode() + b"\0" + body
        if hashlib.new(algorithm, framed).hexdigest() != oid:
            raise ReaderRefused("object_identity_mismatch")
        remaining_bytes -= len(body)
        return body

    commit = read_object("commit", commit_oid)
    first = commit.split(b"\n", 1)[0]
    if not re.fullmatch(rb"tree [0-9a-f]{%d}" % (oid_bytes * 2), first):
        raise ReaderRefused("invalid_commit_tree")
    tree_oid = first[5:].decode("ascii")
    files: list[SnapshotFile] = []
    paths: set[str] = set()

    def walk(oid: str, parent: str, depth: int) -> None:
        if depth > limits.max_depth:
            raise ReaderRefused("depth_limit")
        tree = read_object("tree", oid)
        offset = 0
        while offset < len(tree):
            if time.monotonic() >= deadline:
                raise ReaderRefused("time_limit")
            space, nul = tree.find(b" ", offset), tree.find(b"\0", offset)
            if space < offset or nul <= space or nul + 1 + oid_bytes > len(tree):
                raise ReaderRefused("invalid_tree")
            mode = tree[offset:space]
            name = _component(tree[space + 1:nul])
            child = tree[nul + 1:nul + 1 + oid_bytes].hex()
            offset = nul + 1 + oid_bytes
            path = parent + name
            if path.casefold() in paths:
                raise ReaderRefused("path_collision")
            paths.add(path.casefold())
            if mode == b"40000":
                walk(child, path + "/", depth + 1)
            elif mode in (b"100644", b"100755"):
                if len(files) >= limits.max_files:
                    raise ReaderRefused("file_limit")
                files.append(SnapshotFile(path, mode.decode(), child,
                                          read_object("blob", child)))
            else:
                raise ReaderRefused("unsupported_mode")

    walk(tree_oid, "", 0)
    result = Snapshot(commit_oid, tree_oid, tuple(sorted(files, key=lambda item: item.path)))
    if time.monotonic() >= deadline:
        raise ReaderRefused("time_limit")
    return result
