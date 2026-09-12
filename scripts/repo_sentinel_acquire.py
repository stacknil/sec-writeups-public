"""Acquire one pull-request head as data in a fresh verifier-owned Git database."""

from __future__ import annotations

import math
import os
import re
import stat
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit

from repo_sentinel_reader import ReaderLimits, Snapshot, read_snapshot


class AcquisitionRefused(ValueError):
    """Acquisition failed; the message is a fixed code without remote or path data."""


@dataclass(frozen=True)
class AcquisitionLimits:
    timeout_seconds: float = 60.0
    max_repository_bytes: int = 64 * 1024 * 1024

    def __post_init__(self) -> None:
        if (
            type(self.timeout_seconds) not in (int, float)
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
            or type(self.max_repository_bytes) is not int
            or self.max_repository_bytes <= 0
        ):
            raise AcquisitionRefused("invalid_limits")


@dataclass(frozen=True)
class AcquiredSnapshot:
    snapshot: Snapshot
    source_ref: str
    repository: Path = field(repr=False)


def _regular_directory(path: Path) -> None:
    info = path.lstat()
    reparse = getattr(info, "st_file_attributes", 0) & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
    )
    if reparse or not stat.S_ISDIR(info.st_mode):
        raise AcquisitionRefused("unsafe_scratch_root")


def _remote_argument(remote: str | Path) -> str:
    if isinstance(remote, Path):
        try:
            resolved = remote.resolve(strict=True)
        except OSError:
            raise AcquisitionRefused("invalid_remote") from None
        if not resolved.is_dir():
            raise AcquisitionRefused("invalid_remote")
        return resolved.as_uri()
    if type(remote) is not str or re.search(r"[\x00-\x20\x7f]", remote):
        raise AcquisitionRefused("invalid_remote")
    try:
        parsed = urlsplit(remote)
    except ValueError:
        raise AcquisitionRefused("invalid_remote") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise AcquisitionRefused("invalid_remote")
    return remote


def _environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
        and key.upper() != "SSH_ASKPASS_REQUIRE"
    }
    environment.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_TERMINAL_PROMPT="0",
        GIT_ASKPASS="",
        SSH_ASKPASS="",
        GIT_NO_LAZY_FETCH="1",
    )
    return environment


def _git_arguments(*arguments: str) -> list[str]:
    return [
        "git",
        "--no-replace-objects",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "protocol.file.allow=always",
        "-c", "http.followRedirects=false",
        "-c", "gc.auto=0",
        "-c", "maintenance.auto=false",
        *arguments,
    ]


def _run(
    cwd: Path,
    arguments: list[str],
    deadline: float,
    refusal: str,
    *,
    capture: bool = False,
) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AcquisitionRefused("time_limit")
    try:
        result = subprocess.run(
            arguments,
            cwd=cwd,
            env=_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=remaining,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise AcquisitionRefused("time_limit") from None
    except OSError:
        raise AcquisitionRefused("git_unavailable") from None
    if result.returncode:
        raise AcquisitionRefused(refusal)
    output = result.stdout or b""
    if len(output) > 256:
        raise AcquisitionRefused("invalid_git_output")
    return output


def _repository_size(root: Path, limit: int) -> int:
    total = 0
    try:
        for directory, names, files in os.walk(root, followlinks=False):
            base = Path(directory)
            entries = [*((name, True) for name in names), *((name, False) for name in files)]
            for name, directory_entry in entries:
                info = (base / name).lstat()
                reparse = getattr(info, "st_file_attributes", 0) & getattr(
                    stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
                )
                expected = stat.S_ISDIR if directory_entry else stat.S_ISREG
                if reparse or not expected(info.st_mode):
                    raise AcquisitionRefused("unsafe_git_database")
                if not directory_entry:
                    total += info.st_size
                    if total > limit:
                        return total
    except OSError:
        raise AcquisitionRefused("filesystem_io_failed") from None
    return total


@contextmanager
def acquire_pull_snapshot(
    remote: str | Path,
    pull_number: int,
    expected_head_oid: str,
    scratch_root: Path,
    *,
    acquisition_limits: AcquisitionLimits = AcquisitionLimits(),
    reader_limits: ReaderLimits = ReaderLimits(),
) -> Iterator[AcquiredSnapshot]:
    """Yield a verified pull head and fresh database, then remove the database."""
    if type(pull_number) is not int or not 0 < pull_number <= 2_147_483_647:
        raise AcquisitionRefused("invalid_pull_number")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", expected_head_oid):
        raise AcquisitionRefused("invalid_head_oid")
    algorithm = "sha1" if len(expected_head_oid) == 40 else "sha256"
    remote_argument = _remote_argument(remote)
    deadline = time.monotonic() + acquisition_limits.timeout_seconds
    source_ref = f"refs/pull/{pull_number}/head"
    target_ref = "refs/repo-sentinel/acquired-head"
    temporary: TemporaryDirectory[str] | None = None
    try:
        try:
            _regular_directory(scratch_root)
            temporary = TemporaryDirectory(
                prefix="repo-sentinel-acquire-", dir=scratch_root.resolve()
            )
            root = Path(temporary.name)
            template = root / "empty-template"
            template.mkdir(mode=0o700)
            repository = root / "objects.git"
            _run(
                root,
                _git_arguments(
                    "init", "--bare", "--quiet", f"--object-format={algorithm}",
                    f"--template={template}", str(repository),
                ),
                deadline,
                "init_failed",
            )
            _run(
                repository,
                _git_arguments(
                    "fetch", "--quiet", "--depth=1", "--no-tags",
                    "--no-recurse-submodules", "--no-write-fetch-head", "--",
                    remote_argument, f"+{source_ref}:{target_ref}",
                ),
                deadline,
                "fetch_failed",
            )
            if (
                _repository_size(repository, acquisition_limits.max_repository_bytes)
                > acquisition_limits.max_repository_bytes
            ):
                raise AcquisitionRefused("repository_byte_limit")
            refs = _run(
                repository,
                _git_arguments(
                    "for-each-ref", "--format=%(refname)%00%(objectname)", "refs/"
                ),
                deadline,
                "head_unavailable",
                capture=True,
            )
            expected = f"{target_ref}\0{expected_head_oid}\n".encode("ascii")
            if refs != expected:
                raise AcquisitionRefused("head_mismatch")
            snapshot = read_snapshot(repository, expected_head_oid, limits=reader_limits)
        except OSError:
            raise AcquisitionRefused("filesystem_io_failed") from None
        yield AcquiredSnapshot(snapshot, source_ref, repository)
    finally:
        if temporary is not None:
            try:
                temporary.cleanup()
            except OSError:
                raise AcquisitionRefused("cleanup_failed") from None
