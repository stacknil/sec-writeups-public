"""Run the data-only core of the future authoritative Repo Sentinel gate."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from tempfile import TemporaryDirectory

from repo_sentinel_acquire import (
    AcquiredSnapshot,
    AcquisitionLimits,
    AcquisitionRefused,
    acquire_pull_snapshot,
)
from repo_sentinel_materialize import (
    MaterializationRefused,
    MaterializedSnapshot,
    materialized_snapshot,
)
from repo_sentinel_reader import (
    ReaderLimits,
    ReaderRefused,
    Snapshot,
    SnapshotFile,
    read_snapshot,
)

SCANNER_DISTRIBUTION = "repo-sentinel-lite"
SCANNER_VERSION = "0.8.1"
SCANNER_VERSION_LINE = f"repo-sentinel {SCANNER_VERSION}"

_OID_PATTERN = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_INLINE_SUPPRESSION_PATTERN = re.compile(
    r"repo-sentinel:\s*allow(?:\s+(?P<rules>[A-Za-z0-9_.\-, ]+))?",
    re.IGNORECASE,
)
_SCANNER_TEXT_ENCODINGS = ("utf-8", "utf-8-sig", "utf-16", "cp1252")
_PORTABLE_V1_ASCII_CASE_ALIAS = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "abcdefghijklmnopqrstuvwxyz",
)


def _portable_v1_alias(value: str) -> str:
    return value.translate(_PORTABLE_V1_ASCII_CASE_ALIAS)


_PROTECTED_EXACT_PATHS = frozenset(
    {
        ".reposentinel.toml",
        ".reposentinel-baseline.json",
        "scripts/repo_sentinel_gate.py",
        "scripts/repo_sentinel_authoritative.py",
        "scripts/repo_sentinel_acquire.py",
        "scripts/repo_sentinel_reader.py",
        "scripts/repo_sentinel_materialize.py",
        "scripts/test_repo_sentinel_integration.py",
    }
)
_PROTECTED_PATH_PREFIXES = (
    ".github/workflows/",
    ".github/actions/",
)
_PROTECTED_EXACT_ALIASES = frozenset(
    _portable_v1_alias(path) for path in _PROTECTED_EXACT_PATHS
)
_PROTECTED_PATH_PREFIX_ALIASES = tuple(
    _portable_v1_alias(prefix) for prefix in _PROTECTED_PATH_PREFIXES
)

_REFUSAL_CODES = frozenset(
    {
        "base_reader_refused",
        "cleanup_failed",
        "filesystem_io_failed",
        "head_acquisition_refused",
        "head_materialization_refused",
        "head_reader_refused",
        "head_snapshot_mismatch",
        "invalid_request",
        "invalid_snapshot",
        "protected_control_change",
        "report_collision",
        "report_io_failed",
        "report_missing",
        "report_oversize",
        "scanner_failed",
        "scanner_launch_failed",
        "scanner_output_limit",
        "scanner_result_invalid",
        "scanner_timeout",
        "scanner_version_mismatch",
        "source_suppression_change",
        "unexpected_failure",
        "unsafe_root_layout",
    }
)


class GateVerdict(str, Enum):
    """Stable outcomes that a later authority publisher may sign."""

    PASS = "PASS"
    SCANNER_FINDING = "SCANNER_FINDING"
    INFRASTRUCTURE_REFUSAL = "INFRASTRUCTURE_REFUSAL"
    PROTECTED_CONTROL_CHANGE = "PROTECTED_CONTROL_CHANGE"


class WorkerRefused(RuntimeError):
    """Internal fixed-code refusal without paths or hostile output."""

    def __init__(self, code: str) -> None:
        safe_code = code if code in _REFUSAL_CODES else "unexpected_failure"
        self.code = safe_code
        super().__init__(safe_code)


@dataclass(frozen=True, slots=True)
class AuthoritativeGateRequest:
    """Validated event identity and caller-owned trust roots."""

    repository_identity: str = field(repr=False)
    pull_number: int
    base_oid: str
    head_oid: str
    remote: str | Path = field(repr=False)
    trusted_repository: Path = field(repr=False)
    scratch_root: Path = field(repr=False)
    evidence_root: Path = field(repr=False)


@dataclass(frozen=True, slots=True)
class AuthoritativeLimits:
    """Bounds owned by the worker rather than target repository policy."""

    scanner_timeout_seconds: float = 60.0
    max_capture_bytes: int = 64 * 1024
    max_report_bytes: int = 8 * 1024 * 1024

    def __post_init__(self) -> None:
        if (
            type(self.scanner_timeout_seconds) not in (int, float)
            or not math.isfinite(self.scanner_timeout_seconds)
            or self.scanner_timeout_seconds <= 0
            or type(self.max_capture_bytes) is not int
            or self.max_capture_bytes <= 0
            or type(self.max_report_bytes) is not int
            or self.max_report_bytes <= 0
        ):
            raise WorkerRefused("invalid_request")


@dataclass(frozen=True, slots=True)
class AuthoritativeGateResult:
    """Bounded evidence suitable for a separately reviewed signer."""

    verdict: GateVerdict
    repository_identity: str = field(repr=False)
    pull_number: int
    base_oid: str
    head_oid: str
    changed_count: int
    deleted_count: int
    report_sha256: str | None
    report_size: int
    scanner_version: str | None
    refusal_code: str | None
    report_path: Path | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class SnapshotDelta:
    """Exact D1 path differences without rename inference."""

    changed_paths: tuple[str, ...] = field(repr=False)
    deleted_paths: tuple[str, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class ScannerInvocation:
    """Trusted scanner inputs; target-controlled names stay out of repr."""

    target_root: Path = field(repr=False)
    changed_paths: tuple[str, ...] = field(repr=False)
    baseline_path: Path | None = field(repr=False)
    report_path: Path = field(repr=False)
    execution_directory: Path = field(repr=False)
    timeout_seconds: float
    max_capture_bytes: int


@dataclass(frozen=True, slots=True)
class ScannerExecution:
    """Bounded child result; captured bytes are never rendered by the worker."""

    returncode: int
    scanner_version: str
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class _CommandResult:
    returncode: int
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)


SnapshotReader = Callable[..., Snapshot]
PullAcquirer = Callable[..., Iterator[AcquiredSnapshot]]
SnapshotMaterializer = Callable[..., Iterator[MaterializedSnapshot]]
ScannerRunner = Callable[[ScannerInvocation], ScannerExecution]


def _regular_directory(path: Path) -> Path:
    try:
        info = path.lstat()
        reparse = getattr(info, "st_file_attributes", 0) & getattr(
            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
        )
        if reparse or not stat.S_ISDIR(info.st_mode):
            raise WorkerRefused("unsafe_root_layout")
        return path.resolve(strict=True)
    except WorkerRefused:
        raise
    except OSError:
        raise WorkerRefused("unsafe_root_layout") from None


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _request_identity_is_valid(request: AuthoritativeGateRequest) -> bool:
    return (
        type(request.repository_identity) is str
        and len(request.repository_identity) <= 200
        and _REPOSITORY_PATTERN.fullmatch(request.repository_identity) is not None
        and type(request.pull_number) is int
        and 0 < request.pull_number <= 2_147_483_647
        and type(request.base_oid) is str
        and type(request.head_oid) is str
        and _OID_PATTERN.fullmatch(request.base_oid) is not None
        and _OID_PATTERN.fullmatch(request.head_oid) is not None
        and len(request.base_oid) == len(request.head_oid)
    )


def _validate_request(
    request: AuthoritativeGateRequest,
) -> tuple[Path, Path, Path]:
    if not _request_identity_is_valid(request):
        raise WorkerRefused("invalid_request")

    trusted_repository = _regular_directory(request.trusted_repository)
    scratch_root = _regular_directory(request.scratch_root)
    evidence_root = _regular_directory(request.evidence_root)
    roots = (trusted_repository, scratch_root, evidence_root)
    if any(
        _overlaps(left, right)
        for index, left in enumerate(roots)
        for right in roots[index + 1 :]
    ):
        raise WorkerRefused("unsafe_root_layout")
    return trusted_repository, scratch_root, evidence_root


def _snapshot_files(snapshot: Snapshot) -> dict[str, SnapshotFile]:
    files: dict[str, SnapshotFile] = {}
    for item in snapshot.files:
        if item.path in files:
            raise WorkerRefused("invalid_snapshot")
        files[item.path] = item
    return files


def diff_snapshots(base: Snapshot, head: Snapshot) -> SnapshotDelta:
    """Return the exact D1 added/modified/mode/deleted path sets."""

    base_files = _snapshot_files(base)
    head_files = _snapshot_files(head)
    changed = tuple(
        sorted(
            path
            for path, item in head_files.items()
            if path not in base_files
            or (item.mode, item.oid) != (base_files[path].mode, base_files[path].oid)
        )
    )
    deleted = tuple(sorted(path for path in base_files if path not in head_files))
    return SnapshotDelta(changed, deleted)


def _is_protected_path(path: str) -> bool:
    alias = _portable_v1_alias(path)
    return alias in _PROTECTED_EXACT_ALIASES or alias.startswith(
        _PROTECTED_PATH_PREFIX_ALIASES
    )


def _contains_inline_suppression(data: bytes) -> bool:
    for encoding in _SCANNER_TEXT_ENCODINGS:
        try:
            text = data.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
        if _INLINE_SUPPRESSION_PATTERN.search(text) is not None:
            return True
    return False


def _control_refusal(
    base: Snapshot,
    head: Snapshot,
    delta: SnapshotDelta,
) -> str | None:
    touched_paths = (*delta.changed_paths, *delta.deleted_paths)
    if any(_is_protected_path(path) for path in touched_paths):
        return "protected_control_change"

    base_files = _snapshot_files(base)
    head_files = _snapshot_files(head)
    for path in touched_paths:
        base_item = base_files.get(path)
        head_item = head_files.get(path)
        if (base_item is not None and _contains_inline_suppression(base_item.data)) or (
            head_item is not None and _contains_inline_suppression(head_item.data)
        ):
            return "source_suppression_change"
    return None


def _scanner_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("PYTHON")
        and not key.upper().startswith("REPO_SENTINEL")
    }
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def _consume_stream(
    stream: object,
    limit: int,
    process: subprocess.Popen[bytes],
    overflow: threading.Event,
    failed: threading.Event,
    output: list[bytes],
) -> None:
    collected = bytearray()
    reader = stream.read
    try:
        while True:
            chunk = reader(8192)
            if not chunk:
                break
            remaining = max(0, limit + 1 - len(collected))
            if remaining:
                collected.extend(chunk[:remaining])
            if len(collected) > limit and not overflow.is_set():
                overflow.set()
                try:
                    process.kill()
                except OSError:
                    pass
    except (OSError, ValueError):
        failed.set()
    output.append(bytes(collected[: limit + 1]))


def _run_command_bounded(
    command: list[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    capture_limit: int,
) -> _CommandResult:
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=_scanner_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
        )
    except OSError:
        raise WorkerRefused("scanner_launch_failed") from None

    assert process.stdout is not None
    assert process.stderr is not None
    overflow = threading.Event()
    capture_failed = threading.Event()
    stdout_parts: list[bytes] = []
    stderr_parts: list[bytes] = []
    threads = (
        threading.Thread(
            target=_consume_stream,
            args=(
                process.stdout,
                capture_limit,
                process,
                overflow,
                capture_failed,
                stdout_parts,
            ),
            daemon=True,
        ),
        threading.Thread(
            target=_consume_stream,
            args=(
                process.stderr,
                capture_limit,
                process,
                overflow,
                capture_failed,
                stderr_parts,
            ),
            daemon=True,
        ),
    )
    for thread in threads:
        thread.start()

    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            process.kill()
        except OSError:
            pass
        process.wait()
    finally:
        for thread in threads:
            thread.join(timeout=5.0)
        process.stdout.close()
        process.stderr.close()

    if timed_out:
        raise WorkerRefused("scanner_timeout")
    if overflow.is_set():
        raise WorkerRefused("scanner_output_limit")
    if capture_failed.is_set() or any(thread.is_alive() for thread in threads):
        raise WorkerRefused("scanner_failed")
    return _CommandResult(
        process.returncode,
        stdout_parts[0] if stdout_parts else b"",
        stderr_parts[0] if stderr_parts else b"",
    )


def _run_trusted_scanner(invocation: ScannerInvocation) -> ScannerExecution:
    version = _run_command_bounded(
        [sys.executable, "-I", "-m", "repo_sentinel", "--version"],
        cwd=invocation.execution_directory,
        timeout_seconds=invocation.timeout_seconds,
        capture_limit=invocation.max_capture_bytes,
    )
    try:
        version_line = version.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        raise WorkerRefused("scanner_version_mismatch") from None
    if (
        version.returncode != 0
        or version.stderr
        or version_line != SCANNER_VERSION_LINE
    ):
        raise WorkerRefused("scanner_version_mismatch")

    baseline_arguments = ["--no-default-baseline"]
    if invocation.baseline_path is not None:
        baseline_arguments.extend(["--baseline", str(invocation.baseline_path)])
    command = [
        sys.executable,
        "-I",
        "-m",
        "repo_sentinel",
        "scan",
        *baseline_arguments,
        "--changed-files",
        "--fail-on-severity",
        "error",
        "--format",
        "json",
        "--output",
        str(invocation.report_path),
        str(invocation.target_root),
        "--",
        *invocation.changed_paths,
    ]
    result = _run_command_bounded(
        command,
        cwd=invocation.execution_directory,
        timeout_seconds=invocation.timeout_seconds,
        capture_limit=invocation.max_capture_bytes,
    )
    return ScannerExecution(
        result.returncode,
        SCANNER_VERSION,
        result.stdout,
        result.stderr,
    )


def _regular_file(
    path: Path,
    *,
    missing_code: str,
    invalid_code: str,
) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise WorkerRefused(missing_code) from None
    except OSError:
        raise WorkerRefused(invalid_code) from None
    reparse = getattr(info, "st_file_attributes", 0) & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
    )
    if reparse or not stat.S_ISREG(info.st_mode):
        raise WorkerRefused(invalid_code)
    return info


def _validated_report(
    report_path: Path,
    execution: ScannerExecution,
    limits: AuthoritativeLimits,
) -> tuple[bytes, GateVerdict]:
    if (
        execution.scanner_version != SCANNER_VERSION
        or len(execution.stdout) > limits.max_capture_bytes
        or len(execution.stderr) > limits.max_capture_bytes
    ):
        raise WorkerRefused("scanner_result_invalid")
    if execution.returncode not in (0, 1):
        raise WorkerRefused("scanner_failed")

    info = _regular_file(
        report_path,
        missing_code="report_missing",
        invalid_code="report_io_failed",
    )
    if info.st_size > limits.max_report_bytes:
        raise WorkerRefused("report_oversize")
    try:
        report = report_path.read_bytes()
    except OSError:
        raise WorkerRefused("report_io_failed") from None
    if len(report) != info.st_size:
        raise WorkerRefused("report_io_failed")
    try:
        decoded = report.decode("utf-8", errors="strict")
        parsed = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise WorkerRefused("scanner_result_invalid") from None
    if not isinstance(parsed, dict):
        raise WorkerRefused("scanner_result_invalid")
    findings = parsed.get("findings")
    missing_files = parsed.get("missing_files")
    suspicious_files = parsed.get("suspicious_files")
    if (
        not isinstance(findings, list)
        or not isinstance(missing_files, dict)
        or not isinstance(suspicious_files, list)
    ):
        raise WorkerRefused("scanner_result_invalid")

    has_error = False
    for finding in findings:
        if not isinstance(finding, dict):
            raise WorkerRefused("scanner_result_invalid")
        severity = finding.get("severity")
        if severity not in ("warning", "error"):
            raise WorkerRefused("scanner_result_invalid")
        has_error = has_error or severity == "error"
    if (execution.returncode == 1) != has_error:
        raise WorkerRefused("scanner_result_invalid")
    verdict = GateVerdict.SCANNER_FINDING if has_error else GateVerdict.PASS
    return report, verdict


def _write_private(path: Path, data: bytes, refusal: str) -> None:
    descriptor: int | None = None
    created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags, 0o600)
        created = True
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            if output.write(data) != len(data):
                raise OSError("short write")
            output.flush()
            os.fsync(output.fileno())
        info = _regular_file(
            path,
            missing_code=refusal,
            invalid_code=refusal,
        )
        if info.st_size != len(data) or path.read_bytes() != data:
            raise OSError("readback mismatch")
    except FileExistsError:
        raise WorkerRefused(
            "report_collision" if refusal == "report_io_failed" else refusal
        ) from None
    except WorkerRefused:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                raise WorkerRefused("cleanup_failed") from None
        raise
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                raise WorkerRefused("cleanup_failed") from None
        raise WorkerRefused(refusal) from None


@contextmanager
def _private_temporary_directory(root: Path, prefix: str) -> Iterator[Path]:
    temporary: TemporaryDirectory[str] | None = None
    try:
        try:
            temporary = TemporaryDirectory(prefix=prefix, dir=root)
            directory = Path(temporary.name)
            _regular_directory(directory)
        except OSError:
            raise WorkerRefused("filesystem_io_failed") from None
        yield directory
    finally:
        if temporary is not None:
            try:
                temporary.cleanup()
            except OSError:
                raise WorkerRefused("cleanup_failed") from None


def _base_baseline(snapshot: Snapshot) -> bytes | None:
    for item in snapshot.files:
        if item.path == ".reposentinel-baseline.json":
            return item.data
    return None


def _result(
    request: AuthoritativeGateRequest,
    verdict: GateVerdict,
    *,
    changed_count: int = 0,
    deleted_count: int = 0,
    report: bytes | None = None,
    scanner_version: str | None = None,
    refusal_code: str | None = None,
) -> AuthoritativeGateResult:
    if _request_identity_is_valid(request):
        repository_identity = request.repository_identity
        pull_number = request.pull_number
        base_oid = request.base_oid
        head_oid = request.head_oid
    else:
        repository_identity = ""
        pull_number = 0
        base_oid = ""
        head_oid = ""
    return AuthoritativeGateResult(
        verdict=verdict,
        repository_identity=repository_identity,
        pull_number=pull_number,
        base_oid=base_oid,
        head_oid=head_oid,
        changed_count=changed_count,
        deleted_count=deleted_count,
        report_sha256=(
            hashlib.sha256(report).hexdigest() if report is not None else None
        ),
        report_size=len(report) if report is not None else 0,
        scanner_version=scanner_version,
        refusal_code=refusal_code,
    )


def _execute(
    request: AuthoritativeGateRequest,
    *,
    limits: AuthoritativeLimits,
    acquisition_limits: AcquisitionLimits,
    reader_limits: ReaderLimits,
    snapshot_reader: SnapshotReader,
    pull_acquirer: PullAcquirer,
    snapshot_materializer: SnapshotMaterializer,
    scanner_runner: ScannerRunner,
) -> tuple[AuthoritativeGateResult, bytes | None, Path]:
    trusted_repository, scratch_root, evidence_root = _validate_request(request)
    try:
        base_snapshot = snapshot_reader(
            trusted_repository,
            request.base_oid,
            limits=reader_limits,
        )
    except ReaderRefused:
        raise WorkerRefused("base_reader_refused") from None
    if base_snapshot.commit_oid != request.base_oid:
        raise WorkerRefused("invalid_snapshot")

    try:
        with pull_acquirer(
            request.remote,
            request.pull_number,
            request.head_oid,
            scratch_root,
            acquisition_limits=acquisition_limits,
            reader_limits=reader_limits,
        ) as acquired:
            if acquired.snapshot.commit_oid != request.head_oid:
                raise WorkerRefused("head_snapshot_mismatch")
            acquired_repository = _regular_directory(acquired.repository)
            if (
                acquired_repository == scratch_root
                or not acquired_repository.is_relative_to(scratch_root)
            ):
                raise WorkerRefused("unsafe_root_layout")
            delta = diff_snapshots(base_snapshot, acquired.snapshot)
            control_refusal = _control_refusal(
                base_snapshot,
                acquired.snapshot,
                delta,
            )
            if control_refusal is not None:
                return (
                    _result(
                        request,
                        GateVerdict.PROTECTED_CONTROL_CHANGE,
                        changed_count=len(delta.changed_paths),
                        deleted_count=len(delta.deleted_paths),
                        refusal_code=control_refusal,
                    ),
                    None,
                    evidence_root,
                )
            if not delta.changed_paths and not delta.deleted_paths:
                return (
                    _result(
                        request,
                        GateVerdict.PASS,
                        changed_count=0,
                        deleted_count=len(delta.deleted_paths),
                    ),
                    None,
                    evidence_root,
                )

            with _private_temporary_directory(
                scratch_root, "repo-sentinel-control-"
            ) as control_root:
                baseline_path: Path | None = None
                baseline = _base_baseline(base_snapshot)
                if baseline is not None:
                    baseline_path = control_root / "baseline.json"
                    _write_private(baseline_path, baseline, "filesystem_io_failed")

                with _private_temporary_directory(
                    evidence_root, "repo-sentinel-report-"
                ) as report_root:
                    report_path = report_root / "report.json"
                    with snapshot_materializer(
                        acquired.repository,
                        request.head_oid,
                        scratch_root,
                        limits=reader_limits,
                    ) as materialized:
                        if materialized.snapshot != acquired.snapshot:
                            raise WorkerRefused("head_snapshot_mismatch")
                        materialized_root = _regular_directory(materialized.root)
                        if (
                            materialized_root == scratch_root
                            or not materialized_root.is_relative_to(scratch_root)
                        ):
                            raise WorkerRefused("unsafe_root_layout")
                        if any(
                            _overlaps(materialized_root, protected_root)
                            for protected_root in (
                                trusted_repository,
                                acquired_repository,
                                control_root,
                                evidence_root,
                            )
                        ):
                            raise WorkerRefused("unsafe_root_layout")
                        invocation = ScannerInvocation(
                            target_root=materialized_root,
                            changed_paths=delta.changed_paths,
                            baseline_path=baseline_path,
                            report_path=report_path,
                            execution_directory=control_root,
                            timeout_seconds=limits.scanner_timeout_seconds,
                            max_capture_bytes=limits.max_capture_bytes,
                        )
                        execution = scanner_runner(invocation)
                        report, verdict = _validated_report(
                            report_path,
                            execution,
                            limits,
                        )
            return (
                _result(
                    request,
                    verdict,
                    changed_count=len(delta.changed_paths),
                    deleted_count=len(delta.deleted_paths),
                    report=report,
                    scanner_version=execution.scanner_version,
                ),
                report,
                evidence_root,
            )
    except ReaderRefused:
        raise WorkerRefused("head_reader_refused") from None
    except AcquisitionRefused as error:
        code = (
            "cleanup_failed"
            if str(error) == "cleanup_failed"
            else "head_acquisition_refused"
        )
        raise WorkerRefused(code) from None
    except MaterializationRefused as error:
        code = (
            "cleanup_failed"
            if str(error) == "cleanup_failed"
            else "head_materialization_refused"
        )
        raise WorkerRefused(code) from None


def _persist_report(
    result: AuthoritativeGateResult,
    report: bytes,
    evidence_root: Path,
) -> AuthoritativeGateResult:
    report_path = evidence_root / f"authoritative-report-{result.head_oid}.json"
    _write_private(report_path, report, "report_io_failed")
    return replace(result, report_path=report_path)


def run_authoritative_gate(
    request: AuthoritativeGateRequest,
    *,
    limits: AuthoritativeLimits | None = None,
    acquisition_limits: AcquisitionLimits | None = None,
    reader_limits: ReaderLimits | None = None,
    snapshot_reader: SnapshotReader = read_snapshot,
    pull_acquirer: PullAcquirer = acquire_pull_snapshot,
    snapshot_materializer: SnapshotMaterializer = materialized_snapshot,
    scanner_runner: ScannerRunner = _run_trusted_scanner,
) -> AuthoritativeGateResult:
    """Run the trusted worker core without publishing or printing a result."""

    if limits is None:
        limits = AuthoritativeLimits()
    if acquisition_limits is None:
        acquisition_limits = AcquisitionLimits()
    if reader_limits is None:
        reader_limits = ReaderLimits()

    try:
        result, report, evidence_root = _execute(
            request,
            limits=limits,
            acquisition_limits=acquisition_limits,
            reader_limits=reader_limits,
            snapshot_reader=snapshot_reader,
            pull_acquirer=pull_acquirer,
            snapshot_materializer=snapshot_materializer,
            scanner_runner=scanner_runner,
        )
        if report is not None:
            result = _persist_report(result, report, evidence_root)
        return result
    except WorkerRefused as error:
        return _result(
            request,
            GateVerdict.INFRASTRUCTURE_REFUSAL,
            refusal_code=error.code,
        )
    # A signer must receive a fixed fail-closed result, never an exception string.
    except Exception:  # noqa: BLE001
        return _result(
            request,
            GateVerdict.INFRASTRUCTURE_REFUSAL,
            refusal_code="unexpected_failure",
        )


__all__ = [
    "SCANNER_DISTRIBUTION",
    "SCANNER_VERSION",
    "AuthoritativeGateRequest",
    "AuthoritativeGateResult",
    "AuthoritativeLimits",
    "GateVerdict",
    "ScannerExecution",
    "ScannerInvocation",
    "SnapshotDelta",
    "diff_snapshots",
    "run_authoritative_gate",
]
