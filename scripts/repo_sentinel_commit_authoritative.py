"""Evaluate exact commits against an immutable Repo Sentinel policy epoch."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import stat
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any

from repo_sentinel_materialize import (
    MaterializationRefused,
    MaterializedSnapshot,
    materialized_snapshot,
)
from repo_sentinel_policy_bundle import (
    BUNDLE_FILENAMES,
    PolicyBundleRefused,
    PolicyEntry,
    RuntimeContract,
    VerifiedPolicyBundle,
    contains_inline_suppression,
    is_config_ignored,
    load_policy_bundle,
    portable_v1_alias,
    scanner_exclusion_reason,
    sha256_bytes,
)
from repo_sentinel_reader import ReaderLimits, ReaderRefused, Snapshot, SnapshotFile
from repo_sentinel_reader import read_snapshot

_OID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_REDACTED_TOKEN = re.compile(r"<redacted:sha256:[0-9a-f]{12}>")
_FINDING_RULES = {
    "assignment_context": ("secret.assignment_context", "warning", True),
    "aws_access_key_id": ("secret.aws_access_key_id", "error", True),
    "github_token": ("secret.github_token", "error", True),
    "high_entropy": ("secret.high_entropy", "error", True),
    "missing_file": ("repo.required_file_missing", "warning", False),
    "pem_private_key": ("secret.pem_private_key", "error", False),
    "suspicious_file": ("repo.suspicious_filename", "error", False),
}
_SEMANTIC_DOMAIN = b"repo-sentinel-commit-authority-result-v1\0"
_MAX_SCANNER_ARTIFACT_BYTES = 2 * 1024 * 1024
_FIXED_SCANNER_ENVIRONMENT = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
}
_INFRASTRUCTURE_CODES = frozenset(
    {
        "cleanup_failed",
        "filesystem_io_failed",
        "head_materialization_refused",
        "head_reader_refused",
        "head_snapshot_mismatch",
        "invalid_request",
        "invalid_snapshot",
        "policy_bundle_invalid",
        "policy_bundle_mismatch",
        "policy_schema_unsupported",
        "report_io_failed",
        "report_missing",
        "report_oversize",
        "runtime_mismatch",
        "scanner_artifact_invalid",
        "scanner_artifact_mismatch",
        "scanner_failed",
        "scanner_launch_failed",
        "scanner_output_limit",
        "scanner_result_invalid",
        "scanner_timeout",
        "scanner_version_mismatch",
        "unsafe_root_layout",
        "unexpected_failure",
    }
)
_POLICY_CODES = frozenset(
    {
        "coverage_policy_mismatch",
        "policy_bundle_mirror_mismatch",
        "protected_control_mismatch",
        "suppression_manifest_mismatch",
    }
)
_SCANNER_DRIVER = r"""
import json
import sys
from pathlib import Path

wheel, target_text, baseline_text, output_text, exclusions_text = sys.argv[1:]
sys.path.insert(0, wheel)
import repo_sentinel.cli as cli
import repo_sentinel.scanner as scanner
from repo_sentinel.config import relative_path, sort_key
from repo_sentinel.coverage import build_coverage
from repo_sentinel.walk import TextReadSuccess

target = Path(target_text).resolve()
policy_exclusions = json.loads(Path(exclusions_text).read_text(encoding="utf-8"))
if (
    not isinstance(policy_exclusions, list)
    or not all(isinstance(path, str) for path in policy_exclusions)
    or len(policy_exclusions) != len(set(policy_exclusions))
):
    raise SystemExit(2)
policy_exclusions = set(policy_exclusions)
scanned = []
inspect_text_file = scanner.inspect_text_file
iter_files = scanner.iter_files

def tracked(path, limit):
    result = inspect_text_file(path, limit)
    if isinstance(result, TextReadSuccess):
        scanned.append(relative_path(path, target))
    return result

scanner.inspect_text_file = tracked

def policy_scoped_iter_files(*args, **kwargs):
    for path in iter_files(*args, **kwargs):
        if relative_path(path, target) not in policy_exclusions:
            yield path

scanner.iter_files = policy_scoped_iter_files
returncode = cli.main([
    "scan",
    "--format", "json",
    "--no-default-baseline",
    "--baseline", baseline_text,
    "--fail-on-severity", "error",
    "--output", output_text,
    target_text,
])
if returncode not in (0, 1):
    raise SystemExit(returncode)
report = json.loads(Path(output_text).read_text(encoding="utf-8"))
if "coverage" not in report:
    report["coverage"] = build_coverage(len(scanned), [])
report["authority_coverage"] = {
    "scanned_paths": sorted(scanned, key=sort_key),
}
Path(output_text).write_text(
    json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
raise SystemExit(returncode)
"""
_VERSION_DRIVER = (
    "import sys;sys.path.insert(0,sys.argv[1]);"
    "import repo_sentinel;print('repo-sentinel '+repo_sentinel.__version__)"
)


class CommitAuthorityVerdict(str, Enum):
    PASS = "PASS"
    SCANNER_FINDING = "SCANNER_FINDING"
    POLICY_ADMISSION_FAILURE = "POLICY_ADMISSION_FAILURE"
    INFRASTRUCTURE_REFUSAL = "INFRASTRUCTURE_REFUSAL"


class WorkerRefused(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code if code in _INFRASTRUCTURE_CODES else "unexpected_failure"
        super().__init__(self.code)


class PolicyAdmissionRefused(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code if code in _POLICY_CODES else "coverage_policy_mismatch"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class CommitAuthoritativeRequest:
    repository_id: int
    head_oid: str
    repository: Path = field(repr=False, compare=False)
    policy_bundle_root: Path = field(repr=False, compare=False)
    expected_policy_bundle_sha256: str = field(repr=False)
    policy_selector: str
    scanner_artifact: Path = field(repr=False, compare=False)
    scratch_root: Path = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class CommitAuthoritativeLimits:
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
class CommitAuthoritativeResult:
    policy_schema_version: int | None
    policy_epoch: str | None
    policy_bundle_sha256: str | None
    repository_id: int
    head_oid: str
    protected_manifest_sha256: str | None
    suppression_manifest_sha256: str | None
    coverage_policy_sha256: str | None
    scanner_distribution: str | None
    scanner_version: str | None
    scanner_artifact_sha256: str | None
    files_total: int
    files_scanned: int
    files_policy_excluded: int
    files_scanner_skipped: int
    report_sha256: str | None
    report_size: int
    verdict: CommitAuthorityVerdict
    refusal_code: str | None
    semantic_sha256: str | None


@dataclass(frozen=True, slots=True)
class RuntimeFacts:
    implementation: str
    python_version: str
    os_family: str
    architecture: str


@dataclass(frozen=True, slots=True)
class CoverageInventory:
    scanned_paths: tuple[str, ...]
    policy_excluded_paths: tuple[str, ...]
    scanner_skips: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class ScannerInvocation:
    target_root: Path = field(repr=False)
    scanner_artifact: Path = field(repr=False)
    baseline_path: Path = field(repr=False)
    policy_exclusions_path: Path = field(repr=False)
    report_path: Path = field(repr=False)
    execution_directory: Path = field(repr=False)
    timeout_seconds: float
    max_capture_bytes: int
    expected_version: str


@dataclass(frozen=True, slots=True)
class ScannerExecution:
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
SnapshotMaterializer = Callable[..., Iterator[MaterializedSnapshot]]
ScannerRunner = Callable[[ScannerInvocation], ScannerExecution]
RuntimeFactsProvider = Callable[[], RuntimeFacts]


def current_runtime_facts() -> RuntimeFacts:
    return RuntimeFacts(
        sys.implementation.name,
        platform.python_version(),
        platform.system(),
        platform.machine(),
    )


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


def _valid_request(request: CommitAuthoritativeRequest) -> bool:
    return (
        type(request.repository_id) is int
        and request.repository_id > 0
        and type(request.head_oid) is str
        and _OID.fullmatch(request.head_oid) is not None
        and type(request.expected_policy_bundle_sha256) is str
        and _DIGEST.fullmatch(request.expected_policy_bundle_sha256) is not None
        and type(request.policy_selector) is str
    )


def _validate_request(
    request: CommitAuthoritativeRequest,
) -> tuple[Path, Path, Path]:
    if not _valid_request(request):
        raise WorkerRefused("invalid_request")
    repository = _regular_directory(request.repository)
    policy_root = _regular_directory(request.policy_bundle_root)
    scratch_root = _regular_directory(request.scratch_root)
    roots = (repository, policy_root, scratch_root)
    if any(
        _overlaps(left, right)
        for index, left in enumerate(roots)
        for right in roots[index + 1 :]
    ):
        raise WorkerRefused("unsafe_root_layout")
    return repository, policy_root, scratch_root


def _read_regular(path: Path, limit: int, code: str) -> bytes:
    try:
        info = path.lstat()
        reparse = getattr(info, "st_file_attributes", 0) & getattr(
            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
        )
        if reparse or not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise WorkerRefused(code)
        data = path.read_bytes()
    except WorkerRefused:
        raise
    except OSError:
        raise WorkerRefused(code) from None
    if len(data) != info.st_size:
        raise WorkerRefused(code)
    return data


def _artifact_bytes(path: Path, expected_sha256: str) -> bytes:
    data = _read_regular(path, _MAX_SCANNER_ARTIFACT_BYTES, "scanner_artifact_invalid")
    if sha256_bytes(data) != expected_sha256:
        raise WorkerRefused("scanner_artifact_mismatch")
    return data


def _snapshot_files(snapshot: Snapshot) -> dict[str, SnapshotFile]:
    files = {item.path: item for item in snapshot.files}
    if len(files) != len(snapshot.files):
        raise WorkerRefused("invalid_snapshot")
    return files


def _entry_matches(item: SnapshotFile, entry: PolicyEntry) -> bool:
    return item.mode == entry.mode and sha256_bytes(item.data) == entry.sha256


def _admit_protected(
    files: dict[str, SnapshotFile], bundle: VerifiedPolicyBundle
) -> None:
    approved = {entry.path: entry for entry in bundle.protected_entries}
    aliases = {portable_v1_alias(path): path for path in approved}
    mandatory_aliases = {
        portable_v1_alias(path) for path in bundle.contract.mandatory_protected_paths
    }
    namespace_aliases = tuple(
        portable_v1_alias(path) for path in bundle.protected_namespaces
    )
    for path, item in files.items():
        alias = portable_v1_alias(path)
        protected = alias in mandatory_aliases or alias.startswith(namespace_aliases)
        approved_path = aliases.get(alias)
        if protected and (approved_path != path or path not in approved):
            raise PolicyAdmissionRefused("protected_control_mismatch")
        if path in approved and not _entry_matches(item, approved[path]):
            raise PolicyAdmissionRefused("protected_control_mismatch")
    if set(approved) - set(files):
        raise PolicyAdmissionRefused("protected_control_mismatch")


def _admit_policy_bundle_mirror(
    files: dict[str, SnapshotFile], bundle: VerifiedPolicyBundle
) -> None:
    expected = {
        f"{bundle.contract.mirror_root}{name}": data
        for name, data in bundle.bundle_files
    }
    expected_aliases = {portable_v1_alias(path): path for path in expected}
    mirror_alias_root = portable_v1_alias(bundle.contract.mirror_root)
    observed = {
        path: item
        for path, item in files.items()
        if portable_v1_alias(path).startswith(mirror_alias_root)
    }
    if set(observed) != set(expected):
        raise PolicyAdmissionRefused("policy_bundle_mirror_mismatch")
    for path, item in observed.items():
        if (
            expected_aliases.get(portable_v1_alias(path)) != path
            or item.mode != "100644"
            or item.data != expected[path]
        ):
            raise PolicyAdmissionRefused("policy_bundle_mirror_mismatch")


def _admit_suppressions(
    files: dict[str, SnapshotFile], bundle: VerifiedPolicyBundle
) -> None:
    approved = {entry.path: entry for entry in bundle.suppression_entries}
    actual = {
        path: item
        for path, item in files.items()
        if contains_inline_suppression(item.data)
    }
    if set(actual) != set(approved):
        raise PolicyAdmissionRefused("suppression_manifest_mismatch")
    if any(not _entry_matches(actual[path], entry) for path, entry in approved.items()):
        raise PolicyAdmissionRefused("suppression_manifest_mismatch")


def _coverage_inventory(
    files: dict[str, SnapshotFile], bundle: VerifiedPolicyBundle
) -> CoverageInventory:
    approved = {entry.path: entry for entry in bundle.coverage_entries}
    observed: dict[str, tuple[SnapshotFile, str]] = {}
    scanned: list[str] = []
    ignored: list[str] = []
    skipped: list[tuple[str, str]] = []
    mirror_paths = {f"{bundle.contract.mirror_root}{name}" for name in BUNDLE_FILENAMES}
    for path, item in sorted(files.items()):
        if path in mirror_paths:
            ignored.append(path)
            continue
        reason = (
            "config_ignore"
            if is_config_ignored(path, bundle.effective_ignore_globs)
            else scanner_exclusion_reason(item.data, bundle.max_text_file_size)
        )
        if reason is None:
            scanned.append(path)
            continue
        observed[path] = (item, reason)
        if reason == "config_ignore":
            ignored.append(path)
        else:
            skipped.append((path, reason))
    if set(observed) != set(approved):
        raise PolicyAdmissionRefused("coverage_policy_mismatch")
    for path, (item, reason) in observed.items():
        entry = approved[path]
        if entry.reason != reason or not _entry_matches(item, entry):
            raise PolicyAdmissionRefused("coverage_policy_mismatch")
    return CoverageInventory(tuple(scanned), tuple(ignored), tuple(skipped))


def _scanner_environment() -> dict[str, str]:
    return dict(_FIXED_SCANNER_ENVIRONMENT)


def _consume_stream(
    stream: Any,
    limit: int,
    process: subprocess.Popen[bytes],
    overflow: threading.Event,
    failed: threading.Event,
    output: list[bytes],
) -> None:
    collected = bytearray()
    try:
        while True:
            chunk = stream.read(8192)
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
    command: list[str], *, cwd: Path, timeout_seconds: float, capture_limit: int
) -> _CommandResult:
    executable = Path(sys.executable)
    if not executable.is_absolute():
        raise WorkerRefused("scanner_launch_failed")
    try:
        command[0] = str(executable.resolve(strict=True))
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
    assert process.stdout is not None and process.stderr is not None
    overflow = threading.Event()
    failed = threading.Event()
    stdout: list[bytes] = []
    stderr: list[bytes] = []
    threads = (
        threading.Thread(
            target=_consume_stream,
            args=(process.stdout, capture_limit, process, overflow, failed, stdout),
            daemon=True,
        ),
        threading.Thread(
            target=_consume_stream,
            args=(process.stderr, capture_limit, process, overflow, failed, stderr),
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
        process.kill()
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
    if failed.is_set() or any(thread.is_alive() for thread in threads):
        raise WorkerRefused("scanner_failed")
    return _CommandResult(
        process.returncode,
        stdout[0] if stdout else b"",
        stderr[0] if stderr else b"",
    )


def _run_trusted_scanner(invocation: ScannerInvocation) -> ScannerExecution:
    version = _run_command_bounded(
        [sys.executable, "-I", "-c", _VERSION_DRIVER, str(invocation.scanner_artifact)],
        cwd=invocation.execution_directory,
        timeout_seconds=invocation.timeout_seconds,
        capture_limit=invocation.max_capture_bytes,
    )
    expected_line = f"repo-sentinel {invocation.expected_version}\n".encode()
    if version.returncode != 0 or version.stdout != expected_line or version.stderr:
        raise WorkerRefused("scanner_version_mismatch")
    result = _run_command_bounded(
        [
            sys.executable,
            "-I",
            "-c",
            _SCANNER_DRIVER,
            str(invocation.scanner_artifact),
            str(invocation.target_root),
            str(invocation.baseline_path),
            str(invocation.report_path),
            str(invocation.policy_exclusions_path),
        ],
        cwd=invocation.execution_directory,
        timeout_seconds=invocation.timeout_seconds,
        capture_limit=invocation.max_capture_bytes,
    )
    return ScannerExecution(
        result.returncode,
        invocation.expected_version,
        result.stdout,
        result.stderr,
    )


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON value")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _parse_report(data: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise WorkerRefused("scanner_result_invalid") from None
    if not isinstance(parsed, dict):
        raise WorkerRefused("scanner_result_invalid")
    return parsed


def _non_negative_integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _expected_missing(
    files: dict[str, SnapshotFile], required_files: tuple[str, ...]
) -> dict[str, bool]:
    folded = {path.casefold() for path in files}
    return {
        PurePosixPath(path.replace("\\", "/")).as_posix(): PurePosixPath(
            path.replace("\\", "/")
        )
        .as_posix()
        .casefold()
        not in folded
        for path in required_files
    }


def _validated_report(
    report_path: Path,
    execution: ScannerExecution,
    limits: CommitAuthoritativeLimits,
    files: dict[str, SnapshotFile],
    inventory: CoverageInventory,
    bundle: VerifiedPolicyBundle,
) -> tuple[bytes, CommitAuthorityVerdict]:
    if (
        execution.scanner_version != bundle.scanner_version
        or execution.returncode not in (0, 1)
        or execution.stdout
        or execution.stderr
    ):
        raise WorkerRefused("scanner_result_invalid")
    try:
        info = report_path.lstat()
    except FileNotFoundError:
        raise WorkerRefused("report_missing") from None
    except OSError:
        raise WorkerRefused("report_io_failed") from None
    reparse = getattr(info, "st_file_attributes", 0) & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
    )
    if reparse or not stat.S_ISREG(info.st_mode):
        raise WorkerRefused("report_io_failed")
    if info.st_size > limits.max_report_bytes:
        raise WorkerRefused("report_oversize")
    report = _read_regular(report_path, limits.max_report_bytes, "report_io_failed")
    parsed = _parse_report(report)
    if set(parsed) != {
        "authority_coverage",
        "coverage",
        "findings",
        "high_entropy_findings",
        "missing_files",
        "suspicious_files",
    }:
        raise WorkerRefused("scanner_result_invalid")
    authority_coverage = parsed["authority_coverage"]
    if not isinstance(authority_coverage, dict) or set(authority_coverage) != {
        "scanned_paths"
    }:
        raise WorkerRefused("scanner_result_invalid")
    scanned = authority_coverage["scanned_paths"]
    if (
        not isinstance(scanned, list)
        or not all(isinstance(path, str) for path in scanned)
        or len(scanned) != len(set(scanned))
        or scanned != sorted(scanned, key=lambda path: (path.casefold(), path))
        or set(scanned) != set(inventory.scanned_paths)
    ):
        raise WorkerRefused("scanner_result_invalid")

    coverage = parsed["coverage"]
    if not isinstance(coverage, dict):
        raise WorkerRefused("scanner_result_invalid")
    required_coverage = {
        "files_considered",
        "files_inspected",
        "files_skipped",
        "skipped_by_reason",
        "skipped_files",
    }
    if not required_coverage.issubset(coverage) or set(coverage) - (
        required_coverage | {"directories_skipped", "skipped_directories"}
    ):
        raise WorkerRefused("scanner_result_invalid")
    skipped_files = coverage["skipped_files"]
    if not isinstance(skipped_files, list):
        raise WorkerRefused("scanner_result_invalid")
    observed_skips: list[tuple[str, str]] = []
    for entry in skipped_files:
        if not isinstance(entry, dict) or set(entry) != {"path", "reason"}:
            raise WorkerRefused("scanner_result_invalid")
        path, reason = entry["path"], entry["reason"]
        if not isinstance(path, str) or not isinstance(reason, str):
            raise WorkerRefused("scanner_result_invalid")
        observed_skips.append((path, reason))
    if (
        len(observed_skips) != len(set(observed_skips))
        or observed_skips
        != sorted(observed_skips, key=lambda item: (item[0].casefold(), *item))
        or set(observed_skips) != set(inventory.scanner_skips)
    ):
        raise WorkerRefused("scanner_result_invalid")
    if any(reason in ("unreadable", "symlink_policy") for _, reason in observed_skips):
        raise WorkerRefused("scanner_result_invalid")
    reason_counts = {
        reason: sum(1 for _, candidate in observed_skips if candidate == reason)
        for reason in {candidate for _, candidate in observed_skips}
    }
    reported_reason_counts = coverage["skipped_by_reason"]
    if (
        not all(
            _non_negative_integer(coverage[key])
            for key in ("files_inspected", "files_skipped", "files_considered")
        )
        or not isinstance(reported_reason_counts, dict)
        or not all(
            isinstance(reason, str) and _non_negative_integer(count)
            for reason, count in reported_reason_counts.items()
        )
        or coverage["files_inspected"] != len(scanned)
        or coverage["files_skipped"] != len(observed_skips)
        or coverage["files_considered"] != len(scanned) + len(observed_skips)
        or reported_reason_counts != reason_counts
        or not _non_negative_integer(coverage.get("directories_skipped", 0))
        or coverage.get("directories_skipped", 0) != 0
        or coverage.get("skipped_directories", []) != []
    ):
        raise WorkerRefused("scanner_result_invalid")

    findings = parsed["findings"]
    if not isinstance(findings, list):
        raise WorkerRefused("scanner_result_invalid")
    has_error = False
    fingerprints: set[str] = set()
    expected_entropy: list[dict[str, object]] = []
    expected_suspicious: list[str] = []
    expected_missing_findings: list[str] = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise WorkerRefused("scanner_result_invalid")
        kind = finding.get("kind")
        severity = finding.get("severity")
        fingerprint = finding.get("fingerprint")
        rule = _FINDING_RULES.get(kind) if isinstance(kind, str) else None
        if (
            rule is None
            or finding.get("rule_id") != rule[0]
            or severity != rule[1]
            or finding.get("rule_version") != "1"
            or not isinstance(finding.get("remediation_hint"), str)
            or not finding["remediation_hint"]
            or not isinstance(finding.get("evidence"), dict)
            or not isinstance(fingerprint, str)
            or _DIGEST.fullmatch(fingerprint) is None
        ):
            raise WorkerRefused("scanner_result_invalid")
        if fingerprint in fingerprints:
            raise WorkerRefused("scanner_result_invalid")
        fingerprints.add(fingerprint)
        path = finding.get("path", finding.get("file"))
        if not isinstance(path, str) or (kind != "missing_file" and path not in files):
            raise WorkerRefused("scanner_result_invalid")
        line = finding.get("line")
        line_required = kind not in {"missing_file", "suspicious_file"}
        if line_required != (type(line) is int and line >= 1):
            raise WorkerRefused("scanner_result_invalid")
        token = finding.get("token")
        if rule[2] != (
            isinstance(token, str) and _REDACTED_TOKEN.fullmatch(token) is not None
        ):
            raise WorkerRefused("scanner_result_invalid")
        if line_required and (
            finding.get("file") != path or finding.get("path") != path
        ):
            raise WorkerRefused("scanner_result_invalid")
        evidence = finding["evidence"]
        if rule[2] and (
            not isinstance(evidence.get("token_sha256"), str)
            or _DIGEST.fullmatch(evidence["token_sha256"]) is None
        ):
            raise WorkerRefused("scanner_result_invalid")
        if kind == "high_entropy":
            entropy = finding.get("entropy")
            if (
                type(entropy) not in (int, float)
                or not math.isfinite(entropy)
                or evidence.get("entropy") != entropy
                or evidence.get("line") != line
            ):
                raise WorkerRefused("scanner_result_invalid")
            expected_entropy.append(
                {
                    "entropy": entropy,
                    "file": path,
                    "line": line,
                    "token": token,
                }
            )
        elif kind == "suspicious_file":
            expected_suspicious.append(path)
        elif kind == "missing_file":
            expected_missing_findings.append(path)
        has_error = has_error or severity == "error"
    expected_missing = _expected_missing(files, bundle.required_files)
    if (
        parsed["high_entropy_findings"] != expected_entropy
        or parsed["suspicious_files"]
        != sorted(expected_suspicious, key=lambda path: (path.casefold(), path))
        or parsed["missing_files"] != expected_missing
        or sorted(expected_missing_findings, key=lambda path: (path.casefold(), path))
        != sorted(
            (path for path, missing in expected_missing.items() if missing),
            key=lambda path: (path.casefold(), path),
        )
        or (execution.returncode == 1) != has_error
    ):
        raise WorkerRefused("scanner_result_invalid")
    verdict = (
        CommitAuthorityVerdict.SCANNER_FINDING
        if has_error
        else CommitAuthorityVerdict.PASS
    )
    return report, verdict


def _write_private(path: Path, data: bytes) -> None:
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
        if _read_regular(path, len(data), "filesystem_io_failed") != data:
            raise OSError("readback mismatch")
    except WorkerRefused:
        if created:
            path.unlink(missing_ok=True)
        raise
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                raise WorkerRefused("cleanup_failed") from None
        raise WorkerRefused("filesystem_io_failed") from None


@contextmanager
def _private_directory(root: Path) -> Iterator[Path]:
    temporary: TemporaryDirectory[str] | None = None
    try:
        try:
            temporary = TemporaryDirectory(prefix="commit-authority-", dir=root)
            directory = _regular_directory(Path(temporary.name))
        except OSError:
            raise WorkerRefused("filesystem_io_failed") from None
        yield directory
    finally:
        if temporary is not None:
            try:
                temporary.cleanup()
            except OSError:
                raise WorkerRefused("cleanup_failed") from None


def _verify_materialized_controls(root: Path, bundle: VerifiedPolicyBundle) -> None:
    for entry in bundle.protected_entries:
        candidate = root.joinpath(*entry.path.split("/"))
        data = _read_regular(candidate, 16 * 1024 * 1024, "filesystem_io_failed")
        if sha256_bytes(data) != entry.sha256:
            raise WorkerRefused("head_snapshot_mismatch")


def _semantic_payload(result: CommitAuthoritativeResult) -> dict[str, object]:
    return {
        "policy_schema_version": result.policy_schema_version,
        "policy_epoch": result.policy_epoch,
        "policy_bundle_sha256": result.policy_bundle_sha256,
        "repository_id": result.repository_id,
        "head_oid": result.head_oid,
        "protected_manifest_sha256": result.protected_manifest_sha256,
        "suppression_manifest_sha256": result.suppression_manifest_sha256,
        "coverage_policy_sha256": result.coverage_policy_sha256,
        "scanner_distribution": result.scanner_distribution,
        "scanner_version": result.scanner_version,
        "scanner_artifact_sha256": result.scanner_artifact_sha256,
        "files_total": result.files_total,
        "files_scanned": result.files_scanned,
        "files_policy_excluded": result.files_policy_excluded,
        "files_scanner_skipped": result.files_scanner_skipped,
        "report_sha256": result.report_sha256,
        "report_size": result.report_size,
        "verdict": result.verdict.value,
        "refusal_code": result.refusal_code,
    }


def _with_semantic_digest(
    result: CommitAuthoritativeResult,
) -> CommitAuthoritativeResult:
    encoded = json.dumps(
        _semantic_payload(result),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(
        _SEMANTIC_DOMAIN + len(encoded).to_bytes(8, "big") + encoded
    ).hexdigest()
    return replace(result, semantic_sha256=digest)


def _result(
    request: CommitAuthoritativeRequest,
    verdict: CommitAuthorityVerdict,
    *,
    bundle: VerifiedPolicyBundle | None = None,
    files_total: int = 0,
    inventory: CoverageInventory | None = None,
    report: bytes | None = None,
    refusal_code: str | None = None,
) -> CommitAuthoritativeResult:
    valid = _valid_request(request)
    result = CommitAuthoritativeResult(
        policy_schema_version=bundle.schema_version if bundle else None,
        policy_epoch=bundle.policy_epoch if bundle else None,
        policy_bundle_sha256=bundle.bundle_sha256 if bundle else None,
        repository_id=request.repository_id if valid else 0,
        head_oid=request.head_oid if valid else "",
        protected_manifest_sha256=(
            bundle.protected_manifest_sha256 if bundle else None
        ),
        suppression_manifest_sha256=(
            bundle.suppression_manifest_sha256 if bundle else None
        ),
        coverage_policy_sha256=bundle.coverage_policy_sha256 if bundle else None,
        scanner_distribution=bundle.scanner_distribution if bundle else None,
        scanner_version=bundle.scanner_version if bundle else None,
        scanner_artifact_sha256=(bundle.scanner_artifact_sha256 if bundle else None),
        files_total=files_total,
        files_scanned=len(inventory.scanned_paths) if inventory else 0,
        files_policy_excluded=(
            len(inventory.policy_excluded_paths) if inventory else 0
        ),
        files_scanner_skipped=len(inventory.scanner_skips) if inventory else 0,
        report_sha256=sha256_bytes(report) if report is not None else None,
        report_size=len(report) if report is not None else 0,
        verdict=verdict,
        refusal_code=refusal_code,
        semantic_sha256=None,
    )
    if verdict is CommitAuthorityVerdict.INFRASTRUCTURE_REFUSAL:
        return result
    return _with_semantic_digest(result)


def _runtime_matches(actual: RuntimeFacts, expected: RuntimeContract) -> bool:
    return (
        actual.implementation == expected.implementation
        and actual.python_version == expected.python_version
        and actual.os_family == expected.os_family
        and actual.architecture == expected.architecture
    )


def _execute(
    request: CommitAuthoritativeRequest,
    *,
    limits: CommitAuthoritativeLimits,
    reader_limits: ReaderLimits,
    snapshot_reader: SnapshotReader,
    snapshot_materializer: SnapshotMaterializer,
    scanner_runner: ScannerRunner,
    runtime_facts_provider: RuntimeFactsProvider,
) -> CommitAuthoritativeResult:
    repository, policy_root, scratch_root = _validate_request(request)
    try:
        bundle = load_policy_bundle(
            policy_root,
            request.expected_policy_bundle_sha256,
            policy_selector=request.policy_selector,
        )
    except PolicyBundleRefused as error:
        raise WorkerRefused(str(error)) from None
    if not _runtime_matches(runtime_facts_provider(), bundle.runtime):
        raise WorkerRefused("runtime_mismatch")
    artifact = _artifact_bytes(request.scanner_artifact, bundle.scanner_artifact_sha256)
    try:
        snapshot = snapshot_reader(repository, request.head_oid, limits=reader_limits)
    except ReaderRefused:
        raise WorkerRefused("head_reader_refused") from None
    if snapshot.commit_oid != request.head_oid:
        raise WorkerRefused("invalid_snapshot")
    files = _snapshot_files(snapshot)
    try:
        _admit_protected(files, bundle)
        _admit_policy_bundle_mirror(files, bundle)
        _admit_suppressions(files, bundle)
        inventory = _coverage_inventory(files, bundle)
    except PolicyAdmissionRefused as error:
        return _result(
            request,
            CommitAuthorityVerdict.POLICY_ADMISSION_FAILURE,
            bundle=bundle,
            files_total=len(files),
            refusal_code=error.code,
        )

    try:
        with _private_directory(scratch_root) as control:
            wheel_path = control / "repo_sentinel_lite-0.8.1-py3-none-any.whl"
            baseline_path = control / "baseline.json"
            policy_exclusions_path = control / "policy-exclusions.json"
            report_path = control / "report.json"
            _write_private(wheel_path, artifact)
            _write_private(baseline_path, bundle.baseline)
            _write_private(
                policy_exclusions_path,
                (
                    json.dumps(
                        list(inventory.policy_excluded_paths),
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8"),
            )
            with snapshot_materializer(
                repository,
                request.head_oid,
                scratch_root,
                limits=reader_limits,
            ) as materialized:
                if materialized.snapshot != snapshot:
                    raise WorkerRefused("head_snapshot_mismatch")
                materialized_root = _regular_directory(materialized.root)
                if (
                    materialized_root == scratch_root
                    or not materialized_root.is_relative_to(scratch_root)
                    or _overlaps(materialized_root, control)
                    or _overlaps(materialized_root, repository)
                    or _overlaps(materialized_root, policy_root)
                ):
                    raise WorkerRefused("unsafe_root_layout")
                _verify_materialized_controls(materialized_root, bundle)
                execution = scanner_runner(
                    ScannerInvocation(
                        materialized_root,
                        wheel_path,
                        baseline_path,
                        policy_exclusions_path,
                        report_path,
                        control,
                        limits.scanner_timeout_seconds,
                        limits.max_capture_bytes,
                        bundle.scanner_version,
                    )
                )
                report, verdict = _validated_report(
                    report_path,
                    execution,
                    limits,
                    files,
                    inventory,
                    bundle,
                )
    except MaterializationRefused as error:
        code = (
            "cleanup_failed"
            if str(error) == "cleanup_failed"
            else "head_materialization_refused"
        )
        raise WorkerRefused(code) from None
    return _result(
        request,
        verdict,
        bundle=bundle,
        files_total=len(files),
        inventory=inventory,
        report=report,
    )


def run_commit_authoritative(
    request: CommitAuthoritativeRequest,
    *,
    limits: CommitAuthoritativeLimits | None = None,
    reader_limits: ReaderLimits | None = None,
    snapshot_reader: SnapshotReader = read_snapshot,
    snapshot_materializer: SnapshotMaterializer = materialized_snapshot,
    scanner_runner: ScannerRunner = _run_trusted_scanner,
    runtime_facts_provider: RuntimeFactsProvider = current_runtime_facts,
) -> CommitAuthoritativeResult:
    """Evaluate P_v(H) without publishing a GitHub status."""

    try:
        return _execute(
            request,
            limits=limits or CommitAuthoritativeLimits(),
            reader_limits=reader_limits or ReaderLimits(),
            snapshot_reader=snapshot_reader,
            snapshot_materializer=snapshot_materializer,
            scanner_runner=scanner_runner,
            runtime_facts_provider=runtime_facts_provider,
        )
    except WorkerRefused as error:
        return _result(
            request,
            CommitAuthorityVerdict.INFRASTRUCTURE_REFUSAL,
            refusal_code=error.code,
        )
    except Exception:  # noqa: BLE001
        return _result(
            request,
            CommitAuthorityVerdict.INFRASTRUCTURE_REFUSAL,
            refusal_code="unexpected_failure",
        )


def result_dict(result: CommitAuthoritativeResult) -> dict[str, object]:
    rendered = _semantic_payload(result)
    rendered["semantic_sha256"] = result.semantic_sha256
    return rendered


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-id", type=int, required=True)
    parser.add_argument("--head-oid", required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--policy-bundle", type=Path, required=True)
    parser.add_argument("--policy-bundle-sha256", required=True)
    parser.add_argument("--policy-selector", required=True)
    parser.add_argument("--scanner-artifact", type=Path, required=True)
    parser.add_argument("--scratch-root", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    result = run_commit_authoritative(
        CommitAuthoritativeRequest(
            args.repository_id,
            args.head_oid,
            args.repository,
            args.policy_bundle,
            args.policy_bundle_sha256,
            args.policy_selector,
            args.scanner_artifact,
            args.scratch_root,
        )
    )
    print(json.dumps(result_dict(result), indent=2, sort_keys=True))
    if result.verdict is CommitAuthorityVerdict.PASS:
        return 0
    if result.verdict is CommitAuthorityVerdict.INFRASTRUCTURE_REFUSAL:
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CommitAuthoritativeLimits",
    "CommitAuthoritativeRequest",
    "CommitAuthoritativeResult",
    "CommitAuthorityVerdict",
    "CoverageInventory",
    "RuntimeFacts",
    "ScannerExecution",
    "ScannerInvocation",
    "current_runtime_facts",
    "result_dict",
    "run_commit_authoritative",
]
