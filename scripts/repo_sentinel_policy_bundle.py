"""Build and verify immutable policy bundles for commit authority."""

from __future__ import annotations

import argparse
import codecs
import fnmatch
import hashlib
import json
import re
import stat
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from repo_sentinel_reader import SnapshotFile

POLICY_SCHEMA_VERSION = 1
POLICY_EPOCH = "repo-sentinel-authority-v1"
WORKER_POLICY_VERSION = "commit-authoritative-v1"
PORTABLE_PATH_POLICY_VERSION = "portable-v1"
SCANNER_DISTRIBUTION = "repo-sentinel-lite"
SCANNER_VERSION = "0.8.1"
SCANNER_WHEEL_SHA256 = (
    "0a949a4d00c6e6ae37eba60a6cb74e4e15bc3ec5fce2f1d4c99aa0ef309b36e3"
)

BUNDLE_FILENAMES = frozenset(
    {
        "baseline.json",
        "coverage-policy.json",
        "dependencies.json",
        "epoch.json",
        "protected-manifest.json",
        "scanner-config.toml",
        "suppression-manifest.json",
    }
)
POLICY_BUNDLE_MIRROR_ROOT = "policy/repo-sentinel-authority/v1/"
_COMPONENT_FILENAMES = BUNDLE_FILENAMES - {"epoch.json"}
_BUNDLE_DOMAIN = b"repo-sentinel-authority-policy-bundle-v1\0"
_MAX_BUNDLE_FILE_BYTES = 2 * 1024 * 1024
_MAX_BUNDLE_BYTES = 8 * 1024 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}")
_SUPPRESSION = re.compile(
    r"repo-sentinel:\s*allow(?:\s+(?P<rules>[A-Za-z0-9_.\-, ]+))?",
    re.IGNORECASE,
)
_TEXT_ENCODINGS = ("utf-8", "utf-8-sig", "utf-16", "cp1252")
_TEXT_SAMPLE_SIZE = 8192
_TEXT_CONTROL_BYTES = {7, 8, 9, 10, 12, 13, 27}
_BYTE_ORDER_MARKS = (
    codecs.BOM_UTF8,
    codecs.BOM_UTF16_BE,
    codecs.BOM_UTF16_LE,
    codecs.BOM_UTF32_BE,
    codecs.BOM_UTF32_LE,
)
_ASCII_CASE = {
    codepoint: codepoint + (ord("a") - ord("A"))
    for codepoint in range(ord("A"), ord("Z") + 1)
}

DEFAULT_IGNORE_GLOBS = (
    ".reposentinel-baseline.json",
    "%TEMP%",
    "*.egg-info",
    ".coverage",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    ".venv-*",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "dist-*",
    "htmlcov",
    "node_modules",
    "venv",
)
DEFAULT_MAX_TEXT_FILE_SIZE = 1_048_576
DEFAULT_REQUIRED_FILES = ("README.md", "LICENSE", ".gitignore")
PROTECTED_NAMESPACES = (".github/actions/", ".github/workflows/")
MANDATORY_PROTECTED_PATHS = frozenset(
    {
        ".reposentinel.toml",
        ".reposentinel-baseline.json",
        "scripts/repo_sentinel_gate.py",
        "scripts/repo_sentinel_acquire.py",
        "scripts/repo_sentinel_reader.py",
        "scripts/repo_sentinel_materialize.py",
        "scripts/repo_sentinel_authoritative.py",
        "scripts/repo_sentinel_commit_authoritative.py",
        "scripts/repo_sentinel_policy_bundle.py",
        "scripts/test_repo_sentinel_integration.py",
    }
)
EXCLUSION_REASONS = frozenset(
    {"config_ignore", "binary", "oversize", "unsupported_encoding"}
)


class PolicyBundleRefused(ValueError):
    """Reject malformed trusted policy input with a fixed code."""


@dataclass(frozen=True, slots=True)
class PolicyEntry:
    path: str
    mode: str
    sha256: str
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class RuntimeContract:
    implementation: str
    python_version: str
    os_family: str
    architecture: str


@dataclass(frozen=True, slots=True)
class VerifiedPolicyBundle:
    schema_version: int
    policy_epoch: str
    bundle_sha256: str
    worker_policy_version: str
    portable_path_policy_version: str
    scanner_distribution: str
    scanner_version: str
    scanner_artifact_sha256: str
    runtime: RuntimeContract
    scanner_config: bytes = field(repr=False)
    baseline: bytes = field(repr=False)
    bundle_files: tuple[tuple[str, bytes], ...] = field(repr=False)
    protected_manifest_sha256: str
    suppression_manifest_sha256: str
    coverage_policy_sha256: str
    dependency_closure_sha256: str
    protected_entries: tuple[PolicyEntry, ...] = field(repr=False)
    protected_namespaces: tuple[str, ...]
    suppression_entries: tuple[PolicyEntry, ...] = field(repr=False)
    coverage_entries: tuple[PolicyEntry, ...] = field(repr=False)
    effective_ignore_globs: tuple[str, ...] = field(repr=False)
    max_text_file_size: int
    required_files: tuple[str, ...]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def portable_v1_alias(value: str) -> str:
    return value.translate(_ASCII_CASE)


def _is_regular(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    reparse = getattr(info, "st_file_attributes", 0) & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
    )
    return not reparse and stat.S_ISREG(info.st_mode)


def _read_bundle(root: Path) -> dict[str, bytes]:
    try:
        info = root.lstat()
        reparse = getattr(info, "st_file_attributes", 0) & getattr(
            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
        )
        if reparse or not stat.S_ISDIR(info.st_mode):
            raise PolicyBundleRefused("policy_bundle_invalid")
        entries = tuple(root.iterdir())
    except PolicyBundleRefused:
        raise
    except OSError:
        raise PolicyBundleRefused("policy_bundle_invalid") from None
    names = {entry.name for entry in entries}
    if names != BUNDLE_FILENAMES or len(entries) != len(BUNDLE_FILENAMES):
        raise PolicyBundleRefused("policy_bundle_invalid")
    result: dict[str, bytes] = {}
    total = 0
    for entry in entries:
        if not _is_regular(entry):
            raise PolicyBundleRefused("policy_bundle_invalid")
        try:
            data = entry.read_bytes()
        except OSError:
            raise PolicyBundleRefused("policy_bundle_invalid") from None
        if len(data) > _MAX_BUNDLE_FILE_BYTES:
            raise PolicyBundleRefused("policy_bundle_invalid")
        total += len(data)
        if total > _MAX_BUNDLE_BYTES:
            raise PolicyBundleRefused("policy_bundle_invalid")
        result[entry.name] = data
    return result


def compute_bundle_sha256(files: dict[str, bytes]) -> str:
    if set(files) != BUNDLE_FILENAMES:
        raise PolicyBundleRefused("policy_bundle_invalid")
    digest = hashlib.sha256()
    digest.update(_BUNDLE_DOMAIN)
    for name in sorted(files):
        encoded = name.encode("utf-8")
        data = files[name]
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(bytes.fromhex(sha256_bytes(data)))
    return digest.hexdigest()


def bundle_sha256(root: Path) -> str:
    return compute_bundle_sha256(_read_bundle(root))


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON value")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _json_object(data: bytes) -> dict[str, Any]:
    try:
        text = data.decode("utf-8", errors="strict")
        if text.encode("utf-8") != data:
            raise ValueError("non-round-tripping UTF-8")
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise PolicyBundleRefused("policy_bundle_invalid") from None
    if not isinstance(value, dict):
        raise PolicyBundleRefused("policy_bundle_invalid")
    return value


def _exact_keys(value: dict[str, Any], keys: set[str]) -> None:
    if set(value) != keys:
        raise PolicyBundleRefused("policy_bundle_invalid")


def _digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise PolicyBundleRefused("policy_bundle_invalid")
    return value


def _logical_path(value: object, *, directory: bool = False) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyBundleRefused("policy_bundle_invalid")
    candidate = value[:-1] if directory and value.endswith("/") else value
    if directory and candidate == value:
        raise PolicyBundleRefused("policy_bundle_invalid")
    components = candidate.split("/")
    if any(
        not item
        or item in (".", "..")
        or any(
            ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F
            for character in item
        )
        for item in components
    ):
        raise PolicyBundleRefused("policy_bundle_invalid")
    try:
        encoded = candidate.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise PolicyBundleRefused("policy_bundle_invalid") from None
    if encoded.decode("utf-8", errors="strict") != candidate:
        raise PolicyBundleRefused("policy_bundle_invalid")
    return value


def _policy_entries(value: object, *, reasons: bool) -> tuple[PolicyEntry, ...]:
    if not isinstance(value, list):
        raise PolicyBundleRefused("policy_bundle_invalid")
    entries: list[PolicyEntry] = []
    for raw in value:
        if not isinstance(raw, dict):
            raise PolicyBundleRefused("policy_bundle_invalid")
        keys = (
            {"path", "mode", "sha256", "reason"}
            if reasons
            else {
                "path",
                "mode",
                "sha256",
            }
        )
        _exact_keys(raw, keys)
        path = _logical_path(raw["path"])
        mode = raw["mode"]
        if mode not in ("100644", "100755"):
            raise PolicyBundleRefused("policy_bundle_invalid")
        reason = raw.get("reason")
        if reasons and reason not in EXCLUSION_REASONS:
            raise PolicyBundleRefused("policy_bundle_invalid")
        entries.append(PolicyEntry(path, mode, _digest(raw["sha256"]), reason))
    paths = [entry.path for entry in entries]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise PolicyBundleRefused("policy_bundle_invalid")
    aliases = [portable_v1_alias(path) for path in paths]
    if len(aliases) != len(set(aliases)):
        raise PolicyBundleRefused("policy_bundle_invalid")
    return tuple(entries)


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyBundleRefused("policy_bundle_invalid")
    return tuple(value)


def _config_contract(data: bytes) -> tuple[tuple[str, ...], int, tuple[str, ...]]:
    try:
        decoded = data.decode("utf-8", errors="strict")
        parsed = tomllib.loads(decoded)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise PolicyBundleRefused("policy_bundle_invalid") from None
    configured = parsed.get("ignore_globs", [])
    if not isinstance(configured, list) or not all(
        isinstance(item, str) for item in configured
    ):
        raise PolicyBundleRefused("policy_bundle_invalid")
    max_size = parsed.get("max_text_file_size", DEFAULT_MAX_TEXT_FILE_SIZE)
    if isinstance(max_size, bool) or not isinstance(max_size, int) or max_size < 0:
        raise PolicyBundleRefused("policy_bundle_invalid")
    required = parsed.get("required_files", list(DEFAULT_REQUIRED_FILES))
    if not isinstance(required, list) or not all(
        isinstance(item, str) for item in required
    ):
        raise PolicyBundleRefused("policy_bundle_invalid")
    effective = tuple(dict.fromkeys((*DEFAULT_IGNORE_GLOBS, *configured)))
    return effective, max_size, tuple(required)


def load_policy_bundle(root: Path, expected_sha256: str) -> VerifiedPolicyBundle:
    if _DIGEST.fullmatch(expected_sha256) is None:
        raise PolicyBundleRefused("policy_bundle_invalid")
    files = _read_bundle(root)
    actual_bundle_sha256 = compute_bundle_sha256(files)
    if actual_bundle_sha256 != expected_sha256:
        raise PolicyBundleRefused("policy_bundle_mismatch")

    epoch = _json_object(files["epoch.json"])
    _exact_keys(
        epoch,
        {
            "schema_version",
            "policy_epoch",
            "semantic_worker_policy_version",
            "portable_path_policy_version",
            "scanner",
            "runtime",
            "component_sha256",
        },
    )
    if epoch["schema_version"] != POLICY_SCHEMA_VERSION:
        raise PolicyBundleRefused("policy_schema_unsupported")
    scanner = epoch["scanner"]
    runtime = epoch["runtime"]
    components = epoch["component_sha256"]
    if not isinstance(scanner, dict) or not isinstance(runtime, dict):
        raise PolicyBundleRefused("policy_bundle_invalid")
    if not isinstance(components, dict):
        raise PolicyBundleRefused("policy_bundle_invalid")
    _exact_keys(scanner, {"distribution", "version", "artifact_sha256"})
    _exact_keys(
        runtime,
        {"implementation", "python_version", "os_family", "architecture"},
    )
    if set(components) != _COMPONENT_FILENAMES:
        raise PolicyBundleRefused("policy_bundle_invalid")
    for name in _COMPONENT_FILENAMES:
        if _digest(components[name]) != sha256_bytes(files[name]):
            raise PolicyBundleRefused("policy_bundle_invalid")

    dependencies = _json_object(files["dependencies.json"])
    _exact_keys(dependencies, {"schema_version", "scanner", "runtime_dependencies"})
    dependency_scanner = dependencies["scanner"]
    if dependencies["schema_version"] != POLICY_SCHEMA_VERSION or not isinstance(
        dependency_scanner, dict
    ):
        raise PolicyBundleRefused("policy_bundle_invalid")
    _exact_keys(dependency_scanner, {"distribution", "version", "wheel_sha256"})
    if dependencies["runtime_dependencies"] != []:
        raise PolicyBundleRefused("policy_bundle_invalid")
    if (
        dependency_scanner["distribution"] != scanner["distribution"]
        or dependency_scanner["version"] != scanner["version"]
        or dependency_scanner["wheel_sha256"] != scanner["artifact_sha256"]
    ):
        raise PolicyBundleRefused("policy_bundle_invalid")

    protected = _json_object(files["protected-manifest.json"])
    _exact_keys(protected, {"schema_version", "namespaces", "entries"})
    namespaces = _string_tuple(protected["namespaces"])
    if protected["schema_version"] != POLICY_SCHEMA_VERSION or namespaces != tuple(
        sorted(PROTECTED_NAMESPACES)
    ):
        raise PolicyBundleRefused("policy_bundle_invalid")
    for namespace in namespaces:
        _logical_path(namespace, directory=True)
    protected_entries = _policy_entries(protected["entries"], reasons=False)
    if not MANDATORY_PROTECTED_PATHS.issubset(
        {entry.path for entry in protected_entries}
    ):
        raise PolicyBundleRefused("policy_bundle_invalid")

    suppressions = _json_object(files["suppression-manifest.json"])
    _exact_keys(suppressions, {"schema_version", "entries"})
    if suppressions["schema_version"] != POLICY_SCHEMA_VERSION:
        raise PolicyBundleRefused("policy_bundle_invalid")
    suppression_entries = _policy_entries(suppressions["entries"], reasons=False)

    coverage = _json_object(files["coverage-policy.json"])
    _exact_keys(
        coverage,
        {
            "schema_version",
            "effective_ignore_globs",
            "max_text_file_size",
            "approved_exclusions",
        },
    )
    if coverage["schema_version"] != POLICY_SCHEMA_VERSION:
        raise PolicyBundleRefused("policy_bundle_invalid")
    effective, max_size, required = _config_contract(files["scanner-config.toml"])
    if (
        _string_tuple(coverage["effective_ignore_globs"]) != effective
        or coverage["max_text_file_size"] != max_size
    ):
        raise PolicyBundleRefused("policy_bundle_invalid")
    coverage_entries = _policy_entries(coverage["approved_exclusions"], reasons=True)

    if not all(isinstance(runtime[key], str) for key in runtime):
        raise PolicyBundleRefused("policy_bundle_invalid")
    runtime_contract = RuntimeContract(
        implementation=runtime["implementation"],
        python_version=runtime["python_version"],
        os_family=runtime["os_family"],
        architecture=runtime["architecture"],
    )
    if any(
        not value
        for value in (
            runtime_contract.implementation,
            runtime_contract.python_version,
            runtime_contract.os_family,
            runtime_contract.architecture,
        )
    ):
        raise PolicyBundleRefused("policy_bundle_invalid")
    if (
        epoch["policy_epoch"] != POLICY_EPOCH
        or epoch["semantic_worker_policy_version"] != WORKER_POLICY_VERSION
        or epoch["portable_path_policy_version"] != PORTABLE_PATH_POLICY_VERSION
        or scanner["distribution"] != SCANNER_DISTRIBUTION
        or scanner["version"] != SCANNER_VERSION
        or scanner["artifact_sha256"] != SCANNER_WHEEL_SHA256
    ):
        raise PolicyBundleRefused("policy_schema_unsupported")

    _json_object(files["baseline.json"])

    return VerifiedPolicyBundle(
        schema_version=POLICY_SCHEMA_VERSION,
        policy_epoch=POLICY_EPOCH,
        bundle_sha256=actual_bundle_sha256,
        worker_policy_version=WORKER_POLICY_VERSION,
        portable_path_policy_version=PORTABLE_PATH_POLICY_VERSION,
        scanner_distribution=str(scanner["distribution"]),
        scanner_version=str(scanner["version"]),
        scanner_artifact_sha256=_digest(scanner["artifact_sha256"]),
        runtime=runtime_contract,
        scanner_config=files["scanner-config.toml"],
        baseline=files["baseline.json"],
        bundle_files=tuple(sorted(files.items())),
        protected_manifest_sha256=sha256_bytes(files["protected-manifest.json"]),
        suppression_manifest_sha256=sha256_bytes(files["suppression-manifest.json"]),
        coverage_policy_sha256=sha256_bytes(files["coverage-policy.json"]),
        dependency_closure_sha256=sha256_bytes(files["dependencies.json"]),
        protected_entries=protected_entries,
        protected_namespaces=namespaces,
        suppression_entries=suppression_entries,
        coverage_entries=coverage_entries,
        effective_ignore_globs=effective,
        max_text_file_size=max_size,
        required_files=required,
    )


def contains_inline_suppression(data: bytes) -> bool:
    for encoding in _TEXT_ENCODINGS:
        try:
            text = data.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
        if _SUPPRESSION.search(text) is not None:
            return True
    return False


def _normalize_path(value: str) -> str:
    return PurePosixPath(value.replace("\\", "/")).as_posix()


def _matches_glob(path: str, pattern: str) -> bool:
    normalized = _normalize_path(path)
    filename = PurePosixPath(normalized).name
    folded_pattern = _normalize_path(pattern).casefold()
    return fnmatch.fnmatchcase(
        normalized.casefold(), folded_pattern
    ) or fnmatch.fnmatchcase(filename.casefold(), folded_pattern)


def is_config_ignored(path: str, patterns: tuple[str, ...]) -> bool:
    if any(_matches_glob(path, pattern) for pattern in patterns):
        return True
    components = path.split("/")
    for depth in range(1, len(components)):
        directory = "/".join(components[:depth])
        if directory.casefold() == ".git":
            return True
        for pattern in patterns:
            normalized = _normalize_path(pattern).casefold()
            if any(
                normalized.endswith(suffix)
                and directory.casefold() == normalized[: -len(suffix)]
                for suffix in ("/**/*", "/**", "/*")
            ) or _matches_glob(directory, pattern):
                return True
    return False


def scanner_exclusion_reason(data: bytes, max_size: int) -> str | None:
    if len(data) > max_size:
        return "oversize"
    sample = data[:_TEXT_SAMPLE_SIZE]
    if sample and not any(sample.startswith(mark) for mark in _BYTE_ORDER_MARKS):
        if b"\x00" in sample:
            return "binary"
        try:
            sample.decode("utf-8")
        except UnicodeDecodeError:
            controls = sum(
                1 for byte in sample if byte < 32 and byte not in _TEXT_CONTROL_BYTES
            )
            if controls / len(sample) >= 0.30:
                return "binary"
    for encoding in _TEXT_ENCODINGS:
        try:
            data.decode(encoding)
            return None
        except UnicodeDecodeError:
            continue
    return "unsupported_encoding"


def _entry(item: SnapshotFile, reason: str | None = None) -> PolicyEntry:
    return PolicyEntry(item.path, item.mode, sha256_bytes(item.data), reason)


def _entry_dict(entry: PolicyEntry) -> dict[str, str]:
    result = {"path": entry.path, "mode": entry.mode, "sha256": entry.sha256}
    if entry.reason is not None:
        result["reason"] = entry.reason
    return result


def _render(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def build_policy_bundle(
    files: tuple[SnapshotFile, ...],
    root: Path,
    runtime: RuntimeContract,
    *,
    scanner_artifact_sha256: str = SCANNER_WHEEL_SHA256,
) -> str:
    """Generate a candidate bundle from an explicitly staged repository state."""

    mirror_paths = {f"{POLICY_BUNDLE_MIRROR_ROOT}{name}" for name in BUNDLE_FILENAMES}
    mirror_alias_root = portable_v1_alias(POLICY_BUNDLE_MIRROR_ROOT)
    if any(
        portable_v1_alias(item.path).startswith(mirror_alias_root)
        and item.path not in mirror_paths
        for item in files
    ):
        raise PolicyBundleRefused("policy_source_invalid")
    source_files = tuple(item for item in files if item.path not in mirror_paths)
    by_path = {item.path: item for item in source_files}
    if len(by_path) != len(source_files) or not MANDATORY_PROTECTED_PATHS.issubset(
        by_path
    ):
        raise PolicyBundleRefused("policy_source_invalid")
    scanner_config = by_path[".reposentinel.toml"].data
    baseline = by_path[".reposentinel-baseline.json"].data
    effective, max_size, _required = _config_contract(scanner_config)

    protected_paths = sorted(
        MANDATORY_PROTECTED_PATHS
        | {path for path in by_path if path.startswith(PROTECTED_NAMESPACES)}
    )
    protected_entries = [_entry(by_path[path]) for path in protected_paths]
    suppression_entries = [
        _entry(item)
        for item in sorted(source_files, key=lambda candidate: candidate.path)
        if contains_inline_suppression(item.data)
    ]
    coverage_entries: list[PolicyEntry] = []
    for item in sorted(source_files, key=lambda candidate: candidate.path):
        reason = (
            "config_ignore"
            if is_config_ignored(item.path, effective)
            else scanner_exclusion_reason(item.data, max_size)
        )
        if reason is not None:
            coverage_entries.append(_entry(item, reason))

    components: dict[str, bytes] = {
        "scanner-config.toml": scanner_config,
        "baseline.json": baseline,
        "protected-manifest.json": _render(
            {
                "schema_version": POLICY_SCHEMA_VERSION,
                "namespaces": sorted(PROTECTED_NAMESPACES),
                "entries": [_entry_dict(entry) for entry in protected_entries],
            }
        ),
        "suppression-manifest.json": _render(
            {
                "schema_version": POLICY_SCHEMA_VERSION,
                "entries": [_entry_dict(entry) for entry in suppression_entries],
            }
        ),
        "coverage-policy.json": _render(
            {
                "schema_version": POLICY_SCHEMA_VERSION,
                "effective_ignore_globs": list(effective),
                "max_text_file_size": max_size,
                "approved_exclusions": [
                    _entry_dict(entry) for entry in coverage_entries
                ],
            }
        ),
        "dependencies.json": _render(
            {
                "schema_version": POLICY_SCHEMA_VERSION,
                "scanner": {
                    "distribution": SCANNER_DISTRIBUTION,
                    "version": SCANNER_VERSION,
                    "wheel_sha256": scanner_artifact_sha256,
                },
                "runtime_dependencies": [],
            }
        ),
    }
    epoch = {
        "schema_version": POLICY_SCHEMA_VERSION,
        "policy_epoch": POLICY_EPOCH,
        "semantic_worker_policy_version": WORKER_POLICY_VERSION,
        "portable_path_policy_version": PORTABLE_PATH_POLICY_VERSION,
        "scanner": {
            "distribution": SCANNER_DISTRIBUTION,
            "version": SCANNER_VERSION,
            "artifact_sha256": scanner_artifact_sha256,
        },
        "runtime": {
            "implementation": runtime.implementation,
            "python_version": runtime.python_version,
            "os_family": runtime.os_family,
            "architecture": runtime.architecture,
        },
        "component_sha256": {
            name: sha256_bytes(data) for name, data in sorted(components.items())
        },
    }
    components["epoch.json"] = _render(epoch)

    try:
        root.mkdir(parents=True, exist_ok=True)
        existing = {entry.name for entry in root.iterdir()}
        if existing - BUNDLE_FILENAMES:
            raise PolicyBundleRefused("policy_bundle_invalid")
        for name, data in components.items():
            (root / name).write_bytes(data)
    except PolicyBundleRefused:
        raise
    except OSError:
        raise PolicyBundleRefused("policy_bundle_invalid") from None
    return compute_bundle_sha256(components)


def _staged_files(repository: Path) -> tuple[SnapshotFile, ...]:
    try:
        listing = subprocess.run(
            ["git", "ls-files", "--stage", "-z"],
            cwd=repository,
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        raise PolicyBundleRefused("policy_source_invalid") from None
    files: list[SnapshotFile] = []
    for record in listing.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, oid, stage = metadata.split(b" ", 2)
            path = raw_path.decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError):
            raise PolicyBundleRefused("policy_source_invalid") from None
        if stage != b"0" or mode not in (b"100644", b"100755"):
            raise PolicyBundleRefused("policy_source_invalid")
        try:
            data = subprocess.run(
                ["git", "cat-file", "blob", oid.decode("ascii")],
                cwd=repository,
                check=True,
                capture_output=True,
            ).stdout
        except (OSError, UnicodeDecodeError, subprocess.CalledProcessError):
            raise PolicyBundleRefused("policy_source_invalid") from None
        files.append(
            SnapshotFile(path, mode.decode("ascii"), oid.decode("ascii"), data)
        )
    return tuple(sorted(files, key=lambda item: item.path))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--repository", type=Path, required=True)
    build.add_argument("--bundle", type=Path, required=True)
    build.add_argument("--python-version", required=True)
    build.add_argument("--os-family", required=True)
    build.add_argument("--architecture", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--expected-sha256")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "build":
            runtime = RuntimeContract(
                sys.implementation.name,
                args.python_version,
                args.os_family,
                args.architecture,
            )
            digest = build_policy_bundle(
                _staged_files(args.repository.resolve()),
                args.bundle.resolve(),
                runtime,
            )
        else:
            digest = bundle_sha256(args.bundle.resolve())
            expected = args.expected_sha256 or digest
            load_policy_bundle(args.bundle.resolve(), expected)
    except PolicyBundleRefused as error:
        print(str(error), file=sys.stderr)
        return 2
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "BUNDLE_FILENAMES",
    "MANDATORY_PROTECTED_PATHS",
    "POLICY_BUNDLE_MIRROR_ROOT",
    "POLICY_EPOCH",
    "POLICY_SCHEMA_VERSION",
    "PolicyBundleRefused",
    "PolicyEntry",
    "RuntimeContract",
    "SCANNER_DISTRIBUTION",
    "SCANNER_VERSION",
    "SCANNER_WHEEL_SHA256",
    "VerifiedPolicyBundle",
    "build_policy_bundle",
    "bundle_sha256",
    "contains_inline_suppression",
    "is_config_ignored",
    "load_policy_bundle",
    "portable_v1_alias",
    "scanner_exclusion_reason",
    "sha256_bytes",
]
