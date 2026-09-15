"""Contract tests for commit-intrinsic Repo Sentinel authority."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import sys
import tempfile
import unittest
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import repo_sentinel_commit_authoritative as authoritative  # noqa: E402
import repo_sentinel_policy_bundle as policy  # noqa: E402
from repo_sentinel_materialize import MaterializedSnapshot  # noqa: E402
from repo_sentinel_reader import Snapshot, SnapshotFile  # noqa: E402

HEAD_OID = "b" * 40
RUNTIME = policy.RuntimeContract("cpython", "3.12.3", "Linux", "x86_64")
RUNTIME_FACTS = authoritative.RuntimeFacts("cpython", "3.12.3", "Linux", "x86_64")
EMPTY_BASELINE = b'{"findings": [], "schema_version": 1}\n'


def snapshot_file(
    path: str,
    data: bytes = b"safe fixture\n",
    mode: str = "100644",
) -> SnapshotFile:
    oid = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    return SnapshotFile(path, mode, oid, data)


def minimum_files() -> tuple[SnapshotFile, ...]:
    files = [
        snapshot_file("README.md"),
        snapshot_file("LICENSE"),
        snapshot_file(".gitignore", b"\n"),
        snapshot_file(".reposentinel.toml", b"ignore_globs = []\n"),
        snapshot_file(".reposentinel-baseline.json", EMPTY_BASELINE),
        snapshot_file(".github/workflows/check.yml"),
        snapshot_file(
            "notes/approved.txt",
            b"fixture # repo-sentinel: allow secret.high_entropy\n",
        ),
    ]
    existing = {item.path for item in files}
    files.extend(
        snapshot_file(path)
        for path in policy.MANDATORY_PROTECTED_PATHS
        if path not in existing
    )
    unique = {item.path: item for item in files}
    return tuple(sorted(unique.values(), key=lambda item: item.path))


def replace_file(
    files: tuple[SnapshotFile, ...],
    path: str,
    *,
    data: bytes | None = None,
    mode: str | None = None,
) -> tuple[SnapshotFile, ...]:
    replaced = []
    for item in files:
        if item.path == path:
            replaced.append(
                snapshot_file(
                    path,
                    item.data if data is None else data,
                    item.mode if mode is None else mode,
                )
            )
        else:
            replaced.append(item)
    return tuple(replaced)


def without(files: tuple[SnapshotFile, ...], path: str) -> tuple[SnapshotFile, ...]:
    return tuple(item for item in files if item.path != path)


def with_file(
    files: tuple[SnapshotFile, ...], item: SnapshotFile
) -> tuple[SnapshotFile, ...]:
    return tuple(sorted((*files, item), key=lambda candidate: candidate.path))


class Harness:
    def __init__(
        self,
        files: tuple[SnapshotFile, ...] | None = None,
        *,
        trusted_baseline: bytes | None = None,
    ) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="commit-authority-test-")
        self.root = Path(self._temporary.name)
        self.repository = self.root / "repository"
        self.policy_root = self.root / "trusted-policy"
        self.scratch = self.root / "scratch"
        self.artifact = self.root / "scanner.whl"
        for directory in (self.repository, self.scratch):
            directory.mkdir()
        requested_files = files or minimum_files()
        source_files = tuple(
            item
            for item in requested_files
            if not item.path.startswith(policy.POLICY_BUNDLE_MIRROR_ROOT)
        )
        self.artifact.write_bytes(b"test wheel bytes")
        self.bundle_digest = policy.build_policy_bundle(
            source_files, self.policy_root, RUNTIME
        )
        if trusted_baseline is not None:
            # Preserve the target baseline in the protected manifest while
            # giving the independently authenticated bundle different bytes.
            (self.policy_root / "baseline.json").write_bytes(trusted_baseline)
            epoch_path = self.policy_root / "epoch.json"
            epoch = json.loads(epoch_path.read_text(encoding="utf-8"))
            epoch["component_sha256"]["baseline.json"] = policy.sha256_bytes(
                trusted_baseline
            )
            epoch_path.write_bytes(policy._render(epoch))
            self.bundle_digest = policy.bundle_sha256(self.policy_root)
        self.bundle = policy.load_policy_bundle(self.policy_root, self.bundle_digest)
        mirror_files = tuple(
            snapshot_file(
                f"{policy.POLICY_BUNDLE_MIRROR_ROOT}{name}",
                data,
            )
            for name, data in self.bundle.bundle_files
        )
        self.files = tuple(
            sorted((*source_files, *mirror_files), key=lambda item: item.path)
        )
        self.snapshot = Snapshot(HEAD_OID, "c" * 40, self.files)
        self.request = authoritative.CommitAuthoritativeRequest(
            123456,
            HEAD_OID,
            self.repository,
            self.policy_root,
            self.bundle_digest,
            self.artifact,
            self.scratch,
        )
        self.scanner_calls = 0
        self.materializer_calls = 0

    def cleanup(self) -> None:
        self._temporary.cleanup()

    def reader(self, *_args: object, **_kwargs: object) -> Snapshot:
        return self.snapshot

    def with_policy_mirror(
        self, files: tuple[SnapshotFile, ...]
    ) -> tuple[SnapshotFile, ...]:
        mirror = tuple(
            item
            for item in self.files
            if item.path.startswith(policy.POLICY_BUNDLE_MIRROR_ROOT)
        )
        return tuple(sorted((*files, *mirror), key=lambda item: item.path))

    @contextmanager
    def materializer(
        self, *_args: object, **_kwargs: object
    ) -> Iterator[MaterializedSnapshot]:
        self.materializer_calls += 1
        with tempfile.TemporaryDirectory(dir=self.scratch) as temporary:
            root = Path(temporary) / "data"
            root.mkdir()
            for item in self.snapshot.files:
                target = root.joinpath(*item.path.split("/"))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(item.data)
            yield MaterializedSnapshot(self.snapshot, root)

    def report(self) -> dict[str, object]:
        files = {item.path: item for item in self.snapshot.files}
        inventory = authoritative._coverage_inventory(files, self.bundle)
        skips = sorted(
            (
                {"path": path, "reason": reason}
                for path, reason in inventory.scanner_skips
            ),
            key=lambda item: (
                str(item["path"]).casefold(),
                str(item["path"]),
                str(item["reason"]),
            ),
        )
        counts = {
            reason: sum(1 for item in skips if item["reason"] == reason)
            for reason in {str(item["reason"]) for item in skips}
        }
        return {
            "authority_coverage": {
                "scanned_paths": sorted(
                    inventory.scanned_paths,
                    key=lambda path: (path.casefold(), path),
                ),
            },
            "coverage": {
                "files_considered": len(inventory.scanned_paths) + len(skips),
                "files_inspected": len(inventory.scanned_paths),
                "files_skipped": len(skips),
                "skipped_by_reason": counts,
                "skipped_files": skips,
            },
            "findings": [],
            "high_entropy_findings": [],
            "missing_files": {
                ".gitignore": False,
                "LICENSE": False,
                "README.md": False,
            },
            "suspicious_files": [],
        }

    def scanner(
        self,
        mutate: Callable[[dict[str, object]], None] | None = None,
        *,
        returncode: int = 0,
    ) -> authoritative.ScannerRunner:
        def run(
            invocation: authoritative.ScannerInvocation,
        ) -> authoritative.ScannerExecution:
            self.scanner_calls += 1
            report = self.report()
            if mutate is not None:
                mutate(report)
            invocation.report_path.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return authoritative.ScannerExecution(
                returncode, self.bundle.scanner_version, b"", b""
            )

        return run

    def run(
        self,
        scanner: authoritative.ScannerRunner | None = None,
        *,
        runtime: authoritative.RuntimeFacts = RUNTIME_FACTS,
        materializer: authoritative.SnapshotMaterializer | None = None,
        limits: authoritative.CommitAuthoritativeLimits | None = None,
    ) -> authoritative.CommitAuthoritativeResult:
        with patch.object(authoritative, "_artifact_bytes", return_value=b"wheel"):
            return authoritative.run_commit_authoritative(
                self.request,
                limits=limits,
                snapshot_reader=self.reader,
                snapshot_materializer=materializer or self.materializer,
                scanner_runner=scanner or self.scanner(),
                runtime_facts_provider=lambda: runtime,
            )


class HarnessTestCase(unittest.TestCase):
    def harness(
        self,
        files: tuple[SnapshotFile, ...] | None = None,
        *,
        trusted_baseline: bytes | None = None,
    ) -> Harness:
        harness = Harness(files, trusted_baseline=trusted_baseline)
        self.addCleanup(harness.cleanup)
        return harness


class AuthoritySchemaTests(unittest.TestCase):
    def test_request_identity_excludes_pull_and_base_fields(self) -> None:
        fields = inspect.signature(authoritative.CommitAuthoritativeRequest).parameters
        self.assertIn("repository_id", fields)
        self.assertIn("head_oid", fields)
        self.assertNotIn("pull_number", fields)
        self.assertNotIn("base_oid", fields)

    def test_result_schema_contains_commit_intrinsic_evidence(self) -> None:
        fields = inspect.signature(authoritative.CommitAuthoritativeResult).parameters
        required = {
            "policy_schema_version",
            "policy_epoch",
            "policy_bundle_sha256",
            "repository_id",
            "head_oid",
            "protected_manifest_sha256",
            "suppression_manifest_sha256",
            "coverage_policy_sha256",
            "scanner_distribution",
            "scanner_version",
            "scanner_artifact_sha256",
            "files_total",
            "files_scanned",
            "files_policy_excluded",
            "files_scanner_skipped",
            "report_sha256",
            "report_size",
            "verdict",
            "refusal_code",
            "semantic_sha256",
        }
        self.assertTrue(required.issubset(fields))
        self.assertNotIn("base_oid", fields)
        self.assertNotIn("pull_number", fields)
        self.assertNotIn("report_path", fields)

    def test_bundle_contract_has_no_self_digest_file(self) -> None:
        self.assertNotIn("bundle.sha256", policy.BUNDLE_FILENAMES)
        self.assertNotIn("policy-bundle.sha256", policy.BUNDLE_FILENAMES)


class HappyPathTests(HarnessTestCase):
    def test_pass_has_complete_schema_and_path_level_counts(self) -> None:
        harness = self.harness()
        result = harness.run()

        self.assertEqual(result.verdict, authoritative.CommitAuthorityVerdict.PASS)
        self.assertIsNotNone(result.semantic_sha256)
        self.assertEqual(result.files_total, len(harness.files))
        self.assertEqual(
            result.files_policy_excluded,
            1 + len(policy.BUNDLE_FILENAMES),
        )
        self.assertEqual(result.files_scanner_skipped, 0)
        self.assertEqual(
            result.files_total,
            result.files_scanned
            + result.files_policy_excluded
            + result.files_scanner_skipped,
        )
        self.assertEqual(harness.scanner_calls, 1)

    def test_repeat_and_temporary_directory_changes_preserve_semantic_digest(
        self,
    ) -> None:
        first = self.harness()
        second = self.harness(first.files)

        first_result = first.run()
        second_result = second.run()

        self.assertEqual(first_result.semantic_sha256, second_result.semantic_sha256)
        self.assertEqual(
            authoritative.result_dict(first_result),
            authoritative.result_dict(second_result),
        )

    def test_permitted_ambient_noise_does_not_change_semantic_digest(self) -> None:
        harness = self.harness()
        first = harness.run()
        noise = {
            "HOME": "different-home",
            "XDG_CACHE_HOME": "different-cache",
            "PYTHONPATH": "different-python-path",
            "REPO_SENTINEL_CONFIG": "different-config",
            "VIRTUAL_ENV": "different-venv",
            "PATH": "different-path",
        }
        with patch.dict(os.environ, noise, clear=False):
            second = harness.run()
        self.assertEqual(first.semantic_sha256, second.semantic_sha256)

    def test_warning_is_non_blocking_and_error_is_scanner_finding(self) -> None:
        for severity, returncode, verdict in (
            ("warning", 0, authoritative.CommitAuthorityVerdict.PASS),
            ("error", 1, authoritative.CommitAuthorityVerdict.SCANNER_FINDING),
        ):
            with self.subTest(severity=severity):
                harness = self.harness()

                def finding(report: dict[str, object]) -> None:
                    if severity == "warning":
                        report["findings"] = [
                            {
                                "evidence": {
                                    "line": 1,
                                    "path": "README.md",
                                    "token_sha256": "a" * 64,
                                },
                                "file": "README.md",
                                "fingerprint": "d" * 64,
                                "kind": "assignment_context",
                                "line": 1,
                                "path": "README.md",
                                "remediation_hint": "review the fixture",
                                "rule_id": "secret.assignment_context",
                                "rule_version": "1",
                                "severity": "warning",
                                "token": "<redacted:sha256:aaaaaaaaaaaa>",
                            }
                        ]
                    else:
                        report["findings"] = [
                            {
                                "evidence": {"path": "README.md"},
                                "fingerprint": "d" * 64,
                                "kind": "suspicious_file",
                                "path": "README.md",
                                "remediation_hint": "review the fixture",
                                "rule_id": "repo.suspicious_filename",
                                "rule_version": "1",
                                "severity": "error",
                            }
                        ]
                        report["suspicious_files"] = ["README.md"]

                result = harness.run(harness.scanner(finding, returncode=returncode))
                self.assertEqual(result.verdict, verdict)
                self.assertIsNotNone(result.semantic_sha256)

    def test_runtime_mismatch_is_infrastructure_without_semantic_digest(self) -> None:
        harness = self.harness()
        result = harness.run(
            runtime=authoritative.RuntimeFacts("cpython", "3.12.4", "Linux", "x86_64")
        )

        self.assertEqual(
            result.verdict,
            authoritative.CommitAuthorityVerdict.INFRASTRUCTURE_REFUSAL,
        )
        self.assertEqual(result.refusal_code, "runtime_mismatch")
        self.assertIsNone(result.semantic_sha256)
        self.assertEqual(harness.scanner_calls, 0)


class ProtectedAdmissionTests(HarnessTestCase):
    def test_protected_mutations_fail_before_materialization(self) -> None:
        original = minimum_files()
        cases = {
            "attributes-content": replace_file(
                original, ".gitattributes", data=b"* text=auto\n"
            ),
            "config-content": replace_file(
                original, ".reposentinel.toml", data=b"ignore_globs = ['*']\n"
            ),
            "config-mode": replace_file(original, ".reposentinel.toml", mode="100755"),
            "config-missing": without(original, ".reposentinel.toml"),
            "config-alias": with_file(
                without(original, ".reposentinel.toml"),
                snapshot_file(".RepoSentinel.toml", b"ignore_globs = []\n"),
            ),
            "additional-config-alias": with_file(
                original, snapshot_file(".RepoSentinel.toml")
            ),
            "baseline-content": replace_file(
                original, ".reposentinel-baseline.json", data=b"{}\n"
            ),
            "baseline-missing": without(original, ".reposentinel-baseline.json"),
            "baseline-alias": with_file(
                without(original, ".reposentinel-baseline.json"),
                snapshot_file(".RepoSentinel-Baseline.json", EMPTY_BASELINE),
            ),
            "script-modified": replace_file(
                original, "scripts/repo_sentinel_reader.py", data=b"changed\n"
            ),
            "script-deleted": without(original, "scripts/repo_sentinel_reader.py"),
            "file-directory-substitution": with_file(
                without(original, "scripts/repo_sentinel_gate.py"),
                snapshot_file("scripts/repo_sentinel_gate.py/child.txt"),
            ),
            "new-workflow": with_file(
                original, snapshot_file(".github/workflows/new.yml")
            ),
            "new-action": with_file(
                original, snapshot_file(".github/actions/new/action.yml")
            ),
            "workflow-mode": replace_file(
                original, ".github/workflows/check.yml", mode="100755"
            ),
            "workflow-alias": with_file(
                original, snapshot_file(".GitHub/Workflows/alias.yml")
            ),
        }
        trusted = self.harness(original)
        for name, mutated in cases.items():
            with self.subTest(name=name):
                trusted.snapshot = Snapshot(
                    HEAD_OID, "c" * 40, trusted.with_policy_mirror(mutated)
                )
                result = trusted.run()
                self.assertEqual(
                    result.verdict,
                    authoritative.CommitAuthorityVerdict.POLICY_ADMISSION_FAILURE,
                )
                self.assertEqual(result.refusal_code, "protected_control_mismatch")
                self.assertEqual(trusted.materializer_calls, 0)


class PolicyBundleMirrorAdmissionTests(HarnessTestCase):
    def test_bundle_mirror_mutations_fail_before_materialization(self) -> None:
        harness = self.harness()
        original = harness.files
        path = f"{policy.POLICY_BUNDLE_MIRROR_ROOT}epoch.json"
        cases = {
            "content": replace_file(original, path, data=b"{}\n"),
            "mode": replace_file(original, path, mode="100755"),
            "missing": without(original, path),
            "alias": with_file(
                without(original, path),
                snapshot_file("Policy/repo-sentinel-authority/v1/epoch.json"),
            ),
            "extra": with_file(
                original,
                snapshot_file(f"{policy.POLICY_BUNDLE_MIRROR_ROOT}unreviewed.json"),
            ),
        }

        for name, mutated in cases.items():
            with self.subTest(name=name):
                harness.snapshot = Snapshot(HEAD_OID, "c" * 40, mutated)
                result = harness.run()
                self.assertEqual(
                    result.verdict,
                    authoritative.CommitAuthorityVerdict.POLICY_ADMISSION_FAILURE,
                )
                self.assertEqual(result.refusal_code, "policy_bundle_mirror_mismatch")
                self.assertEqual(harness.materializer_calls, 0)


class SuppressionAdmissionTests(HarnessTestCase):
    def test_suppression_mutations_fail_before_scanner(self) -> None:
        original = minimum_files()
        cases = {
            "new-inline": with_file(
                original,
                snapshot_file("notes/new.txt", b"# repo-sentinel: allow\n"),
            ),
            "modified-approved": replace_file(
                original,
                "notes/approved.txt",
                data=b"changed # repo-sentinel: allow\n",
            ),
            "copied": with_file(
                original,
                snapshot_file(
                    "notes/copied.txt",
                    b"fixture # repo-sentinel: allow secret.high_entropy\n",
                ),
            ),
            "mode": replace_file(original, "notes/approved.txt", mode="100755"),
            "utf16": with_file(
                original,
                snapshot_file(
                    "notes/utf16.txt", "# repo-sentinel: allow\n".encode("utf-16")
                ),
            ),
            "cp1252": with_file(
                original,
                snapshot_file(
                    "notes/cp1252.txt",
                    "café # repo-sentinel: allow\n".encode("cp1252"),
                ),
            ),
        }
        trusted = self.harness(original)
        for name, mutated in cases.items():
            with self.subTest(name=name):
                trusted.snapshot = Snapshot(
                    HEAD_OID, "c" * 40, trusted.with_policy_mirror(mutated)
                )
                result = trusted.run()
                self.assertEqual(
                    result.verdict,
                    authoritative.CommitAuthorityVerdict.POLICY_ADMISSION_FAILURE,
                )
                self.assertEqual(result.refusal_code, "suppression_manifest_mismatch")
                self.assertEqual(trusted.scanner_calls, 0)


class CoverageTests(HarnessTestCase):
    def test_unexpected_exclusions_fail_and_approved_exclusions_pass(self) -> None:
        original = minimum_files()
        cases = {
            "binary": snapshot_file("data.bin", b"a\0b"),
            "unsupported_encoding": snapshot_file("odd.txt", b"\x81"),
            "ignored-directory": snapshot_file(".venv/hidden.txt"),
        }
        for name, item in cases.items():
            with self.subTest(name=name):
                trusted = self.harness(original)
                mutated = with_file(original, item)
                trusted.snapshot = Snapshot(
                    HEAD_OID, "c" * 40, trusted.with_policy_mirror(mutated)
                )
                rejected = trusted.run()
                self.assertEqual(rejected.refusal_code, "coverage_policy_mismatch")

                approved = self.harness(mutated)
                accepted = approved.run()
                self.assertEqual(
                    accepted.verdict, authoritative.CommitAuthorityVerdict.PASS
                )
                self.assertEqual(
                    accepted.files_total,
                    accepted.files_scanned
                    + accepted.files_policy_excluded
                    + accepted.files_scanner_skipped,
                )

    def test_unexpected_and_approved_oversize_are_distinguished(self) -> None:
        configured = replace_file(
            minimum_files(),
            ".reposentinel.toml",
            data=b"ignore_globs = []\nmax_text_file_size = 128\n",
        )
        trusted = self.harness(configured)
        oversized = with_file(configured, snapshot_file("large.txt", b"x" * 129))
        trusted.snapshot = Snapshot(
            HEAD_OID, "c" * 40, trusted.with_policy_mirror(oversized)
        )
        self.assertEqual(
            trusted.run().refusal_code,
            "coverage_policy_mismatch",
        )
        approved = self.harness(oversized)
        result = approved.run()
        self.assertEqual(result.verdict, authoritative.CommitAuthorityVerdict.PASS)
        self.assertEqual(result.files_scanner_skipped, 1)

    def test_report_coverage_tampering_is_infrastructure(self) -> None:
        mutators: dict[str, Callable[[dict[str, object]], None]] = {
            "missing": lambda report: report.pop("coverage"),
            "count": lambda report: report["coverage"].__setitem__(
                "files_inspected", 999
            ),
            "boolean-count": lambda report: report["coverage"].__setitem__(
                "files_inspected", True
            ),
            "path": lambda report: report["authority_coverage"].__setitem__(
                "scanned_paths", ["unknown.txt"]
            ),
            "duplicate": lambda report: report["authority_coverage"].__setitem__(
                "scanned_paths",
                [
                    *report["authority_coverage"]["scanned_paths"],
                    report["authority_coverage"]["scanned_paths"][0],
                ],
            ),
        }
        for name, mutate in mutators.items():
            with self.subTest(name=name):
                harness = self.harness()
                result = harness.run(harness.scanner(mutate))
                self.assertEqual(
                    result.verdict,
                    authoritative.CommitAuthorityVerdict.INFRASTRUCTURE_REFUSAL,
                )
                self.assertEqual(result.refusal_code, "scanner_result_invalid")

    def test_report_scanned_path_set_must_match_even_when_counts_are_valid(
        self,
    ) -> None:
        def substitute_policy_excluded_path(report: dict[str, object]) -> None:
            paths = report["authority_coverage"]["scanned_paths"]
            paths[0] = ".reposentinel-baseline.json"
            paths.sort(key=lambda path: (path.casefold(), path))

        harness = self.harness()
        result = harness.run(harness.scanner(substitute_policy_excluded_path))

        self.assertEqual(
            result.verdict,
            authoritative.CommitAuthorityVerdict.INFRASTRUCTURE_REFUSAL,
        )
        self.assertEqual(result.refusal_code, "scanner_result_invalid")

    def test_report_derived_views_must_match_findings(self) -> None:
        mutators: dict[str, Callable[[dict[str, object]], None]] = {
            "entropy": lambda report: report["high_entropy_findings"].append(
                {
                    "entropy": 4.2,
                    "file": "README.md",
                    "line": 1,
                    "token": "<redacted:sha256:aaaaaaaaaaaa>",
                }
            ),
            "suspicious": lambda report: report["suspicious_files"].append("README.md"),
            "missing": lambda report: report["missing_files"].__setitem__(
                "LICENSE", True
            ),
        }
        for name, mutate in mutators.items():
            with self.subTest(name=name):
                harness = self.harness()
                result = harness.run(harness.scanner(mutate))
                self.assertEqual(result.refusal_code, "scanner_result_invalid")

    def test_skip_reason_and_skip_path_must_match_approved_entry(self) -> None:
        files = with_file(minimum_files(), snapshot_file("data.bin", b"a\0b"))
        for name, mutate in (
            (
                "reason",
                lambda report: report["coverage"]["skipped_files"][0].update(
                    reason="unreadable"
                ),
            ),
            (
                "path",
                lambda report: report["coverage"]["skipped_files"][0].update(
                    path="README.md"
                ),
            ),
            (
                "duplicate",
                lambda report: report["coverage"]["skipped_files"].append(
                    dict(report["coverage"]["skipped_files"][0])
                ),
            ),
        ):
            with self.subTest(name=name):
                harness = self.harness(files)

                def adjusted(report: dict[str, object]) -> None:
                    mutate(report)
                    skipped = report["coverage"]["skipped_files"]
                    report["coverage"]["files_skipped"] = len(skipped)
                    report["coverage"]["files_considered"] = report["coverage"][
                        "files_inspected"
                    ] + len(skipped)
                    counts: dict[str, int] = {}
                    for item in skipped:
                        reason = item["reason"]
                        counts[reason] = counts.get(reason, 0) + 1
                    report["coverage"]["skipped_by_reason"] = counts

                result = harness.run(harness.scanner(adjusted))
                self.assertEqual(result.refusal_code, "scanner_result_invalid")


class ReportFailureTests(HarnessTestCase):
    def test_report_and_scanner_failures_are_infrastructure(self) -> None:
        harness = self.harness()

        def no_report(
            _invocation: authoritative.ScannerInvocation,
        ) -> authoritative.ScannerExecution:
            return authoritative.ScannerExecution(0, "0.8.1", b"", b"")

        def malformed(
            invocation: authoritative.ScannerInvocation,
        ) -> authoritative.ScannerExecution:
            invocation.report_path.write_bytes(b"not json\n")
            return authoritative.ScannerExecution(0, "0.8.1", b"", b"")

        def raised(
            _invocation: authoritative.ScannerInvocation,
        ) -> authoritative.ScannerExecution:
            raise authoritative.WorkerRefused("scanner_timeout")

        for name, scanner, code in (
            ("missing", no_report, "report_missing"),
            ("malformed", malformed, "scanner_result_invalid"),
            ("timeout", raised, "scanner_timeout"),
        ):
            with self.subTest(name=name):
                result = harness.run(scanner)
                self.assertEqual(
                    result.verdict,
                    authoritative.CommitAuthorityVerdict.INFRASTRUCTURE_REFUSAL,
                )
                self.assertEqual(result.refusal_code, code)
                self.assertIsNone(result.semantic_sha256)

    def test_return_code_report_contradiction_is_rejected(self) -> None:
        harness = self.harness()
        result = harness.run(harness.scanner(returncode=1))
        self.assertEqual(result.refusal_code, "scanner_result_invalid")

    def test_oversize_report_is_distinct_from_missing_report(self) -> None:
        harness = self.harness()
        limits = authoritative.CommitAuthoritativeLimits(max_report_bytes=64)
        result = harness.run(limits=limits)
        self.assertEqual(result.refusal_code, "report_oversize")

    def test_duplicate_json_keys_are_rejected(self) -> None:
        harness = self.harness()

        def duplicate(
            invocation: authoritative.ScannerInvocation,
        ) -> authoritative.ScannerExecution:
            invocation.report_path.write_bytes(b'{"coverage":{},"coverage":{}}\n')
            return authoritative.ScannerExecution(0, "0.8.1", b"", b"")

        result = harness.run(duplicate)
        self.assertEqual(result.refusal_code, "scanner_result_invalid")

    def test_invalid_snapshot_identity_is_infrastructure(self) -> None:
        harness = self.harness()
        harness.snapshot = Snapshot("a" * 40, "c" * 40, harness.files)
        result = harness.run()
        self.assertEqual(result.refusal_code, "invalid_snapshot")
        self.assertEqual(harness.materializer_calls, 0)

    def test_duplicate_snapshot_path_is_infrastructure(self) -> None:
        harness = self.harness()
        duplicate = snapshot_file("README.md")
        harness.snapshot = Snapshot(
            HEAD_OID,
            "c" * 40,
            (*harness.files, duplicate),
        )
        result = harness.run()
        self.assertEqual(result.refusal_code, "invalid_snapshot")


class EnvironmentTests(HarnessTestCase):
    def test_scanner_receives_private_trusted_bundle_baseline(self) -> None:
        target_baseline = (
            b'{"findings": [], "generated_at": "2026-09-15T00:00:00Z", '
            b'"schema_version": 1}\n'
        )
        trusted_baseline = (
            b'{"findings": [], "generated_at": "2026-09-15T00:00:01Z", '
            b'"schema_version": 1}\n'
        )
        files = replace_file(
            minimum_files(),
            ".reposentinel-baseline.json",
            data=target_baseline,
        )
        harness = self.harness(files, trusted_baseline=trusted_baseline)
        underlying = harness.scanner()

        def scanner(
            invocation: authoritative.ScannerInvocation,
        ) -> authoritative.ScannerExecution:
            self.assertEqual(
                invocation.baseline_path.parent,
                invocation.execution_directory,
            )
            self.assertEqual(invocation.baseline_path.read_bytes(), trusted_baseline)
            self.assertEqual(
                invocation.baseline_path.read_bytes(), harness.bundle.baseline
            )
            self.assertNotEqual(invocation.baseline_path.read_bytes(), target_baseline)
            return underlying(invocation)

        result = harness.run(scanner)

        self.assertEqual(result.verdict, authoritative.CommitAuthorityVerdict.PASS)

    def test_real_child_receives_only_fixed_environment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="commit-authority-env-") as temporary:
            marker = Path(temporary) / "executed"
            hostile = {
                "HOME": "attacker-home",
                "XDG_CONFIG_HOME": "attacker-xdg",
                "PYTHONPATH": str(Path(temporary)),
                "PYTHONSTARTUP": str(Path(temporary) / "startup.py"),
                "REPO_SENTINEL_CONFIG": "attacker",
                "VIRTUAL_ENV": "attacker-venv",
                "PIP_CONFIG_FILE": "attacker-pip",
                "LD_PRELOAD": "attacker-library",
                "PATH": "attacker-path",
            }
            (Path(temporary) / "sitecustomize.py").write_text(
                f"from pathlib import Path; Path({str(marker)!r}).touch()\n",
                encoding="utf-8",
            )
            command = [
                sys.executable,
                "-I",
                "-c",
                "import json,os;print(json.dumps(dict(os.environ),sort_keys=True))",
            ]
            with patch.dict(os.environ, hostile, clear=False):
                result = authoritative._run_command_bounded(
                    command,
                    cwd=Path(temporary),
                    timeout_seconds=5,
                    capture_limit=4096,
                )
            observed = json.loads(result.stdout.decode("utf-8"))
            self.assertEqual(observed, authoritative._scanner_environment())
            self.assertFalse(marker.exists())

    def test_target_python_hooks_and_executable_content_remain_data(self) -> None:
        with tempfile.TemporaryDirectory(prefix="commit-authority-marker-") as temp:
            marker = Path(temp) / "executed"
            payload = (
                f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
            ).encode()
            files = minimum_files()
            for path, mode in (
                ("repo_sentinel.py", "100644"),
                ("sitecustomize.py", "100644"),
                ("usercustomize.py", "100644"),
                ("bootstrap.pth", "100644"),
                ("run.py", "100755"),
            ):
                files = with_file(files, snapshot_file(path, payload, mode))
            harness = self.harness(files)
            underlying = harness.scanner()

            def scanner(
                invocation: authoritative.ScannerInvocation,
            ) -> authoritative.ScannerExecution:
                self.assertNotEqual(
                    invocation.target_root, invocation.execution_directory
                )
                self.assertFalse(marker.exists())
                return underlying(invocation)

            result = harness.run(scanner)

            self.assertEqual(result.verdict, authoritative.CommitAuthorityVerdict.PASS)
            self.assertFalse(marker.exists())

    def test_scanner_command_uses_verified_wheel_and_no_changed_files(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="commit-authority-command-"
        ) as temporary:
            root = Path(temporary)
            invocation = authoritative.ScannerInvocation(
                root / "target",
                root / "scanner.whl",
                root / "baseline.json",
                root / "policy-exclusions.json",
                root / "report.json",
                root,
                5,
                1024,
                "0.8.1",
            )
            calls: list[list[str]] = []

            def command(
                arguments: list[str], **_kwargs: object
            ) -> authoritative._CommandResult:
                calls.append(arguments)
                if len(calls) == 1:
                    return authoritative._CommandResult(
                        0, b"repo-sentinel 0.8.1\n", b""
                    )
                return authoritative._CommandResult(0, b"", b"")

            with patch.object(
                authoritative, "_run_command_bounded", side_effect=command
            ):
                authoritative._run_trusted_scanner(invocation)

            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[1][1:3], ["-I", "-c"])
            self.assertIn(str(invocation.scanner_artifact), calls[1])
            self.assertIn(str(invocation.policy_exclusions_path), calls[1])
            self.assertNotIn("--changed-files", calls[1])
            self.assertNotIn(str(invocation.target_root), calls[1][:4])
            self.assertIn('"--no-default-baseline"', authoritative._SCANNER_DRIVER)
            self.assertIn('"--baseline"', authoritative._SCANNER_DRIVER)
            self.assertIn('"--fail-on-severity"', authoritative._SCANNER_DRIVER)
            self.assertNotIn('"--changed-files"', authoritative._SCANNER_DRIVER)

    def test_real_bounded_command_rejects_timeout_and_output_overflow(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="commit-authority-bounds-"
        ) as temporary:
            cases = (
                (
                    [sys.executable, "-I", "-c", "import time;time.sleep(2)"],
                    0.05,
                    1024,
                    "scanner_timeout",
                ),
                (
                    [sys.executable, "-I", "-c", "print('x'*4096)"],
                    5,
                    64,
                    "scanner_output_limit",
                ),
            )
            for command, timeout, limit, code in cases:
                with self.subTest(code=code):
                    with self.assertRaises(authoritative.WorkerRefused) as raised:
                        authoritative._run_command_bounded(
                            command,
                            cwd=Path(temporary),
                            timeout_seconds=timeout,
                            capture_limit=limit,
                        )
                    self.assertEqual(raised.exception.code, code)


class MaterializationTests(HarnessTestCase):
    def test_materialized_control_readback_detects_byte_change(self) -> None:
        harness = self.harness()

        @contextmanager
        def changed(
            *_args: object, **_kwargs: object
        ) -> Iterator[MaterializedSnapshot]:
            with harness.materializer() as materialized:
                (materialized.root / ".reposentinel.toml").write_bytes(b"changed\n")
                yield materialized

        result = harness.run(materializer=changed)
        self.assertEqual(result.refusal_code, "head_snapshot_mismatch")
        self.assertEqual(harness.scanner_calls, 0)

    def test_cleanup_failure_overrides_a_semantic_result(self) -> None:
        harness = self.harness()

        @contextmanager
        def cleanup_failure(
            *_args: object, **_kwargs: object
        ) -> Iterator[MaterializedSnapshot]:
            with harness.materializer() as materialized:
                yield materialized
            raise authoritative.MaterializationRefused("cleanup_failed")

        result = harness.run(materializer=cleanup_failure)
        self.assertEqual(
            result.verdict,
            authoritative.CommitAuthorityVerdict.INFRASTRUCTURE_REFUSAL,
        )
        self.assertEqual(result.refusal_code, "cleanup_failed")


class PolicyBundleTests(HarnessTestCase):
    @staticmethod
    def rewrite_component(harness: Harness, name: str, value: object) -> str:
        data = policy._render(value)
        (harness.policy_root / name).write_bytes(data)
        epoch_path = harness.policy_root / "epoch.json"
        epoch = json.loads(epoch_path.read_text(encoding="utf-8"))
        epoch["component_sha256"][name] = policy.sha256_bytes(data)
        epoch_path.write_bytes(policy._render(epoch))
        return policy.bundle_sha256(harness.policy_root)

    def test_rebuild_ignores_the_exact_in_tree_bundle_mirror(self) -> None:
        harness = self.harness()
        rebuilt = harness.root / "rebuilt-policy"

        digest = policy.build_policy_bundle(harness.files, rebuilt, RUNTIME)

        self.assertEqual(digest, harness.bundle_digest)
        for name in policy.BUNDLE_FILENAMES:
            self.assertEqual(
                (rebuilt / name).read_bytes(),
                (harness.policy_root / name).read_bytes(),
            )

    def test_unknown_missing_and_digest_mismatch_fail_closed(self) -> None:
        for name in ("unknown", "missing", "digest"):
            with self.subTest(name=name):
                harness = self.harness()
                if name == "unknown":
                    (harness.policy_root / "extra.json").write_text("{}\n")
                elif name == "missing":
                    (harness.policy_root / "baseline.json").unlink()
                expected = "0" * 64 if name == "digest" else harness.bundle_digest
                with self.assertRaises(policy.PolicyBundleRefused):
                    policy.load_policy_bundle(harness.policy_root, expected)

    def test_duplicate_manifest_path_is_rejected_with_matching_bundle_digest(
        self,
    ) -> None:
        harness = self.harness()
        path = harness.policy_root / "suppression-manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["entries"].append(dict(manifest["entries"][0]))
        expected = self.rewrite_component(
            harness, "suppression-manifest.json", manifest
        )
        with self.assertRaises(policy.PolicyBundleRefused):
            policy.load_policy_bundle(harness.policy_root, expected)

    def test_unsupported_epoch_is_rejected_with_recomputed_bundle_digest(self) -> None:
        harness = self.harness()
        path = harness.policy_root / "epoch.json"
        epoch = json.loads(path.read_text(encoding="utf-8"))
        epoch["schema_version"] = 2
        path.write_bytes(policy._render(epoch))
        expected = policy.bundle_sha256(harness.policy_root)
        with self.assertRaises(policy.PolicyBundleRefused) as raised:
            policy.load_policy_bundle(harness.policy_root, expected)
        self.assertEqual(str(raised.exception), "policy_schema_unsupported")

    def test_invalid_baseline_is_rejected_before_scanner(self) -> None:
        harness = self.harness()
        expected = self.rewrite_component(
            harness, "baseline.json", "not a baseline object"
        )
        with self.assertRaises(policy.PolicyBundleRefused):
            policy.load_policy_bundle(harness.policy_root, expected)

    def test_non_suppression_phrase_is_not_overmatched(self) -> None:
        self.assertFalse(policy.contains_inline_suppression(b"repo sentinel allow\n"))

    def test_artifact_mismatch_is_detected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="commit-authority-artifact-"
        ) as temporary:
            artifact = Path(temporary) / "scanner.whl"
            artifact.write_bytes(b"wrong")
            with self.assertRaises(authoritative.WorkerRefused) as raised:
                authoritative._artifact_bytes(artifact, policy.SCANNER_WHEEL_SHA256)
        self.assertEqual(raised.exception.code, "scanner_artifact_mismatch")


if __name__ == "__main__":
    unittest.main()
