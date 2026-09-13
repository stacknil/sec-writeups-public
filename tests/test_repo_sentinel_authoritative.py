from __future__ import annotations

import hashlib
import importlib.metadata
import io
import json
import shutil
import subprocess
import sys
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import repo_sentinel_authoritative as authoritative
from repo_sentinel_acquire import AcquiredSnapshot, AcquisitionRefused
from repo_sentinel_materialize import MaterializedSnapshot
from repo_sentinel_reader import Snapshot, SnapshotFile

BASE_OID = "1" * 40
HEAD_OID = "2" * 40
BASELINE = b'{"schema_version":1,"generated_at":"2026-01-01T00:00:00Z","findings":[]}\n'
EMPTY_REPORT = {
    "findings": [],
    "missing_files": {},
    "suspicious_files": [],
}


def exact_scanner_available() -> bool:
    try:
        return importlib.metadata.version("repo-sentinel-lite") == "0.8.1"
    except importlib.metadata.PackageNotFoundError:
        return False


def snapshot_file(
    path: str,
    data: bytes = b"fixture\n",
    *,
    mode: str = "100644",
    oid: str | None = None,
) -> SnapshotFile:
    digest = oid or hashlib.sha1(data).hexdigest()
    return SnapshotFile(path, mode, digest, data)


def snapshot(
    commit_oid: str,
    *files: SnapshotFile,
) -> Snapshot:
    return Snapshot(
        commit_oid, "3" * 40, tuple(sorted(files, key=lambda item: item.path))
    )


def scanner_execution(
    returncode: int = 0,
    *,
    stdout: bytes = b"",
    stderr: bytes = b"",
) -> authoritative.ScannerExecution:
    return authoritative.ScannerExecution(
        returncode,
        authoritative.SCANNER_VERSION,
        stdout,
        stderr,
    )


def write_report(
    invocation: authoritative.ScannerInvocation,
    report: object = EMPTY_REPORT,
) -> None:
    invocation.report_path.write_text(
        json.dumps(report, sort_keys=True) + "\n",
        encoding="utf-8",
    )


class WorkerHarness:
    def __init__(self, test: unittest.TestCase, base: Snapshot, head: Snapshot) -> None:
        self.base = base
        self.head = head
        self.directories: list[TemporaryDirectory[str]] = []
        self.trusted_repository = self._directory(test, "authoritative-base-")
        self.scratch_root = self._directory(test, "authoritative-scratch-")
        self.evidence_root = self._directory(test, "authoritative-evidence-")
        self.head_repository = self.scratch_root / "head.git"
        self.head_repository.mkdir()
        self.target_root = self.scratch_root / "target"
        self.acquirer_exited = False
        self.materializer_exited = False

    def _directory(self, test: unittest.TestCase, prefix: str) -> Path:
        temporary = TemporaryDirectory(prefix=prefix)
        self.directories.append(temporary)
        test.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    @property
    def request(self) -> authoritative.AuthoritativeGateRequest:
        return authoritative.AuthoritativeGateRequest(
            repository_identity="stacknil/sec-writeups-public",
            pull_number=7,
            base_oid=self.base.commit_oid,
            head_oid=self.head.commit_oid,
            remote="https://example.com/repository.git",
            trusted_repository=self.trusted_repository,
            scratch_root=self.scratch_root,
            evidence_root=self.evidence_root,
        )

    def reader(self, _repository: Path, oid: str, **_kwargs: object) -> Snapshot:
        if oid != self.base.commit_oid:
            raise AssertionError("worker read an unexpected base object")
        return self.base

    @contextmanager
    def acquirer(self, *_args: object, **_kwargs: object):
        try:
            yield AcquiredSnapshot(
                self.head,
                f"refs/pull/{self.request.pull_number}/head",
                self.head_repository,
            )
        finally:
            self.acquirer_exited = True

    @contextmanager
    def materializer(self, *_args: object, **_kwargs: object):
        self.target_root.mkdir()
        for item in self.head.files:
            target = self.target_root.joinpath(*item.path.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(item.data)
        try:
            yield MaterializedSnapshot(self.head, self.target_root)
        finally:
            self.materializer_exited = True
            shutil.rmtree(self.target_root)

    def run(
        self,
        scanner: authoritative.ScannerRunner,
        *,
        limits: authoritative.AuthoritativeLimits | None = None,
    ) -> authoritative.AuthoritativeGateResult:
        return authoritative.run_authoritative_gate(
            self.request,
            limits=limits or authoritative.AuthoritativeLimits(),
            snapshot_reader=self.reader,
            pull_acquirer=self.acquirer,
            snapshot_materializer=self.materializer,
            scanner_runner=scanner,
        )


class SnapshotDiffTests(unittest.TestCase):
    def test_d1_added_modified_mode_changed_deleted_and_identical(self) -> None:
        original = snapshot_file("same.txt", b"same")
        base = snapshot(
            BASE_OID,
            original,
            snapshot_file("blob.txt", b"old"),
            snapshot_file("mode.txt", b"mode", mode="100644"),
            snapshot_file("deleted.txt", b"gone"),
        )
        head = snapshot(
            HEAD_OID,
            original,
            snapshot_file("blob.txt", b"new"),
            snapshot_file("mode.txt", b"mode", mode="100755"),
            snapshot_file("added.txt", b"added"),
        )

        delta = authoritative.diff_snapshots(base, head)

        self.assertEqual(
            delta.changed_paths,
            ("added.txt", "blob.txt", "mode.txt"),
        )
        self.assertEqual(delta.deleted_paths, ("deleted.txt",))
        self.assertEqual(
            authoritative.diff_snapshots(base, snapshot(HEAD_OID, *base.files)),
            authoritative.SnapshotDelta((), ()),
        )

    def test_d1_preserves_exact_unicode_identity(self) -> None:
        nfc = "notes/caf\N{LATIN SMALL LETTER E WITH ACUTE}.md"
        nfd = "notes/cafe\N{COMBINING ACUTE ACCENT}.md"
        base = snapshot(BASE_OID, snapshot_file(nfc))
        head = snapshot(HEAD_OID, snapshot_file(nfd))

        delta = authoritative.diff_snapshots(base, head)

        self.assertEqual(delta.changed_paths, (nfd,))
        self.assertEqual(delta.deleted_paths, (nfc,))

    def test_duplicate_snapshot_path_fails_closed(self) -> None:
        duplicate = snapshot_file("same.txt")
        invalid = Snapshot(BASE_OID, "3" * 40, (duplicate, duplicate))

        with self.assertRaises(authoritative.WorkerRefused) as raised:
            authoritative.diff_snapshots(invalid, snapshot(HEAD_OID))

        self.assertEqual(raised.exception.code, "invalid_snapshot")


class AuthoritativeWorkerTests(unittest.TestCase):
    def harness(
        self,
        *,
        base_files: tuple[SnapshotFile, ...] = (),
        head_files: tuple[SnapshotFile, ...] = (),
    ) -> WorkerHarness:
        return WorkerHarness(
            self,
            snapshot(BASE_OID, *base_files),
            snapshot(HEAD_OID, *head_files),
        )

    def passing_scanner(
        self,
        calls: list[authoritative.ScannerInvocation] | None = None,
    ) -> authoritative.ScannerRunner:
        def scanner(
            invocation: authoritative.ScannerInvocation,
        ) -> authoritative.ScannerExecution:
            if calls is not None:
                calls.append(invocation)
            write_report(invocation)
            return scanner_execution()

        return scanner

    def test_pass_uses_base_baseline_and_trusted_execution_directory(self) -> None:
        base_files = (
            snapshot_file("README.md"),
            snapshot_file(".reposentinel-baseline.json", BASELINE),
        )
        head_files = (*base_files, snapshot_file("notes/new.md", b"new\n"))
        harness = self.harness(base_files=base_files, head_files=head_files)
        calls: list[authoritative.ScannerInvocation] = []
        observed_baseline: list[bytes] = []

        def scanner(
            invocation: authoritative.ScannerInvocation,
        ) -> authoritative.ScannerExecution:
            calls.append(invocation)
            assert invocation.baseline_path is not None
            observed_baseline.append(invocation.baseline_path.read_bytes())
            write_report(invocation)
            return scanner_execution()

        result = harness.run(scanner)

        self.assertEqual(result.verdict, authoritative.GateVerdict.PASS)
        self.assertEqual(result.changed_count, 1)
        self.assertEqual(result.deleted_count, 0)
        self.assertEqual(result.scanner_version, "0.8.1")
        self.assertIsNotNone(result.report_path)
        assert result.report_path is not None
        self.assertEqual(
            result.report_sha256,
            hashlib.sha256(result.report_path.read_bytes()).hexdigest(),
        )
        invocation = calls[0]
        self.assertEqual(invocation.changed_paths, ("notes/new.md",))
        self.assertEqual(observed_baseline, [BASELINE])
        self.assertNotEqual(invocation.execution_directory, invocation.target_root)
        self.assertFalse(
            invocation.execution_directory.is_relative_to(invocation.target_root)
        )
        self.assertFalse(invocation.report_path.is_relative_to(invocation.target_root))
        self.assertTrue(harness.acquirer_exited)
        self.assertTrue(harness.materializer_exited)

    def test_baseline_bytes_are_selected_from_base_snapshot(self) -> None:
        baseline_oid = "4" * 40
        base_baseline = snapshot_file(
            ".reposentinel-baseline.json",
            BASELINE,
            oid=baseline_oid,
        )
        head_baseline = snapshot_file(
            ".reposentinel-baseline.json",
            b'{"head_owned":true}\n',
            oid=baseline_oid,
        )
        harness = self.harness(
            base_files=(base_baseline,),
            head_files=(head_baseline, snapshot_file("notes/new.md")),
        )
        observed_baseline: list[bytes] = []

        def scanner(
            invocation: authoritative.ScannerInvocation,
        ) -> authoritative.ScannerExecution:
            assert invocation.baseline_path is not None
            observed_baseline.append(invocation.baseline_path.read_bytes())
            write_report(invocation)
            return scanner_execution()

        result = harness.run(scanner)

        self.assertEqual(result.verdict, authoritative.GateVerdict.PASS)
        self.assertEqual(observed_baseline, [BASELINE])

    def test_absent_base_baseline_disables_explicit_baseline(self) -> None:
        harness = self.harness(head_files=(snapshot_file("new.md"),))
        calls: list[authoritative.ScannerInvocation] = []

        result = harness.run(self.passing_scanner(calls))

        self.assertEqual(result.verdict, authoritative.GateVerdict.PASS)
        self.assertIsNone(calls[0].baseline_path)

    def test_scanner_error_finding_is_a_bounded_result(self) -> None:
        harness = self.harness(head_files=(snapshot_file("new.md"),))

        def scanner(
            invocation: authoritative.ScannerInvocation,
        ) -> authoritative.ScannerExecution:
            report = {
                "findings": [{"severity": "error"}],
                "missing_files": {},
                "suspicious_files": [],
            }
            write_report(invocation, report)
            return scanner_execution(1)

        result = harness.run(scanner)

        self.assertEqual(result.verdict, authoritative.GateVerdict.SCANNER_FINDING)
        self.assertIsNone(result.refusal_code)
        self.assertGreater(result.report_size, 0)

    def test_warning_remains_non_blocking(self) -> None:
        harness = self.harness(head_files=(snapshot_file("new.md"),))

        def scanner(
            invocation: authoritative.ScannerInvocation,
        ) -> authoritative.ScannerExecution:
            report = {
                "findings": [{"severity": "warning"}],
                "missing_files": {},
                "suspicious_files": [],
            }
            write_report(invocation, report)
            return scanner_execution()

        result = harness.run(scanner)

        self.assertEqual(result.verdict, authoritative.GateVerdict.PASS)

    def test_identical_and_deletion_only_snapshots_do_not_launch_scanner(self) -> None:
        existing = snapshot_file("ordinary.txt")
        for head_files, deleted in (((existing,), 0), ((), 1)):
            with self.subTest(deleted=deleted):
                harness = self.harness(
                    base_files=(existing,),
                    head_files=head_files,
                )
                result = harness.run(
                    lambda _invocation: self.fail("scanner must not run")
                )
                self.assertEqual(result.verdict, authoritative.GateVerdict.PASS)
                self.assertEqual(result.changed_count, 0)
                self.assertEqual(result.deleted_count, deleted)

    def test_protected_exact_and_subtree_changes_block_before_scanner(self) -> None:
        cases = (
            ".reposentinel.toml",
            ".reposentinel-baseline.json",
            "scripts/repo_sentinel_authoritative.py",
            "scripts/repo_sentinel_acquire.py",
            "scripts/repo_sentinel_reader.py",
            "scripts/repo_sentinel_materialize.py",
            "scripts/repo_sentinel_gate.py",
            "scripts/test_repo_sentinel_integration.py",
            ".github/workflows/attack.yml",
            ".github/actions/local/action.yml",
        )
        for path in cases:
            with self.subTest(path=path):
                harness = self.harness(head_files=(snapshot_file(path),))
                result = harness.run(
                    lambda _invocation: self.fail("scanner must not run")
                )
                self.assertEqual(
                    result.verdict,
                    authoritative.GateVerdict.PROTECTED_CONTROL_CHANGE,
                )
                self.assertEqual(result.refusal_code, "protected_control_change")

    def test_deleting_protected_control_blocks(self) -> None:
        protected = snapshot_file(".github/workflows/gate.yml")
        harness = self.harness(base_files=(protected,))

        result = harness.run(lambda _invocation: self.fail("scanner must not run"))

        self.assertEqual(
            result.verdict,
            authoritative.GateVerdict.PROTECTED_CONTROL_CHANGE,
        )

    def test_inline_suppression_change_blocks_exact_scanner_syntax(self) -> None:
        controls = (
            b"# repo-sentinel: allow\nvalue\n",
            b"# RePo-SeNtInEl: allow secret.high_entropy, github_token\nvalue\n",
        )
        for data in controls:
            with self.subTest(data=data):
                harness = self.harness(
                    head_files=(snapshot_file("notes/controlled.md", data),)
                )
                result = harness.run(
                    lambda _invocation: self.fail("scanner must not run")
                )
                self.assertEqual(
                    result.verdict,
                    authoritative.GateVerdict.PROTECTED_CONTROL_CHANGE,
                )
                self.assertEqual(result.refusal_code, "source_suppression_change")

    def test_deleting_file_with_inline_suppression_blocks(self) -> None:
        controlled = snapshot_file(
            "notes/controlled.md",
            b"# repo-sentinel: allow secret.high_entropy\nfixture\n",
        )
        harness = self.harness(base_files=(controlled,))

        result = harness.run(lambda _invocation: self.fail("scanner must not run"))

        self.assertEqual(result.refusal_code, "source_suppression_change")

    def test_similar_non_directive_text_does_not_block(self) -> None:
        harness = self.harness(
            head_files=(
                snapshot_file(
                    "notes/ordinary.md",
                    b"The repo-sentinel policy allows reviewed fixtures.\n",
                ),
            )
        )

        result = harness.run(self.passing_scanner())

        self.assertEqual(result.verdict, authoritative.GateVerdict.PASS)

    def test_hostile_report_content_is_never_printed_or_interpreted(self) -> None:
        harness = self.harness(head_files=(snapshot_file("new.md"),))
        payloads = (
            "::warning::payload",
            "::error::payload",
            "::add-mask::payload",
            "::stop-commands::payload",
            "\u001b[31mcontrol-like\u001b[0m",
        )

        def scanner(
            invocation: authoritative.ScannerInvocation,
        ) -> authoritative.ScannerExecution:
            report = {**EMPTY_REPORT, "hostile_data": payloads}
            write_report(invocation, report)
            return scanner_execution(
                stdout=b"::warning::stdout\n",
                stderr=b"::error::stderr\n",
            )

        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = harness.run(scanner)

        self.assertEqual(result.verdict, authoritative.GateVerdict.PASS)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        assert result.report_path is not None
        persisted = result.report_path.read_text(encoding="utf-8")
        for payload in payloads:
            self.assertIn(json.dumps(payload)[1:-1], persisted)

    def test_malicious_filename_is_hidden_and_materializer_failure_is_closed(
        self,
    ) -> None:
        path = "::error::not-a-workflow-command"
        harness = self.harness(head_files=(snapshot_file(path),))

        @contextmanager
        def refusing_materializer(*_args: object, **_kwargs: object):
            raise authoritative.MaterializationRefused("unsupported_host_path")
            yield  # pragma: no cover

        result = authoritative.run_authoritative_gate(
            harness.request,
            snapshot_reader=harness.reader,
            pull_acquirer=harness.acquirer,
            snapshot_materializer=refusing_materializer,
            scanner_runner=lambda _invocation: self.fail("scanner must not run"),
        )

        self.assertEqual(
            result.verdict, authoritative.GateVerdict.INFRASTRUCTURE_REFUSAL
        )
        self.assertEqual(result.refusal_code, "head_materialization_refused")
        self.assertNotIn(path, repr(result))

    def test_missing_oversized_malformed_and_inconsistent_reports_fail_closed(
        self,
    ) -> None:
        cases: tuple[tuple[str, authoritative.ScannerRunner, str], ...] = (
            (
                "missing",
                lambda _invocation: scanner_execution(),
                "report_missing",
            ),
            (
                "oversized",
                self._raw_report_scanner(b"x" * 65),
                "report_oversize",
            ),
            (
                "malformed",
                self._raw_report_scanner(b"not-json\n"),
                "scanner_result_invalid",
            ),
            (
                "exit-mismatch",
                self._raw_report_scanner(
                    (json.dumps(EMPTY_REPORT) + "\n").encode(),
                    returncode=1,
                ),
                "scanner_result_invalid",
            ),
        )
        for name, scanner, refusal in cases:
            with self.subTest(name=name):
                harness = self.harness(head_files=(snapshot_file("new.md"),))
                result = harness.run(
                    scanner,
                    limits=authoritative.AuthoritativeLimits(max_report_bytes=64),
                )
                self.assertEqual(
                    result.verdict,
                    authoritative.GateVerdict.INFRASTRUCTURE_REFUSAL,
                )
                self.assertEqual(result.refusal_code, refusal)
                self.assertEqual(list(harness.evidence_root.iterdir()), [])

    @staticmethod
    def _raw_report_scanner(
        data: bytes,
        *,
        returncode: int = 0,
    ) -> authoritative.ScannerRunner:
        def scanner(
            invocation: authoritative.ScannerInvocation,
        ) -> authoritative.ScannerExecution:
            invocation.report_path.write_bytes(data)
            return scanner_execution(returncode)

        return scanner

    def test_scanner_exception_cleans_every_temporary_boundary(self) -> None:
        harness = self.harness(head_files=(snapshot_file("new.md"),))
        transient_paths: list[Path] = []

        def scanner(
            invocation: authoritative.ScannerInvocation,
        ) -> authoritative.ScannerExecution:
            transient_paths.extend(
                [
                    invocation.execution_directory,
                    invocation.report_path.parent,
                    invocation.target_root,
                ]
            )
            raise RuntimeError("hostile raw detail")

        result = harness.run(scanner)

        self.assertEqual(
            result.verdict, authoritative.GateVerdict.INFRASTRUCTURE_REFUSAL
        )
        self.assertEqual(result.refusal_code, "unexpected_failure")
        self.assertTrue(harness.acquirer_exited)
        self.assertTrue(harness.materializer_exited)
        self.assertTrue(all(not path.exists() for path in transient_paths))
        self.assertNotIn("hostile raw detail", repr(result))

    def test_boundary_failures_return_fixed_infrastructure_codes(self) -> None:
        cases: list[
            tuple[
                str,
                authoritative.SnapshotReader,
                authoritative.PullAcquirer,
                authoritative.SnapshotMaterializer,
                authoritative.ScannerRunner,
                str,
            ]
        ] = []
        for name, worker_code in (
            ("scanner-launch", "scanner_launch_failed"),
            ("scanner-timeout", "scanner_timeout"),
            ("scanner-output", "scanner_output_limit"),
        ):
            harness = self.harness(head_files=(snapshot_file("new.md"),))

            def refused_scanner(
                _invocation: authoritative.ScannerInvocation,
                code: str = worker_code,
            ) -> authoritative.ScannerExecution:
                raise authoritative.WorkerRefused(code)

            cases.append(
                (
                    name,
                    harness.reader,
                    harness.acquirer,
                    harness.materializer,
                    refused_scanner,
                    worker_code,
                )
            )

        for name, reader, acquirer, materializer, scanner, code in cases:
            with self.subTest(name=name):
                request = reader.__self__.request
                result = authoritative.run_authoritative_gate(
                    request,
                    snapshot_reader=reader,
                    pull_acquirer=acquirer,
                    snapshot_materializer=materializer,
                    scanner_runner=scanner,
                )
                self.assertEqual(
                    result.verdict,
                    authoritative.GateVerdict.INFRASTRUCTURE_REFUSAL,
                )
                self.assertEqual(result.refusal_code, code)

    def test_base_and_head_read_failures_are_distinguished(self) -> None:
        base_harness = self.harness()

        def refused_base(*_args: object, **_kwargs: object) -> Snapshot:
            raise authoritative.ReaderRefused("object_unavailable")

        base_result = authoritative.run_authoritative_gate(
            base_harness.request,
            snapshot_reader=refused_base,
        )
        self.assertEqual(base_result.refusal_code, "base_reader_refused")

        head_harness = self.harness()

        @contextmanager
        def refused_head(*_args: object, **_kwargs: object):
            raise authoritative.ReaderRefused("object_unavailable")
            yield  # pragma: no cover

        head_result = authoritative.run_authoritative_gate(
            head_harness.request,
            snapshot_reader=head_harness.reader,
            pull_acquirer=refused_head,
        )
        self.assertEqual(head_result.refusal_code, "head_reader_refused")

    def test_acquisition_refusal_is_fixed_and_cleans(self) -> None:
        harness = self.harness()

        @contextmanager
        def refused_acquisition(*_args: object, **_kwargs: object):
            raise AcquisitionRefused("fetch_failed")
            yield  # pragma: no cover

        result = authoritative.run_authoritative_gate(
            harness.request,
            snapshot_reader=harness.reader,
            pull_acquirer=refused_acquisition,
        )

        self.assertEqual(result.refusal_code, "head_acquisition_refused")

    def test_final_report_is_exclusive_and_never_overwrites_evidence(self) -> None:
        harness = self.harness(head_files=(snapshot_file("new.md"),))
        final_path = harness.evidence_root / f"authoritative-report-{HEAD_OID}.json"
        original = b"reviewed evidence\n"
        final_path.write_bytes(original)

        result = harness.run(self.passing_scanner())

        self.assertEqual(
            result.verdict, authoritative.GateVerdict.INFRASTRUCTURE_REFUSAL
        )
        self.assertEqual(result.refusal_code, "report_collision")
        self.assertEqual(final_path.read_bytes(), original)

    def test_acquisition_cleanup_failure_is_infrastructure(self) -> None:
        harness = self.harness()

        @contextmanager
        def cleanup_failure(*_args: object, **_kwargs: object):
            yield AcquiredSnapshot(
                harness.head, "refs/pull/7/head", harness.head_repository
            )
            raise AcquisitionRefused("cleanup_failed")

        result = authoritative.run_authoritative_gate(
            harness.request,
            snapshot_reader=harness.reader,
            pull_acquirer=cleanup_failure,
            snapshot_materializer=harness.materializer,
            scanner_runner=self.passing_scanner(),
        )

        self.assertEqual(
            result.verdict, authoritative.GateVerdict.INFRASTRUCTURE_REFUSAL
        )
        self.assertEqual(result.refusal_code, "cleanup_failed")

    def test_unsafe_overlapping_roots_fail_before_reader(self) -> None:
        harness = self.harness()
        request = authoritative.AuthoritativeGateRequest(
            repository_identity="stacknil/sec-writeups-public",
            pull_number=7,
            base_oid=BASE_OID,
            head_oid=HEAD_OID,
            remote="https://example.com/repository.git",
            trusted_repository=harness.trusted_repository,
            scratch_root=harness.trusted_repository,
            evidence_root=harness.evidence_root,
        )

        result = authoritative.run_authoritative_gate(
            request,
            snapshot_reader=lambda *_args, **_kwargs: self.fail("reader must not run"),
        )

        self.assertEqual(result.refusal_code, "unsafe_root_layout")

    def test_materialized_target_cannot_overlap_head_object_database(self) -> None:
        harness = self.harness(head_files=(snapshot_file("new.md"),))
        materializer_exited = False

        @contextmanager
        def overlapping_materializer(*_args: object, **_kwargs: object):
            nonlocal materializer_exited
            try:
                yield MaterializedSnapshot(harness.head, harness.head_repository)
            finally:
                materializer_exited = True

        result = authoritative.run_authoritative_gate(
            harness.request,
            snapshot_reader=harness.reader,
            pull_acquirer=harness.acquirer,
            snapshot_materializer=overlapping_materializer,
            scanner_runner=lambda _invocation: self.fail("scanner must not run"),
        )

        self.assertEqual(
            result.verdict, authoritative.GateVerdict.INFRASTRUCTURE_REFUSAL
        )
        self.assertEqual(result.refusal_code, "unsafe_root_layout")
        self.assertTrue(materializer_exited)
        self.assertTrue(harness.acquirer_exited)

    def test_default_repr_hides_paths_and_untrusted_strings(self) -> None:
        secret_path = Path("D:/private/control")
        request = authoritative.AuthoritativeGateRequest(
            "owner/repository",
            1,
            BASE_OID,
            HEAD_OID,
            "https://example.invalid/private.git",
            secret_path,
            secret_path / "scratch",
            secret_path / "evidence",
        )
        result = authoritative.AuthoritativeGateResult(
            authoritative.GateVerdict.PASS,
            "owner/repository",
            1,
            BASE_OID,
            HEAD_OID,
            1,
            0,
            "a" * 64,
            1,
            "0.8.1",
            None,
            secret_path / "raw-report.json",
        )

        for rendered in (repr(request), repr(result)):
            self.assertNotIn("private", rendered)
            self.assertNotIn("owner/repository", rendered)
            self.assertNotIn("example.invalid", rendered)


class ScannerRunnerTests(unittest.TestCase):
    def directory(self, prefix: str) -> Path:
        temporary = TemporaryDirectory(prefix=prefix)
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def test_command_is_isolated_array_with_explicit_policy_inputs(self) -> None:
        control = self.directory("scanner-control-")
        target = self.directory("scanner-target-")
        report_root = self.directory("scanner-report-")
        baseline = control / "baseline.json"
        baseline.write_bytes(BASELINE)
        report_path = report_root / "report.json"
        marker = target / "executed"
        for name in (
            "repo_sentinel.py",
            "sitecustomize.py",
            "usercustomize.py",
            "fixture.pth",
        ):
            (target / name).write_text(
                f'from pathlib import Path\nPath(r"{marker}").touch()\n',
                encoding="utf-8",
            )
        calls: list[tuple[list[str], Path]] = []

        def command_runner(
            command: list[str],
            *,
            cwd: Path,
            timeout_seconds: float,
            capture_limit: int,
        ) -> authoritative._CommandResult:
            del timeout_seconds, capture_limit
            calls.append((command, cwd))
            if "--version" in command:
                return authoritative._CommandResult(0, b"repo-sentinel 0.8.1\n", b"")
            report_path.write_text(json.dumps(EMPTY_REPORT) + "\n", encoding="utf-8")
            return authoritative._CommandResult(0, b"", b"")

        invocation = authoritative.ScannerInvocation(
            target,
            ("repo_sentinel.py", "sitecustomize.py", "fixture.pth"),
            baseline,
            report_path,
            control,
            10.0,
            1024,
        )
        with patch.object(
            authoritative, "_run_command_bounded", side_effect=command_runner
        ):
            execution = authoritative._run_trusted_scanner(invocation)

        self.assertEqual(execution.returncode, 0)
        self.assertFalse(marker.exists())
        self.assertEqual(len(calls), 2)
        command, cwd = calls[1]
        self.assertEqual(command[:4], [sys.executable, "-I", "-m", "repo_sentinel"])
        self.assertEqual(cwd, control)
        self.assertNotEqual(cwd, target)
        self.assertIn("--no-default-baseline", command)
        self.assertEqual(command[command.index("--baseline") + 1], str(baseline))
        self.assertEqual(command[command.index("--output") + 1], str(report_path))
        self.assertEqual(
            command[command.index("--") + 1 :], list(invocation.changed_paths)
        )

    def test_real_bounded_command_rejects_timeout_and_output_overflow(self) -> None:
        cwd = self.directory("bounded-command-")
        cases = (
            (
                [sys.executable, "-c", "import time; time.sleep(2)"],
                0.05,
                1024,
                "scanner_timeout",
            ),
            (
                [sys.executable, "-c", "import sys; sys.stdout.write('x' * 4096)"],
                5.0,
                64,
                "scanner_output_limit",
            ),
        )
        for command, timeout, limit, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(authoritative.WorkerRefused) as raised:
                    authoritative._run_command_bounded(
                        command,
                        cwd=cwd,
                        timeout_seconds=timeout,
                        capture_limit=limit,
                    )
                self.assertEqual(raised.exception.code, code)

    @unittest.skipUnless(
        exact_scanner_available(),
        "requires the exact production scanner",
    )
    def test_real_pinned_scanner_keeps_target_python_inert(self) -> None:
        control = self.directory("scanner-real-control-")
        target = self.directory("scanner-real-target-")
        report_root = self.directory("scanner-real-report-")
        marker = target / "target-python-executed"
        marker_code = f'import pathlib; pathlib.Path(r"{marker}").touch()\n'
        for name in (
            "repo_sentinel.py",
            "sitecustomize.py",
            "usercustomize.py",
            "fixture.pth",
        ):
            (target / name).write_text(marker_code, encoding="utf-8")
        for name in ("README.md", "LICENSE", ".gitignore"):
            (target / name).write_text("fixture\n", encoding="utf-8")
        invocation = authoritative.ScannerInvocation(
            target,
            (
                "repo_sentinel.py",
                "sitecustomize.py",
                "usercustomize.py",
                "fixture.pth",
            ),
            None,
            report_root / "report.json",
            control,
            10.0,
            64 * 1024,
        )

        execution = authoritative._run_trusted_scanner(invocation)

        self.assertEqual(execution.returncode, 0)
        self.assertEqual(execution.scanner_version, "0.8.1")
        self.assertFalse(marker.exists())
        report = json.loads(invocation.report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["findings"], [])


def run_git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()


class CrossLayerWorkerTests(unittest.TestCase):
    def test_real_local_acquisition_reader_and_materializer(self) -> None:
        roots = [
            TemporaryDirectory(prefix=f"authoritative-real-{name}-")
            for name in ("repo", "scratch", "evidence")
        ]
        for temporary in roots:
            self.addCleanup(temporary.cleanup)
        repository, scratch, evidence = (Path(item.name) for item in roots)
        run_git(repository, "init", "--quiet")
        run_git(repository, "config", "user.name", "Contract Test")
        run_git(repository, "config", "user.email", "contract@example.com")
        run_git(repository, "config", "commit.gpgsign", "false")
        (repository / "README.md").write_text("Base.\n", encoding="utf-8")
        (repository / "LICENSE").write_text("CC BY 4.0\n", encoding="utf-8")
        (repository / ".gitignore").write_text("\n", encoding="utf-8")
        run_git(repository, "add", "--all")
        run_git(repository, "commit", "--quiet", "-m", "test: base")
        base_oid = run_git(repository, "rev-parse", "HEAD")
        notes = repository / "notes"
        notes.mkdir()
        exact_data = b"exact acquired bytes\x00remain data\n"
        (notes / "safe & exact!.md").write_bytes(exact_data)
        run_git(repository, "add", "--all")
        run_git(repository, "commit", "--quiet", "-m", "test: head")
        head_oid = run_git(repository, "rev-parse", "HEAD")
        run_git(repository, "update-ref", "refs/pull/1/head", head_oid)
        observed: dict[str, object] = {}

        def scanner(
            invocation: authoritative.ScannerInvocation,
        ) -> authoritative.ScannerExecution:
            observed["cwd"] = invocation.execution_directory
            observed["target"] = invocation.target_root
            observed["bytes"] = (
                invocation.target_root / "notes" / "safe & exact!.md"
            ).read_bytes()
            write_report(invocation)
            return scanner_execution()

        request = authoritative.AuthoritativeGateRequest(
            "stacknil/sec-writeups-public",
            1,
            base_oid,
            head_oid,
            repository,
            repository,
            scratch,
            evidence,
        )
        result = authoritative.run_authoritative_gate(request, scanner_runner=scanner)

        self.assertEqual(result.verdict, authoritative.GateVerdict.PASS)
        self.assertEqual(result.changed_count, 1)
        self.assertEqual(observed["bytes"], exact_data)
        self.assertNotEqual(observed["cwd"], observed["target"])
        self.assertFalse(any(scratch.iterdir()))
        self.assertEqual(len(list(evidence.iterdir())), 1)


if __name__ == "__main__":
    unittest.main()
