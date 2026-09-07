from __future__ import annotations

import io
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import repo_sentinel_gate  # noqa: E402


BASELINE_BYTES = b'{"schema_version":1,"findings":[]}\n'
PROTECTED_POLICY_FILES = (".reposentinel.toml", ".reposentinel-baseline.json")


def run_git(repository: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()


def initialize_repository(repository: Path, *, with_baseline: bool = True) -> str:
    run_git(repository, "init", "--quiet")
    run_git(repository, "config", "user.name", "Contract Test")
    run_git(repository, "config", "user.email", "contract@example.com")
    run_git(repository, "config", "commit.gpgsign", "false")

    (repository / "README.md").write_text("Fixture repository.\n", encoding="utf-8")
    (repository / "LICENSE").write_text("CC BY 4.0\n", encoding="utf-8")
    (repository / ".gitignore").write_text("\n", encoding="utf-8")
    (repository / ".reposentinel.toml").write_text(
        'ignore_globs = [".reposentinel-baseline.json"]\n',
        encoding="utf-8",
    )
    notes = repository / "notes"
    notes.mkdir()
    (notes / "existing.md").write_text("Existing note.\n", encoding="utf-8")
    if with_baseline:
        (repository / ".reposentinel-baseline.json").write_bytes(BASELINE_BYTES)

    run_git(repository, "add", "--all")
    run_git(repository, "commit", "--quiet", "-m", "test: base")
    return run_git(repository, "rev-parse", "HEAD")


def commit(repository: Path, message: str) -> str:
    run_git(repository, "add", "--all")
    run_git(repository, "commit", "--quiet", "-m", message)
    return run_git(repository, "rev-parse", "HEAD")


class RepoSentinelGatePlanTests(unittest.TestCase):
    def repository(self, *, with_baseline: bool = True) -> tuple[Path, str]:
        temporary = TemporaryDirectory(prefix="repo-sentinel-gate-")
        self.addCleanup(temporary.cleanup)
        repository = Path(temporary.name)
        return repository, initialize_repository(repository, with_baseline=with_baseline)

    def test_plan_uses_base_baseline_and_deterministic_changed_paths(self) -> None:
        repository, base_sha = self.repository()
        (repository / "notes" / "z-last.md").write_text("Last.\n", encoding="utf-8")
        (repository / "notes" / "a-first.md").write_text("First.\n", encoding="utf-8")
        head_sha = commit(repository, "test: add notes")

        # The working tree is untrusted; read the baseline blob from base_sha.
        (repository / ".reposentinel-baseline.json").write_text(
            '{"untrusted":"working-tree"}\n', encoding="utf-8"
        )
        plan = repo_sentinel_gate.build_gate_plan(repository, base_sha, head_sha)

        self.assertEqual(
            plan.changed_files,
            ("notes/a-first.md", "notes/z-last.md"),
        )
        self.assertEqual(plan.deleted_files, ())
        self.assertEqual(plan.trusted_baseline, BASELINE_BYTES)

    def test_base_without_baseline_disables_default_baseline(self) -> None:
        repository, base_sha = self.repository(with_baseline=False)
        (repository / "notes" / "new.md").write_text("New.\n", encoding="utf-8")
        head_sha = commit(repository, "test: add note")

        plan = repo_sentinel_gate.build_gate_plan(repository, base_sha, head_sha)

        self.assertIsNone(plan.trusted_baseline)

    def test_pull_request_baseline_cannot_self_suppress(self) -> None:
        repository, base_sha = self.repository()
        (repository / ".reposentinel-baseline.json").write_text(
            '{"untrusted":"head-suppression"}\n', encoding="utf-8"
        )
        head_sha = commit(repository, "test: attempt head suppression")

        with self.assertRaises(repo_sentinel_gate.ProtectedPolicyChange):
            repo_sentinel_gate.build_gate_plan(repository, base_sha, head_sha)

    def test_checked_out_tree_must_match_requested_head(self) -> None:
        repository, base_sha = self.repository()
        (repository / "notes" / "new.md").write_text("New.\n", encoding="utf-8")
        head_sha = commit(repository, "test: add note")
        run_git(repository, "checkout", "--quiet", "--detach", base_sha)

        with self.assertRaises(repo_sentinel_gate.CheckoutMismatch):
            repo_sentinel_gate.build_gate_plan(repository, base_sha, head_sha)

    def test_graph_plan_does_not_require_a_target_checkout(self) -> None:
        repository, base_sha = self.repository()
        (repository / "notes" / "new.md").write_text("New.\n", encoding="utf-8")
        head_sha = commit(repository, "test: add note")
        run_git(repository, "checkout", "--quiet", "--detach", base_sha)

        plan = repo_sentinel_gate.build_gate_plan_from_graph(
            repository, base_sha, head_sha
        )

        self.assertEqual(plan.changed_files, ("notes/new.md",))
        self.assertEqual(plan.trusted_baseline, BASELINE_BYTES)

    def test_graph_plan_ignores_local_replace_refs(self) -> None:
        repository, base_sha = self.repository()
        (repository / "notes" / "new.md").write_text("New.\n", encoding="utf-8")
        head_sha = commit(repository, "test: add note")
        baseline_oid = run_git(
            repository, "rev-parse", f"{base_sha}:.reposentinel-baseline.json"
        )
        replacement = repository / "replacement.json"
        replacement.write_text('{"untrusted":"replacement"}\n', encoding="utf-8")
        replacement_oid = run_git(repository, "hash-object", "-w", str(replacement))
        run_git(repository, "replace", baseline_oid, replacement_oid)

        plan = repo_sentinel_gate.build_gate_plan_from_graph(
            repository, base_sha, head_sha
        )

        self.assertEqual(plan.trusted_baseline, BASELINE_BYTES)

    def test_protected_policy_changes_fail_closed(self) -> None:
        for path in PROTECTED_POLICY_FILES:
            for operation in ("modify", "delete", "rename"):
                with self.subTest(path=path, operation=operation):
                    repository, base_sha = self.repository()
                    target = repository / path
                    if operation == "modify":
                        target.write_bytes(target.read_bytes() + b"\n")
                    elif operation == "delete":
                        target.unlink()
                    else:
                        target.rename(repository / f"{path}.moved")
                    head_sha = commit(repository, f"test: {operation} {path}")

                    with self.assertRaises(
                        repo_sentinel_gate.ProtectedPolicyChange
                    ) as raised:
                        repo_sentinel_gate.build_gate_plan(
                            repository, base_sha, head_sha
                        )
                    self.assertIn(path, raised.exception.paths)

    def test_deletion_only_is_explicitly_audit_only(self) -> None:
        repository, base_sha = self.repository()
        (repository / "notes" / "existing.md").unlink()
        head_sha = commit(repository, "test: delete note")
        scanner_calls: list[repo_sentinel_gate.GatePlan] = []
        report_path = repository / "report.txt"
        report_path.write_text("stale report\n", encoding="utf-8")

        def scanner(
            plan: repo_sentinel_gate.GatePlan,
            _repository: Path,
            _report_path: Path,
        ) -> int:
            scanner_calls.append(plan)
            return 0

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = repo_sentinel_gate.run_gate(
                repository,
                base_sha,
                head_sha,
                report_path,
                scanner_runner=scanner,
            )

        self.assertEqual(status, 0)
        self.assertEqual(scanner_calls, [])
        self.assertIn("Deleted files (audit-only): 1", stdout.getvalue())
        self.assertIn("not sent to the changed-file scanner", stdout.getvalue())
        self.assertIn("Baseline audit (non-blocking)", stdout.getvalue())
        self.assertFalse(report_path.exists())

    def test_report_cleanup_cannot_delete_a_tracked_scan_input(self) -> None:
        repository, base_sha = self.repository()
        report_path = repository / "report.txt"
        original = b"Tracked pull request content must be scanned.\n"
        report_path.write_bytes(original)
        head_sha = commit(repository, "test: add tracked report path")

        with self.assertRaises(repo_sentinel_gate.UnsafeReportPath):
            repo_sentinel_gate.run_gate(
                repository, base_sha, head_sha, report_path,
                scanner_runner=lambda *_args: 0,
            )

        self.assertEqual(report_path.read_bytes(), original)

    def test_report_cleanup_cannot_follow_a_symbolic_link(self) -> None:
        repository, base_sha = self.repository()
        target = repository / "untracked.txt"
        original = b"Keep untracked user content.\n"
        target.write_bytes(original)
        report_path = repository / "report.txt"
        try:
            report_path.symlink_to(target)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")

        with self.assertRaises(repo_sentinel_gate.UnsafeReportPath):
            repo_sentinel_gate.run_gate(
                repository, base_sha, base_sha, report_path,
                scanner_runner=lambda *_args: 0,
            )

        self.assertTrue(report_path.is_symlink())
        self.assertEqual(target.read_bytes(), original)

    def test_rename_scans_destination_and_audits_source(self) -> None:
        repository, base_sha = self.repository()
        (repository / "notes" / "existing.md").rename(
            repository / "notes" / "new.md"
        )
        head_sha = commit(repository, "test: rename note")
        scanner_calls: list[repo_sentinel_gate.GatePlan] = []

        def scanner(
            plan: repo_sentinel_gate.GatePlan,
            _repository: Path,
            report_path: Path,
        ) -> int:
            scanner_calls.append(plan)
            report_path.write_text("Synthetic scanner report.\n", encoding="utf-8")
            return 0

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = repo_sentinel_gate.run_gate(
                repository,
                base_sha,
                head_sha,
                repository / "report.txt",
                scanner_runner=scanner,
            )

        self.assertEqual(status, 0)
        self.assertEqual(len(scanner_calls), 1)
        self.assertEqual(scanner_calls[0].changed_files, ("notes/new.md",))
        self.assertEqual(scanner_calls[0].deleted_files, ("notes/existing.md",))
        self.assertIn("Synthetic scanner report.", stdout.getvalue())

    def test_scanner_command_keeps_only_errors_blocking(self) -> None:
        repository, _base_sha = self.repository()
        report_path = repository / "report.txt"
        captured: list[tuple[list[str], Path]] = []

        def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
            captured.append((command, Path(_kwargs["cwd"])))
            if "--baseline" in command:
                baseline_index = command.index("--baseline") + 1
                self.assertEqual(
                    Path(command[baseline_index]).read_bytes(), BASELINE_BYTES
                )
            return subprocess.CompletedProcess(command, 0)

        with patch.object(repo_sentinel_gate.subprocess, "run", side_effect=run):
            trusted_status = repo_sentinel_gate._run_repo_sentinel(
                repo_sentinel_gate.GatePlan(
                    ("notes/new.md",), (), BASELINE_BYTES
                ),
                repository,
                report_path,
                execution_directory=repository.parent,
            )
            untrusted_status = repo_sentinel_gate._run_repo_sentinel(
                repo_sentinel_gate.GatePlan(("notes/new.md",), (), None),
                repository,
                report_path,
            )

        self.assertEqual((trusted_status, untrusted_status), (0, 0))
        self.assertEqual(len(captured), 2)
        command = captured[0][0]
        for invocation, _cwd in captured:
            self.assertEqual(
                invocation[:4], [sys.executable, "-I", "-m", "repo_sentinel"]
            )
            self.assertIn(str(repository), invocation)
        self.assertIn("--changed-files", command)
        severity_index = command.index("--fail-on-severity")
        self.assertEqual(command[severity_index + 1], "error")
        self.assertNotIn("warning", command)
        self.assertEqual(captured[0][1], repository.parent)
        self.assertEqual(captured[1][1], repository)
        self.assertIn("--no-default-baseline", captured[1][0])
        self.assertNotIn("--baseline", captured[1][0])

    def test_scanner_failure_status_is_preserved(self) -> None:
        repository, base_sha = self.repository()
        (repository / "notes" / "new.md").write_text("New.\n", encoding="utf-8")
        head_sha = commit(repository, "test: add note")

        def scanner(
            _plan: repo_sentinel_gate.GatePlan,
            _repository: Path,
            _report_path: Path,
        ) -> int:
            return 7

        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = repo_sentinel_gate.run_gate(
                repository,
                base_sha,
                head_sha,
                repository / "report.txt",
                scanner_runner=scanner,
            )

        self.assertEqual(status, 7)
        self.assertIn("error findings block", stderr.getvalue())
