#!/usr/bin/env python3
"""Run the trusted-base Repo Sentinel pull-request gate."""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory


PROTECTED_POLICY_FILES = frozenset(
    {
        ".reposentinel.toml",
        ".reposentinel-baseline.json",
    }
)


@dataclass(frozen=True)
class GatePlan:
    """Deterministic inputs for one changed-file gate run."""

    changed_files: tuple[str, ...]
    deleted_files: tuple[str, ...]
    trusted_baseline: bytes | None = field(repr=False)


class ProtectedPolicyChange(RuntimeError):
    """Raised when a pull request changes trusted scanner policy."""

    def __init__(self, paths: Sequence[str]) -> None:
        self.paths = tuple(sorted(paths))
        joined = ", ".join(self.paths)
        super().__init__(f"protected security policy changed: {joined}")


class CheckoutMismatch(RuntimeError):
    """Raised when the scanner worktree is not the requested head commit."""


class UnsafeReportPath(ValueError):
    """Raised when report cleanup could remove a repository input."""


ScannerRunner = Callable[[GatePlan, Path, Path], int]


def _run_git(
    repository: Path,
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=check,
        capture_output=True,
    )


def _decode_paths(output: bytes) -> tuple[str, ...]:
    paths = {
        item.decode("utf-8", errors="surrogateescape")
        for item in output.split(b"\0")
        if item
    }
    return tuple(sorted(paths))


def _diff_paths(
    repository: Path,
    base_sha: str,
    head_sha: str,
    diff_filter: str,
) -> tuple[str, ...]:
    result = _run_git(
        repository,
        "diff",
        "--name-only",
        f"--diff-filter={diff_filter}",
        "--no-renames",
        "-z",
        base_sha,
        head_sha,
    )
    return _decode_paths(result.stdout)


def _read_trusted_baseline(repository: Path, base_sha: str) -> bytes | None:
    object_name = f"{base_sha}:.reposentinel-baseline.json"
    exists = _run_git(repository, "cat-file", "-e", object_name, check=False)
    if exists.returncode != 0:
        return None
    return _run_git(repository, "show", object_name).stdout


def build_gate_plan(
    repository: Path,
    base_sha: str,
    head_sha: str,
) -> GatePlan:
    """Build a gate plan using only the committed base/head graph."""

    repository = repository.resolve()
    checked_out_head = _run_git(
        repository, "rev-parse", "--verify", "HEAD^{commit}"
    ).stdout.strip()
    requested_head = _run_git(
        repository, "rev-parse", "--verify", f"{head_sha}^{{commit}}"
    ).stdout.strip()
    if checked_out_head != requested_head:
        raise CheckoutMismatch("checked-out HEAD does not match requested HEAD_SHA")

    policy_changes = _diff_paths(
        repository,
        base_sha,
        head_sha,
        "ACMRTD",
    )
    protected_changes = PROTECTED_POLICY_FILES.intersection(policy_changes)
    if protected_changes:
        raise ProtectedPolicyChange(tuple(protected_changes))

    changed_files = _diff_paths(repository, base_sha, head_sha, "ACMRT")
    deleted_files = _diff_paths(repository, base_sha, head_sha, "D")
    return GatePlan(
        changed_files=changed_files,
        deleted_files=deleted_files,
        trusted_baseline=(
            _read_trusted_baseline(repository, base_sha) if changed_files else None
        ),
    )


def _run_repo_sentinel(
    plan: GatePlan,
    repository: Path,
    report_path: Path,
) -> int:
    baseline_arguments = ["--no-default-baseline"]
    with TemporaryDirectory(prefix="repo-sentinel-base-") as temporary:
        if plan.trusted_baseline is not None:
            baseline_path = Path(temporary) / "baseline.json"
            baseline_path.write_bytes(plan.trusted_baseline)
            baseline_arguments = ["--baseline", str(baseline_path)]

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_sentinel",
                "scan",
                *baseline_arguments,
                "--changed-files",
                "--fail-on-severity",
                "error",
                "--format",
                "text",
                "--output",
                str(report_path),
                ".",
                "--",
                *plan.changed_files,
            ],
            cwd=repository,
            check=False,
        )
    return result.returncode


def _prepare_report(repository: Path, report_path: Path) -> Path:
    if report_path.is_symlink():
        raise UnsafeReportPath("report output must not be a symbolic link")
    report_path = report_path.resolve()
    if report_path.is_relative_to(repository):
        relative = report_path.relative_to(repository)
        tracked = _run_git(
            repository, "ls-files", "--cached", "-z", "--",
            f":(literal){relative.as_posix()}",
        ).stdout
        if tracked or (relative.parts and relative.parts[0].casefold() == ".git"):
            raise UnsafeReportPath("report output must not replace tracked or Git files")
    if report_path.is_file():
        report_path.unlink()
    return report_path


def run_gate(
    repository: Path,
    base_sha: str,
    head_sha: str,
    report_path: Path,
    *,
    scanner_runner: ScannerRunner = _run_repo_sentinel,
) -> int:
    """Run the gate and preserve the scanner's blocking exit status."""

    repository = repository.resolve()
    report_path = _prepare_report(repository, report_path)
    plan = build_gate_plan(repository, base_sha, head_sha)

    print(f"Changed files: {len(plan.changed_files)}")
    print(f"Deleted files (audit-only): {len(plan.deleted_files)}")
    if plan.deleted_files:
        print(
            "Deleted paths are not sent to the changed-file scanner; "
            "repository-level effects remain visible in Baseline audit "
            "(non-blocking)."
        )

    if not plan.changed_files:
        print("No non-deleted changed files; the blocking gate has nothing to scan.")
        return 0

    if plan.trusted_baseline is None:
        print("No baseline at BASE_SHA; PR-head default baseline is disabled.")
    else:
        print("Using .reposentinel-baseline.json from BASE_SHA.")

    status = scanner_runner(plan, repository, report_path)
    if report_path.is_file():
        print(report_path.read_text(encoding="utf-8"), end="")

    if status != 0:
        message = "Changed-file error findings block this pull request."
        print(message, file=sys.stderr)
        return status

    print("Changed-file error gate passed; warnings and coverage skips are report-only.")
    return 0


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    description = "Run the trusted-base Repo Sentinel pull-request gate."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("repo-sentinel-changed.txt"),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    report_path = args.output
    if not report_path.is_absolute():
        report_path = repository / report_path

    try:
        return run_gate(
            repository,
            args.base_sha,
            args.head_sha,
            report_path,
        )
    except ProtectedPolicyChange as error:
        for path in error.paths:
            print(f"Protected security policy changed: {path}", file=sys.stderr)
        print(
            "Require dedicated policy review before this pull request can merge.",
            file=sys.stderr,
        )
        return 1
    except (CheckoutMismatch, UnsafeReportPath) as error:
        print(f"Repo Sentinel gate refused unsafe inputs: {error}", file=sys.stderr)
        return 2
    except (OSError, subprocess.CalledProcessError, UnicodeError) as error:
        print(f"Repo Sentinel gate could not establish trusted inputs: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
