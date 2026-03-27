#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from run_markdownlint import resolve_markdownlint_launcher

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_SOURCE = ROOT / ".markdownlint-cli2-debt.jsonc"
DEFAULT_OUTPUT = ROOT / "reports" / "markdownlint-debt-current-local.txt"
SUPPORTED_CONFIG_NAME = "markdownlint-debt.markdownlint-cli2.jsonc"
BATCH_SIZE = 20
SUMMARY_RE = re.compile(r"^Summary:\s+(?P<count>\d+)\s+error\(s\)$")


def resolve_repo_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    return path.resolve()


def build_report(stdout: str, stderr: str, returncode: int) -> str:
    parts = [part.rstrip() for part in (stdout, stderr) if part.strip()]
    if parts:
        return "\n".join(parts) + "\n"

    if returncode == 0:
        return "Summary: 0 error(s)\n"

    return "markdownlint-cli2 exited with a non-zero status and produced no output.\n"


def load_jsonc_config(path: Path) -> dict:
    lines: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("//"):
            continue
        lines.append(line)
    return json.loads("\n".join(lines))


def tracked_markdown_files() -> list[str]:
    completed = subprocess.run(
        ["git", "-c", "core.quotepath=false", "ls-files", "-z", "--", "*.md"],
        cwd=ROOT,
        shell=False,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        print(stderr or "git ls-files failed", file=sys.stderr)
        raise SystemExit(completed.returncode)

    return [
        entry
        for entry in completed.stdout.decode("utf-8", errors="replace").split("\0")
        if entry.strip()
    ]


def batched(items: list[str], size: int) -> list[list[str]]:
    return [items[index : index + size] for index in range(0, len(items), size)]


def run_markdownlint(
    launcher: list[str],
    temp_config: Path,
    markdownlint_args: list[str],
) -> subprocess.CompletedProcess[str]:
    cmd = [
        *launcher,
        "--yes",
        "markdownlint-cli2@0.18.1",
        "--config",
        str(temp_config),
        *markdownlint_args,
    ]
    return subprocess.run(
        cmd,
        cwd=ROOT,
        shell=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def collect_chunk_findings(output: str) -> tuple[str | None, int, list[str]]:
    version_line: str | None = None
    error_count = 0
    findings: list[str] = []

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("markdownlint-cli2 v"):
            version_line = version_line or stripped
            continue
        if stripped.startswith("Finding:") or stripped.startswith("Linting:"):
            continue
        summary_match = SUMMARY_RE.match(stripped)
        if summary_match:
            error_count += int(summary_match.group("count"))
            continue
        findings.append(line.rstrip())

    return version_line, error_count, findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the repo-wide markdownlint debt audit using a temporary config file name "
            "that markdownlint-cli2 accepts, then write the combined report to disk."
        )
    )
    parser.add_argument(
        "--config-source",
        default=str(DEFAULT_CONFIG_SOURCE),
        help=(
            "Path to the source markdownlint config. Defaults to "
            f"{DEFAULT_CONFIG_SOURCE.relative_to(ROOT).as_posix()}."
        ),
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=(
            "Path for the generated debt report. Defaults to "
            f"{DEFAULT_OUTPUT.relative_to(ROOT).as_posix()}."
        ),
    )
    parser.add_argument(
        "markdownlint_args",
        nargs="*",
        help="Optional extra arguments passed through to markdownlint-cli2.",
    )
    args = parser.parse_args()

    config_source = resolve_repo_path(args.config_source)
    if not config_source.exists():
        print(f"Missing markdownlint config source: {config_source}", file=sys.stderr)
        return 2

    output_path = resolve_repo_path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    launcher = resolve_markdownlint_launcher()
    markdownlint_args = list(args.markdownlint_args)
    config_data = load_jsonc_config(config_source)

    with tempfile.TemporaryDirectory(prefix="markdownlint-debt-") as temp_dir:
        temp_config = Path(temp_dir) / SUPPORTED_CONFIG_NAME
        if markdownlint_args:
            config_data.pop("globs", None)
            temp_config.write_text(json.dumps(config_data, indent=2) + "\n", encoding="utf-8")
            completed = run_markdownlint(launcher, temp_config, markdownlint_args)
            report = build_report(completed.stdout, completed.stderr, completed.returncode)
            returncode = completed.returncode
        else:
            tracked_files = tracked_markdown_files()
            if not tracked_files:
                report = "Summary: 0 error(s)\n"
                returncode = 0
            else:
                config_data.pop("globs", None)
                temp_config.write_text(json.dumps(config_data, indent=2) + "\n", encoding="utf-8")

                version_line: str | None = None
                total_errors = 0
                findings: list[str] = []
                returncode = 0

                for chunk in batched(tracked_files, BATCH_SIZE):
                    completed = run_markdownlint(launcher, temp_config, chunk)
                    combined_output = "\n".join(
                        part.rstrip()
                        for part in (completed.stdout, completed.stderr)
                        if part.strip()
                    )
                    chunk_version, chunk_errors, chunk_findings = collect_chunk_findings(
                        combined_output
                    )
                    version_line = version_line or chunk_version
                    total_errors += chunk_errors
                    findings.extend(chunk_findings)
                    if completed.returncode and returncode == 0:
                        returncode = completed.returncode

                header = version_line or "markdownlint-cli2 v0.18.1 (markdownlint v0.38.0)"
                lines = [
                    header,
                    "Finding: tracked Markdown files from git ls-files",
                    f"Linting: {len(tracked_files)} file(s)",
                    f"Summary: {total_errors} error(s)",
                ]
                if findings:
                    lines.extend(findings)
                report = "\n".join(lines) + "\n"

    output_path.write_text(report, encoding="utf-8")

    try:
        display_output = output_path.relative_to(ROOT).as_posix()
    except ValueError:
        display_output = str(output_path)
    print(f"Wrote markdownlint debt report to {display_output}")
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
