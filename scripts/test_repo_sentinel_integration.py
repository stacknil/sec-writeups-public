"""Exercise the published repo-sentinel consumer contract with synthetic data."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def _run_scan(repository: Path, report_path: Path, *extra: str) -> tuple[int, dict[str, object]]:
    command = [
        sys.executable,
        "-m",
        "repo_sentinel",
        "scan",
        "--no-default-baseline",
        "--format",
        "json",
        "--output",
        str(report_path),
        *extra,
        str(repository),
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    return result.returncode, report


def _write_minimum_repository(repository: Path) -> None:
    (repository / "README.md").write_text("Synthetic repository fixture.\n", encoding="utf-8")
    (repository / "LICENSE").write_text("CC BY 4.0\n", encoding="utf-8")
    (repository / ".gitignore").write_text("\n", encoding="utf-8")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="repo-sentinel-contract-") as temporary:
        repository = Path(temporary)
        _write_minimum_repository(repository)

        pass_status, pass_report = _run_scan(
            repository,
            repository / "pass.json",
            "--fail-on-severity",
            "error",
        )
        if pass_status != 0 or pass_report["findings"]:
            raise AssertionError("synthetic PASS fixture produced an unexpected finding")
        print("synthetic PASS: passed")

        token = base64.urlsafe_b64encode(
            hashlib.sha256(b"repo-sentinel synthetic fixture").digest()
        ).decode("ascii")
        (repository / "synthetic.txt").write_text(
            f"SYNTHETIC_VALUE={token}\n",
            encoding="utf-8",
        )

        fail_status, fail_report = _run_scan(
            repository,
            repository / "fail.json",
            "--fail-on-severity",
            "error",
        )
        findings = fail_report["findings"]
        if fail_status == 0 or not findings:
            raise AssertionError("synthetic FAIL fixture did not fail")
        print("synthetic FAIL: passed")

        serialized = json.dumps(fail_report, sort_keys=True)
        if token in serialized:
            raise AssertionError("redaction contract exposed the synthetic token")
        first_finding = findings[0]
        redacted_token = first_finding["token"]
        if not isinstance(redacted_token, str) or not redacted_token.startswith(
            "<redacted:sha256:"
        ):
            raise AssertionError("redaction contract did not emit a redacted token")
        print("redaction: passed")


if __name__ == "__main__":
    main()
