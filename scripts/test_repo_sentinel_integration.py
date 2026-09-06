"""Exercise the published repo-sentinel consumer contract with synthetic data."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from repo_sentinel_gate import GatePlan, _run_repo_sentinel


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


def _check_import_isolation(repository: Path, token: str) -> None:
    marker = repository / "shadow-module-executed"
    (repository / "repo_sentinel.py").write_text(
        'from pathlib import Path\nPath("shadow-module-executed").touch()\n',
        encoding="utf-8",
    )
    report_path = repository / "isolated.txt"
    status = _run_repo_sentinel(
        GatePlan(("repo_sentinel.py", "synthetic.txt"), (), None),
        repository,
        report_path,
    )
    if marker.exists():
        raise AssertionError("scanner executed the fixture's shadow module")
    if status != 1 or not report_path.is_file():
        raise AssertionError("isolated scanner did not report the error fixture")
    report = report_path.read_text(encoding="utf-8")
    if "synthetic.txt" not in report or "<redacted:sha256:" not in report:
        raise AssertionError("isolated scanner lost the expected redacted finding")
    if token in report:
        raise AssertionError("isolated scanner exposed the synthetic token")
    print("scanner import isolation: passed")


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
        _check_import_isolation(repository, token)


if __name__ == "__main__":
    main()
