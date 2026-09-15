"""Orchestrate exact-commit authority from a sanitized trusted process."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import ModuleType

CONTROLLER_SCHEMA_VERSION = 1
REPOSITORY_ID = 1_130_304_545
OWNER_ID = 219_124_580
REPOSITORY = "stacknil/sec-writeups-public"
REMOTE_URL = "https://github.com/stacknil/sec-writeups-public.git"
POLICY_EPOCH = "v1"
WORKER_POLICY_EPOCH = "repo-sentinel-authority-v1"
POLICY_BUNDLE_SHA256 = (
    "6f25ebb773ce1453e8de623bca5aaecc936f1f188288f8df20aedeadb3bf4612"
)
SCANNER_ARTIFACT_SHA256 = (
    "0a949a4d00c6e6ae37eba60a6cb74e4e15bc3ec5fce2f1d4c99aa0ef309b36e3"
)
EXPECTED_RUNTIME = ("cpython", "3.12.3", "Linux", "x86_64")
FIXED_ENVIRONMENT = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "TZ": "UTC",
}

_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_DECIMAL = re.compile(r"[0-9]+\Z")
_SAFE_GIT_VERSION = re.compile(
    r"git version [0-9]+(?:\.[0-9]+)+(?:\.[-+0-9A-Za-z.]+)?\n?\Z"
)
_WORKER_SEMANTIC_DOMAIN = b"repo-sentinel-commit-authority-result-v1\0"
_POLICY_REFUSALS = frozenset(
    {
        "coverage_policy_mismatch",
        "policy_bundle_mirror_mismatch",
        "protected_control_mismatch",
        "suppression_manifest_mismatch",
    }
)
_REFUSAL_CODES = frozenset(
    {
        "acquired_head_mismatch",
        "acquisition_refused",
        "cleanup_failed",
        "environment_mismatch",
        "git_identity_mismatch",
        "invalid_head_oid",
        "invalid_request",
        "launch_not_isolated",
        "policy_bundle_mismatch",
        "repository_identity_mismatch",
        "runtime_mismatch",
        "unsafe_control_root",
        "unsafe_root_layout",
        "unexpected_failure",
        "unknown_policy_epoch",
        "worker_infrastructure_refusal",
        "worker_result_invalid",
    }
)
_REQUEST_OPTIONS = (
    "--repository-id",
    "--owner-id",
    "--repository",
    "--remote-url",
    "--pull-number",
    "--head-oid",
    "--policy-epoch",
    "--policy-bundle-sha256",
    "--scratch-root",
    "--scanner-artifact",
)
_WORKER_RESULT_KEYS = frozenset(
    {
        "coverage_policy_sha256",
        "files_policy_excluded",
        "files_scanned",
        "files_scanner_skipped",
        "files_total",
        "head_oid",
        "policy_bundle_sha256",
        "policy_epoch",
        "policy_schema_version",
        "protected_manifest_sha256",
        "refusal_code",
        "report_sha256",
        "report_size",
        "repository_id",
        "scanner_artifact_sha256",
        "scanner_distribution",
        "scanner_version",
        "semantic_sha256",
        "suppression_manifest_sha256",
        "verdict",
    }
)
_TRUSTED_MODULE_PATHS = {
    "repo_sentinel_acquire": "repo_sentinel_acquire.py",
    "repo_sentinel_commit_authoritative": "repo_sentinel_commit_authoritative.py",
    "repo_sentinel_materialize": "repo_sentinel_materialize.py",
    "repo_sentinel_policy_bundle": "repo_sentinel_policy_bundle.py",
    "repo_sentinel_reader": "repo_sentinel_reader.py",
}


class ControllerOutcome(str, Enum):
    AUTHORITY_RESULT = "AUTHORITY_RESULT"
    INFRASTRUCTURE_REFUSAL = "INFRASTRUCTURE_REFUSAL"


class ControllerRefused(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code if code in _REFUSAL_CODES else "unexpected_failure"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class ControllerRequest:
    repository_id: int
    owner_id: int
    repository: str
    remote_url: str = field(repr=False)
    pull_number: int
    head_oid: str
    policy_epoch: str
    expected_policy_bundle_sha256: str = field(repr=False)
    scratch_root: Path = field(repr=False)
    scanner_artifact: Path = field(repr=False)


@dataclass(frozen=True, slots=True)
class ControllerResult:
    controller_schema_version: int
    repository_id: int
    head_oid: str | None
    policy_epoch: str | None
    policy_bundle_sha256: str
    worker_result: dict[str, object] | None
    worker_semantic_sha256: str | None
    controller_outcome: ControllerOutcome
    fixed_refusal_code: str | None


@dataclass(frozen=True, slots=True)
class RuntimeFacts:
    implementation: str
    python_version: str
    os_family: str
    architecture: str


@dataclass(frozen=True, slots=True)
class ControllerWorkspace:
    root: Path = field(repr=False)
    acquisition: Path = field(repr=False)
    worker: Path = field(repr=False)


@dataclass(frozen=True, slots=True)
class TrustedStack:
    acquire_pull_snapshot: Callable[..., Iterator[object]]
    acquisition_refused: type[Exception]
    worker_request: Callable[..., object]
    run_worker: Callable[[object], object]
    render_worker: Callable[[object], dict[str, object]]


RuntimeFactsProvider = Callable[[], RuntimeFacts]
GitProbe = Callable[[Path], None]
WorkspaceFactory = Callable[[Path], Iterator[ControllerWorkspace]]


def current_runtime_facts() -> RuntimeFacts:
    return RuntimeFacts(
        sys.implementation.name,
        platform.python_version(),
        platform.system(),
        platform.machine(),
    )


def _has_reparse(info: os.stat_result) -> bool:
    return bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _without_aliases(path: Path, *, directory: bool) -> Path:
    if not path.is_absolute():
        raise ControllerRefused("unsafe_root_layout")
    current = path
    while True:
        try:
            info = current.lstat()
        except OSError:
            raise ControllerRefused("unsafe_root_layout") from None
        if stat.S_ISLNK(info.st_mode) or _has_reparse(info):
            raise ControllerRefused("unsafe_root_layout")
        if current.parent == current:
            break
        current = current.parent
    try:
        resolved = path.resolve(strict=True)
        info = resolved.lstat()
    except OSError:
        raise ControllerRefused("unsafe_root_layout") from None
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if _has_reparse(info) or not expected(info.st_mode):
        raise ControllerRefused("unsafe_root_layout")
    return resolved


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _control_root() -> Path:
    source = Path(__file__)
    if not source.is_absolute():
        raise ControllerRefused("unsafe_control_root")
    try:
        controller = _without_aliases(source, directory=False)
        root = _without_aliases(controller.parent.parent, directory=True)
    except ControllerRefused:
        raise ControllerRefused("unsafe_control_root") from None
    if controller != root / "scripts" / Path(__file__).name:
        raise ControllerRefused("unsafe_control_root")
    return root


def _validate_launch(runtime_facts_provider: RuntimeFactsProvider) -> None:
    flags = sys.flags
    if not (
        flags.isolated
        and flags.ignore_environment
        and flags.no_user_site
        and flags.no_site
        and flags.safe_path
        and flags.dont_write_bytecode
    ):
        raise ControllerRefused("launch_not_isolated")
    if dict(os.environ) != FIXED_ENVIRONMENT:
        raise ControllerRefused("environment_mismatch")
    facts = runtime_facts_provider()
    if (
        facts.implementation,
        facts.python_version,
        facts.os_family,
        facts.architecture,
    ) != EXPECTED_RUNTIME:
        raise ControllerRefused("runtime_mismatch")
    try:
        _without_aliases(Path(sys.executable), directory=False)
    except ControllerRefused:
        raise ControllerRefused("runtime_mismatch") from None


def _trusted_git_probe(control_root: Path) -> None:
    expected = Path("/usr/bin/git")
    selected = shutil.which("git", path=FIXED_ENVIRONMENT["PATH"])
    if selected != str(expected):
        raise ControllerRefused("git_identity_mismatch")
    try:
        if _without_aliases(expected, directory=False) != expected:
            raise ControllerRefused("git_identity_mismatch")
        completed = subprocess.run(
            [str(expected), "--version"],
            cwd=control_root,
            env=FIXED_ENVIRONMENT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except (ControllerRefused, OSError, subprocess.TimeoutExpired):
        raise ControllerRefused("git_identity_mismatch") from None
    try:
        version = completed.stdout.decode("ascii", "strict")
    except UnicodeDecodeError:
        raise ControllerRefused("git_identity_mismatch") from None
    if (
        completed.returncode != 0
        or len(completed.stdout) > 128
        or _SAFE_GIT_VERSION.fullmatch(version) is None
    ):
        raise ControllerRefused("git_identity_mismatch")


def _validated_control_file(root: Path, relative: str) -> Path:
    expected = root.joinpath(*relative.split("/"))
    try:
        resolved = _without_aliases(expected, directory=False)
    except ControllerRefused:
        raise ControllerRefused("unsafe_control_root") from None
    if resolved != expected:
        raise ControllerRefused("unsafe_control_root")
    return resolved


def _load_module(name: str, expected: Path) -> ModuleType:
    existing = sys.modules.get(name)
    module = existing if existing is not None else importlib.import_module(name)
    module_file = getattr(module, "__file__", None)
    if type(module_file) is not str:
        raise ControllerRefused("unsafe_control_root")
    try:
        actual = _without_aliases(Path(module_file), directory=False)
    except ControllerRefused:
        raise ControllerRefused("unsafe_control_root") from None
    if actual != expected:
        raise ControllerRefused("unsafe_control_root")
    return module


def load_trusted_stack(control_root: Path) -> TrustedStack:
    scripts = _without_aliases(control_root / "scripts", directory=True)
    expected = {
        name: _validated_control_file(control_root, f"scripts/{relative}")
        for name, relative in _TRUSTED_MODULE_PATHS.items()
    }
    scripts_text = str(scripts)
    if scripts_text not in sys.path:
        sys.path.insert(0, scripts_text)
    acquisition = _load_module(
        "repo_sentinel_acquire", expected["repo_sentinel_acquire"]
    )
    worker = _load_module(
        "repo_sentinel_commit_authoritative",
        expected["repo_sentinel_commit_authoritative"],
    )
    for name in (
        "repo_sentinel_materialize",
        "repo_sentinel_policy_bundle",
        "repo_sentinel_reader",
    ):
        _load_module(name, expected[name])
    return TrustedStack(
        acquisition.acquire_pull_snapshot,
        acquisition.AcquisitionRefused,
        worker.CommitAuthoritativeRequest,
        worker.run_commit_authoritative,
        worker.result_dict,
    )


def _parse_decimal(value: str) -> int:
    if len(value) > 10 or _DECIMAL.fullmatch(value) is None:
        raise ControllerRefused("invalid_request")
    return int(value)


def parse_request(argv: list[str]) -> ControllerRequest:
    if len(argv) != len(_REQUEST_OPTIONS) * 2:
        raise ControllerRefused("invalid_request")
    values: dict[str, str] = {}
    for index in range(0, len(argv), 2):
        option, value = argv[index : index + 2]
        if option not in _REQUEST_OPTIONS or option in values or type(value) is not str:
            raise ControllerRefused("invalid_request")
        values[option] = value
    if set(values) != set(_REQUEST_OPTIONS):
        raise ControllerRefused("invalid_request")
    return ControllerRequest(
        repository_id=_parse_decimal(values["--repository-id"]),
        owner_id=_parse_decimal(values["--owner-id"]),
        repository=values["--repository"],
        remote_url=values["--remote-url"],
        pull_number=_parse_decimal(values["--pull-number"]),
        head_oid=values["--head-oid"],
        policy_epoch=values["--policy-epoch"],
        expected_policy_bundle_sha256=values["--policy-bundle-sha256"],
        scratch_root=Path(values["--scratch-root"]),
        scanner_artifact=Path(values["--scanner-artifact"]),
    )


def _validate_request(
    request: ControllerRequest, control_root: Path
) -> tuple[Path, Path]:
    if (
        type(request.repository_id) is not int
        or type(request.owner_id) is not int
        or type(request.pull_number) is not int
        or not 0 < request.pull_number <= 2_147_483_647
        or type(request.repository) is not str
        or type(request.remote_url) is not str
        or type(request.head_oid) is not str
        or type(request.policy_epoch) is not str
        or type(request.expected_policy_bundle_sha256) is not str
        or not isinstance(request.scratch_root, Path)
        or not isinstance(request.scanner_artifact, Path)
    ):
        raise ControllerRefused("invalid_request")
    if (
        request.repository_id != REPOSITORY_ID
        or request.owner_id != OWNER_ID
        or request.repository != REPOSITORY
        or request.remote_url != REMOTE_URL
    ):
        raise ControllerRefused("repository_identity_mismatch")
    if request.policy_epoch != POLICY_EPOCH:
        raise ControllerRefused("unknown_policy_epoch")
    if request.expected_policy_bundle_sha256 != POLICY_BUNDLE_SHA256:
        raise ControllerRefused("policy_bundle_mismatch")
    if _OID.fullmatch(request.head_oid) is None:
        raise ControllerRefused("invalid_head_oid")
    for path in (request.scratch_root, request.scanner_artifact):
        value = os.fspath(path)
        if (
            not 0 < len(value) <= 4096
            or re.search(r"[\x00-\x1f\x7f]", value)
            or ".." in path.parts
        ):
            raise ControllerRefused("invalid_request")
    scratch = _without_aliases(request.scratch_root, directory=True)
    artifact = _without_aliases(request.scanner_artifact, directory=False)
    if _overlaps(control_root, scratch):
        raise ControllerRefused("unsafe_root_layout")
    return scratch, artifact


@contextmanager
def controller_workspace(scratch_root: Path) -> Iterator[ControllerWorkspace]:
    root: Path | None = None
    try:
        root = Path(
            tempfile.mkdtemp(prefix="repo-sentinel-controller-", dir=scratch_root)
        )
        root.chmod(0o700)
        acquisition = root / "acquisition"
        worker = root / "worker"
        acquisition.mkdir(mode=0o700)
        worker.mkdir(mode=0o700)
        yield ControllerWorkspace(root, acquisition, worker)
    finally:
        if root is not None:
            try:
                shutil.rmtree(root)
            except OSError:
                raise ControllerRefused("cleanup_failed") from None


def _valid_digest(value: object, *, optional: bool = False) -> bool:
    return (optional and value is None) or (
        type(value) is str and _DIGEST.fullmatch(value) is not None
    )


def _valid_count(value: object) -> bool:
    return type(value) is int and value >= 0


def _worker_semantic_digest(payload: Mapping[str, object]) -> str:
    semantic = {
        key: value for key, value in payload.items() if key != "semantic_sha256"
    }
    encoded = json.dumps(
        semantic,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(
        _WORKER_SEMANTIC_DOMAIN + len(encoded).to_bytes(8, "big") + encoded
    ).hexdigest()


def _validate_worker_result(
    value: object,
    request: ControllerRequest,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != _WORKER_RESULT_KEYS:
        raise ControllerRefused("worker_result_invalid")
    payload = dict(value)
    verdict = payload["verdict"]
    if verdict == "INFRASTRUCTURE_REFUSAL":
        raise ControllerRefused("worker_infrastructure_refusal")
    if verdict not in {"PASS", "SCANNER_FINDING", "POLICY_ADMISSION_FAILURE"}:
        raise ControllerRefused("worker_result_invalid")
    counts = (
        payload["files_total"],
        payload["files_scanned"],
        payload["files_policy_excluded"],
        payload["files_scanner_skipped"],
        payload["report_size"],
    )
    if not all(_valid_count(item) for item in counts):
        raise ControllerRefused("worker_result_invalid")
    if verdict in {"PASS", "SCANNER_FINDING"} and payload["files_total"] != sum(
        counts[1:4]
    ):
        raise ControllerRefused("worker_result_invalid")
    required_digests = (
        payload["policy_bundle_sha256"],
        payload["protected_manifest_sha256"],
        payload["suppression_manifest_sha256"],
        payload["coverage_policy_sha256"],
        payload["scanner_artifact_sha256"],
        payload["semantic_sha256"],
    )
    if not all(_valid_digest(item) for item in required_digests):
        raise ControllerRefused("worker_result_invalid")
    if not _valid_digest(payload["report_sha256"], optional=True):
        raise ControllerRefused("worker_result_invalid")
    refusal = payload["refusal_code"]
    if verdict == "POLICY_ADMISSION_FAILURE":
        if refusal not in _POLICY_REFUSALS:
            raise ControllerRefused("worker_result_invalid")
        if (
            any(counts[1:4])
            or payload["report_sha256"] is not None
            or payload["report_size"] != 0
        ):
            raise ControllerRefused("worker_result_invalid")
    elif refusal is not None:
        raise ControllerRefused("worker_result_invalid")
    elif payload["report_sha256"] is None or payload["report_size"] == 0:
        raise ControllerRefused("worker_result_invalid")
    if (
        payload["policy_schema_version"] != 1
        or payload["policy_epoch"] != WORKER_POLICY_EPOCH
        or payload["policy_bundle_sha256"] != POLICY_BUNDLE_SHA256
        or payload["repository_id"] != REPOSITORY_ID
        or payload["head_oid"] != request.head_oid
        or payload["scanner_distribution"] != "repo-sentinel-lite"
        or payload["scanner_version"] != "0.8.1"
        or payload["scanner_artifact_sha256"] != SCANNER_ARTIFACT_SHA256
        or payload["semantic_sha256"] != _worker_semantic_digest(payload)
    ):
        raise ControllerRefused("worker_result_invalid")
    if (payload["report_sha256"] is None) != (payload["report_size"] == 0):
        raise ControllerRefused("worker_result_invalid")
    return payload


def _refusal(request: ControllerRequest | None, code: str) -> ControllerResult:
    safe_head = (
        request.head_oid
        if request is not None and _OID.fullmatch(request.head_oid) is not None
        else None
    )
    safe_epoch = (
        request.policy_epoch
        if request is not None and request.policy_epoch == POLICY_EPOCH
        else None
    )
    return ControllerResult(
        CONTROLLER_SCHEMA_VERSION,
        REPOSITORY_ID,
        safe_head,
        safe_epoch,
        POLICY_BUNDLE_SHA256,
        None,
        None,
        ControllerOutcome.INFRASTRUCTURE_REFUSAL,
        code if code in _REFUSAL_CODES else "unexpected_failure",
    )


def _authority_result(
    request: ControllerRequest, worker: dict[str, object]
) -> ControllerResult:
    return ControllerResult(
        CONTROLLER_SCHEMA_VERSION,
        REPOSITORY_ID,
        request.head_oid,
        POLICY_EPOCH,
        POLICY_BUNDLE_SHA256,
        worker,
        str(worker["semantic_sha256"]),
        ControllerOutcome.AUTHORITY_RESULT,
        None,
    )


def run_controller(
    request: ControllerRequest,
    *,
    control_root: Path,
    stack: TrustedStack,
    runtime_facts_provider: RuntimeFactsProvider = current_runtime_facts,
    git_probe: GitProbe = _trusted_git_probe,
    workspace_factory: WorkspaceFactory = controller_workspace,
) -> ControllerResult:
    """Run trusted orchestration without publishing an authority status."""

    try:
        facts = runtime_facts_provider()
        if (
            facts.implementation,
            facts.python_version,
            facts.os_family,
            facts.architecture,
        ) != EXPECTED_RUNTIME:
            raise ControllerRefused("runtime_mismatch")
        control = _without_aliases(control_root, directory=True)
        scratch, artifact = _validate_request(request, control)
        policy = _without_aliases(
            control / "policy" / "repo-sentinel-authority" / "v1",
            directory=True,
        )
        git_probe(control)
        with workspace_factory(scratch) as workspace:
            workspace_root = _without_aliases(workspace.root, directory=True)
            acquisition_root = _without_aliases(workspace.acquisition, directory=True)
            worker_root = _without_aliases(workspace.worker, directory=True)
            if (
                not acquisition_root.is_relative_to(workspace_root)
                or not worker_root.is_relative_to(workspace_root)
                or _overlaps(acquisition_root, worker_root)
                or _overlaps(control, workspace_root)
            ):
                raise ControllerRefused("unsafe_root_layout")
            try:
                with stack.acquire_pull_snapshot(
                    request.remote_url,
                    request.pull_number,
                    request.head_oid,
                    acquisition_root,
                ) as acquired:
                    snapshot = getattr(acquired, "snapshot", None)
                    repository = getattr(acquired, "repository", None)
                    if getattr(
                        snapshot, "commit_oid", None
                    ) != request.head_oid or not isinstance(repository, Path):
                        raise ControllerRefused("acquired_head_mismatch")
                    acquired_root = _without_aliases(repository, directory=True)
                    if (
                        acquired_root == acquisition_root
                        or not acquired_root.is_relative_to(acquisition_root)
                        or _overlaps(acquired_root, worker_root)
                        or _overlaps(acquired_root, control)
                    ):
                        raise ControllerRefused("unsafe_root_layout")
                    worker_request = stack.worker_request(
                        REPOSITORY_ID,
                        request.head_oid,
                        acquired_root,
                        policy,
                        POLICY_BUNDLE_SHA256,
                        artifact,
                        worker_root,
                    )
                    try:
                        raw_worker = stack.render_worker(
                            stack.run_worker(worker_request)
                        )
                    except ControllerRefused:
                        raise
                    except Exception:
                        raise ControllerRefused(
                            "worker_infrastructure_refusal"
                        ) from None
                    worker = _validate_worker_result(raw_worker, request)
            except ControllerRefused:
                raise
            except stack.acquisition_refused as error:
                code = (
                    "cleanup_failed"
                    if str(error) == "cleanup_failed"
                    else "acquisition_refused"
                )
                raise ControllerRefused(code) from None
            except Exception:
                raise ControllerRefused("acquisition_refused") from None
        return _authority_result(request, worker)
    except ControllerRefused as error:
        return _refusal(request, error.code)
    except Exception:
        return _refusal(request, "unexpected_failure")


def result_dict(result: ControllerResult) -> dict[str, object]:
    return {
        "controller_outcome": result.controller_outcome.value,
        "controller_schema_version": result.controller_schema_version,
        "fixed_refusal_code": result.fixed_refusal_code,
        "head_oid": result.head_oid,
        "policy_bundle_sha256": result.policy_bundle_sha256,
        "policy_epoch": result.policy_epoch,
        "repository_id": result.repository_id,
        "worker_result": result.worker_result,
        "worker_semantic_sha256": result.worker_semantic_sha256,
    }


def render_result(result: ControllerResult) -> str:
    return (
        json.dumps(
            result_dict(result),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


def main(argv: list[str] | None = None) -> int:
    request: ControllerRequest | None = None
    try:
        _validate_launch(current_runtime_facts)
        control = _control_root()
        os.chdir(control)
        stack = load_trusted_stack(control)
        request = parse_request(list(sys.argv[1:] if argv is None else argv))
        result = run_controller(request, control_root=control, stack=stack)
    except ControllerRefused as error:
        result = _refusal(request, error.code)
    except Exception:
        result = _refusal(request, "unexpected_failure")
    sys.stdout.write(render_result(result))
    if result.controller_outcome is ControllerOutcome.INFRASTRUCTURE_REFUSAL:
        return 2
    assert result.worker_result is not None
    return 0 if result.worker_result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ControllerOutcome",
    "ControllerRequest",
    "ControllerResult",
    "RuntimeFacts",
    "TrustedStack",
    "current_runtime_facts",
    "load_trusted_stack",
    "main",
    "parse_request",
    "render_result",
    "result_dict",
    "run_controller",
]
