"""Contract tests for the trusted Repo Sentinel authority controller."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import repo_sentinel_authority_controller as controller  # noqa: E402

HEAD_OID = "b" * 40
OTHER_OID = "c" * 40
EXACT_RUNTIME = controller.RuntimeFacts("cpython", "3.12.3", "Linux", "x86_64")


class FakeAcquisitionRefused(ValueError):
    pass


def worker_payload(
    verdict: str = "PASS",
    *,
    head_oid: str = HEAD_OID,
    refusal_code: str | None = None,
) -> dict[str, object]:
    semantic = verdict != "INFRASTRUCTURE_REFUSAL"
    report = semantic and verdict != "POLICY_ADMISSION_FAILURE"
    payload: dict[str, object] = {
        "coverage_policy_sha256": "a" * 64 if semantic else None,
        "files_policy_excluded": 1 if report else 0,
        "files_scanned": 2 if report else 0,
        "files_scanner_skipped": 0,
        "files_total": 3 if semantic else 0,
        "head_oid": head_oid if semantic else "",
        "policy_bundle_sha256": (controller.POLICY_BUNDLE_SHA256 if semantic else None),
        "policy_epoch": controller.WORKER_POLICY_EPOCH if semantic else None,
        "policy_schema_version": 1 if semantic else None,
        "protected_manifest_sha256": "b" * 64 if semantic else None,
        "refusal_code": refusal_code,
        "report_sha256": "c" * 64 if report else None,
        "report_size": 123 if report else 0,
        "repository_id": controller.REPOSITORY_ID if semantic else 0,
        "scanner_artifact_sha256": (
            controller.SCANNER_ARTIFACT_SHA256 if semantic else None
        ),
        "scanner_distribution": "repo-sentinel-lite" if semantic else None,
        "scanner_version": "0.8.1" if semantic else None,
        "semantic_sha256": None,
        "suppression_manifest_sha256": "d" * 64 if semantic else None,
        "verdict": verdict,
    }
    if semantic:
        payload["semantic_sha256"] = controller._worker_semantic_digest(payload)
    return payload


class Harness:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="controller-contract-")
        self.root = Path(self.temporary.name)
        self.control = self.root / "control"
        self.scratch = self.root / "scratch"
        self.artifact = self.root / "scanner.whl"
        (self.control / "policy" / "repo-sentinel-authority" / "v1").mkdir(parents=True)
        self.scratch.mkdir()
        self.artifact.write_bytes(b"fixture")
        self.request = controller.ControllerRequest(
            controller.REPOSITORY_ID,
            controller.OWNER_ID,
            controller.REPOSITORY,
            controller.REMOTE_URL,
            7,
            HEAD_OID,
            controller.POLICY_EPOCH,
            controller.POLICY_BUNDLE_SHA256,
            self.scratch,
            self.artifact,
        )
        self.acquired_head = HEAD_OID
        self.acquisition_error: Exception | None = None
        self.worker = worker_payload()
        self.worker_arguments: tuple[object, ...] | None = None
        self.git_calls = 0

    def close(self) -> None:
        self.temporary.cleanup()

    @contextmanager
    def acquire(
        self,
        _remote: str,
        _pull: int,
        _head: str,
        scratch: Path,
    ):
        if self.acquisition_error is not None:
            raise self.acquisition_error
        repository = scratch / "objects.git"
        repository.mkdir()
        snapshot = SimpleNamespace(commit_oid=self.acquired_head)
        yield SimpleNamespace(snapshot=snapshot, repository=repository)

    def make_worker_request(self, *arguments: object) -> object:
        self.worker_arguments = arguments
        return arguments

    def git_probe(self, _control: Path) -> None:
        self.git_calls += 1

    def stack(self) -> controller.TrustedStack:
        return controller.TrustedStack(
            self.acquire,
            FakeAcquisitionRefused,
            self.make_worker_request,
            lambda _request: self.worker,
            lambda result: result,
        )

    def run(
        self,
        request: controller.ControllerRequest | None = None,
        **kwargs: object,
    ) -> controller.ControllerResult:
        return controller.run_controller(
            request or self.request,
            control_root=self.control,
            stack=self.stack(),
            runtime_facts_provider=kwargs.pop(
                "runtime_facts_provider", lambda: EXACT_RUNTIME
            ),
            git_probe=kwargs.pop("git_probe", self.git_probe),
            **kwargs,
        )


class HarnessTestCase(unittest.TestCase):
    def harness(self) -> Harness:
        harness = Harness()
        self.addCleanup(harness.close)
        return harness


class RequestContractTests(HarnessTestCase):
    def argv(self, harness: Harness) -> list[str]:
        request = harness.request
        return [
            "--repository-id",
            str(request.repository_id),
            "--owner-id",
            str(request.owner_id),
            "--repository",
            request.repository,
            "--remote-url",
            request.remote_url,
            "--pull-number",
            str(request.pull_number),
            "--head-oid",
            request.head_oid,
            "--policy-epoch",
            request.policy_epoch,
            "--policy-bundle-sha256",
            request.expected_policy_bundle_sha256,
            "--scratch-root",
            str(request.scratch_root),
            "--scanner-artifact",
            str(request.scanner_artifact),
        ]

    def test_strict_parser_accepts_only_complete_unique_option_pairs(self) -> None:
        harness = self.harness()
        argv = self.argv(harness)
        self.assertEqual(controller.parse_request(argv), harness.request)
        for candidate in (
            argv[:-2],
            [*argv, "--extra", "value"],
            ["--repository-id", "1", *argv[2:-2], "--repository-id", "2"],
            ["--repository-id=1130304545", *argv[2:]],
            ["--repository-id", "9" * 100, *argv[2:]],
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaisesRegex(
                    controller.ControllerRefused, "invalid_request"
                ):
                    controller.parse_request(candidate)

    def test_repository_policy_and_head_inputs_fail_closed(self) -> None:
        harness = self.harness()
        cases = {
            "repository-id": (
                replace(harness.request, repository_id=1),
                "repository_identity_mismatch",
            ),
            "owner-id": (
                replace(harness.request, owner_id=1),
                "repository_identity_mismatch",
            ),
            "repository": (
                replace(harness.request, repository="other/repository"),
                "repository_identity_mismatch",
            ),
            "remote": (
                replace(harness.request, remote_url="https://example.com/repo.git"),
                "repository_identity_mismatch",
            ),
            "epoch": (
                replace(harness.request, policy_epoch="v2"),
                "unknown_policy_epoch",
            ),
            "digest": (
                replace(harness.request, expected_policy_bundle_sha256="0" * 64),
                "policy_bundle_mismatch",
            ),
            "head": (
                replace(harness.request, head_oid="HEAD\n::error::secret"),
                "invalid_head_oid",
            ),
            "pull": (replace(harness.request, pull_number=0), "invalid_request"),
        }
        for name, (request, code) in cases.items():
            with self.subTest(name=name):
                result = harness.run(request)
                self.assertEqual(
                    result.controller_outcome.value, "INFRASTRUCTURE_REFUSAL"
                )
                self.assertEqual(result.fixed_refusal_code, code)
                rendered = controller.render_result(result)
                self.assertNotIn("secret", rendered)
                self.assertNotIn("::error::", rendered)

    def test_scratch_must_be_absolute_non_aliasing_and_outside_control(self) -> None:
        harness = self.harness()
        for request, code in (
            (
                replace(harness.request, scratch_root=Path("relative")),
                "unsafe_root_layout",
            ),
            (
                replace(harness.request, scratch_root=harness.control),
                "unsafe_root_layout",
            ),
            (
                replace(harness.request, scratch_root=Path("bad\npath")),
                "invalid_request",
            ),
        ):
            with self.subTest(path=request.scratch_root):
                self.assertEqual(harness.run(request).fixed_refusal_code, code)


class OrchestrationTests(HarnessTestCase):
    def test_pass_is_bounded_and_worker_handoff_is_commit_intrinsic(self) -> None:
        harness = self.harness()
        result = harness.run()

        self.assertEqual(result.controller_outcome.value, "AUTHORITY_RESULT")
        self.assertIsNone(result.fixed_refusal_code)
        self.assertEqual(result.worker_result, harness.worker)
        self.assertEqual(
            result.worker_semantic_sha256,
            harness.worker["semantic_sha256"],
        )
        self.assertEqual(harness.git_calls, 1)
        self.assertIsNotNone(harness.worker_arguments)
        arguments = harness.worker_arguments
        assert arguments is not None
        self.assertEqual(arguments[0], controller.REPOSITORY_ID)
        self.assertEqual(arguments[1], HEAD_OID)
        self.assertEqual(
            arguments[3],
            harness.control / "policy" / "repo-sentinel-authority" / "v1",
        )
        self.assertEqual(arguments[4], controller.POLICY_BUNDLE_SHA256)
        self.assertEqual(arguments[5], harness.artifact)
        self.assertNotIn(harness.request.pull_number, arguments[0:2])
        self.assertEqual(list(harness.scratch.iterdir()), [])

    def test_semantic_failure_results_are_preserved(self) -> None:
        harness = self.harness()
        for verdict, refusal in (
            ("SCANNER_FINDING", None),
            ("POLICY_ADMISSION_FAILURE", "protected_control_mismatch"),
        ):
            with self.subTest(verdict=verdict):
                harness.worker = worker_payload(verdict, refusal_code=refusal)
                result = harness.run()
                self.assertEqual(result.controller_outcome.value, "AUTHORITY_RESULT")
                self.assertEqual(result.worker_result, harness.worker)

    def test_wrong_acquired_head_and_acquisition_refusal_have_no_authority(
        self,
    ) -> None:
        harness = self.harness()
        harness.acquired_head = OTHER_OID
        result = harness.run()
        self.assertEqual(result.fixed_refusal_code, "acquired_head_mismatch")
        self.assertIsNone(result.worker_result)

        harness = self.harness()
        harness.acquisition_error = FakeAcquisitionRefused("fetch_failed\nsecret")
        result = harness.run()
        self.assertEqual(result.fixed_refusal_code, "acquisition_refused")
        self.assertNotIn("secret", controller.render_result(result))

    def test_worker_infrastructure_or_invalid_result_has_no_authority(self) -> None:
        harness = self.harness()
        harness.worker = worker_payload(
            "INFRASTRUCTURE_REFUSAL", refusal_code="scanner_failed"
        )
        self.assertEqual(
            harness.run().fixed_refusal_code,
            "worker_infrastructure_refusal",
        )

        harness = self.harness()
        harness.worker = worker_payload()
        harness.worker["head_oid"] = OTHER_OID
        self.assertEqual(harness.run().fixed_refusal_code, "worker_result_invalid")

    def test_worker_semantic_digest_is_recomputed(self) -> None:
        harness = self.harness()
        harness.worker["files_scanned"] = 1
        harness.worker["files_scanner_skipped"] = 1
        self.assertEqual(harness.run().fixed_refusal_code, "worker_result_invalid")

    def test_wrong_runtime_stops_before_git_or_acquisition(self) -> None:
        harness = self.harness()
        result = harness.run(
            runtime_facts_provider=lambda: controller.RuntimeFacts(
                "cpython", "3.12.14", "Linux", "x86_64"
            )
        )
        self.assertEqual(result.fixed_refusal_code, "runtime_mismatch")
        self.assertEqual(harness.git_calls, 0)

    def test_cleanup_failure_overrides_semantic_success(self) -> None:
        harness = self.harness()

        @contextmanager
        def cleanup_failure(scratch: Path):
            root = scratch / "workspace"
            acquisition = root / "acquisition"
            worker = root / "worker"
            acquisition.mkdir(parents=True)
            worker.mkdir()
            yield controller.ControllerWorkspace(root, acquisition, worker)
            raise controller.ControllerRefused("cleanup_failed")

        result = harness.run(workspace_factory=cleanup_failure)
        self.assertEqual(result.fixed_refusal_code, "cleanup_failed")
        self.assertIsNone(result.worker_result)

    def test_repeated_execution_is_independent_of_neutralized_parent_noise(
        self,
    ) -> None:
        harness = self.harness()
        first = controller.result_dict(harness.run())
        hostile = {
            "HOME": "hostile",
            "PYTHONPATH": "hostile",
            "REPO_SENTINEL_CONFIG": "hostile",
            "XDG_CONFIG_HOME": "hostile",
        }
        with patch.dict(os.environ, hostile, clear=False):
            second = controller.result_dict(harness.run())
        self.assertEqual(first, second)

    def test_target_python_and_shell_files_remain_data(self) -> None:
        harness = self.harness()
        marker = harness.root / "target-executed"
        original = harness.acquire

        @contextmanager
        def malicious_target(*args: object, **kwargs: object):
            with original(*args, **kwargs) as acquired:
                repository = acquired.repository
                payload = f"from pathlib import Path;Path({str(marker)!r}).touch()\n"
                for name in (
                    "sitecustomize.py",
                    "usercustomize.py",
                    "hashlib.py",
                    "repo_sentinel.py",
                    "setup.py",
                    "run.sh",
                ):
                    (repository / name).write_text(payload, encoding="utf-8")
                self.assertNotIn(str(repository), sys.path)
                yield acquired

        stack = replace(harness.stack(), acquire_pull_snapshot=malicious_target)
        result = controller.run_controller(
            harness.request,
            control_root=harness.control,
            stack=stack,
            runtime_facts_provider=lambda: EXACT_RUNTIME,
            git_probe=harness.git_probe,
        )
        self.assertEqual(result.controller_outcome.value, "AUTHORITY_RESULT")
        self.assertFalse(marker.exists())


def replace_flags(flags: SimpleNamespace, **changes: object) -> SimpleNamespace:
    values = vars(flags).copy()
    values.update(changes)
    return SimpleNamespace(**values)


class LaunchAndImportContractTests(HarnessTestCase):
    def isolated_flags(self) -> SimpleNamespace:
        return SimpleNamespace(
            isolated=1,
            ignore_environment=1,
            no_user_site=1,
            no_site=1,
            safe_path=True,
            dont_write_bytecode=1,
        )

    def test_launch_requires_exact_fixed_environment_and_isolation_flags(self) -> None:
        executable = str(self.harness().artifact)
        with (
            patch.object(controller.sys, "flags", self.isolated_flags()),
            patch.object(controller.sys, "executable", executable),
            patch.dict(os.environ, controller.FIXED_ENVIRONMENT, clear=True),
        ):
            controller._validate_launch(lambda: EXACT_RUNTIME)

        hostile = dict(controller.FIXED_ENVIRONMENT, PYTHONPATH="marker")
        with (
            patch.object(controller.sys, "flags", self.isolated_flags()),
            patch.object(controller.sys, "executable", executable),
            patch.dict(os.environ, hostile, clear=True),
        ):
            with self.assertRaisesRegex(
                controller.ControllerRefused, "environment_mismatch"
            ):
                controller._validate_launch(lambda: EXACT_RUNTIME)

        flags = replace_flags(self.isolated_flags(), isolated=0)
        with (
            patch.object(controller.sys, "flags", flags),
            patch.object(controller.sys, "executable", executable),
            patch.dict(os.environ, controller.FIXED_ENVIRONMENT, clear=True),
        ):
            with self.assertRaisesRegex(
                controller.ControllerRefused, "launch_not_isolated"
            ):
                controller._validate_launch(lambda: EXACT_RUNTIME)

    def test_trusted_module_loader_binds_files_under_control_scripts(self) -> None:
        stack = controller.load_trusted_stack(ROOT)
        self.assertEqual(
            stack.acquire_pull_snapshot.__module__, "repo_sentinel_acquire"
        )
        self.assertEqual(
            stack.run_worker.__module__,
            "repo_sentinel_commit_authoritative",
        )
        for name, relative in controller._TRUSTED_MODULE_PATHS.items():
            module = sys.modules[name]
            self.assertEqual(
                Path(module.__file__).resolve(),
                (SCRIPTS / relative).resolve(),
            )

    def test_rendered_refusal_never_contains_raw_exception_or_workflow_commands(
        self,
    ) -> None:
        harness = self.harness()

        @contextmanager
        def injected(*_args: object, **_kwargs: object):
            raise RuntimeError("::warning::\n\x1b[31msecret-path")
            yield

        stack = replace(harness.stack(), acquire_pull_snapshot=injected)
        result = controller.run_controller(
            harness.request,
            control_root=harness.control,
            stack=stack,
            runtime_facts_provider=lambda: EXACT_RUNTIME,
            git_probe=harness.git_probe,
        )
        rendered = controller.render_result(result)
        self.assertNotIn("::warning::", rendered)
        self.assertNotIn("secret-path", rendered)
        self.assertNotIn("\x1b", rendered)
        self.assertEqual(rendered.count("\n"), 1)


class BootstrapTests(unittest.TestCase):
    def bootstrap_source(self) -> str:
        return (SCRIPTS / "repo_sentinel_authority_bootstrap.sh").read_text(
            encoding="utf-8"
        )

    def test_bootstrap_contract_is_static_and_mutation_sensitive(self) -> None:
        source = self.bootstrap_source()

        def satisfies_contract(candidate: str) -> bool:
            required = (
                "exec /usr/bin/env -i",
                "PATH=/usr/bin:/bin",
                '"$trusted_python" -I -S -B "$controller"',
                "unset LD_PRELOAD LD_LIBRARY_PATH",
                "unset BASH_ENV ENV CDPATH GLOBIGNORE",
            )
            return all(item in candidate for item in required)

        self.assertTrue(satisfies_contract(source))
        mutations = (
            source.replace("env -i", "env"),
            source.replace("PATH=/usr/bin:/bin", "PATH=$PATH"),
            source.replace(
                '"$trusted_python" -I -S -B "$controller"',
                'python -I -S -B "$controller"',
            ),
            source.replace(" -I -S -B ", " -S -B "),
        )
        for mutation in mutations:
            with self.subTest():
                self.assertFalse(satisfies_contract(mutation))
        self.assertNotIn("eval ", source)
        self.assertNotIn("source ", source)

    @unittest.skipIf(os.name == "nt", "POSIX bootstrap executes on Linux CI")
    def test_hostile_parent_cannot_shadow_python_stdlib_or_git(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bootstrap-hostile-") as temporary:
            root = Path(temporary)
            hostile = root / "hostile"
            fake_bin = root / "bin"
            home = root / "home"
            hostile.mkdir()
            fake_bin.mkdir()
            home.mkdir()
            marker = root / "marker"
            output = root / "output.json"
            startup = root / "startup.py"
            probe = root / "probe.py"
            marker_code = f"from pathlib import Path;Path({str(marker)!r}).touch()\n"
            for name in (
                "hashlib.py",
                "json.py",
                "sitecustomize.py",
                "usercustomize.py",
            ):
                (hostile / name).write_text(marker_code, encoding="utf-8")
            (hostile / "marker.pth").write_text(marker_code, encoding="utf-8")
            startup.write_text(marker_code, encoding="utf-8")
            for name in ("git", "python"):
                executable = fake_bin / name
                executable.write_text(
                    f"#!/bin/sh\nprintf x >> {str(marker)!r}\nexit 99\n",
                    encoding="utf-8",
                )
                executable.chmod(0o700)
            probe.write_text(
                "import json,os,shutil,subprocess,sys\n"
                "from pathlib import Path\n"
                "result=subprocess.run(['git','--version'],capture_output=True,check=True,text=True)\n"
                "Path(sys.argv[1]).write_text(json.dumps({\n"
                "'environment':dict(os.environ),\n"
                "'executable':sys.executable,\n"
                "'git':shutil.which('git'),\n"
                "'git_version':result.stdout.strip(),\n"
                "'isolated':sys.flags.isolated,\n"
                "'no_site':sys.flags.no_site,\n"
                "'dont_write_bytecode':sys.flags.dont_write_bytecode,\n"
                "},sort_keys=True),encoding='utf-8')\n",
                encoding="utf-8",
            )
            environment = dict(os.environ)
            environment.update(
                {
                    "BASH_ENV": str(startup),
                    "ENV": str(startup),
                    "HOME": str(home),
                    "LD_LIBRARY_PATH": str(hostile),
                    "PATH": f"{fake_bin}{os.pathsep}{environment.get('PATH', '')}",
                    "PIP_CONFIG_FILE": str(root / "pip.ini"),
                    "PIP_INDEX_URL": "https://example.invalid/simple",
                    "PYTHONBREAKPOINT": "marker.breakpoint",
                    "PYTHONHOME": str(hostile),
                    "PYTHONINSPECT": "1",
                    "PYTHONPATH": str(hostile),
                    "PYTHONPYCACHEPREFIX": str(hostile),
                    "PYTHONSAFEPATH": "0",
                    "PYTHONSTARTUP": str(startup),
                    "PYTHONUSERBASE": str(hostile),
                    "PYTHONWARNINGS": "error",
                    "REPO_SENTINEL_CONFIG": "hostile",
                    "VIRTUAL_ENV": str(hostile),
                    "XDG_CONFIG_HOME": str(hostile),
                }
            )
            completed = subprocess.run(
                [
                    "/bin/sh",
                    str(SCRIPTS / "repo_sentinel_authority_bootstrap.sh"),
                    str(Path(sys.executable).resolve()),
                    str(probe),
                    str(output),
                ],
                cwd=root,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            observed = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(observed["environment"], controller.FIXED_ENVIRONMENT)
            self.assertEqual(
                Path(observed["executable"]).resolve(),
                Path(sys.executable).resolve(),
            )
            self.assertEqual(observed["git"], "/usr/bin/git")
            self.assertRegex(observed["git_version"], r"^git version [0-9]")
            self.assertEqual(observed["isolated"], 1)
            self.assertEqual(observed["no_site"], 1)
            self.assertEqual(observed["dont_write_bytecode"], 1)
            self.assertFalse(marker.exists())
            self.assertEqual(completed.stdout, b"")
            self.assertEqual(completed.stderr, b"")


if __name__ == "__main__":
    unittest.main()
