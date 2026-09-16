"""Compatibility and self-reference tests for trusted policy contracts."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import repo_sentinel_policy_bundle as policy  # noqa: E402
from tests.test_repo_sentinel_commit_authoritative import (  # noqa: E402
    RUNTIME,
    minimum_files,
    replace_file,
)

V1_BUNDLE_SHA256 = "6f25ebb773ce1453e8de623bca5aaecc936f1f188288f8df20aedeadb3bf4612"
RUNTIME_SOURCES = (
    "scripts/repo_sentinel_authority_bootstrap.sh",
    "scripts/repo_sentinel_authority_controller.py",
    "scripts/repo_sentinel_commit_authoritative.py",
    "scripts/repo_sentinel_policy_bundle.py",
)


def v2_source_files():
    files = minimum_files(policy.V2_POLICY_CONTRACT)
    for path in RUNTIME_SOURCES:
        files = replace_file(
            files,
            path,
            data=(ROOT / path).read_bytes(),
            mode="100755" if path.endswith("bootstrap.sh") else "100644",
        )
    return files


def rewrite_component(root: Path, name: str, value: object) -> str:
    data = policy._render(value)
    (root / name).write_bytes(data)
    epoch_path = root / "epoch.json"
    epoch = json.loads(epoch_path.read_text(encoding="utf-8"))
    epoch["component_sha256"][name] = policy.sha256_bytes(data)
    epoch_path.write_bytes(policy._render(epoch))
    return policy.bundle_sha256(root)


class TrustedContractTests(unittest.TestCase):
    def test_contracts_are_immutable_and_only_known_selectors_resolve(self) -> None:
        self.assertIs(
            policy.trusted_policy_contract("v1"),
            policy.V1_POLICY_CONTRACT,
        )
        self.assertIs(
            policy.trusted_policy_contract("v2"),
            policy.V2_POLICY_CONTRACT,
        )
        with self.assertRaises(FrozenInstanceError):
            policy.V2_POLICY_CONTRACT.policy_epoch = "changed"  # type: ignore[misc]
        for candidate in ("latest", "repo-sentinel-authority-v2", 2):
            with self.subTest(candidate=candidate):
                with self.assertRaisesRegex(
                    policy.PolicyBundleRefused,
                    "policy_schema_unsupported",
                ):
                    policy.trusted_policy_contract(candidate)  # type: ignore[arg-type]

    def test_v1_historical_bundle_reproduces_exact_contract(self) -> None:
        contract = policy.V1_POLICY_CONTRACT
        root = ROOT.joinpath(*contract.mirror_root.rstrip("/").split("/"))

        digest = policy.bundle_sha256(root)
        bundle = policy.load_policy_bundle(
            root,
            V1_BUNDLE_SHA256,
            policy_selector="v1",
        )
        epoch = json.loads((root / "epoch.json").read_text(encoding="utf-8"))

        self.assertEqual(digest, V1_BUNDLE_SHA256)
        self.assertIs(bundle.contract, contract)
        self.assertEqual(bundle.schema_version, 1)
        self.assertEqual(bundle.policy_epoch, "repo-sentinel-authority-v1")
        self.assertEqual(bundle.worker_policy_version, "commit-authoritative-v1")
        self.assertEqual(bundle.portable_path_policy_version, "portable-v1")
        self.assertEqual(bundle.scanner_distribution, "repo-sentinel-lite")
        self.assertEqual(bundle.scanner_version, "0.8.1")
        self.assertEqual(
            bundle.scanner_artifact_sha256,
            policy.SCANNER_WHEEL_SHA256,
        )
        self.assertEqual(
            bundle.runtime,
            policy.RuntimeContract("cpython", "3.12.3", "Linux", "x86_64"),
        )
        self.assertEqual(bundle.contract.mirror_root, contract.mirror_root)
        self.assertEqual(
            bundle.contract.mandatory_protected_paths,
            policy.MANDATORY_PROTECTED_PATHS,
        )
        for name, expected in epoch["component_sha256"].items():
            self.assertEqual(policy.sha256_bytes((root / name).read_bytes()), expected)

    def test_synthetic_v2_is_deterministic_and_keeps_v1_algorithms(self) -> None:
        files = v2_source_files()
        with tempfile.TemporaryDirectory(prefix="synthetic-policy-v2-") as temporary:
            first = Path(temporary) / "first"
            second = Path(temporary) / "second"
            first_digest = policy.build_policy_bundle(
                files,
                first,
                RUNTIME,
                policy_selector="v2",
            )
            second_digest = policy.build_policy_bundle(
                files,
                second,
                RUNTIME,
                policy_selector="v2",
            )
            bundle = policy.load_policy_bundle(
                first,
                first_digest,
                policy_selector="v2",
            )

            self.assertEqual(first_digest, second_digest)
            self.assertEqual(
                {name: (first / name).read_bytes() for name in policy.BUNDLE_FILENAMES},
                {
                    name: (second / name).read_bytes()
                    for name in policy.BUNDLE_FILENAMES
                },
            )
            self.assertIs(bundle.contract, policy.V2_POLICY_CONTRACT)
            self.assertEqual(bundle.schema_version, 1)
            self.assertEqual(bundle.policy_epoch, "repo-sentinel-authority-v2")
            self.assertEqual(bundle.worker_policy_version, "commit-authoritative-v1")
            self.assertEqual(bundle.portable_path_policy_version, "portable-v1")
            self.assertEqual(bundle.scanner_distribution, "repo-sentinel-lite")
            self.assertEqual(bundle.scanner_version, "0.8.1")
            self.assertEqual(
                bundle.scanner_artifact_sha256,
                policy.SCANNER_WHEEL_SHA256,
            )

    def test_epoch_path_cross_wiring_and_digest_mismatch_fail_closed(self) -> None:
        v1 = policy.V1_POLICY_CONTRACT
        v1_root = ROOT.joinpath(*v1.mirror_root.rstrip("/").split("/"))
        with self.assertRaisesRegex(
            policy.PolicyBundleRefused,
            "policy_bundle_invalid",
        ):
            policy.load_policy_bundle(
                v1_root,
                V1_BUNDLE_SHA256,
                policy_selector="v2",
            )

        with tempfile.TemporaryDirectory(prefix="synthetic-policy-v2-") as temporary:
            root = Path(temporary) / "bundle"
            digest = policy.build_policy_bundle(
                v2_source_files(),
                root,
                RUNTIME,
                policy_selector="v2",
            )
            with self.assertRaisesRegex(
                policy.PolicyBundleRefused,
                "policy_schema_unsupported",
            ):
                policy.load_policy_bundle(root, digest, policy_selector="v1")
            with self.assertRaisesRegex(
                policy.PolicyBundleRefused,
                "policy_bundle_mismatch",
            ):
                policy.load_policy_bundle(root, "0" * 64, policy_selector="v2")
            (root / "baseline.json").write_bytes(b'{"findings": []}\n')
            with self.assertRaisesRegex(
                policy.PolicyBundleRefused,
                "policy_bundle_mismatch",
            ):
                policy.load_policy_bundle(root, digest, policy_selector="v2")

    def test_v2_requires_bootstrap_and_controller_in_source_and_manifest(self) -> None:
        files = v2_source_files()
        for path in (
            "scripts/repo_sentinel_authority_bootstrap.sh",
            "scripts/repo_sentinel_authority_controller.py",
        ):
            with self.subTest(stage="source", path=path):
                with tempfile.TemporaryDirectory(
                    prefix="synthetic-policy-v2-"
                ) as temporary:
                    with self.assertRaisesRegex(
                        policy.PolicyBundleRefused,
                        "policy_source_invalid",
                    ):
                        policy.build_policy_bundle(
                            tuple(item for item in files if item.path != path),
                            Path(temporary) / "bundle",
                            RUNTIME,
                            policy_selector="v2",
                        )

            with self.subTest(stage="manifest", path=path):
                with tempfile.TemporaryDirectory(
                    prefix="synthetic-policy-v2-"
                ) as temporary:
                    root = Path(temporary) / "bundle"
                    policy.build_policy_bundle(
                        files,
                        root,
                        RUNTIME,
                        policy_selector="v2",
                    )
                    manifest = json.loads(
                        (root / "protected-manifest.json").read_text(encoding="utf-8")
                    )
                    manifest["entries"] = [
                        entry for entry in manifest["entries"] if entry["path"] != path
                    ]
                    digest = rewrite_component(
                        root,
                        "protected-manifest.json",
                        manifest,
                    )
                    with self.assertRaisesRegex(
                        policy.PolicyBundleRefused,
                        "policy_bundle_invalid",
                    ):
                        policy.load_policy_bundle(
                            root,
                            digest,
                            policy_selector="v2",
                        )

    def test_v2_build_terminates_without_writing_digest_back_to_runtime(self) -> None:
        files = v2_source_files()
        before = {
            item.path: item.data for item in files if item.path in RUNTIME_SOURCES
        }
        with tempfile.TemporaryDirectory(prefix="synthetic-policy-v2-") as temporary:
            root = Path(temporary) / "bundle"
            digest = policy.build_policy_bundle(
                files,
                root,
                RUNTIME,
                policy_selector="v2",
            )
            self.assertEqual(
                {item.name for item in root.iterdir()}, set(policy.BUNDLE_FILENAMES)
            )
        after = {path: (ROOT / path).read_bytes() for path in RUNTIME_SOURCES}

        self.assertEqual(before, after)
        self.assertTrue(
            all(digest.encode("ascii") not in data for data in after.values())
        )

    def test_runtime_has_no_policy_bundle_digest_back_edge_symbol(self) -> None:
        for path in RUNTIME_SOURCES:
            with self.subTest(path=path):
                source = (ROOT / path).read_text(encoding="utf-8")
                self.assertNotIn("POLICY_BUNDLE_SHA256", source)
                self.assertNotIn("EXPECTED_POLICY_BUNDLE_SHA256", source)


if __name__ == "__main__":
    unittest.main()
