"""Regression tests for commit-authority policy provenance."""

from __future__ import annotations

import json
from dataclasses import replace

from tests.test_repo_sentinel_commit_authoritative import (
    HEAD_OID,
    HarnessTestCase,
    minimum_files,
    replace_file,
    snapshot_file,
)

import repo_sentinel_commit_authoritative as authoritative  # noqa: E402
import repo_sentinel_policy_bundle as policy  # noqa: E402
from repo_sentinel_reader import Snapshot  # noqa: E402


class BaselineProvenanceTests(HarnessTestCase):
    def test_scanner_receives_authenticated_bundle_baseline_not_target(self) -> None:
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
        harness = self.harness(files)

        (harness.policy_root / "baseline.json").write_bytes(trusted_baseline)
        epoch_path = harness.policy_root / "epoch.json"
        epoch = json.loads(epoch_path.read_text(encoding="utf-8"))
        epoch["component_sha256"]["baseline.json"] = policy.sha256_bytes(
            trusted_baseline
        )
        epoch_path.write_bytes(policy._render(epoch))
        harness.bundle_digest = policy.bundle_sha256(harness.policy_root)
        harness.bundle = policy.load_policy_bundle(
            harness.policy_root, harness.bundle_digest
        )

        source_files = tuple(
            item
            for item in harness.files
            if not item.path.startswith(policy.POLICY_BUNDLE_MIRROR_ROOT)
        )
        mirror_files = tuple(
            snapshot_file(
                f"{policy.POLICY_BUNDLE_MIRROR_ROOT}{name}",
                data,
            )
            for name, data in harness.bundle.bundle_files
        )
        harness.files = tuple(
            sorted((*source_files, *mirror_files), key=lambda item: item.path)
        )
        harness.snapshot = Snapshot(HEAD_OID, "c" * 40, harness.files)
        harness.request = replace(
            harness.request,
            expected_policy_bundle_sha256=harness.bundle_digest,
        )
        underlying = harness.scanner()

        def scanner(
            invocation: authoritative.ScannerInvocation,
        ) -> authoritative.ScannerExecution:
            observed = invocation.baseline_path.read_bytes()
            self.assertEqual(observed, trusted_baseline)
            self.assertEqual(observed, harness.bundle.baseline)
            self.assertNotEqual(observed, target_baseline)
            return underlying(invocation)

        result = harness.run(scanner)

        self.assertEqual(result.verdict, authoritative.CommitAuthorityVerdict.PASS)
