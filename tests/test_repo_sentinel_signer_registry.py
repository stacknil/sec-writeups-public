"""Immutable registry and activation tests for signer v1."""

from __future__ import annotations

import threading
import unittest
from dataclasses import FrozenInstanceError, replace

from tests.signer_test_support import (
    REPOSITORY_ID,
    Harness,
    controller_result,
    digest,
    oid,
    registry_record,
)

from repo_sentinel_signer import (  # noqa: E402
    InMemoryRegistry,
    SignerRefused,
)


class RegistryRecordTests(unittest.TestCase):
    def test_records_are_frozen_values(self) -> None:
        record = registry_record()

        with self.assertRaises(FrozenInstanceError):
            record.policy_epoch = "changed"  # type: ignore[misc]

    def test_same_key_with_changed_content_is_rejected(self) -> None:
        registry = InMemoryRegistry()
        record = registry.add(registry_record())

        with self.assertRaisesRegex(SignerRefused, "registry_record_mutation"):
            registry.add(replace(record, scanner_version="9.9.9"))

    def test_new_operational_revision_may_retain_same_epoch_and_digest(self) -> None:
        registry = InMemoryRegistry()
        first = registry.add(registry_record())
        second = registry.add(
            replace(first, revision=2, workflow_sha=oid("replacement-workflow"))
        )

        self.assertEqual(first.policy_digest, second.policy_digest)
        self.assertNotEqual(first.workflow_sha, second.workflow_sha)

    def test_same_repository_epoch_cannot_acquire_second_digest(self) -> None:
        registry = InMemoryRegistry()
        first = registry.add(registry_record())

        with self.assertRaisesRegex(SignerRefused, "registry_epoch_authority_conflict"):
            registry.add(
                replace(
                    first,
                    record_id="second-record",
                    revision=1,
                    policy_digest=digest("different-policy"),
                )
            )

    def test_different_digest_requires_different_policy_epoch(self) -> None:
        registry = InMemoryRegistry()
        first = registry.add(registry_record())
        second = registry.add(
            replace(
                first,
                record_id="second-record",
                policy_epoch="synthetic-policy-v2",
                policy_digest=digest("different-policy"),
                status_context="Repo Sentinel / authoritative gate v2",
            )
        )

        self.assertNotEqual(first.policy_epoch, second.policy_epoch)
        self.assertNotEqual(first.policy_digest, second.policy_digest)

    def test_same_epoch_freezes_context_and_publisher(self) -> None:
        for field, value in (
            ("status_context", "Repo Sentinel / replacement gate"),
            ("publisher_identity", "mock-publisher-b"),
        ):
            registry = InMemoryRegistry()
            first = registry.add(registry_record())
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    SignerRefused, "registry_epoch_authority_conflict"
                ),
            ):
                registry.add(
                    replace(
                        first,
                        record_id=f"second-{field}",
                        **{field: value},
                    )
                )

    def test_status_context_is_reserved_across_epochs_case_insensitively(self) -> None:
        for context in (
            "Repo Sentinel / authoritative gate",
            "repo sentinel / AUTHORITATIVE GATE",
        ):
            registry = InMemoryRegistry()
            first = registry.add(registry_record())
            with (
                self.subTest(context=context),
                self.assertRaisesRegex(
                    SignerRefused, "registry_status_context_conflict"
                ),
            ):
                registry.add(
                    replace(
                        first,
                        record_id="second-record",
                        policy_epoch="synthetic-policy-v2",
                        policy_digest=digest("different-policy"),
                        status_context=context,
                    )
                )

    def test_revocation_does_not_release_context_namespace(self) -> None:
        registry = InMemoryRegistry()
        first = registry.add(registry_record())
        registry.revoke(first.key)

        with self.assertRaisesRegex(SignerRefused, "registry_status_context_conflict"):
            registry.add(
                replace(
                    first,
                    record_id="replacement-record",
                    policy_epoch="synthetic-policy-v2",
                    policy_digest=digest("replacement-policy"),
                )
            )

    def test_new_epoch_with_distinct_context_is_allowed(self) -> None:
        registry = InMemoryRegistry()
        first = registry.add(registry_record())

        second = registry.add(
            replace(
                first,
                record_id="second-record",
                policy_epoch="synthetic-policy-v2",
                policy_digest=digest("different-policy"),
                status_context="Repo Sentinel / authoritative gate v2",
            )
        )

        self.assertNotEqual(first.policy_epoch, second.policy_epoch)
        self.assertNotEqual(first.status_context, second.status_context)

    def test_status_context_requires_printable_ascii(self) -> None:
        for context in ("Repo Sentinel / gaté", "Repo Sentinel / gate\x7f"):
            with (
                self.subTest(context=context),
                self.assertRaisesRegex(SignerRefused, "invalid_status_context"),
            ):
                registry_record(status_context=context)

    def test_activation_is_explicit_and_latest_lookup_is_unsupported(self) -> None:
        registry = InMemoryRegistry()
        first = registry.add(registry_record())
        second = registry.add(replace(first, revision=2))

        with self.assertRaisesRegex(SignerRefused, "registry_activation_ambiguous"):
            registry.resolve_active(REPOSITORY_ID, "authoritative")
        registry.activate(REPOSITORY_ID, "authoritative", first.key)
        self.assertEqual(registry.resolve_active(REPOSITORY_ID, "authoritative"), first)
        self.assertNotEqual(
            registry.resolve_active(REPOSITORY_ID, "authoritative"), second
        )
        with self.assertRaisesRegex(SignerRefused, "unsupported_registry_lookup"):
            registry.resolve_latest(REPOSITORY_ID)

    def test_corrupt_ambiguous_activation_fails_closed(self) -> None:
        registry = InMemoryRegistry()
        record = registry.add(registry_record())
        registry.activate(REPOSITORY_ID, "authoritative", record.key)
        registry._active[(REPOSITORY_ID, "authoritative")] = {record.key}  # noqa: SLF001

        with self.assertRaisesRegex(SignerRefused, "registry_activation_ambiguous"):
            registry.resolve_active(REPOSITORY_ID, "authoritative")

    def test_revoked_record_cannot_be_activated(self) -> None:
        registry = InMemoryRegistry()
        record = registry.add(registry_record())
        registry.revoke(record.key)

        with self.assertRaisesRegex(SignerRefused, "registry_record_revoked"):
            registry.activate(REPOSITORY_ID, "authoritative", record.key)


class RegistryFreezeTests(unittest.TestCase):
    def test_evaluation_registry_revision_is_frozen_and_not_client_selectable(
        self,
    ) -> None:
        harness = Harness()
        ticket = harness.issue()
        evaluation = harness.store.get(ticket.evaluation_id)

        with self.assertRaises(FrozenInstanceError):
            evaluation.registry_revision = 2  # type: ignore[misc]

    def test_evaluation_remains_bound_to_r1_after_r2_activation(self) -> None:
        harness = Harness()
        ticket = harness.issue()
        r1 = harness.record
        r2 = harness.registry.add(
            replace(r1, revision=2, workflow_sha=oid("workflow-r2"))
        )
        harness.registry.activate(REPOSITORY_ID, "authoritative", r2.key)

        result = harness.service.finalize_evaluation(
            harness.final_claims("final-r1"),
            ticket.evaluation_id,
            controller_result(ticket, r1),
        )

        self.assertEqual(result.evaluation_state.value, "PUBLISHED")
        evaluation = harness.store.get(ticket.evaluation_id)
        self.assertEqual(evaluation.registry_key, r1.key)

    def test_revoking_r1_after_issuance_rejects_finalization(self) -> None:
        harness = Harness()
        ticket = harness.issue()
        harness.registry.revoke(harness.record.key)

        with self.assertRaisesRegex(SignerRefused, "registry_record_revoked"):
            harness.service.finalize_evaluation(
                harness.final_claims("final-after-revoke"),
                ticket.evaluation_id,
                controller_result(ticket, harness.record),
            )
        self.assertEqual(harness.publisher.calls, ())

    def test_concurrent_activation_cannot_create_mixed_revision_evaluation(
        self,
    ) -> None:
        harness = Harness()
        r1 = harness.record
        r2 = harness.registry.add(replace(r1, revision=2))
        barrier = threading.Barrier(2)
        issued = []

        def issue() -> None:
            barrier.wait()
            issued.append(harness.issue())

        def activate() -> None:
            barrier.wait()
            harness.registry.activate(REPOSITORY_ID, "authoritative", r2.key)

        threads = [threading.Thread(target=issue), threading.Thread(target=activate)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(issued), 1)
        evaluation = harness.store.get(issued[0].evaluation_id)
        self.assertIn(evaluation.registry_key, {r1.key, r2.key})
        selected = harness.registry.get(evaluation.registry_key)
        self.assertEqual(
            evaluation.policy_digest,
            selected.policy_digest,
        )
        self.assertEqual(evaluation.workflow_sha, selected.workflow_sha)


if __name__ == "__main__":
    unittest.main()
