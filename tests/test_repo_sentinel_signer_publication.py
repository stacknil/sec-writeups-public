"""Publication-slot, uncertainty, and concurrency tests for signer v1."""

from __future__ import annotations

import inspect
import threading
import unittest

from tests.signer_test_support import (
    PULL_NUMBER,
    REPOSITORY_ID,
    Harness,
    controller_result,
)

from repo_sentinel_signer import (  # noqa: E402
    EvaluationState,
    MockPublishMode,
    PublicationSlotState,
    PullRequestSnapshot,
    SignerRefused,
)


class VerdictMappingTests(unittest.TestCase):
    def test_semantic_verdicts_map_to_only_success_or_failure(self) -> None:
        expected = {
            "PASS": (
                "success",
                "Repo Sentinel authority: PASS",
            ),
            "SCANNER_FINDING": (
                "failure",
                "Repo Sentinel authority: SCANNER_FINDING",
            ),
            "POLICY_ADMISSION_FAILURE": (
                "failure",
                "Repo Sentinel authority: POLICY_ADMISSION_FAILURE",
            ),
        }
        for verdict, (state, description) in expected.items():
            harness = Harness()
            ticket = harness.issue()
            result = harness.service.finalize_evaluation(
                harness.final_claims(f"final-{verdict}"),
                ticket.evaluation_id,
                controller_result(ticket, harness.record, verdict),
            )
            with self.subTest(verdict=verdict):
                self.assertEqual(result.slot_state, PublicationSlotState.PUBLISHED)
                self.assertEqual(len(harness.publisher.calls), 1)
                payload = harness.publisher.calls[0]
                self.assertEqual(payload.state, state)
                self.assertEqual(payload.description, description)
                self.assertNotIn(payload.state, {"pending", "error"})
                self.assertIsNone(payload.target_url)

    def test_publication_fields_are_not_finalize_parameters(self) -> None:
        parameters = inspect.signature(Harness().service.finalize_evaluation).parameters

        self.assertEqual(
            set(parameters),
            {"verified_oidc", "evaluation_id", "controller_result"},
        )

    def test_registry_supplies_context_and_publisher_identity(self) -> None:
        harness = Harness()
        ticket = harness.issue()
        harness.service.finalize_evaluation(
            harness.final_claims("final-context"),
            ticket.evaluation_id,
            controller_result(ticket, harness.record),
        )

        payload = harness.publisher.calls[0]
        self.assertEqual(payload.context, harness.record.status_context)
        self.assertEqual(harness.publisher.identity, harness.record.publisher_identity)

    def test_wrong_publisher_fails_before_call(self) -> None:
        harness = Harness()
        ticket = harness.issue()
        harness.publisher._identity = "mock-other"  # noqa: SLF001

        with self.assertRaisesRegex(SignerRefused, "publisher_identity_mismatch"):
            harness.service.finalize_evaluation(
                harness.final_claims("wrong-publisher"),
                ticket.evaluation_id,
                controller_result(ticket, harness.record),
            )
        self.assertEqual(harness.publisher.calls, ())


class UnknownPublicationTests(unittest.TestCase):
    def test_unknown_before_write_retries_only_identical_payload(self) -> None:
        harness = Harness(
            outcomes=[
                MockPublishMode.UNKNOWN_BEFORE_WRITE,
                MockPublishMode.PUBLISHED,
            ]
        )
        ticket = harness.issue()
        result = harness.service.finalize_evaluation(
            harness.final_claims("unknown-before-one"),
            ticket.evaluation_id,
            controller_result(ticket, harness.record),
        )
        self.assertEqual(result.slot_state, PublicationSlotState.UNKNOWN)

        result = harness.service.finalize_evaluation(
            harness.final_claims("unknown-before-two"),
            ticket.evaluation_id,
            controller_result(ticket, harness.record),
        )

        self.assertEqual(result.slot_state, PublicationSlotState.PUBLISHED)
        self.assertEqual(len(harness.publisher.calls), 2)
        self.assertEqual(
            harness.publisher.calls[0].canonical_digest(),
            harness.publisher.calls[1].canonical_digest(),
        )

    def test_unknown_after_write_reconciles_without_duplicate_call(self) -> None:
        harness = Harness(outcomes=[MockPublishMode.UNKNOWN_AFTER_WRITE])
        ticket = harness.issue()
        first = harness.service.finalize_evaluation(
            harness.final_claims("unknown-after-one"),
            ticket.evaluation_id,
            controller_result(ticket, harness.record),
        )
        self.assertEqual(first.slot_state, PublicationSlotState.UNKNOWN)

        second = harness.service.finalize_evaluation(
            harness.final_claims("unknown-after-two"),
            ticket.evaluation_id,
            controller_result(ticket, harness.record),
        )

        self.assertEqual(second.slot_state, PublicationSlotState.PUBLISHED)
        self.assertEqual(len(harness.publisher.calls), 1)
        self.assertIsNotNone(second.receipt)

    def test_definite_failure_remains_reserved_and_exactly_retryable(self) -> None:
        harness = Harness(
            outcomes=[MockPublishMode.DEFINITE_FAILURE, MockPublishMode.PUBLISHED]
        )
        ticket = harness.issue()
        first = harness.service.finalize_evaluation(
            harness.final_claims("definite-one"),
            ticket.evaluation_id,
            controller_result(ticket, harness.record),
        )
        self.assertEqual(first.slot_state, PublicationSlotState.RESERVED)
        self.assertTrue(first.retryable)

        second = harness.service.finalize_evaluation(
            harness.final_claims("definite-two"),
            ticket.evaluation_id,
            controller_result(ticket, harness.record),
        )

        self.assertEqual(second.slot_state, PublicationSlotState.PUBLISHED)
        self.assertEqual(len(harness.publisher.calls), 2)
        self.assertEqual(harness.publisher.calls[0], harness.publisher.calls[1])

    def test_opposite_payload_after_unknown_is_rejected(self) -> None:
        for first, second in (
            ("PASS", "SCANNER_FINDING"),
            ("SCANNER_FINDING", "PASS"),
        ):
            harness = Harness(outcomes=[MockPublishMode.UNKNOWN_BEFORE_WRITE])
            ticket = harness.issue()
            harness.service.finalize_evaluation(
                harness.final_claims(f"unknown-{first}"),
                ticket.evaluation_id,
                controller_result(ticket, harness.record, first),
            )
            with (
                self.subTest(first=first),
                self.assertRaisesRegex(SignerRefused, "publication_slot_conflict"),
            ):
                harness.service.finalize_evaluation(
                    harness.final_claims(f"opposite-{second}"),
                    ticket.evaluation_id,
                    controller_result(ticket, harness.record, second),
                )
            self.assertEqual(len(harness.publisher.calls), 1)

    def test_unknown_is_not_downgraded_by_later_infrastructure_refusal(self) -> None:
        harness = Harness(outcomes=[MockPublishMode.UNKNOWN_BEFORE_WRITE])
        ticket = harness.issue()
        first = harness.service.finalize_evaluation(
            harness.final_claims("unknown-before-infra"),
            ticket.evaluation_id,
            controller_result(ticket, harness.record),
        )

        second = harness.service.finalize_evaluation(
            harness.final_claims("infra-after-unknown"),
            ticket.evaluation_id,
            controller_result(
                ticket,
                harness.record,
                infrastructure_refusal=True,
            ),
        )

        self.assertEqual(first.evaluation_state, EvaluationState.UNKNOWN)
        self.assertEqual(second.evaluation_state, EvaluationState.UNKNOWN)
        self.assertTrue(second.retryable)
        self.assertEqual(len(harness.publisher.calls), 1)

    def test_definite_failure_does_not_downgrade_unknown(self) -> None:
        harness = Harness(
            outcomes=[
                MockPublishMode.UNKNOWN_BEFORE_WRITE,
                MockPublishMode.DEFINITE_FAILURE,
            ]
        )
        ticket = harness.issue()
        harness.service.finalize_evaluation(
            harness.final_claims("unknown-before-definite"),
            ticket.evaluation_id,
            controller_result(ticket, harness.record),
        )

        result = harness.service.finalize_evaluation(
            harness.final_claims("definite-after-unknown"),
            ticket.evaluation_id,
            controller_result(ticket, harness.record),
        )

        self.assertEqual(result.evaluation_state, EvaluationState.UNKNOWN)
        self.assertEqual(result.slot_state, PublicationSlotState.UNKNOWN)
        self.assertTrue(result.retryable)
        self.assertEqual(len(harness.publisher.calls), 2)

    def test_published_evaluation_rejects_later_infrastructure_refusal(self) -> None:
        harness = Harness()
        ticket = harness.issue()
        harness.service.finalize_evaluation(
            harness.final_claims("publish-before-infra"),
            ticket.evaluation_id,
            controller_result(ticket, harness.record),
        )

        with self.assertRaisesRegex(SignerRefused, "evaluation_already_published"):
            harness.service.finalize_evaluation(
                harness.final_claims("infra-after-publish"),
                ticket.evaluation_id,
                controller_result(
                    ticket,
                    harness.record,
                    infrastructure_refusal=True,
                ),
            )

        self.assertEqual(
            harness.store.get(ticket.evaluation_id).finalization_state,
            EvaluationState.PUBLISHED,
        )
        self.assertEqual(len(harness.publisher.calls), 1)

    def test_store_rejects_evaluation_and_slot_state_regression(self) -> None:
        harness = Harness()
        ticket = harness.issue()
        harness.service.finalize_evaluation(
            harness.final_claims("publish-before-regression"),
            ticket.evaluation_id,
            controller_result(ticket, harness.record),
        )
        slot_key = (REPOSITORY_ID, ticket.head_oid, ticket.policy_epoch)

        with self.assertRaisesRegex(SignerRefused, "evaluation_state_regression"):
            harness.store.set_state(ticket.evaluation_id, EvaluationState.UNKNOWN)
        with self.assertRaisesRegex(SignerRefused, "publication_slot_state_regression"):
            harness.store.set_slot_state(slot_key, PublicationSlotState.UNKNOWN)


class OrderingAndSharingTests(unittest.TestCase):
    def two_pr_tickets(self, harness: Harness):
        second_pull = PULL_NUMBER + 1
        harness.reader.set(
            PullRequestSnapshot(
                REPOSITORY_ID,
                second_pull,
                "open",
                harness.head_oid,
                "main",
            )
        )
        first = harness.issue(jti="admission-a", pull_number=PULL_NUMBER)
        second = harness.issue(jti="admission-b", pull_number=second_pull)
        return first, second

    def test_same_h_same_epoch_cross_pr_results_share_one_slot(self) -> None:
        harness = Harness()
        first, second = self.two_pr_tickets(harness)

        harness.service.finalize_evaluation(
            harness.final_claims("second-first"),
            second.evaluation_id,
            controller_result(second, harness.record),
        )
        result = harness.service.finalize_evaluation(
            harness.final_claims("first-later"),
            first.evaluation_id,
            controller_result(first, harness.record),
        )

        self.assertEqual(result.slot_state, PublicationSlotState.PUBLISHED)
        self.assertEqual(harness.store.slot_count(), 1)
        self.assertEqual(len(harness.publisher.calls), 1)

    def test_finalization_jti_cannot_be_replayed_across_evaluations(self) -> None:
        harness = Harness()
        first, second = self.two_pr_tickets(harness)
        claims = harness.final_claims("shared-finalization-jti")
        harness.service.finalize_evaluation(
            claims,
            first.evaluation_id,
            controller_result(first, harness.record),
        )

        with self.assertRaisesRegex(SignerRefused, "finalization_jti_reused"):
            harness.service.finalize_evaluation(
                claims,
                second.evaluation_id,
                controller_result(second, harness.record),
            )

        self.assertEqual(len(harness.publisher.calls), 1)

    def test_late_opposite_finalizer_conflicts_without_second_call(self) -> None:
        harness = Harness()
        first, second = self.two_pr_tickets(harness)
        harness.service.finalize_evaluation(
            harness.final_claims("second-pass"),
            second.evaluation_id,
            controller_result(second, harness.record, "PASS"),
        )

        with self.assertRaisesRegex(SignerRefused, "publication_slot_conflict"):
            harness.service.finalize_evaluation(
                harness.final_claims("first-failure"),
                first.evaluation_id,
                controller_result(first, harness.record, "SCANNER_FINDING"),
            )
        self.assertEqual(len(harness.publisher.calls), 1)

    def test_concurrent_idempotent_ticket_issuance_creates_one_evaluation(self) -> None:
        harness = Harness()
        barrier = threading.Barrier(8)
        tickets = []
        errors = []

        def issue(index: int) -> None:
            try:
                barrier.wait()
                tickets.append(harness.issue(jti=f"concurrent-admission-{index}"))
            except Exception as error:  # noqa: BLE001
                errors.append(error)

        threads = [threading.Thread(target=issue, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(len({ticket.evaluation_id for ticket in tickets}), 1)
        self.assertEqual(harness.store.evaluation_count(), 1)

    def test_concurrent_finalizers_publish_once(self) -> None:
        harness = Harness()
        first, second = self.two_pr_tickets(harness)
        barrier = threading.Barrier(2)
        results = []
        errors = []

        def finalize(ticket: object, jti: str) -> None:
            try:
                barrier.wait()
                results.append(
                    harness.service.finalize_evaluation(
                        harness.final_claims(jti),
                        ticket.evaluation_id,
                        controller_result(ticket, harness.record),
                    )
                )
            except Exception as error:  # noqa: BLE001
                errors.append(error)

        threads = [
            threading.Thread(target=finalize, args=(first, "concurrent-first")),
            threading.Thread(target=finalize, args=(second, "concurrent-second")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(len(harness.publisher.calls), 1)
        self.assertEqual(harness.store.slot_count(), 1)


if __name__ == "__main__":
    unittest.main()
