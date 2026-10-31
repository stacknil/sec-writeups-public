"""Authorization time must be sampled after waiting for the signer transaction."""

from __future__ import annotations

import threading
import unittest
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from functools import partial
from unittest.mock import patch

from tests.signer_test_support import NOW, PULL_NUMBER, Harness, controller_result

from repo_sentinel_signer import SignerRefused, TicketRequest  # noqa: E402


class TransactionTimeTests(unittest.TestCase):
    def after_lock_wait(
        self, harness: Harness, operation: Callable[[], object], resume_at: int
    ) -> object:
        """Use the real shared lock and a logical clock; never sleep for expiry."""
        attempted = threading.Event()
        transaction = harness.store.transaction

        @contextmanager
        def observed_transaction() -> Iterator[None]:
            attempted.set()
            with transaction():
                yield

        with (
            patch.object(harness.store, "transaction", observed_transaction),
            ThreadPoolExecutor(max_workers=1) as executor,
        ):
            with harness.lock:
                future = executor.submit(operation)
                self.assertTrue(attempted.wait(timeout=5), "transaction not reached")
                harness.clock.now = resume_at
            return future.result(timeout=5)

    def test_oidc_expiring_while_queued_is_rejected(self) -> None:
        for operation in ("admission", "admission-retry", "finalization"):
            with self.subTest(operation=operation):
                harness = Harness()
                ticket = harness.issue()
                claims = harness.final_claims(
                    "queued-identity",
                    exp=NOW + 1,
                    run_id=7002 if operation == "admission" else 7001,
                )
                evidence = controller_result(ticket, harness.record)

                if operation != "finalization":
                    request = partial(
                        harness.service.issue_evaluation,
                        claims,
                        TicketRequest(PULL_NUMBER),
                    )
                else:
                    request = partial(
                        harness.service.finalize_evaluation,
                        claims,
                        ticket.evaluation_id,
                        evidence,
                    )

                with self.assertRaisesRegex(SignerRefused, "^oidc_expired$"):
                    self.after_lock_wait(harness, request, NOW + 2)

                self.assertEqual(harness.store.evaluation_count(), 1)
                self.assertEqual(harness.store.slot_count(), 0)
                self.assertEqual(harness.publisher.calls, ())
                self.assertEqual(
                    harness.store.get(ticket.evaluation_id).finalization_state.value,
                    "ISSUED",
                )

    def test_queued_expiry_consumes_jti(self) -> None:
        harness = Harness()
        ticket = harness.issue()
        claims = harness.final_claims("queued-evaluation", exp=ticket.expires_at + 100)
        evidence = controller_result(ticket, harness.record)

        def finalize() -> object:
            return harness.service.finalize_evaluation(
                claims, ticket.evaluation_id, evidence
            )

        with self.assertRaisesRegex(SignerRefused, "^evaluation_expired$"):
            self.after_lock_wait(harness, finalize, ticket.expires_at + 1)
        with self.assertRaisesRegex(SignerRefused, "^finalization_jti_reused$"):
            finalize()
        self.assertEqual(harness.store.slot_count(), 0)
        self.assertEqual(harness.publisher.calls, ())

    def test_valid_admission_uses_time_after_wait_for_issued_at_and_ttl(self) -> None:
        harness = Harness()
        claims = harness.final_claims("queued-admission")

        ticket = self.after_lock_wait(
            harness,
            lambda: harness.service.issue_evaluation(
                claims, TicketRequest(PULL_NUMBER)
            ),
            NOW + 10,
        )

        evaluation = harness.store.get(ticket.evaluation_id)
        self.assertEqual(evaluation.issued_at, NOW + 10)
        self.assertEqual(ticket.expires_at, NOW + 10 + 900)
        self.assertEqual(harness.store.evaluation_count(), 1)

    def test_finalization_at_exact_expiry_retains_inclusive_contract(self) -> None:
        harness = Harness()
        ticket = harness.issue()
        claims = harness.final_claims("queued-at-boundary", exp=ticket.expires_at)
        evidence = controller_result(ticket, harness.record)

        result = self.after_lock_wait(
            harness,
            lambda: harness.service.finalize_evaluation(
                claims, ticket.evaluation_id, evidence
            ),
            ticket.expires_at,
        )

        self.assertEqual(result.evaluation_state.value, "PUBLISHED")
        self.assertEqual(len(harness.publisher.calls), 1)


if __name__ == "__main__":
    unittest.main()
