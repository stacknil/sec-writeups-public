"""Ticket, PR freshness, and controller binding tests for signer v1."""

from __future__ import annotations

import copy
import unittest
from dataclasses import replace

from tests.signer_test_support import (
    OWNER_ID,
    POLICY_DIGEST_KEY,
    PULL_NUMBER,
    REPOSITORY_ID,
    WORKER_DIGEST_KEY,
    Harness,
    controller_result,
    digest,
    oid,
    worker_semantic_digest,
)

from repo_sentinel_signer import (  # noqa: E402
    PullRequestSnapshot,
    SignerRefused,
)


class TicketIssuanceTests(unittest.TestCase):
    def test_ticket_contains_only_server_selected_evaluation_parameters(self) -> None:
        harness = Harness()

        ticket = harness.issue()

        self.assertEqual(ticket.repository_id, REPOSITORY_ID)
        self.assertEqual(ticket.pull_number, PULL_NUMBER)
        self.assertEqual(ticket.head_oid, harness.head_oid)
        self.assertEqual(ticket.policy_epoch, harness.record.policy_epoch)
        self.assertEqual(
            ticket.policy_digest,
            harness.record.policy_digest,
        )
        transport = ticket.to_mapping()
        digest_key = "_".join(("expected", "policy", "bundle", "sha256"))
        self.assertEqual(
            set(transport),
            {
                "evaluation_id",
                "repository_id",
                "pull_number",
                "head_oid",
                "policy_selector",
                "policy_epoch",
                digest_key,
                "controller_protocol",
                "controller_schema_version",
                "scanner_distribution",
                "scanner_version",
                "scanner_artifact_sha256",
                "expires_at",
            },
        )
        self.assertEqual(transport[digest_key], harness.record.policy_digest)
        self.assertFalse(hasattr(ticket, "status_context"))
        self.assertFalse(hasattr(ticket, "publisher_identity"))
        self.assertFalse(hasattr(ticket, "workflow_sha"))

    def test_pr_head_is_taken_from_server_side_reader(self) -> None:
        harness = Harness(head_oid=oid("server-side-head"))

        ticket = harness.issue()

        self.assertEqual(ticket.head_oid, oid("server-side-head"))

    def test_missing_closed_or_wrong_identity_pr_is_rejected(self) -> None:
        cases = ("missing", "closed", "wrong-identity")
        for case in cases:
            harness = Harness()
            if case == "missing":
                harness.reader.remove(REPOSITORY_ID, PULL_NUMBER)
            elif case == "closed":
                harness.reader.set(
                    PullRequestSnapshot(
                        REPOSITORY_ID,
                        PULL_NUMBER,
                        "closed",
                        harness.head_oid,
                        "main",
                    )
                )
            else:

                class WrongReader:
                    def read(self, _repository_id: int, _pull_number: int):
                        return PullRequestSnapshot(
                            REPOSITORY_ID,
                            PULL_NUMBER + 1,
                            "open",
                            harness.head_oid,
                            "main",
                        )

                harness.service._pull_requests = WrongReader()  # noqa: SLF001
            with self.subTest(case=case), self.assertRaises(SignerRefused):
                harness.issue()

    def test_same_execution_ticket_is_idempotent_across_fresh_admission_jtis(
        self,
    ) -> None:
        harness = Harness()

        first = harness.issue(jti="admission-one")
        second = harness.issue(jti="admission-two")

        self.assertEqual(first, second)
        self.assertEqual(harness.store.evaluation_count(), 1)

    def test_same_admission_jti_cannot_create_different_evaluation(self) -> None:
        harness = Harness()
        harness.issue(jti="one-jti")
        harness.reader.set(
            PullRequestSnapshot(
                REPOSITORY_ID,
                PULL_NUMBER,
                "open",
                oid("new-head"),
                "main",
            )
        )

        with self.assertRaisesRegex(SignerRefused, "admission_jti_reused"):
            harness.issue(jti="one-jti")


class FinalizationIdentityTests(unittest.TestCase):
    def test_fresh_oidc_is_required(self) -> None:
        harness = Harness()
        ticket = harness.issue(jti="admission-jti")

        with self.assertRaisesRegex(SignerRefused, "fresh_oidc_required"):
            harness.service.finalize_evaluation(
                harness.final_claims("admission-jti"),
                ticket.evaluation_id,
                controller_result(ticket, harness.record),
            )

    def test_any_jti_used_for_idempotent_admission_is_not_fresh(self) -> None:
        harness = Harness()
        ticket = harness.issue(jti="admission-one")
        harness.issue(jti="admission-two")

        with self.assertRaisesRegex(SignerRefused, "fresh_oidc_required"):
            harness.service.finalize_evaluation(
                harness.final_claims("admission-two"),
                ticket.evaluation_id,
                controller_result(ticket, harness.record),
            )

    def test_execution_tuple_mismatches_cannot_finalize(self) -> None:
        cases = {
            "run-id": {"run_id": 8002},
            "run-attempt": {"run_attempt": 2},
            "workflow-sha": {"workflow_sha": oid("wrong-workflow")},
            "repository": {"repository_id": REPOSITORY_ID + 1},
            "owner": {"repository_owner_id": OWNER_ID + 1},
        }
        for name, changes in cases.items():
            harness = Harness()
            ticket = harness.issue()
            claims = replace(harness.final_claims(f"final-{name}"), **changes)
            with self.subTest(name=name), self.assertRaises(SignerRefused):
                harness.service.finalize_evaluation(
                    claims,
                    ticket.evaluation_id,
                    controller_result(ticket, harness.record),
                )
            self.assertEqual(harness.publisher.calls, ())

    def test_finalization_jti_cannot_be_reused_after_retryable_refusal(self) -> None:
        harness = Harness()
        ticket = harness.issue()
        claims = harness.final_claims("one-finalization-jti")
        refusal = controller_result(ticket, harness.record, infrastructure_refusal=True)
        harness.service.finalize_evaluation(claims, ticket.evaluation_id, refusal)

        with self.assertRaisesRegex(SignerRefused, "finalization_jti_reused"):
            harness.service.finalize_evaluation(claims, ticket.evaluation_id, refusal)

    def test_malformed_evidence_consumes_authenticated_finalization_jti(self) -> None:
        harness = Harness()
        ticket = harness.issue()
        malformed = controller_result(ticket, harness.record)
        malformed["extra"] = "not-allowed"
        reused = harness.final_claims("malformed-evidence-jti")

        with self.assertRaisesRegex(SignerRefused, "controller_result_invalid"):
            harness.service.finalize_evaluation(
                reused,
                ticket.evaluation_id,
                malformed,
            )
        with self.assertRaisesRegex(SignerRefused, "finalization_jti_reused"):
            harness.service.finalize_evaluation(
                reused,
                ticket.evaluation_id,
                controller_result(ticket, harness.record),
            )

        result = harness.service.finalize_evaluation(
            harness.final_claims("fresh-after-malformed"),
            ticket.evaluation_id,
            controller_result(ticket, harness.record),
        )

        self.assertEqual(result.evaluation_state.value, "PUBLISHED")

    def test_expired_evaluation_requires_new_admission(self) -> None:
        harness = Harness()
        ticket = harness.issue()
        harness.clock.now = ticket.expires_at + 1

        with self.assertRaisesRegex(SignerRefused, "evaluation_expired"):
            harness.service.finalize_evaluation(
                harness.final_claims("late-finalization"),
                ticket.evaluation_id,
                controller_result(ticket, harness.record),
            )


class PullRequestFreshnessTests(unittest.TestCase):
    def test_head_change_and_pr_close_reject_finalization(self) -> None:
        for state, head, code in (
            ("open", oid("advanced-head"), "pull_request_head_changed"),
            ("closed", oid("pull-head"), "pull_request_closed"),
        ):
            harness = Harness()
            ticket = harness.issue()
            harness.reader.set(
                PullRequestSnapshot(
                    REPOSITORY_ID,
                    PULL_NUMBER,
                    state,
                    head,
                    "main",
                )
            )
            with self.subTest(state=state), self.assertRaisesRegex(SignerRefused, code):
                harness.service.finalize_evaluation(
                    harness.final_claims(f"fresh-{state}"),
                    ticket.evaluation_id,
                    controller_result(ticket, harness.record),
                )

    def test_base_only_movement_does_not_change_p_of_h(self) -> None:
        harness = Harness()
        ticket = harness.issue()
        harness.reader.set(
            PullRequestSnapshot(
                REPOSITORY_ID,
                PULL_NUMBER,
                "open",
                harness.head_oid,
                "release",
            )
        )

        result = harness.service.finalize_evaluation(
            harness.final_claims("base-moved"),
            ticket.evaluation_id,
            controller_result(ticket, harness.record),
        )

        self.assertEqual(result.evaluation_state.value, "PUBLISHED")


class ControllerResultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.ticket = self.harness.issue()
        self.valid = controller_result(self.ticket, self.harness.record)

    def assert_refused_without_publish(self, candidate: object, suffix: str) -> None:
        with self.assertRaises(SignerRefused):
            self.harness.service.finalize_evaluation(
                self.harness.final_claims(f"invalid-{suffix}"),
                self.ticket.evaluation_id,
                candidate,
            )
        self.assertEqual(self.harness.publisher.calls, ())

    def test_extra_missing_and_subclassed_top_level_shapes_are_rejected(self) -> None:
        extra = copy.deepcopy(self.valid)
        extra["extra"] = "value"
        revision_substitution = copy.deepcopy(self.valid)
        revision_substitution["registry_revision"] = 2
        missing = copy.deepcopy(self.valid)
        missing.pop("head_oid")

        class MappingAlias(dict):
            pass

        for name, candidate in (
            ("extra", extra),
            ("registry-revision", revision_substitution),
            ("missing", missing),
            ("mapping-subclass", MappingAlias(self.valid)),
        ):
            with self.subTest(name=name):
                self.assert_refused_without_publish(candidate, name)

    def test_top_level_binding_substitution_is_rejected(self) -> None:
        cases = {
            "repository_id": REPOSITORY_ID + 1,
            "head_oid": oid("substituted-head"),
            "policy_selector": "v3",
            "policy_epoch": "other-epoch",
            POLICY_DIGEST_KEY: digest("other-bundle"),
            "controller_protocol": "other-controller",
            "controller_schema_version": 2,
        }
        for field, value in cases.items():
            candidate = copy.deepcopy(self.valid)
            candidate[field] = value
            with self.subTest(field=field):
                self.assert_refused_without_publish(candidate, field)

    def test_worker_binding_substitution_is_rejected_even_with_rehashed_semantic(
        self,
    ) -> None:
        cases = {
            "repository_id": REPOSITORY_ID + 1,
            "head_oid": oid("substituted-worker-head"),
            "policy_epoch": "other-epoch",
            POLICY_DIGEST_KEY: digest("other-worker-bundle"),
            "scanner_distribution": "other-scanner",
            "scanner_version": "9.9.9",
            "scanner_artifact_sha256": digest("other-scanner-artifact"),
        }
        for field, value in cases.items():
            candidate = copy.deepcopy(self.valid)
            worker = candidate["worker_result"]
            worker[field] = value
            worker["semantic_sha256"] = worker_semantic_digest(worker)
            candidate[WORKER_DIGEST_KEY] = worker["semantic_sha256"]
            with self.subTest(field=field):
                self.assert_refused_without_publish(candidate, f"worker-{field}")

    def test_semantic_digest_substitution_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.valid)
        candidate[WORKER_DIGEST_KEY] = digest("wrong-semantic")

        self.assert_refused_without_publish(candidate, "semantic")

    def test_bool_int_confusion_and_string_subclass_are_rejected(self) -> None:
        bool_value = copy.deepcopy(self.valid)
        bool_value["repository_id"] = True

        class StringAlias(str):
            pass

        alias = copy.deepcopy(self.valid)
        alias["controller_protocol"] = StringAlias(
            self.harness.record.controller_protocol
        )
        for name, candidate in (("bool", bool_value), ("alias", alias)):
            with self.subTest(name=name):
                self.assert_refused_without_publish(candidate, name)

    def test_worker_extra_missing_invalid_verdict_and_refusal_are_rejected(
        self,
    ) -> None:
        candidates = []
        extra = copy.deepcopy(self.valid)
        extra["worker_result"]["extra"] = 1
        candidates.append(extra)
        missing = copy.deepcopy(self.valid)
        missing["worker_result"].pop("files_total")
        candidates.append(missing)
        verdict = copy.deepcopy(self.valid)
        verdict["worker_result"]["verdict"] = "ERROR"
        candidates.append(verdict)
        refusal = copy.deepcopy(self.valid)
        refusal["worker_result"]["refusal_code"] = "unexpected"
        candidates.append(refusal)

        for index, candidate in enumerate(candidates):
            with self.subTest(index=index):
                self.assert_refused_without_publish(candidate, f"worker-{index}")

    def test_infrastructure_refusal_creates_no_publication_slot(self) -> None:
        refusal = controller_result(
            self.ticket, self.harness.record, infrastructure_refusal=True
        )

        result = self.harness.service.finalize_evaluation(
            self.harness.final_claims("infra-refusal"),
            self.ticket.evaluation_id,
            refusal,
        )

        self.assertTrue(result.retryable)
        self.assertIsNone(result.slot_state)
        self.assertEqual(self.harness.store.slot_count(), 0)
        self.assertEqual(self.harness.publisher.calls, ())

    def test_malformed_infrastructure_refusal_is_rejected(self) -> None:
        refusal = controller_result(
            self.ticket, self.harness.record, infrastructure_refusal=True
        )
        refusal["worker_result"] = self.valid["worker_result"]

        self.assert_refused_without_publish(refusal, "malformed-infra")

    def test_unknown_infrastructure_refusal_code_is_rejected(self) -> None:
        refusal = controller_result(
            self.ticket, self.harness.record, infrastructure_refusal=True
        )
        refusal["fixed_refusal_code"] = "caller_selected_refusal"

        self.assert_refused_without_publish(refusal, "unknown-infra-code")


if __name__ == "__main__":
    unittest.main()
