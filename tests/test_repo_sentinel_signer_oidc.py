"""OIDC claim and execution-identity tests for signer v1."""

from __future__ import annotations

import unittest

from tests.signer_test_support import (
    NOW,
    OWNER_ID,
    REPOSITORY_ID,
    Harness,
    raw_claims,
    registry_record,
    verified_claims,
)

from repo_sentinel_signer import (  # noqa: E402
    SIGNER_AUDIENCE,
    MockOidcVerifier,
    SignerRefused,
    TicketRequest,
    VerifiedOidcClaims,
)


class ClaimModelTests(unittest.TestCase):
    def test_canonical_decimal_claims_are_parsed(self) -> None:
        record = registry_record()
        claims = VerifiedOidcClaims.from_verified_mapping(raw_claims(record))

        self.assertEqual(claims.repository_id, REPOSITORY_ID)
        self.assertEqual(claims.repository_owner_id, OWNER_ID)
        self.assertEqual(claims.run_id, 7001)
        self.assertEqual(claims.run_attempt, 1)

    def test_malformed_numeric_claims_fail_closed(self) -> None:
        record = registry_record()
        invalid = (
            True,
            1.0,
            -1,
            0,
            "0",
            "-1",
            "+1",
            " 1",
            "1 ",
            "01",
            "1.0",
            "one",
            "",
        )
        for field in (
            "repository_id",
            "repository_owner_id",
            "run_id",
            "run_attempt",
        ):
            for value in invalid:
                with self.subTest(field=field, value=value):
                    claims = raw_claims(record)
                    claims[field] = value
                    with self.assertRaises(SignerRefused):
                        VerifiedOidcClaims.from_verified_mapping(claims)

    def test_timestamp_claims_require_exact_nonnegative_integers(self) -> None:
        record = registry_record()
        for field in ("iat", "nbf", "exp"):
            for value in (True, 1.0, "1", -1):
                with self.subTest(field=field, value=value):
                    claims = raw_claims(record)
                    claims[field] = value
                    with self.assertRaises(SignerRefused):
                        VerifiedOidcClaims.from_verified_mapping(claims)

    def test_claim_shape_rejects_missing_extra_and_unpaired_reusable_fields(
        self,
    ) -> None:
        record = registry_record(reusable=True)
        cases = []
        missing = raw_claims(record)
        missing.pop("jti")
        cases.append(missing)
        extra = raw_claims(record)
        extra["actor"] = "someone"
        cases.append(extra)
        unpaired = raw_claims(record)
        unpaired.pop("job_workflow_sha")
        cases.append(unpaired)

        for candidate in cases:
            with self.subTest(keys=sorted(candidate)):
                with self.assertRaisesRegex(SignerRefused, "invalid_oidc_claims"):
                    VerifiedOidcClaims.from_verified_mapping(candidate)

    def test_empty_jti_and_bad_workflow_sha_are_rejected(self) -> None:
        record = registry_record()
        for field, value in (("jti", ""), ("workflow_sha", "A" * 40)):
            claims = raw_claims(record)
            claims[field] = value
            with self.subTest(field=field), self.assertRaises(SignerRefused):
                VerifiedOidcClaims.from_verified_mapping(claims)


class MockVerifierTests(unittest.TestCase):
    def test_mock_verifier_returns_only_validated_claim_model(self) -> None:
        record = registry_record()
        verifier = MockOidcVerifier({"opaque-token": raw_claims(record)})

        claims = verifier.verify("opaque-token", SIGNER_AUDIENCE)

        self.assertIs(type(claims), VerifiedOidcClaims)

    def test_mock_verifier_rejects_unknown_token_and_wrong_audience(self) -> None:
        record = registry_record()
        verifier = MockOidcVerifier({"opaque-token": raw_claims(record)})

        with self.assertRaisesRegex(SignerRefused, "oidc_verification_failed"):
            verifier.verify("other-token", SIGNER_AUDIENCE)
        with self.assertRaisesRegex(SignerRefused, "oidc_audience_mismatch"):
            verifier.verify("opaque-token", "wrong-audience")

    def test_no_production_looking_verifier_is_exported(self) -> None:
        import repo_sentinel_signer as signer

        self.assertFalse(hasattr(signer, "GitHubOidcVerifier"))
        self.assertFalse(hasattr(signer, "ProductionOidcVerifier"))


class AdmissionAuthorizationTests(unittest.TestCase):
    def test_service_rejects_unverified_mapping(self) -> None:
        harness = Harness()

        with self.assertRaisesRegex(SignerRefused, "unverified_oidc_claims"):
            harness.service.issue_evaluation(  # type: ignore[arg-type]
                raw_claims(harness.record), TicketRequest(22)
            )

    def test_execution_identity_mismatches_fail_closed(self) -> None:
        harness = Harness()
        valid = raw_claims(harness.record, now=harness.clock.now)
        cases = {
            "issuer": ("iss", "https://issuer.example"),
            "audience": ("aud", "wrong-audience"),
            "repository-id": ("repository_id", str(REPOSITORY_ID + 1)),
            "owner-id": ("repository_owner_id", str(OWNER_ID + 1)),
            "repository": ("repository", "stacknil/other"),
            "owner": ("repository_owner", "other-owner"),
            "event": ("event_name", "pull_request"),
            "runner": ("runner_environment", "self-hosted"),
            "workflow-ref": (
                "workflow_ref",
                "stacknil/other/.github/workflows/x.yml@main",
            ),
            "workflow-sha": ("workflow_sha", "f" * 40),
        }
        for name, (field, value) in cases.items():
            candidate = dict(valid)
            candidate[field] = value
            claims = VerifiedOidcClaims.from_verified_mapping(candidate)
            with self.subTest(name=name), self.assertRaises(SignerRefused):
                harness.service.issue_evaluation(claims, TicketRequest(22))

    def test_reusable_binding_is_exact(self) -> None:
        harness = Harness(record=registry_record(reusable=True))
        cases = (
            {"job_workflow_ref": "stacknil/other/.github/workflows/x.yml@v1"},
            {"job_workflow_sha": "f" * 40},
        )
        for changes in cases:
            claims = verified_claims(harness.record, **changes)
            with (
                self.subTest(changes=changes),
                self.assertRaisesRegex(SignerRefused, "oidc_reusable_mismatch"),
            ):
                harness.service.issue_evaluation(claims, TicketRequest(22))

    def test_unconfigured_reusable_identity_is_not_silently_accepted(self) -> None:
        harness = Harness()
        claims = raw_claims(harness.record)
        claims["job_workflow_ref"] = "stacknil/shared/.github/workflows/x.yml@v1"
        claims["job_workflow_sha"] = "f" * 40

        with self.assertRaisesRegex(SignerRefused, "oidc_reusable_mismatch"):
            harness.service.issue_evaluation(
                VerifiedOidcClaims.from_verified_mapping(claims), TicketRequest(22)
            )

    def test_time_window_uses_injected_clock_and_explicit_skew(self) -> None:
        harness = Harness()
        cases = (
            ({"nbf": NOW + 1}, "oidc_not_yet_valid"),
            ({"exp": NOW - 1}, "oidc_expired"),
            ({"iat": NOW + 31}, "oidc_issued_in_future"),
        )
        for changes, code in cases:
            claims = verified_claims(harness.record, **changes)
            with (
                self.subTest(changes=changes),
                self.assertRaisesRegex(SignerRefused, code),
            ):
                harness.service.issue_evaluation(claims, TicketRequest(22))

    def test_token_lifetime_is_not_forced_to_an_arbitrary_duration(self) -> None:
        harness = Harness()
        claims = verified_claims(
            harness.record,
            iat=NOW - 10_000,
            nbf=NOW - 10_000,
            exp=NOW + 1,
        )

        ticket = harness.service.issue_evaluation(claims, TicketRequest(22))

        self.assertEqual(ticket.head_oid, harness.head_oid)


if __name__ == "__main__":
    unittest.main()
