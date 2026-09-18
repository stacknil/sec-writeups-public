"""OIDC verification abstraction and deterministic mock implementation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from .model import (
    SignerRefused,
    VerifiedOidcClaims,
    copy_claim_mapping,
    require_string,
)


class OidcVerifier(Protocol):
    def verify(self, raw_token: str, expected_audience: str) -> VerifiedOidcClaims: ...


class MockOidcVerifier:
    """Return pre-registered claims; this class performs no cryptography."""

    def __init__(self, tokens: Mapping[str, Mapping[str, object]]) -> None:
        self._tokens: dict[str, dict[str, object]] = {}
        for token, claims in tokens.items():
            key = require_string(token, "raw_token")
            if key in self._tokens:
                raise SignerRefused("duplicate_mock_token")
            self._tokens[key] = copy_claim_mapping(claims)

    def verify(self, raw_token: str, expected_audience: str) -> VerifiedOidcClaims:
        token = require_string(raw_token, "raw_token")
        audience = require_string(expected_audience, "expected_audience")
        try:
            raw_claims = self._tokens[token]
        except KeyError:
            raise SignerRefused("oidc_verification_failed") from None
        claims = VerifiedOidcClaims.from_verified_mapping(raw_claims)
        if claims.aud != audience:
            raise SignerRefused("oidc_audience_mismatch")
        return claims
