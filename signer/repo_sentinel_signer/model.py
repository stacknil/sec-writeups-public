"""Immutable values and strict boundary validation for signer v1."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

SIGNER_PROTOCOL = "repo-sentinel-signer-v1"
GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
SIGNER_AUDIENCE = "repo-sentinel-authoritative-signer-v1"

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_CANONICAL_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_PUBLICATION_DOMAIN = b"repo-sentinel-signer-publication-v1\0"
_TICKET_DIGEST_KEY = "_".join(("expected", "policy", "bundle", "sha256"))


class SignerRefused(RuntimeError):
    """Fail-closed signer refusal with a stable machine-readable code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def require_string(value: object, field: str, *, maximum: int = 512) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise SignerRefused(f"invalid_{field}")
    if value != value.strip() or any(ord(character) < 0x20 for character in value):
        raise SignerRefused(f"invalid_{field}")
    return value


def normalize_status_context(value: object) -> str:
    """Return the portable physical namespace key for a Commit Status context."""

    context = require_string(value, "status_context", maximum=100)
    if any(not 0x20 <= ord(character) <= 0x7E for character in context):
        raise SignerRefused("invalid_status_context")
    return context.lower()


def require_digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise SignerRefused(f"invalid_{field}")
    return value


def require_oid(value: object, field: str) -> str:
    if type(value) is not str or _OID.fullmatch(value) is None:
        raise SignerRefused(f"invalid_{field}")
    return value


def require_positive_int(value: object, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise SignerRefused(f"invalid_{field}")
    return value


def parse_canonical_decimal(value: object, field: str, *, positive: bool = True) -> int:
    if type(value) is int:
        parsed = value
    elif type(value) is str and _CANONICAL_DECIMAL.fullmatch(value) is not None:
        parsed = int(value)
    else:
        raise SignerRefused(f"invalid_{field}")
    if parsed < 0 or (positive and parsed == 0):
        raise SignerRefused(f"invalid_{field}")
    return parsed


def _require_timestamp(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise SignerRefused(f"invalid_{field}")
    return value


@dataclass(frozen=True, slots=True)
class VerifiedOidcClaims:
    """Claims returned only after an OIDC verifier establishes authenticity."""

    iss: str
    aud: str
    sub: str
    jti: str
    iat: int
    nbf: int
    exp: int
    repository: str
    repository_id: int
    repository_owner: str
    repository_owner_id: int
    event_name: str
    runner_environment: str
    workflow_ref: str
    workflow_sha: str
    run_id: int
    run_attempt: int
    job_workflow_ref: str | None = None
    job_workflow_sha: str | None = None

    def __post_init__(self) -> None:
        for field in (
            "iss",
            "aud",
            "sub",
            "jti",
            "repository",
            "repository_owner",
            "event_name",
            "runner_environment",
            "workflow_ref",
        ):
            require_string(getattr(self, field), field)
        require_oid(self.workflow_sha, "workflow_sha")
        require_positive_int(self.repository_id, "repository_id")
        require_positive_int(self.repository_owner_id, "repository_owner_id")
        require_positive_int(self.run_id, "run_id")
        require_positive_int(self.run_attempt, "run_attempt")
        _require_timestamp(self.iat, "iat")
        _require_timestamp(self.nbf, "nbf")
        _require_timestamp(self.exp, "exp")
        if self.nbf > self.exp:
            raise SignerRefused("invalid_oidc_time_window")
        paired = (self.job_workflow_ref is None, self.job_workflow_sha is None)
        if paired[0] != paired[1]:
            raise SignerRefused("invalid_job_workflow_identity")
        if self.job_workflow_ref is not None:
            require_string(self.job_workflow_ref, "job_workflow_ref")
            require_oid(self.job_workflow_sha, "job_workflow_sha")

    @classmethod
    def from_verified_mapping(cls, value: object) -> VerifiedOidcClaims:
        required = {
            "iss",
            "aud",
            "sub",
            "jti",
            "iat",
            "nbf",
            "exp",
            "repository",
            "repository_id",
            "repository_owner",
            "repository_owner_id",
            "event_name",
            "runner_environment",
            "workflow_ref",
            "workflow_sha",
            "run_id",
            "run_attempt",
        }
        optional = {"job_workflow_ref", "job_workflow_sha"}
        if type(value) is not dict:
            raise SignerRefused("invalid_oidc_claims")
        keys = set(value)
        if not required.issubset(keys) or not keys.issubset(required | optional):
            raise SignerRefused("invalid_oidc_claims")
        if bool(keys & optional) and not optional.issubset(keys):
            raise SignerRefused("invalid_oidc_claims")
        claims = dict(value)
        return cls(
            iss=require_string(claims["iss"], "iss"),
            aud=require_string(claims["aud"], "aud"),
            sub=require_string(claims["sub"], "sub"),
            jti=require_string(claims["jti"], "jti"),
            iat=_require_timestamp(claims["iat"], "iat"),
            nbf=_require_timestamp(claims["nbf"], "nbf"),
            exp=_require_timestamp(claims["exp"], "exp"),
            repository=require_string(claims["repository"], "repository"),
            repository_id=parse_canonical_decimal(
                claims["repository_id"], "repository_id"
            ),
            repository_owner=require_string(
                claims["repository_owner"], "repository_owner"
            ),
            repository_owner_id=parse_canonical_decimal(
                claims["repository_owner_id"], "repository_owner_id"
            ),
            event_name=require_string(claims["event_name"], "event_name"),
            runner_environment=require_string(
                claims["runner_environment"], "runner_environment"
            ),
            workflow_ref=require_string(claims["workflow_ref"], "workflow_ref"),
            workflow_sha=require_oid(claims["workflow_sha"], "workflow_sha"),
            run_id=parse_canonical_decimal(claims["run_id"], "run_id"),
            run_attempt=parse_canonical_decimal(claims["run_attempt"], "run_attempt"),
            job_workflow_ref=(
                require_string(claims["job_workflow_ref"], "job_workflow_ref")
                if "job_workflow_ref" in claims
                else None
            ),
            job_workflow_sha=(
                require_oid(claims["job_workflow_sha"], "job_workflow_sha")
                if "job_workflow_sha" in claims
                else None
            ),
        )

    def execution_tuple(self) -> tuple[object, ...]:
        return (
            self.repository_id,
            self.repository_owner_id,
            self.workflow_ref,
            self.workflow_sha,
            self.job_workflow_ref,
            self.job_workflow_sha,
            self.run_id,
            self.run_attempt,
        )


@dataclass(frozen=True, slots=True)
class PullRequestSnapshot:
    repository_id: int
    pull_number: int
    state: str
    head_oid: str
    base_ref: str

    def __post_init__(self) -> None:
        require_positive_int(self.repository_id, "repository_id")
        require_positive_int(self.pull_number, "pull_number")
        if type(self.state) is not str or self.state not in {"open", "closed"}:
            raise SignerRefused("invalid_pull_request_state")
        require_oid(self.head_oid, "head_oid")
        require_string(self.base_ref, "base_ref")


@dataclass(frozen=True, slots=True)
class RegistryRecord:
    record_id: str
    revision: int
    repository_id: int
    repository_owner_id: int
    repository: str
    policy_selector: str
    policy_epoch: str
    policy_digest: str
    controller_protocol: str
    controller_schema_version: int
    scanner_distribution: str
    scanner_version: str
    scanner_artifact_sha256: str
    workflow_ref: str
    workflow_sha: str
    status_context: str
    publisher_identity: str
    job_workflow_ref: str | None = None
    job_workflow_sha: str | None = None

    def __post_init__(self) -> None:
        for field in (
            "record_id",
            "repository",
            "policy_selector",
            "policy_epoch",
            "controller_protocol",
            "scanner_distribution",
            "scanner_version",
            "workflow_ref",
            "publisher_identity",
        ):
            require_string(getattr(self, field), field)
        require_positive_int(self.revision, "revision")
        require_positive_int(self.repository_id, "repository_id")
        require_positive_int(self.repository_owner_id, "repository_owner_id")
        require_positive_int(
            self.controller_schema_version, "controller_schema_version"
        )
        require_digest(self.policy_digest, "policy_digest")
        require_digest(self.scanner_artifact_sha256, "scanner_artifact_sha256")
        require_oid(self.workflow_sha, "workflow_sha")
        normalize_status_context(self.status_context)
        owner, separator, name = self.repository.partition("/")
        if not separator or not owner or not name or "/" in name:
            raise SignerRefused("invalid_repository")
        paired = (self.job_workflow_ref is None, self.job_workflow_sha is None)
        if paired[0] != paired[1]:
            raise SignerRefused("invalid_job_workflow_identity")
        if self.job_workflow_ref is not None:
            require_string(self.job_workflow_ref, "job_workflow_ref")
            require_oid(self.job_workflow_sha, "job_workflow_sha")

    @property
    def key(self) -> tuple[str, int]:
        return self.record_id, self.revision


@dataclass(frozen=True, slots=True)
class TicketRequest:
    pull_number: int

    def __post_init__(self) -> None:
        require_positive_int(self.pull_number, "pull_number")


@dataclass(frozen=True, slots=True)
class TicketResponse:
    evaluation_id: str
    repository_id: int
    pull_number: int
    head_oid: str
    policy_selector: str
    policy_epoch: str
    policy_digest: str
    controller_protocol: str
    controller_schema_version: int
    scanner_distribution: str
    scanner_version: str
    scanner_artifact_sha256: str
    expires_at: int

    def __post_init__(self) -> None:
        require_string(self.evaluation_id, "evaluation_id")
        require_positive_int(self.repository_id, "repository_id")
        require_positive_int(self.pull_number, "pull_number")
        require_oid(self.head_oid, "head_oid")
        for field in (
            "policy_selector",
            "policy_epoch",
            "controller_protocol",
            "scanner_distribution",
            "scanner_version",
        ):
            require_string(getattr(self, field), field)
        require_digest(self.policy_digest, "policy_digest")
        require_positive_int(
            self.controller_schema_version,
            "controller_schema_version",
        )
        require_digest(self.scanner_artifact_sha256, "scanner_artifact_sha256")
        _require_timestamp(self.expires_at, "expires_at")

    def to_mapping(self) -> dict[str, object]:
        """Render the exact transport field names required by signer v1."""

        return {
            "evaluation_id": self.evaluation_id,
            "repository_id": self.repository_id,
            "pull_number": self.pull_number,
            "head_oid": self.head_oid,
            "policy_selector": self.policy_selector,
            "policy_epoch": self.policy_epoch,
            _TICKET_DIGEST_KEY: self.policy_digest,
            "controller_protocol": self.controller_protocol,
            "controller_schema_version": self.controller_schema_version,
            "scanner_distribution": self.scanner_distribution,
            "scanner_version": self.scanner_version,
            "scanner_artifact_sha256": self.scanner_artifact_sha256,
            "expires_at": self.expires_at,
        }


class EvaluationState(str, Enum):
    ISSUED = "ISSUED"
    RETRYABLE = "RETRYABLE"
    UNKNOWN = "UNKNOWN"
    PUBLISHED = "PUBLISHED"


@dataclass(frozen=True, slots=True)
class EvaluationRecord:
    evaluation_id: str
    registry_record_id: str
    registry_revision: int
    repository_id: int
    repository_owner_id: int
    pull_number: int
    head_oid: str
    policy_selector: str
    policy_epoch: str
    policy_digest: str
    controller_protocol: str
    controller_schema_version: int
    scanner_distribution: str
    scanner_version: str
    scanner_artifact_sha256: str
    workflow_ref: str
    workflow_sha: str
    job_workflow_ref: str | None
    job_workflow_sha: str | None
    run_id: int
    run_attempt: int
    admission_jti: str
    issued_at: int
    expires_at: int
    finalization_state: EvaluationState = EvaluationState.ISSUED

    def __post_init__(self) -> None:
        for field in (
            "evaluation_id",
            "registry_record_id",
            "policy_selector",
            "policy_epoch",
            "controller_protocol",
            "scanner_distribution",
            "scanner_version",
            "workflow_ref",
            "admission_jti",
        ):
            require_string(getattr(self, field), field)
        for field in (
            "registry_revision",
            "repository_id",
            "repository_owner_id",
            "pull_number",
            "controller_schema_version",
            "run_id",
            "run_attempt",
        ):
            require_positive_int(getattr(self, field), field)
        require_oid(self.head_oid, "head_oid")
        require_digest(self.policy_digest, "policy_digest")
        require_digest(self.scanner_artifact_sha256, "scanner_artifact_sha256")
        require_oid(self.workflow_sha, "workflow_sha")
        paired = (self.job_workflow_ref is None, self.job_workflow_sha is None)
        if paired[0] != paired[1]:
            raise SignerRefused("invalid_job_workflow_identity")
        if self.job_workflow_ref is not None:
            require_string(self.job_workflow_ref, "job_workflow_ref")
            require_oid(self.job_workflow_sha, "job_workflow_sha")
        _require_timestamp(self.issued_at, "issued_at")
        _require_timestamp(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise SignerRefused("invalid_evaluation_window")
        if type(self.finalization_state) is not EvaluationState:
            raise SignerRefused("invalid_evaluation_state")

    @property
    def registry_key(self) -> tuple[str, int]:
        return self.registry_record_id, self.registry_revision

    @property
    def execution_tuple(self) -> tuple[object, ...]:
        return (
            self.repository_id,
            self.repository_owner_id,
            self.workflow_ref,
            self.workflow_sha,
            self.job_workflow_ref,
            self.job_workflow_sha,
            self.run_id,
            self.run_attempt,
        )


@dataclass(frozen=True, slots=True)
class PublicationPayload:
    repository_id: int
    head_oid: str
    context: str
    state: str
    description: str
    target_url: None = None

    def __post_init__(self) -> None:
        require_positive_int(self.repository_id, "repository_id")
        require_oid(self.head_oid, "head_oid")
        normalize_status_context(self.context)
        if type(self.state) is not str or self.state not in {"success", "failure"}:
            raise SignerRefused("invalid_publication_state")
        require_string(self.description, "description", maximum=140)
        if self.target_url is not None:
            raise SignerRefused("invalid_target_url")

    def canonical_digest(self) -> str:
        encoded = json.dumps(
            {
                "context": self.context,
                "description": self.description,
                "head_oid": self.head_oid,
                "repository_id": self.repository_id,
                "state": self.state,
                "target_url": self.target_url,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        return hashlib.sha256(
            _PUBLICATION_DOMAIN + len(encoded).to_bytes(8, "big") + encoded
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class PublicationReceipt:
    provider_record_id: str
    payload_sha256: str
    publisher_identity: str

    def __post_init__(self) -> None:
        require_string(self.provider_record_id, "provider_record_id")
        require_digest(self.payload_sha256, "payload_sha256")
        require_string(self.publisher_identity, "publisher_identity")


class PublicationSlotState(str, Enum):
    RESERVED = "RESERVED"
    UNKNOWN = "UNKNOWN"
    PUBLISHED = "PUBLISHED"


@dataclass(frozen=True, slots=True)
class PublicationSlot:
    repository_id: int
    head_oid: str
    policy_epoch: str
    payload: PublicationPayload
    payload_sha256: str
    publisher_identity: str
    state: PublicationSlotState
    receipt: PublicationReceipt | None = None

    def __post_init__(self) -> None:
        require_positive_int(self.repository_id, "repository_id")
        require_oid(self.head_oid, "head_oid")
        require_string(self.policy_epoch, "policy_epoch")
        if type(self.payload) is not PublicationPayload:
            raise SignerRefused("invalid_publication_payload")
        if (
            self.payload.repository_id != self.repository_id
            or self.payload.head_oid != self.head_oid
        ):
            raise SignerRefused("publication_slot_binding_mismatch")
        require_digest(self.payload_sha256, "payload_sha256")
        if self.payload_sha256 != self.payload.canonical_digest():
            raise SignerRefused("publication_slot_digest_mismatch")
        require_string(self.publisher_identity, "publisher_identity")
        if type(self.state) is not PublicationSlotState:
            raise SignerRefused("invalid_publication_slot_state")
        if self.state is PublicationSlotState.PUBLISHED:
            if type(self.receipt) is not PublicationReceipt:
                raise SignerRefused("invalid_publication_receipt")
            if self.receipt.payload_sha256 != self.payload_sha256:
                raise SignerRefused("publication_receipt_mismatch")
            if self.receipt.publisher_identity != self.publisher_identity:
                raise SignerRefused("publication_receipt_source_mismatch")
        elif self.receipt is not None:
            raise SignerRefused("unexpected_publication_receipt")

    @property
    def key(self) -> tuple[int, str, str]:
        return self.repository_id, self.head_oid, self.policy_epoch


@dataclass(frozen=True, slots=True)
class FinalizationResult:
    evaluation_id: str
    evaluation_state: EvaluationState
    slot_state: PublicationSlotState | None
    receipt: PublicationReceipt | None
    retryable: bool

    def __post_init__(self) -> None:
        require_string(self.evaluation_id, "evaluation_id")
        if type(self.evaluation_state) is not EvaluationState:
            raise SignerRefused("invalid_evaluation_state")
        if (
            self.slot_state is not None
            and type(self.slot_state) is not PublicationSlotState
        ):
            raise SignerRefused("invalid_publication_slot_state")
        if self.receipt is not None and type(self.receipt) is not PublicationReceipt:
            raise SignerRefused("invalid_publication_receipt")
        if type(self.retryable) is not bool:
            raise SignerRefused("invalid_retryable")


def exact_mapping(value: object, keys: set[str], code: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise SignerRefused(code)
    return dict(value)


def copy_claim_mapping(value: Mapping[str, object]) -> dict[str, object]:
    if type(value) is not dict:
        raise SignerRefused("invalid_oidc_claims")
    return dict(value)
