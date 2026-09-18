"""Mock-only reference core for the Repo Sentinel signer v1 protocol."""

from .model import (
    GITHUB_OIDC_ISSUER,
    SIGNER_AUDIENCE,
    SIGNER_PROTOCOL,
    EvaluationRecord,
    EvaluationState,
    FinalizationResult,
    PublicationPayload,
    PublicationReceipt,
    PublicationSlot,
    PublicationSlotState,
    PullRequestSnapshot,
    RegistryRecord,
    SignerRefused,
    TicketRequest,
    TicketResponse,
    VerifiedOidcClaims,
)
from .oidc import MockOidcVerifier, OidcVerifier
from .publisher import (
    MockPublisher,
    MockPublishMode,
    Publisher,
    PublishDisposition,
    PublishOutcome,
)
from .registry import InMemoryRegistry
from .service import MockPullRequestReader, PullRequestReader, SignerService
from .store import InMemoryEvaluationStore

__all__ = [
    "GITHUB_OIDC_ISSUER",
    "SIGNER_AUDIENCE",
    "SIGNER_PROTOCOL",
    "EvaluationRecord",
    "EvaluationState",
    "FinalizationResult",
    "InMemoryEvaluationStore",
    "InMemoryRegistry",
    "MockOidcVerifier",
    "MockPublishMode",
    "MockPublisher",
    "MockPullRequestReader",
    "OidcVerifier",
    "PublicationPayload",
    "PublicationReceipt",
    "PublicationSlot",
    "PublicationSlotState",
    "PublishDisposition",
    "PublishOutcome",
    "Publisher",
    "PullRequestReader",
    "PullRequestSnapshot",
    "RegistryRecord",
    "SignerRefused",
    "SignerService",
    "TicketRequest",
    "TicketResponse",
    "VerifiedOidcClaims",
]
