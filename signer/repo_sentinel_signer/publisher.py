"""Publication abstraction and deterministic mock Commit Status publisher."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from .model import PublicationPayload, PublicationReceipt, SignerRefused, require_string


class PublishDisposition(str, Enum):
    PUBLISHED = "PUBLISHED"
    DEFINITE_FAILURE = "DEFINITE_FAILURE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class PublishOutcome:
    disposition: PublishDisposition
    receipt: PublicationReceipt | None = None

    def __post_init__(self) -> None:
        if type(self.disposition) is not PublishDisposition:
            raise SignerRefused("invalid_publish_disposition")
        if self.disposition is PublishDisposition.PUBLISHED:
            if type(self.receipt) is not PublicationReceipt:
                raise SignerRefused("invalid_publication_receipt")
        elif self.receipt is not None:
            raise SignerRefused("unexpected_publication_receipt")


class Publisher(Protocol):
    @property
    def identity(self) -> str: ...

    def publish(self, payload: PublicationPayload) -> PublishOutcome: ...

    def lookup(self, payload: PublicationPayload) -> PublicationReceipt | None: ...


class MockPublishMode(str, Enum):
    PUBLISHED = "PUBLISHED"
    DEFINITE_FAILURE = "DEFINITE_FAILURE"
    UNKNOWN_BEFORE_WRITE = "UNKNOWN_BEFORE_WRITE"
    UNKNOWN_AFTER_WRITE = "UNKNOWN_AFTER_WRITE"


class MockPublisher:
    """Exercise definite, uncertain-before, and uncertain-after publication."""

    def __init__(
        self,
        identity: str,
        outcomes: list[MockPublishMode] | None = None,
    ) -> None:
        self._identity = require_string(identity, "publisher_identity")
        self._outcomes = list(outcomes or [])
        if not all(type(outcome) is MockPublishMode for outcome in self._outcomes):
            raise SignerRefused("invalid_mock_publish_mode")
        self._lock = threading.Lock()
        self._calls: list[PublicationPayload] = []
        self._visible: dict[tuple[int, str, str], PublicationReceipt] = {}
        self._counter = 0

    @property
    def identity(self) -> str:
        return self._identity

    @property
    def calls(self) -> tuple[PublicationPayload, ...]:
        with self._lock:
            return tuple(self._calls)

    def _receipt(self, payload: PublicationPayload) -> PublicationReceipt:
        key = payload.repository_id, payload.head_oid, payload.context
        digest = payload.canonical_digest()
        existing = self._visible.get(key)
        if existing is not None:
            if existing.payload_sha256 != digest:
                raise SignerRefused("publisher_payload_conflict")
            return existing
        self._counter += 1
        receipt = PublicationReceipt(f"mock-status-{self._counter}", digest)
        self._visible[key] = receipt
        return receipt

    def publish(self, payload: PublicationPayload) -> PublishOutcome:
        if type(payload) is not PublicationPayload:
            raise SignerRefused("invalid_publication_payload")
        with self._lock:
            self._calls.append(payload)
            mode = (
                self._outcomes.pop(0) if self._outcomes else MockPublishMode.PUBLISHED
            )
            if mode is MockPublishMode.PUBLISHED:
                return PublishOutcome(
                    PublishDisposition.PUBLISHED, self._receipt(payload)
                )
            if mode is MockPublishMode.DEFINITE_FAILURE:
                return PublishOutcome(PublishDisposition.DEFINITE_FAILURE)
            if mode is MockPublishMode.UNKNOWN_AFTER_WRITE:
                self._receipt(payload)
            return PublishOutcome(PublishDisposition.UNKNOWN)

    def lookup(self, payload: PublicationPayload) -> PublicationReceipt | None:
        if type(payload) is not PublicationPayload:
            raise SignerRefused("invalid_publication_payload")
        with self._lock:
            key = payload.repository_id, payload.head_oid, payload.context
            receipt = self._visible.get(key)
            if receipt is None or receipt.payload_sha256 != payload.canonical_digest():
                return None
            return receipt
