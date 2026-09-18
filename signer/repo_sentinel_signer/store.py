"""In-memory evaluation and publication state with one transaction lock."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace

from .model import (
    EvaluationRecord,
    EvaluationState,
    PublicationPayload,
    PublicationReceipt,
    PublicationSlot,
    PublicationSlotState,
    SignerRefused,
    require_string,
)

IdempotencyKey = tuple[int, int, int, int, str, str, int]
SlotKey = tuple[int, str, str]


class InMemoryEvaluationStore:
    """Reference state engine; all compound operations use one shared lock."""

    def __init__(self, *, lock: threading.RLock | None = None) -> None:
        self._lock = lock or threading.RLock()
        self._evaluations: dict[str, EvaluationRecord] = {}
        self._idempotency: dict[IdempotencyKey, str] = {}
        self._admission_jtis: dict[str, IdempotencyKey] = {}
        self._finalization_jtis: dict[str, str] = {}
        self._slots: dict[SlotKey, PublicationSlot] = {}

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            yield

    def issue(
        self, evaluation: EvaluationRecord, idempotency_key: IdempotencyKey
    ) -> tuple[EvaluationRecord, bool]:
        if type(evaluation) is not EvaluationRecord:
            raise SignerRefused("invalid_evaluation_record")
        if type(idempotency_key) is not tuple or len(idempotency_key) != 7:
            raise SignerRefused("invalid_idempotency_key")
        with self._lock:
            existing_id = self._idempotency.get(idempotency_key)
            if existing_id is not None:
                previous_key = self._admission_jtis.get(evaluation.admission_jti)
                if previous_key is not None and previous_key != idempotency_key:
                    raise SignerRefused("admission_jti_reused")
                self._admission_jtis[evaluation.admission_jti] = idempotency_key
                return self._evaluations[existing_id], False
            previous_key = self._admission_jtis.get(evaluation.admission_jti)
            if previous_key is not None and previous_key != idempotency_key:
                raise SignerRefused("admission_jti_reused")
            if evaluation.evaluation_id in self._evaluations:
                raise SignerRefused("evaluation_id_collision")
            self._evaluations[evaluation.evaluation_id] = evaluation
            self._idempotency[idempotency_key] = evaluation.evaluation_id
            self._admission_jtis[evaluation.admission_jti] = idempotency_key
            return evaluation, True

    def get(self, evaluation_id: str) -> EvaluationRecord:
        key = require_string(evaluation_id, "evaluation_id")
        with self._lock:
            try:
                return self._evaluations[key]
            except KeyError:
                raise SignerRefused("evaluation_not_found") from None

    def set_state(self, evaluation_id: str, state: EvaluationState) -> EvaluationRecord:
        if type(state) is not EvaluationState:
            raise SignerRefused("invalid_evaluation_state")
        with self._lock:
            current = self.get(evaluation_id)
            allowed = {
                EvaluationState.ISSUED: {
                    EvaluationState.ISSUED,
                    EvaluationState.RETRYABLE,
                    EvaluationState.UNKNOWN,
                    EvaluationState.PUBLISHED,
                },
                EvaluationState.RETRYABLE: {
                    EvaluationState.RETRYABLE,
                    EvaluationState.UNKNOWN,
                    EvaluationState.PUBLISHED,
                },
                EvaluationState.UNKNOWN: {
                    EvaluationState.UNKNOWN,
                    EvaluationState.PUBLISHED,
                },
                EvaluationState.PUBLISHED: {EvaluationState.PUBLISHED},
            }
            if state not in allowed[current.finalization_state]:
                raise SignerRefused("evaluation_state_regression")
            updated = replace(current, finalization_state=state)
            self._evaluations[evaluation_id] = updated
            return updated

    def consume_finalization_jti(self, evaluation_id: str, jti: str) -> None:
        token_id = require_string(jti, "jti")
        with self._lock:
            self.get(evaluation_id)
            if token_id in self._admission_jtis:
                raise SignerRefused("fresh_oidc_required")
            if token_id in self._finalization_jtis:
                raise SignerRefused("finalization_jti_reused")
            self._finalization_jtis[token_id] = evaluation_id

    def reserve_slot(
        self, payload: PublicationPayload, policy_epoch: str
    ) -> PublicationSlot:
        if type(payload) is not PublicationPayload:
            raise SignerRefused("invalid_publication_payload")
        epoch = require_string(policy_epoch, "policy_epoch")
        key = payload.repository_id, payload.head_oid, epoch
        digest = payload.canonical_digest()
        with self._lock:
            existing = self._slots.get(key)
            if existing is not None:
                if existing.payload_sha256 != digest or existing.payload != payload:
                    raise SignerRefused("publication_slot_conflict")
                return existing
            slot = PublicationSlot(
                repository_id=payload.repository_id,
                head_oid=payload.head_oid,
                policy_epoch=epoch,
                payload=payload,
                payload_sha256=digest,
                state=PublicationSlotState.RESERVED,
            )
            self._slots[key] = slot
            return slot

    def get_slot(self, key: SlotKey) -> PublicationSlot:
        with self._lock:
            try:
                return self._slots[key]
            except KeyError:
                raise SignerRefused("publication_slot_not_found") from None

    def set_slot_state(
        self,
        key: SlotKey,
        state: PublicationSlotState,
        receipt: PublicationReceipt | None = None,
    ) -> PublicationSlot:
        if type(state) is not PublicationSlotState:
            raise SignerRefused("invalid_publication_slot_state")
        with self._lock:
            current = self.get_slot(key)
            allowed = {
                PublicationSlotState.RESERVED: {
                    PublicationSlotState.RESERVED,
                    PublicationSlotState.UNKNOWN,
                    PublicationSlotState.PUBLISHED,
                },
                PublicationSlotState.UNKNOWN: {
                    PublicationSlotState.UNKNOWN,
                    PublicationSlotState.PUBLISHED,
                },
                PublicationSlotState.PUBLISHED: {PublicationSlotState.PUBLISHED},
            }
            if state not in allowed[current.state]:
                raise SignerRefused("publication_slot_state_regression")
            if state is PublicationSlotState.PUBLISHED:
                if type(receipt) is not PublicationReceipt:
                    raise SignerRefused("invalid_publication_receipt")
                if receipt.payload_sha256 != current.payload_sha256:
                    raise SignerRefused("publication_receipt_mismatch")
            elif receipt is not None:
                raise SignerRefused("unexpected_publication_receipt")
            updated = replace(current, state=state, receipt=receipt)
            self._slots[key] = updated
            return updated

    def evaluation_count(self) -> int:
        with self._lock:
            return len(self._evaluations)

    def slot_count(self) -> int:
        with self._lock:
            return len(self._slots)
