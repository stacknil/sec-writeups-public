"""Transport-neutral signer admission, finalization, and publication state machine."""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable, Mapping
from typing import Protocol

from .model import (
    GITHUB_OIDC_ISSUER,
    SIGNER_AUDIENCE,
    EvaluationRecord,
    EvaluationState,
    FinalizationResult,
    PublicationPayload,
    PublicationSlotState,
    PullRequestSnapshot,
    RegistryRecord,
    SignerRefused,
    TicketRequest,
    TicketResponse,
    VerifiedOidcClaims,
    exact_mapping,
    require_digest,
    require_oid,
    require_positive_int,
    require_string,
)
from .publisher import PublishDisposition, Publisher, PublishOutcome
from .registry import InMemoryRegistry
from .store import InMemoryEvaluationStore

Clock = Callable[[], int]
EvaluationIdGenerator = Callable[[], str]

_CONTROLLER_KEYS = frozenset(
    {
        "controller_outcome",
        "controller_protocol",
        "controller_schema_version",
        "fixed_refusal_code",
        "head_oid",
        "policy_bundle_sha256",
        "policy_epoch",
        "policy_selector",
        "repository_id",
        "worker_result",
        "worker_semantic_sha256",
    }
)
_WORKER_KEYS = frozenset(
    {
        "coverage_policy_sha256",
        "files_policy_excluded",
        "files_scanned",
        "files_scanner_skipped",
        "files_total",
        "head_oid",
        "policy_bundle_sha256",
        "policy_epoch",
        "policy_schema_version",
        "protected_manifest_sha256",
        "refusal_code",
        "report_sha256",
        "report_size",
        "repository_id",
        "scanner_artifact_sha256",
        "scanner_distribution",
        "scanner_version",
        "semantic_sha256",
        "suppression_manifest_sha256",
        "verdict",
    }
)
_SEMANTIC_DOMAIN = b"repo-sentinel-commit-authority-result-v1\0"
_POLICY_REFUSALS = frozenset(
    {
        "coverage_policy_mismatch",
        "policy_bundle_mirror_mismatch",
        "protected_control_mismatch",
        "suppression_manifest_mismatch",
    }
)
_CONTROLLER_REFUSALS = frozenset(
    {
        "acquired_head_mismatch",
        "acquisition_refused",
        "cleanup_failed",
        "environment_mismatch",
        "git_identity_mismatch",
        "invalid_head_oid",
        "invalid_request",
        "launch_not_isolated",
        "policy_bundle_mismatch",
        "repository_identity_mismatch",
        "runtime_mismatch",
        "unsafe_control_root",
        "unsafe_root_layout",
        "unexpected_failure",
        "unknown_policy_epoch",
        "worker_infrastructure_refusal",
        "worker_result_invalid",
    }
)
_SEMANTIC_VERDICTS = frozenset({"PASS", "SCANNER_FINDING", "POLICY_ADMISSION_FAILURE"})


def _publication_fields(verdict: str) -> tuple[str, str]:
    if verdict == "PASS":
        return "success", "Repo Sentinel authority: PASS"
    if verdict == "SCANNER_FINDING":
        return "failure", "Repo Sentinel authority: SCANNER_FINDING"
    if verdict == "POLICY_ADMISSION_FAILURE":
        return "failure", "Repo Sentinel authority: POLICY_ADMISSION_FAILURE"
    raise SignerRefused("controller_result_invalid")


class PullRequestReader(Protocol):
    def read(
        self, repository_id: int, pull_number: int
    ) -> PullRequestSnapshot | None: ...


class MockPullRequestReader:
    """Mutable test double whose returned snapshots remain immutable values."""

    def __init__(self, snapshots: list[PullRequestSnapshot] | None = None) -> None:
        self._lock = threading.Lock()
        self._snapshots: dict[tuple[int, int], PullRequestSnapshot] = {}
        for snapshot in snapshots or []:
            self.set(snapshot)

    def set(self, snapshot: PullRequestSnapshot) -> None:
        if type(snapshot) is not PullRequestSnapshot:
            raise SignerRefused("invalid_pull_request_snapshot")
        with self._lock:
            self._snapshots[(snapshot.repository_id, snapshot.pull_number)] = snapshot

    def remove(self, repository_id: int, pull_number: int) -> None:
        with self._lock:
            self._snapshots.pop((repository_id, pull_number), None)

    def read(self, repository_id: int, pull_number: int) -> PullRequestSnapshot | None:
        require_positive_int(repository_id, "repository_id")
        require_positive_int(pull_number, "pull_number")
        with self._lock:
            return self._snapshots.get((repository_id, pull_number))


def _valid_count(value: object) -> bool:
    return type(value) is int and value >= 0


def _worker_semantic_digest(payload: Mapping[str, object]) -> str:
    semantic = {
        key: value for key, value in payload.items() if key != "semantic_sha256"
    }
    encoded = json.dumps(
        semantic,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(
        _SEMANTIC_DOMAIN + len(encoded).to_bytes(8, "big") + encoded
    ).hexdigest()


class SignerService:
    """Authorize evaluations and publish one immutable verdict per R/H/v slot."""

    def __init__(
        self,
        *,
        registry: InMemoryRegistry,
        store: InMemoryEvaluationStore,
        pull_requests: PullRequestReader,
        publisher: Publisher,
        clock: Clock,
        evaluation_id_generator: EvaluationIdGenerator,
        authority_slot: str = "authoritative",
        evaluation_ttl_seconds: int = 900,
        allowed_clock_skew_seconds: int = 30,
    ) -> None:
        if registry.lock is not store.lock:
            raise SignerRefused("state_lock_mismatch")
        if type(evaluation_ttl_seconds) is not int or evaluation_ttl_seconds <= 0:
            raise SignerRefused("invalid_evaluation_ttl")
        if (
            type(allowed_clock_skew_seconds) is not int
            or allowed_clock_skew_seconds < 0
        ):
            raise SignerRefused("invalid_clock_skew")
        self._registry = registry
        self._store = store
        self._pull_requests = pull_requests
        self._publisher = publisher
        self._clock = clock
        self._evaluation_id_generator = evaluation_id_generator
        self._authority_slot = require_string(authority_slot, "authority_slot")
        self._evaluation_ttl_seconds = evaluation_ttl_seconds
        self._allowed_clock_skew_seconds = allowed_clock_skew_seconds

    def _now(self) -> int:
        value = self._clock()
        if type(value) is not int or value < 0:
            raise SignerRefused("invalid_clock")
        return value

    def _authorize_oidc(
        self,
        claims: VerifiedOidcClaims,
        record: RegistryRecord,
        now: int,
    ) -> None:
        if type(claims) is not VerifiedOidcClaims:
            raise SignerRefused("unverified_oidc_claims")
        if claims.iss != GITHUB_OIDC_ISSUER:
            raise SignerRefused("oidc_issuer_mismatch")
        if claims.aud != SIGNER_AUDIENCE:
            raise SignerRefused("oidc_audience_mismatch")
        if claims.nbf > now:
            raise SignerRefused("oidc_not_yet_valid")
        if now > claims.exp:
            raise SignerRefused("oidc_expired")
        if claims.iat > now + self._allowed_clock_skew_seconds:
            raise SignerRefused("oidc_issued_in_future")
        if claims.repository_id != record.repository_id:
            raise SignerRefused("oidc_repository_mismatch")
        if claims.repository_owner_id != record.repository_owner_id:
            raise SignerRefused("oidc_owner_mismatch")
        if claims.repository != record.repository:
            raise SignerRefused("oidc_repository_mismatch")
        if claims.repository_owner != record.repository.partition("/")[0]:
            raise SignerRefused("oidc_owner_mismatch")
        if claims.event_name != "pull_request_target":
            raise SignerRefused("oidc_event_mismatch")
        if claims.runner_environment != "github-hosted":
            raise SignerRefused("oidc_runner_mismatch")
        if (
            claims.workflow_ref != record.workflow_ref
            or claims.workflow_sha != record.workflow_sha
        ):
            raise SignerRefused("oidc_workflow_mismatch")
        if (
            claims.job_workflow_ref != record.job_workflow_ref
            or claims.job_workflow_sha != record.job_workflow_sha
        ):
            raise SignerRefused("oidc_reusable_workflow_mismatch")

    def _read_open_pull(
        self, repository_id: int, pull_number: int
    ) -> PullRequestSnapshot:
        snapshot = self._pull_requests.read(repository_id, pull_number)
        if type(snapshot) is not PullRequestSnapshot:
            raise SignerRefused("pull_request_unavailable")
        if (
            snapshot.repository_id != repository_id
            or snapshot.pull_number != pull_number
        ):
            raise SignerRefused("pull_request_identity_mismatch")
        if snapshot.state != "open":
            raise SignerRefused("pull_request_closed")
        return snapshot

    def issue_evaluation(
        self,
        verified_oidc: VerifiedOidcClaims,
        request: TicketRequest,
    ) -> TicketResponse:
        if type(request) is not TicketRequest:
            raise SignerRefused("invalid_ticket_request")
        now = self._now()
        with self._store.transaction():
            if type(verified_oidc) is not VerifiedOidcClaims:
                raise SignerRefused("unverified_oidc_claims")
            record = self._registry.resolve_active(
                verified_oidc.repository_id, self._authority_slot
            )
            self._authorize_oidc(verified_oidc, record, now)
            snapshot = self._read_open_pull(record.repository_id, request.pull_number)
            idempotency_key = (
                record.repository_id,
                verified_oidc.run_id,
                verified_oidc.run_attempt,
                request.pull_number,
                snapshot.head_oid,
                record.record_id,
                record.revision,
            )
            evaluation = EvaluationRecord(
                evaluation_id=require_string(
                    self._evaluation_id_generator(), "evaluation_id"
                ),
                registry_record_id=record.record_id,
                registry_revision=record.revision,
                repository_id=record.repository_id,
                repository_owner_id=record.repository_owner_id,
                pull_number=request.pull_number,
                head_oid=snapshot.head_oid,
                policy_selector=record.policy_selector,
                policy_epoch=record.policy_epoch,
                expected_policy_bundle_sha256=record.policy_bundle_sha256,
                controller_protocol=record.controller_protocol,
                controller_schema_version=record.controller_schema_version,
                scanner_distribution=record.scanner_distribution,
                scanner_version=record.scanner_version,
                scanner_artifact_sha256=record.scanner_artifact_sha256,
                workflow_ref=record.workflow_ref,
                workflow_sha=record.workflow_sha,
                job_workflow_ref=record.job_workflow_ref,
                job_workflow_sha=record.job_workflow_sha,
                run_id=verified_oidc.run_id,
                run_attempt=verified_oidc.run_attempt,
                admission_jti=verified_oidc.jti,
                issued_at=now,
                expires_at=now + self._evaluation_ttl_seconds,
            )
            stored, _created = self._store.issue(evaluation, idempotency_key)
            return TicketResponse(
                evaluation_id=stored.evaluation_id,
                repository_id=stored.repository_id,
                pull_number=stored.pull_number,
                head_oid=stored.head_oid,
                policy_selector=stored.policy_selector,
                policy_epoch=stored.policy_epoch,
                expected_policy_bundle_sha256=stored.expected_policy_bundle_sha256,
                controller_protocol=stored.controller_protocol,
                controller_schema_version=stored.controller_schema_version,
                scanner_distribution=stored.scanner_distribution,
                scanner_version=stored.scanner_version,
                scanner_artifact_sha256=stored.scanner_artifact_sha256,
                expires_at=stored.expires_at,
            )

    def _validate_worker(
        self,
        value: object,
        evaluation: EvaluationRecord,
    ) -> tuple[str, dict[str, object]]:
        worker = exact_mapping(value, _WORKER_KEYS, "controller_result_invalid")
        verdict = worker["verdict"]
        if type(verdict) is not str or verdict not in _SEMANTIC_VERDICTS:
            raise SignerRefused("controller_result_invalid")
        if type(worker["policy_schema_version"]) is not int:
            raise SignerRefused("controller_result_invalid")
        if worker["policy_schema_version"] != 1:
            raise SignerRefused("controller_result_invalid")
        if type(worker["repository_id"]) is not int:
            raise SignerRefused("controller_result_invalid")
        if worker["repository_id"] != evaluation.repository_id:
            raise SignerRefused("controller_result_binding_mismatch")
        for key, expected in (
            ("head_oid", evaluation.head_oid),
            ("policy_epoch", evaluation.policy_epoch),
            ("policy_bundle_sha256", evaluation.expected_policy_bundle_sha256),
            ("scanner_distribution", evaluation.scanner_distribution),
            ("scanner_version", evaluation.scanner_version),
            ("scanner_artifact_sha256", evaluation.scanner_artifact_sha256),
        ):
            actual = worker[key]
            if type(actual) is not str or actual != expected:
                raise SignerRefused("controller_result_binding_mismatch")
        for key in (
            "policy_bundle_sha256",
            "protected_manifest_sha256",
            "suppression_manifest_sha256",
            "coverage_policy_sha256",
            "scanner_artifact_sha256",
            "semantic_sha256",
        ):
            require_digest(worker[key], "controller_result")
        report_digest = worker["report_sha256"]
        if report_digest is not None:
            require_digest(report_digest, "controller_result")
        counts = [
            worker["files_total"],
            worker["files_scanned"],
            worker["files_policy_excluded"],
            worker["files_scanner_skipped"],
            worker["report_size"],
        ]
        if not all(_valid_count(count) for count in counts):
            raise SignerRefused("controller_result_invalid")
        refusal = worker["refusal_code"]
        if verdict == "POLICY_ADMISSION_FAILURE":
            if type(refusal) is not str or refusal not in _POLICY_REFUSALS:
                raise SignerRefused("controller_result_invalid")
            if (
                any(counts[1:4])
                or report_digest is not None
                or worker["report_size"] != 0
            ):
                raise SignerRefused("controller_result_invalid")
        else:
            if refusal is not None:
                raise SignerRefused("controller_result_invalid")
            if report_digest is None or worker["report_size"] == 0:
                raise SignerRefused("controller_result_invalid")
            if worker["files_total"] != sum(counts[1:4]):
                raise SignerRefused("controller_result_invalid")
        semantic = worker["semantic_sha256"]
        if semantic != _worker_semantic_digest(worker):
            raise SignerRefused("controller_result_invalid")
        return verdict, worker

    def _parse_controller_result(
        self,
        value: object,
        evaluation: EvaluationRecord,
        record: RegistryRecord,
    ) -> tuple[str, str | None]:
        result = exact_mapping(value, _CONTROLLER_KEYS, "controller_result_invalid")
        outcome = result["controller_outcome"]
        if type(outcome) is not str or outcome not in {
            "AUTHORITY_RESULT",
            "INFRASTRUCTURE_REFUSAL",
        }:
            raise SignerRefused("controller_result_invalid")
        if (
            type(result["controller_protocol"]) is not str
            or result["controller_protocol"] != record.controller_protocol
            or type(result["controller_schema_version"]) is not int
            or result["controller_schema_version"] != record.controller_schema_version
            or type(result["repository_id"]) is not int
            or result["repository_id"] != evaluation.repository_id
        ):
            raise SignerRefused("controller_result_binding_mismatch")
        for key, expected in (
            ("head_oid", evaluation.head_oid),
            ("policy_selector", evaluation.policy_selector),
            ("policy_epoch", evaluation.policy_epoch),
            ("policy_bundle_sha256", evaluation.expected_policy_bundle_sha256),
        ):
            actual = result[key]
            if type(actual) is not str or actual != expected:
                raise SignerRefused("controller_result_binding_mismatch")
        require_oid(result["head_oid"], "controller_result")
        require_digest(result["policy_bundle_sha256"], "controller_result")
        if outcome == "INFRASTRUCTURE_REFUSAL":
            refusal = result["fixed_refusal_code"]
            if type(refusal) is not str or refusal not in _CONTROLLER_REFUSALS:
                raise SignerRefused("controller_result_invalid")
            if (
                result["worker_result"] is not None
                or result["worker_semantic_sha256"] is not None
            ):
                raise SignerRefused("controller_result_invalid")
            return outcome, None
        if result["fixed_refusal_code"] is not None:
            raise SignerRefused("controller_result_invalid")
        verdict, worker = self._validate_worker(result["worker_result"], evaluation)
        worker_semantic = result["worker_semantic_sha256"]
        require_digest(worker_semantic, "controller_result")
        if worker_semantic != worker["semantic_sha256"]:
            raise SignerRefused("controller_result_binding_mismatch")
        return outcome, verdict

    def _payload(
        self,
        evaluation: EvaluationRecord,
        record: RegistryRecord,
        verdict: str,
    ) -> PublicationPayload:
        state, description = _publication_fields(verdict)
        return PublicationPayload(
            repository_id=evaluation.repository_id,
            head_oid=evaluation.head_oid,
            context=record.status_context,
            state=state,
            description=description,
            target_url=None,
        )

    def finalize_evaluation(
        self,
        verified_oidc: VerifiedOidcClaims,
        evaluation_id: str,
        controller_result: object,
    ) -> FinalizationResult:
        now = self._now()
        with self._store.transaction():
            evaluation = self._store.get(evaluation_id)
            record = self._registry.get(evaluation.registry_key)
            if self._registry.is_revoked(record.key):
                raise SignerRefused("registry_record_revoked")
            self._authorize_oidc(verified_oidc, record, now)
            if verified_oidc.execution_tuple() != evaluation.execution_tuple:
                raise SignerRefused("finalization_execution_mismatch")
            if verified_oidc.jti == evaluation.admission_jti:
                raise SignerRefused("fresh_oidc_required")
            if now > evaluation.expires_at:
                raise SignerRefused("evaluation_expired")
            snapshot = self._read_open_pull(
                evaluation.repository_id, evaluation.pull_number
            )
            if snapshot.head_oid != evaluation.head_oid:
                raise SignerRefused("pull_request_head_changed")
            outcome, verdict = self._parse_controller_result(
                controller_result, evaluation, record
            )
            self._store.consume_finalization_jti(evaluation_id, verified_oidc.jti)
            if outcome == "INFRASTRUCTURE_REFUSAL":
                if evaluation.finalization_state is EvaluationState.PUBLISHED:
                    raise SignerRefused("evaluation_already_published")
                retry_state = (
                    EvaluationState.UNKNOWN
                    if evaluation.finalization_state is EvaluationState.UNKNOWN
                    else EvaluationState.RETRYABLE
                )
                updated = self._store.set_state(evaluation_id, retry_state)
                return FinalizationResult(
                    updated.evaluation_id,
                    updated.finalization_state,
                    None,
                    None,
                    True,
                )
            assert verdict is not None
            publisher_identity = self._publisher.identity
            if (
                type(publisher_identity) is not str
                or publisher_identity != record.publisher_identity
            ):
                raise SignerRefused("publisher_identity_mismatch")
            payload = self._payload(evaluation, record, verdict)
            slot = self._store.reserve_slot(payload, evaluation.policy_epoch)
            if slot.state is PublicationSlotState.PUBLISHED:
                updated = self._store.set_state(
                    evaluation_id, EvaluationState.PUBLISHED
                )
                return FinalizationResult(
                    updated.evaluation_id,
                    updated.finalization_state,
                    slot.state,
                    slot.receipt,
                    False,
                )
            if slot.state is PublicationSlotState.UNKNOWN:
                receipt = self._publisher.lookup(slot.payload)
                if receipt is not None:
                    slot = self._store.set_slot_state(
                        slot.key, PublicationSlotState.PUBLISHED, receipt
                    )
                    updated = self._store.set_state(
                        evaluation_id, EvaluationState.PUBLISHED
                    )
                    return FinalizationResult(
                        updated.evaluation_id,
                        updated.finalization_state,
                        slot.state,
                        slot.receipt,
                        False,
                    )
            published = self._publisher.publish(slot.payload)
            if type(published) is not PublishOutcome:
                raise SignerRefused("publisher_result_invalid")
            if published.disposition is PublishDisposition.PUBLISHED:
                slot = self._store.set_slot_state(
                    slot.key, PublicationSlotState.PUBLISHED, published.receipt
                )
                updated = self._store.set_state(
                    evaluation_id, EvaluationState.PUBLISHED
                )
                return FinalizationResult(
                    updated.evaluation_id,
                    updated.finalization_state,
                    slot.state,
                    slot.receipt,
                    False,
                )
            if published.disposition is PublishDisposition.UNKNOWN:
                slot = self._store.set_slot_state(
                    slot.key, PublicationSlotState.UNKNOWN
                )
                updated = self._store.set_state(evaluation_id, EvaluationState.UNKNOWN)
                return FinalizationResult(
                    updated.evaluation_id,
                    updated.finalization_state,
                    slot.state,
                    None,
                    True,
                )
            retry_state = (
                EvaluationState.UNKNOWN
                if evaluation.finalization_state is EvaluationState.UNKNOWN
                else EvaluationState.RETRYABLE
            )
            updated = self._store.set_state(evaluation_id, retry_state)
            return FinalizationResult(
                updated.evaluation_id,
                updated.finalization_state,
                slot.state,
                None,
                True,
            )
