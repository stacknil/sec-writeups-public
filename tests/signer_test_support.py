"""Synthetic fixtures for signer v1 contract tests."""

from __future__ import annotations

import hashlib
import itertools
import json
import sys
import threading
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SIGNER = ROOT / "signer"
sys.path.insert(0, str(SIGNER))

from repo_sentinel_signer import (  # noqa: E402
    GITHUB_OIDC_ISSUER,
    SIGNER_AUDIENCE,
    InMemoryEvaluationStore,
    InMemoryRegistry,
    MockPublisher,
    MockPublishMode,
    MockPullRequestReader,
    PublicationPayload,
    PublicationReceipt,
    Publisher,
    PublishDisposition,
    PublishOutcome,
    PullRequestSnapshot,
    RegistryRecord,
    SignerService,
    TicketRequest,
    VerifiedOidcClaims,
)

NOW = 2_000_000_000
REPOSITORY_ID = 1_130_304_545
OWNER_ID = 219_124_580
REPOSITORY = "stacknil/sec-writeups-public"
OWNER = "stacknil"
PULL_NUMBER = 22


def field(*parts: str) -> str:
    return "_".join(parts)


POLICY_DIGEST_KEY = field("policy", "bundle", "sha256")
WORKER_DIGEST_KEY = field("worker", "semantic", "sha256")
COVERAGE_DIGEST_KEY = field("coverage", "policy", "sha256")
PROTECTED_DIGEST_KEY = field("protected", "manifest", "sha256")


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def oid(label: str) -> str:
    return digest(label)[:40]


def registry_record(
    *,
    record_id: str = "synthetic-record",
    revision: int = 1,
    policy_epoch: str = "synthetic-policy-v1",
    policy_digest: str | None = None,
    workflow_sha: str | None = None,
    status_context: str = "Repo Sentinel / authoritative gate",
    publisher_identity: str | None = None,
    reusable: bool = False,
) -> RegistryRecord:
    return RegistryRecord(
        record_id=record_id,
        revision=revision,
        repository_id=REPOSITORY_ID,
        repository_owner_id=OWNER_ID,
        repository=REPOSITORY,
        policy_selector="v2",
        policy_epoch=policy_epoch,
        policy_digest=policy_digest or digest(f"policy-{policy_epoch}"),
        controller_protocol="external-policy-root-v1",
        controller_schema_version=1,
        scanner_distribution="repo-sentinel-lite",
        scanner_version="0.8.1",
        scanner_artifact_sha256=digest("synthetic-scanner-wheel"),
        workflow_ref="stacknil/sec-writeups-public/.github/workflows/authority.yml@main",
        workflow_sha=workflow_sha or oid("trusted-workflow"),
        status_context=status_context,
        publisher_identity=(
            publisher_identity or f"mock-publisher-{digest('publisher-identity')[:12]}"
        ),
        job_workflow_ref=(
            "stacknil/trusted-workflows/.github/workflows/signer.yml@v1"
            if reusable
            else None
        ),
        job_workflow_sha=oid("trusted-reusable-workflow") if reusable else None,
    )


def raw_claims(
    record: RegistryRecord,
    *,
    jti: str = "synthetic-jti",
    run_id: int = 7001,
    run_attempt: int = 1,
    now: int = NOW,
) -> dict[str, object]:
    claims: dict[str, object] = {
        "iss": GITHUB_OIDC_ISSUER,
        "aud": SIGNER_AUDIENCE,
        "sub": "repo:stacknil/sec-writeups-public:event_name:pull_request_target",
        "jti": jti,
        "iat": now - 5,
        "nbf": now - 5,
        "exp": now + 300,
        "repository": record.repository,
        "repository_id": str(record.repository_id),
        "repository_owner": OWNER,
        "repository_owner_id": str(record.repository_owner_id),
        "event_name": "pull_request_target",
        "runner_environment": "github-hosted",
        "workflow_ref": record.workflow_ref,
        "workflow_sha": record.workflow_sha,
        "run_id": str(run_id),
        "run_attempt": str(run_attempt),
    }
    if record.job_workflow_ref is not None:
        claims["job_workflow_ref"] = record.job_workflow_ref
        claims["job_workflow_sha"] = record.job_workflow_sha
    return claims


def verified_claims(
    record: RegistryRecord,
    *,
    jti: str = "synthetic-jti",
    run_id: int = 7001,
    run_attempt: int = 1,
    now: int = NOW,
    **changes: object,
) -> VerifiedOidcClaims:
    claims = raw_claims(
        record,
        jti=jti,
        run_id=run_id,
        run_attempt=run_attempt,
        now=now,
    )
    claims.update(changes)
    return VerifiedOidcClaims.from_verified_mapping(claims)


def worker_semantic_digest(payload: dict[str, object]) -> str:
    semantic = {
        key: value for key, value in payload.items() if key != "semantic_sha256"
    }
    encoded = json.dumps(
        semantic,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    domain = b"repo-sentinel-commit-authority-result-v1\0"
    return hashlib.sha256(
        domain + len(encoded).to_bytes(8, "big") + encoded
    ).hexdigest()


def controller_result(
    ticket: object,
    record: RegistryRecord,
    verdict: str = "PASS",
    *,
    infrastructure_refusal: bool = False,
) -> dict[str, object]:
    if infrastructure_refusal:
        return {
            "controller_outcome": "INFRASTRUCTURE_REFUSAL",
            "controller_protocol": record.controller_protocol,
            "controller_schema_version": record.controller_schema_version,
            "fixed_refusal_code": "acquisition_refused",
            "head_oid": ticket.head_oid,
            POLICY_DIGEST_KEY: ticket.policy_digest,
            "policy_epoch": ticket.policy_epoch,
            "policy_selector": ticket.policy_selector,
            "repository_id": ticket.repository_id,
            "worker_result": None,
            WORKER_DIGEST_KEY: None,
        }
    policy_failure = verdict == "POLICY_ADMISSION_FAILURE"
    worker: dict[str, object] = {
        COVERAGE_DIGEST_KEY: digest("coverage-policy"),
        "files_policy_excluded": 0 if policy_failure else 2,
        "files_scanned": 0 if policy_failure else 7,
        "files_scanner_skipped": 0,
        "files_total": 9,
        "head_oid": ticket.head_oid,
        POLICY_DIGEST_KEY: ticket.policy_digest,
        "policy_epoch": ticket.policy_epoch,
        "policy_schema_version": 1,
        PROTECTED_DIGEST_KEY: digest("protected-manifest"),
        "refusal_code": "protected_control_mismatch" if policy_failure else None,
        "report_sha256": None if policy_failure else digest("scanner-report"),
        "report_size": 0 if policy_failure else 128,
        "repository_id": ticket.repository_id,
        "scanner_artifact_sha256": ticket.scanner_artifact_sha256,
        "scanner_distribution": ticket.scanner_distribution,
        "scanner_version": ticket.scanner_version,
        "semantic_sha256": None,
        "suppression_manifest_sha256": digest("suppression-manifest"),
        "verdict": verdict,
    }
    worker["semantic_sha256"] = worker_semantic_digest(worker)
    return {
        "controller_outcome": "AUTHORITY_RESULT",
        "controller_protocol": record.controller_protocol,
        "controller_schema_version": record.controller_schema_version,
        "fixed_refusal_code": None,
        "head_oid": ticket.head_oid,
        POLICY_DIGEST_KEY: ticket.policy_digest,
        "policy_epoch": ticket.policy_epoch,
        "policy_selector": ticket.policy_selector,
        "repository_id": ticket.repository_id,
        "worker_result": worker,
        WORKER_DIGEST_KEY: worker["semantic_sha256"],
    }


class MutableClock:
    def __init__(self, now: int = NOW) -> None:
        self.now = now

    def __call__(self) -> int:
        return self.now


class PermissivePublisher:
    """Test-only provider that accepts repeated writes to one physical context."""

    def __init__(self, identity: str) -> None:
        self._identity = identity
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

    def publish(self, payload: PublicationPayload) -> PublishOutcome:
        with self._lock:
            self._calls.append(payload)
            self._counter += 1
            receipt = PublicationReceipt(
                f"permissive-status-{self._counter}",
                payload.canonical_digest(),
                self.identity,
            )
            key = payload.repository_id, payload.head_oid, payload.context.lower()
            self._visible[key] = receipt
            return PublishOutcome(PublishDisposition.PUBLISHED, receipt)

    def lookup(self, payload: PublicationPayload) -> PublicationReceipt | None:
        with self._lock:
            key = payload.repository_id, payload.head_oid, payload.context.lower()
            receipt = self._visible.get(key)
            if receipt is None or receipt.payload_sha256 != payload.canonical_digest():
                return None
            return receipt


class Harness:
    def __init__(
        self,
        *,
        record: RegistryRecord | None = None,
        outcomes: list[MockPublishMode] | None = None,
        head_oid: str | None = None,
        publisher: Publisher | None = None,
    ) -> None:
        self.lock = threading.RLock()
        self.record = record or registry_record()
        self.registry = InMemoryRegistry(lock=self.lock)
        self.registry.add(self.record)
        self.registry.activate(
            self.record.repository_id, "authoritative", self.record.key
        )
        self.store = InMemoryEvaluationStore(lock=self.lock)
        self.head_oid = head_oid or oid("pull-head")
        self.reader = MockPullRequestReader(
            [
                PullRequestSnapshot(
                    self.record.repository_id,
                    PULL_NUMBER,
                    "open",
                    self.head_oid,
                    "main",
                )
            ]
        )
        if publisher is not None and outcomes is not None:
            raise ValueError("publisher and outcomes are mutually exclusive")
        self.publisher = publisher or MockPublisher(
            self.record.publisher_identity, outcomes
        )
        self.clock = MutableClock()
        self._ids = itertools.count(1)
        self.service = SignerService(
            registry=self.registry,
            store=self.store,
            pull_requests=self.reader,
            publisher=self.publisher,
            clock=self.clock,
            evaluation_id_generator=lambda: f"evaluation-{next(self._ids)}",
        )

    def issue(
        self,
        *,
        jti: str = "admission-jti",
        pull_number: int = PULL_NUMBER,
        run_id: int = 7001,
        run_attempt: int = 1,
    ):
        claims = verified_claims(
            self.record,
            jti=jti,
            run_id=run_id,
            run_attempt=run_attempt,
            now=self.clock.now,
        )
        return self.service.issue_evaluation(claims, TicketRequest(pull_number))

    def final_claims(
        self,
        jti: str,
        *,
        run_id: int = 7001,
        run_attempt: int = 1,
        **changes: object,
    ) -> VerifiedOidcClaims:
        return verified_claims(
            self.record,
            jti=jti,
            run_id=run_id,
            run_attempt=run_attempt,
            now=self.clock.now,
            **changes,
        )


def mutate_claims(claims: VerifiedOidcClaims, **changes: object) -> VerifiedOidcClaims:
    return replace(claims, **changes)
