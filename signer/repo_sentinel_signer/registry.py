"""Immutable registry records and explicit activation pointers."""

from __future__ import annotations

import threading

from .model import RegistryRecord, SignerRefused, require_positive_int, require_string

RegistryKey = tuple[str, int]


class InMemoryRegistry:
    """Thread-safe reference registry with no implicit latest-record lookup."""

    def __init__(self, *, lock: threading.RLock | None = None) -> None:
        self._lock = lock or threading.RLock()
        self._records: dict[RegistryKey, RegistryRecord] = {}
        self._epoch_digests: dict[tuple[int, str], str] = {}
        self._active: dict[tuple[int, str], object] = {}
        self._revoked: set[RegistryKey] = set()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def add(self, record: RegistryRecord) -> RegistryRecord:
        if type(record) is not RegistryRecord:
            raise SignerRefused("invalid_registry_record")
        with self._lock:
            existing = self._records.get(record.key)
            if existing is not None:
                if existing != record:
                    raise SignerRefused("registry_record_mutation")
                return existing
            for candidate in self._records.values():
                if (
                    candidate.record_id == record.record_id
                    and candidate.repository_id != record.repository_id
                ):
                    raise SignerRefused("registry_record_identity_conflict")
            epoch_key = record.repository_id, record.policy_epoch
            approved_digest = self._epoch_digests.get(epoch_key)
            if approved_digest is not None and approved_digest != record.policy_digest:
                raise SignerRefused("registry_epoch_digest_conflict")
            self._records[record.key] = record
            self._epoch_digests.setdefault(epoch_key, record.policy_digest)
            return record

    def get(self, key: RegistryKey) -> RegistryRecord:
        with self._lock:
            if type(key) is not tuple or len(key) != 2:
                raise SignerRefused("invalid_registry_key")
            record_id, revision = key
            require_string(record_id, "record_id")
            require_positive_int(revision, "revision")
            try:
                return self._records[key]
            except KeyError:
                raise SignerRefused("registry_record_not_found") from None

    def activate(
        self, repository_id: int, authority_slot: str, key: RegistryKey
    ) -> RegistryRecord:
        require_positive_int(repository_id, "repository_id")
        slot = require_string(authority_slot, "authority_slot")
        with self._lock:
            record = self.get(key)
            if record.repository_id != repository_id:
                raise SignerRefused("registry_repository_mismatch")
            if key in self._revoked:
                raise SignerRefused("registry_record_revoked")
            self._active[(repository_id, slot)] = key
            return record

    def resolve_active(self, repository_id: int, authority_slot: str) -> RegistryRecord:
        require_positive_int(repository_id, "repository_id")
        slot = require_string(authority_slot, "authority_slot")
        with self._lock:
            pointer = self._active.get((repository_id, slot))
            if (
                type(pointer) is not tuple
                or len(pointer) != 2
                or type(pointer[0]) is not str
                or type(pointer[1]) is not int
            ):
                raise SignerRefused("registry_activation_ambiguous")
            record = self.get(pointer)
            if record.key in self._revoked:
                raise SignerRefused("registry_record_revoked")
            return record

    def revoke(self, key: RegistryKey) -> None:
        with self._lock:
            self.get(key)
            self._revoked.add(key)

    def is_revoked(self, key: RegistryKey) -> bool:
        with self._lock:
            self.get(key)
            return key in self._revoked

    def resolve_latest(self, *_args: object, **_kwargs: object) -> RegistryRecord:
        raise SignerRefused("unsupported_registry_lookup")
