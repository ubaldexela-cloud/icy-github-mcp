"""Bounded in-memory store for one textual result per task.

C2 only. This module does not talk to the task registry, the background
worker, the voice path, or GitHub. A caller that drops a terminal task
must call ``remove`` itself. Nothing here watches registry eviction.

Identity matches the registry rule: 1-128 characters from
``[A-Za-z0-9_.:-]``, with no spaces. Credential-like text uses the same
patterns as the registry and is rejected without being copied into the
error.

Retention keeps at most ``capacity`` records, default 8, maximum 64.
A new task evicts the oldest insertion. Storing the same operation and
the same payload again is idempotent and does not change that order.
One task holds one operation. The store does not change task lifecycle
state.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

DEFAULT_CAPACITY = 8
MAX_CAPACITY = 64
MAX_PAYLOAD_BYTES = 8192

_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_SECRET_RE = re.compile(
    r"(ghp_[A-Za-z0-9]|github_pat_|bearer\s+\S|sk-[A-Za-z0-9])",
    re.IGNORECASE,
)


class ResultStoreError(Exception):
    """Base class for result-store failures. Messages do not contain payloads."""


class ResultNotFound(ResultStoreError):
    """No result is stored for this conversation and task."""


class ResultMismatch(ResultStoreError):
    """The task has a result, but not for this operation id."""


class ResultConflict(ResultStoreError):
    """The task already has a different operation or a different payload."""


class ResultRejected(ResultStoreError):
    """An identifier, payload, or capacity value is not allowed."""


@dataclass(frozen=True)
class ResultRecord:
    """Immutable copy of one stored result."""

    conversation_id: str
    task_id: str
    operation_id: str
    payload: str
    stored_at: datetime


@dataclass(frozen=True)
class StoreStatus:
    """Capacity and occupancy. It contains no payloads."""

    capacity: int
    count: int


class _Stored:
    __slots__ = ("conversation_id", "task_id", "operation_id", "payload", "stored_at")

    def __init__(
        self,
        conversation_id: str,
        task_id: str,
        operation_id: str,
        payload: str,
        stored_at: datetime,
    ) -> None:
        self.conversation_id = conversation_id
        self.task_id = task_id
        self.operation_id = operation_id
        self.payload = payload
        self.stored_at = stored_at

    def record(self) -> ResultRecord:
        return ResultRecord(
            self.conversation_id,
            self.task_id,
            self.operation_id,
            self.payload,
            self.stored_at,
        )


class TaskResultStore:
    """Process-local result map. Public methods take the store lock."""

    def __init__(
        self,
        *,
        capacity: int = DEFAULT_CAPACITY,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int):
            raise ResultRejected("capacity must be an integer from 1 to 64")
        if capacity < 1 or capacity > MAX_CAPACITY:
            raise ResultRejected("capacity must be an integer from 1 to 64")
        self._capacity = capacity
        self._clock = clock or _utc_now
        self._lock = threading.Lock()
        self._records: dict[tuple[str, str], _Stored] = {}
        self._order: list[tuple[str, str]] = []

    def put(
        self,
        conversation_id: str,
        task_id: str,
        operation_id: str,
        payload: str,
    ) -> ResultRecord:
        """Store one payload for one task.

        The same operation and the same payload return the existing record.
        A different payload for that operation, or a second operation id
        for the task, raises ``ResultConflict``. An empty string is
        rejected. Text that is only spaces is stored unchanged when it
        fits in the byte limit.
        """
        conversation_id = _identity(conversation_id, "conversation_id")
        task_id = _identity(task_id, "task_id")
        operation_id = _identity(operation_id, "operation_id")
        payload = _payload(payload)
        with self._lock:
            key = (conversation_id, task_id)
            current = self._records.get(key)
            if current is not None:
                if current.operation_id != operation_id:
                    raise ResultConflict("task already has a stored operation")
                if current.payload != payload:
                    raise ResultConflict("stored payload does not match")
                return current.record()
            stored_at = self._checked_now()
            if len(self._records) >= self._capacity:
                oldest = self._order.pop(0)
                self._records.pop(oldest, None)
            stored = _Stored(
                conversation_id,
                task_id,
                operation_id,
                payload,
                stored_at,
            )
            self._records[key] = stored
            self._order.append(key)
            return stored.record()

    def get(
        self,
        conversation_id: str,
        task_id: str,
        operation_id: str,
    ) -> ResultRecord:
        """Return a copy. Another conversation or task is not found.

        A matching task with a different operation raises ``ResultMismatch``
        and does not reveal the stored payload.
        """
        conversation_id = _identity(conversation_id, "conversation_id")
        task_id = _identity(task_id, "task_id")
        operation_id = _identity(operation_id, "operation_id")
        with self._lock:
            current = self._records.get((conversation_id, task_id))
            if current is None:
                raise ResultNotFound("result not found")
            if current.operation_id != operation_id:
                raise ResultMismatch("operation_id does not match the stored record")
            return current.record()

    def remove(self, conversation_id: str, task_id: str) -> bool:
        """Drop one task's result. Missing records return false."""
        conversation_id = _identity(conversation_id, "conversation_id")
        task_id = _identity(task_id, "task_id")
        key = (conversation_id, task_id)
        with self._lock:
            if key not in self._records:
                return False
            self._records.pop(key, None)
            self._order = [item for item in self._order if item != key]
            return True

    def remove_conversation(self, conversation_id: str) -> int:
        """Drop every result in one conversation. Other conversations stay."""
        conversation_id = _identity(conversation_id, "conversation_id")
        with self._lock:
            keys = [key for key in self._order if key[0] == conversation_id]
            for key in keys:
                self._records.pop(key, None)
            if keys:
                gone = set(keys)
                self._order = [key for key in self._order if key not in gone]
            return len(keys)

    def status(self) -> StoreStatus:
        """Return capacity and count. Payloads are not included."""
        with self._lock:
            return StoreStatus(self._capacity, len(self._records))

    def _checked_now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ResultRejected("clock must return a timezone-aware datetime")
        return now.astimezone(timezone.utc)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _identity(value: str, field: str) -> str:
    if not isinstance(value, str):
        raise ResultRejected(f"{field} must be a string")
    if value == "" or value.strip() != value or not _ID_RE.fullmatch(value):
        raise ResultRejected(f"{field} must be 1-128 characters without spaces")
    if _SECRET_RE.search(value):
        raise ResultRejected(f"{field} must not contain a credential")
    return value


def _payload(value: str) -> str:
    if not isinstance(value, str):
        raise ResultRejected("payload must be a string")
    if value == "":
        raise ResultRejected("payload must be a non-empty string")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ResultRejected("payload must be valid text") from exc
    if size > MAX_PAYLOAD_BYTES:
        raise ResultRejected("payload exceeds 8192 bytes")
    if _SECRET_RE.search(value):
        raise ResultRejected("payload must not contain a credential")
    return value
