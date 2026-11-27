"""In-memory task identity and lifecycle registry.

Phase A only. This module does not start a worker, queue, executor, or
asyncio task. It does not call MCP, GitHub, the voice engine, or the
microphone path. Records live in this process and disappear on restart.

Deduplication scope is ``(conversation_id, deduplication_key)`` and only
while a task is unfinished (``queued``, ``running``, or
``cancel_requested``). The same key in another conversation is a different
task. A missing key always creates a new task. A terminal task does not
keep the key reserved.

Terminal retention keeps at most ``max_terminal`` finished records. The
oldest terminal record is the one that entered a terminal state earliest
(monotonic completion order, then task id). Unfinished tasks are never
evicted. Task ids are never reused for the lifetime of the registry object,
including after a terminal record is dropped.

Cancellation request and the terminal ``cancelled`` state are different.
``cancel_requested`` means a cancel was asked for. ``cancelled`` means a
later layer confirmed that local execution has stopped and a late result
must be discarded. A dispatched operation with ``interruptible`` false can
still be running remotely after either of those states. This registry does
not interrupt remote work.

``note_finished(..., outcome="returned")`` records that the dispatched call
was observed to return. That operation then stops contributing to
``remote_may_still_run``. ``outcome="abandoned"`` records that the local
caller stopped waiting. It does not mean the remote request was cancelled,
and a non-interruptible dispatched operation keeps
``remote_may_still_run`` true until a later ``returned`` observation.
Neither outcome changes the task lifecycle state.
"""

from __future__ import annotations

import enum
import re
import threading
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


class TaskState(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    CANCEL_REQUESTED = "cancel_requested"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


TERMINAL_STATES = frozenset({
    TaskState.COMPLETED,
    TaskState.FAILED,
    TaskState.CANCELLED,
    TaskState.TIMED_OUT,
})

ACTIVE_STATES = frozenset({
    TaskState.QUEUED,
    TaskState.RUNNING,
    TaskState.CANCEL_REQUESTED,
})

_TRANSITIONS: dict[TaskState, frozenset[TaskState]] = {
    TaskState.QUEUED: frozenset({
        TaskState.RUNNING,
        TaskState.CANCEL_REQUESTED,
        TaskState.CANCELLED,
        TaskState.FAILED,
    }),
    TaskState.RUNNING: frozenset({
        TaskState.CANCEL_REQUESTED,
        TaskState.COMPLETED,
        TaskState.FAILED,
        TaskState.TIMED_OUT,
    }),
    TaskState.CANCEL_REQUESTED: frozenset({
        TaskState.CANCELLED,
        TaskState.FAILED,
        TaskState.TIMED_OUT,
    }),
}

_FAILURE_STATES = frozenset({TaskState.FAILED, TaskState.TIMED_OUT})
_FINISH_OUTCOMES = frozenset({"returned", "abandoned"})
_SECRET_RE = re.compile(
    r"(ghp_[A-Za-z0-9]|github_pat_|bearer\s+\S|sk-[A-Za-z0-9])",
    re.IGNORECASE,
)
_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_TOOL_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_META_KEY_RE = re.compile(r"^[A-Za-z0-9_]{1,32}$")
_MAX_ERROR_CODE = 64
_MAX_ERROR_MESSAGE = 240
_MAX_META_ITEMS = 8
_MAX_META_TEXT = 120


class TaskRegistryError(Exception):
    """Base class for registry failures."""


class TaskNotFound(TaskRegistryError):
    """The task id is unknown or its record has already been evicted."""

    def __init__(self, task_id: str) -> None:
        self.task_id = task_id
        super().__init__(f"task not found: {task_id}")


class InvalidTransition(TaskRegistryError):
    """The requested state change is not in the lifecycle table."""

    def __init__(self, task_id: str, current: str, requested: str) -> None:
        self.task_id = task_id
        self.current = current
        self.requested = requested
        super().__init__(
            f"invalid transition for {task_id}: {current} -> {requested}"
        )


class CapacityError(TaskRegistryError):
    """A new task would require discarding an unfinished task."""


class DuplicateOperation(TaskRegistryError):
    """An operation id is already registered, including on another task."""

    def __init__(self, operation_id: str, task_id: str) -> None:
        self.operation_id = operation_id
        self.task_id = task_id
        super().__init__(
            f"operation {operation_id} already belongs to task {task_id}"
        )


class RegistryValueError(TaskRegistryError):
    """A caller-supplied value is empty, oversized, or not allowed."""


@dataclass(frozen=True)
class OperationSnapshot:
    """Immutable view of one tool operation. It has no payload body."""

    operation_id: str
    task_id: str
    tool_name: str
    state: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error_code: str | None
    dispatched: bool
    interruptible: bool


@dataclass(frozen=True)
class TaskSnapshot:
    """Immutable view of one task. Mutating it cannot change the registry."""

    task_id: str
    conversation_id: str
    origin_turn_id: str
    task_type: str | None
    state: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    updated_at: datetime
    cancel_requested_at: datetime | None
    error_code: str | None
    error_message: str | None
    operations: tuple[OperationSnapshot, ...]
    result_metadata: tuple[tuple[str, str | int | bool | None], ...]
    deduplication_key: str | None
    remote_may_still_run: bool


class _Operation:
    def __init__(self, operation_id: str, task_id: str, tool_name: str, created_at: datetime) -> None:
        self.operation_id = operation_id
        self.task_id = task_id
        self.tool_name = tool_name
        self.state = "recorded"
        self.created_at = created_at
        self.started_at: datetime | None = None
        self.finished_at: datetime | None = None
        self.error_code: str | None = None
        self.dispatched = False
        self.interruptible = False

    def snapshot(self) -> OperationSnapshot:
        return OperationSnapshot(
            operation_id=self.operation_id,
            task_id=self.task_id,
            tool_name=self.tool_name,
            state=self.state,
            created_at=self.created_at,
            started_at=self.started_at,
            finished_at=self.finished_at,
            error_code=self.error_code,
            dispatched=self.dispatched,
            interruptible=self.interruptible,
        )


class _Task:
    def __init__(
        self,
        task_id: str,
        conversation_id: str,
        origin_turn_id: str,
        task_type: str | None,
        deduplication_key: str | None,
        created_at: datetime,
        sequence: int,
    ) -> None:
        self.task_id = task_id
        self.conversation_id = conversation_id
        self.origin_turn_id = origin_turn_id
        self.task_type = task_type
        self.deduplication_key = deduplication_key
        self.state = TaskState.QUEUED
        self.created_at = created_at
        self.started_at: datetime | None = None
        self.finished_at: datetime | None = None
        self.updated_at = created_at
        self.cancel_requested_at: datetime | None = None
        self.error_code: str | None = None
        self.error_message: str | None = None
        self.operations: dict[str, _Operation] = {}
        self.operation_order: list[str] = []
        self.result_metadata: tuple[tuple[str, str | int | bool | None], ...] = ()
        self.sequence = sequence
        self.terminal_sequence: int | None = None


class TaskRegistry:
    """Process-local registry. Callers share it across threads through its lock."""

    def __init__(
        self,
        *,
        max_terminal: int = 8,
        max_active: int | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if max_terminal < 0:
            raise RegistryValueError("max_terminal must be zero or greater")
        if max_active is not None and max_active < 1:
            raise RegistryValueError("max_active must be at least 1 when set")
        self._max_terminal = max_terminal
        self._max_active = max_active
        self._clock = clock or _utc_now
        self._lock = threading.Lock()
        self._tasks: dict[str, _Task] = {}
        self._used_ids: set[str] = set()
        self._operations: dict[str, str] = {}
        self._dedup: dict[tuple[str, str], str] = {}
        self._creation_order: list[str] = []
        self._terminal_order: list[str] = []
        self._next_sequence = 0
        self._next_terminal_sequence = 0

    def create(
        self,
        conversation_id: str,
        origin_turn_id: str,
        *,
        task_type: str | None = None,
        deduplication_key: str | None = None,
    ) -> str:
        """Create a queued task, or return the active task for this dedup scope."""
        conversation_id = _identity(conversation_id, "conversation_id")
        origin_turn_id = _identity(origin_turn_id, "origin_turn_id")
        task_type = _optional_label(task_type, "task_type")
        deduplication_key = _optional_label(deduplication_key, "deduplication_key")
        with self._lock:
            if deduplication_key is not None:
                existing_id = self._dedup.get((conversation_id, deduplication_key))
                if existing_id is not None:
                    return existing_id
            active = sum(1 for task in self._tasks.values() if task.state in ACTIVE_STATES)
            if self._max_active is not None and active >= self._max_active:
                raise CapacityError(
                    "active task capacity is full; unfinished tasks are not evicted"
                )
            now = self._checked_now()
            task_id = self._new_task_id()
            task = _Task(
                task_id,
                conversation_id,
                origin_turn_id,
                task_type,
                deduplication_key,
                now,
                self._next_sequence,
            )
            self._next_sequence += 1
            self._tasks[task_id] = task
            self._creation_order.append(task_id)
            if deduplication_key is not None:
                self._dedup[(conversation_id, deduplication_key)] = task_id
            return task_id

    def get(self, task_id: str) -> TaskSnapshot:
        """Return an immutable snapshot. Unknown and evicted ids raise TaskNotFound."""
        with self._lock:
            return self._snapshot(self._require(task_id))

    def list_tasks(
        self,
        *,
        conversation_id: str | None = None,
        state: str | None = None,
        task_type: str | None = None,
    ) -> tuple[TaskSnapshot, ...]:
        """Return snapshots in creation order. Filters compare exact strings."""
        wanted_state = _parse_state(state) if state is not None else None
        with self._lock:
            found: list[TaskSnapshot] = []
            for task_id in self._creation_order:
                task = self._tasks.get(task_id)
                if task is None:
                    continue
                if conversation_id is not None and task.conversation_id != conversation_id:
                    continue
                if wanted_state is not None and task.state != wanted_state:
                    continue
                if task_type is not None and task.task_type != task_type:
                    continue
                found.append(self._snapshot(task))
            return tuple(found)

    def transition(
        self,
        task_id: str,
        new_state: str,
        *,
        error_code: str | None = None,
        error_message: str | None = None,
        result_metadata: Mapping[str, Any] | None = None,
    ) -> TaskSnapshot:
        """Apply one legal transition. Terminal states accept no further move."""
        requested = _parse_state(new_state)
        code = _optional_code(error_code)
        message = _optional_message(error_message)
        metadata = _metadata(result_metadata) if result_metadata is not None else None
        with self._lock:
            task = self._require(task_id)
            allowed = _TRANSITIONS.get(task.state, frozenset())
            if requested not in allowed:
                raise InvalidTransition(task.task_id, task.state.value, requested.value)
            if (code or message) and requested not in _FAILURE_STATES:
                raise RegistryValueError("error fields belong on failed or timed_out")
            now = self._checked_now()
            self._apply(task, requested, now, code, message, metadata)
            snapshot = self._snapshot(task)
            self._evict_terminal_overflow()
            return snapshot

    def request_cancel(self, task_id: str) -> TaskSnapshot:
        """Move an unfinished task to cancel_requested.

        A repeated call keeps the original cancel timestamp and does not
        change a task that is already ``cancel_requested``. A running task
        stays uncancelled until ``transition(..., cancelled)``. Terminal
        tasks raise InvalidTransition.
        """
        with self._lock:
            task = self._require(task_id)
            if task.state == TaskState.CANCEL_REQUESTED:
                return self._snapshot(task)
            if task.state in TERMINAL_STATES or TaskState.CANCEL_REQUESTED not in _TRANSITIONS.get(task.state, frozenset()):
                raise InvalidTransition(
                    task.task_id,
                    task.state.value,
                    TaskState.CANCEL_REQUESTED.value,
                )
            now = self._checked_now()
            self._apply(task, TaskState.CANCEL_REQUESTED, now, None, None, None)
            return self._snapshot(task)

    def register_operation(
        self,
        task_id: str,
        tool_name: str,
        operation_id: str | None = None,
    ) -> OperationSnapshot:
        """Attach one operation to one task. The id is unique in this registry."""
        tool_name = _tool_name(tool_name)
        with self._lock:
            task = self._require(task_id)
            if task.state in TERMINAL_STATES:
                raise InvalidTransition(task.task_id, task.state.value, "register_operation")
            if operation_id is None:
                operation_id = self._new_operation_id()
            else:
                operation_id = _identity(operation_id, "operation_id")
            if operation_id in self._operations or operation_id in self._used_ids:
                owner = self._operations.get(operation_id, "")
                raise DuplicateOperation(operation_id, owner or task.task_id)
            now = self._checked_now()
            operation = _Operation(operation_id, task.task_id, tool_name, now)
            task.operations[operation_id] = operation
            task.operation_order.append(operation_id)
            self._operations[operation_id] = task.task_id
            self._used_ids.add(operation_id)
            task.updated_at = now
            return operation.snapshot()

    def note_dispatched(
        self,
        task_id: str,
        operation_id: str,
        *,
        interruptible: bool = False,
    ) -> OperationSnapshot:
        """Record that an operation was handed off.

        ``interruptible`` false means a later cancel must not claim the
        remote call has stopped. Phase A does not perform that call.
        """
        with self._lock:
            task = self._require(task_id)
            operation = task.operations.get(operation_id)
            if operation is None or self._operations.get(operation_id) != task.task_id:
                raise RegistryValueError("operation is not registered on this task")
            if operation.dispatched:
                return operation.snapshot()
            if operation.state != "recorded":
                raise InvalidTransition(task.task_id, operation.state, "dispatched")
            now = self._checked_now()
            operation.dispatched = True
            operation.interruptible = bool(interruptible)
            operation.state = "started"
            operation.started_at = now
            task.updated_at = now
            return operation.snapshot()

    def note_finished(
        self,
        task_id: str,
        operation_id: str,
        *,
        outcome: str,
    ) -> OperationSnapshot:
        """Record a local observation of one dispatched operation.

        ``returned`` means the call was observed to finish. That operation
        no longer keeps ``remote_may_still_run`` set. ``abandoned`` means
        the local caller stopped waiting without seeing the call return.
        Dispatch history stays in place, and a non-interruptible abandoned
        operation still reports that the remote work may be running.

        Repeating the same outcome keeps the original finish timestamp.
        ``abandoned`` may later be followed by ``returned`` when the call
        is actually observed to finish. ``returned`` cannot later become
        ``abandoned``. An operation that was never dispatched is rejected.

        This does not change the task state, mark the task completed, or
        turn an operation observation into a successful task.
        """
        if not isinstance(outcome, str) or outcome not in _FINISH_OUTCOMES:
            raise RegistryValueError("outcome must be returned or abandoned")
        operation_id = _identity(operation_id, "operation_id")
        with self._lock:
            task = self._require(task_id)
            operation = task.operations.get(operation_id)
            if operation is None or self._operations.get(operation_id) != task.task_id:
                raise RegistryValueError("operation is not registered on this task")
            if operation.state == outcome:
                return operation.snapshot()
            if operation.state == "returned" or not operation.dispatched or operation.state == "recorded":
                raise InvalidTransition(task.task_id, operation.state, outcome)
            if operation.state not in {"started", "abandoned"}:
                raise InvalidTransition(task.task_id, operation.state, outcome)
            if operation.state == "abandoned" and outcome != "returned":
                raise InvalidTransition(task.task_id, operation.state, outcome)
            now = self._checked_now()
            operation.state = outcome
            operation.finished_at = now
            task.updated_at = now
            return operation.snapshot()

    def _apply(
        self,
        task: _Task,
        requested: TaskState,
        now: datetime,
        error_code: str | None,
        error_message: str | None,
        metadata: tuple[tuple[str, str | int | bool | None], ...] | None,
    ) -> None:
        if requested == TaskState.RUNNING and task.started_at is None:
            task.started_at = now
        if requested == TaskState.CANCEL_REQUESTED and task.cancel_requested_at is None:
            task.cancel_requested_at = now
        if requested in TERMINAL_STATES:
            task.finished_at = now
            task.terminal_sequence = self._next_terminal_sequence
            self._next_terminal_sequence += 1
            self._terminal_order.append(task.task_id)
            if task.deduplication_key is not None:
                scope = (task.conversation_id, task.deduplication_key)
                if self._dedup.get(scope) == task.task_id:
                    self._dedup.pop(scope, None)
        if requested in _FAILURE_STATES:
            task.error_code = error_code
            task.error_message = error_message
        if metadata is not None:
            task.result_metadata = metadata
        task.state = requested
        task.updated_at = now

    def _evict_terminal_overflow(self) -> None:
        while len(self._terminal_order) > self._max_terminal:
            oldest_id = self._terminal_order.pop(0)
            task = self._tasks.get(oldest_id)
            if task is None or task.state not in TERMINAL_STATES:
                continue
            for operation_id in task.operation_order:
                self._operations.pop(operation_id, None)
            self._tasks.pop(oldest_id, None)

    def _snapshot(self, task: _Task) -> TaskSnapshot:
        operations = tuple(task.operations[operation_id].snapshot() for operation_id in task.operation_order)
        remote = any(
            item.dispatched and not item.interruptible and item.state != "returned"
            for item in operations
        )
        return TaskSnapshot(
            task_id=task.task_id,
            conversation_id=task.conversation_id,
            origin_turn_id=task.origin_turn_id,
            task_type=task.task_type,
            state=task.state.value,
            created_at=task.created_at,
            started_at=task.started_at,
            finished_at=task.finished_at,
            updated_at=task.updated_at,
            cancel_requested_at=task.cancel_requested_at,
            error_code=task.error_code,
            error_message=task.error_message,
            operations=operations,
            result_metadata=task.result_metadata,
            deduplication_key=task.deduplication_key,
            remote_may_still_run=remote,
        )

    def _require(self, task_id: str) -> _Task:
        task = self._tasks.get(task_id)
        if task is None:
            raise TaskNotFound(str(task_id))
        return task

    def _new_task_id(self) -> str:
        while True:
            task_id = str(uuid.uuid4())
            if task_id not in self._used_ids:
                self._used_ids.add(task_id)
                return task_id

    def _new_operation_id(self) -> str:
        while True:
            operation_id = str(uuid.uuid4())
            if operation_id not in self._used_ids and operation_id not in self._operations:
                return operation_id

    def _checked_now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise RegistryValueError("registry clock must return a timezone-aware datetime")
        return now.astimezone(timezone.utc)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_state(value: str) -> TaskState:
    try:
        return TaskState(value)
    except ValueError as exc:
        raise InvalidTransition("", "", str(value)) from exc


def _identity(value: str, field: str) -> str:
    if not isinstance(value, str):
        raise RegistryValueError(f"{field} must be a string")
    text = value.strip()
    if text != value or not _ID_RE.fullmatch(text):
        raise RegistryValueError(f"{field} must be 1-128 characters without spaces")
    _reject_secret(text, field)
    return text


def _optional_label(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    return _identity(value, field)


def _tool_name(value: str) -> str:
    if not isinstance(value, str) or not _TOOL_RE.fullmatch(value):
        raise RegistryValueError("tool_name must be 1-64 letters, digits, or underscores")
    _reject_secret(value, "tool_name")
    return value


def _optional_code(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _ID_RE.fullmatch(value) or len(value) > _MAX_ERROR_CODE:
        raise RegistryValueError("error_code must be a short identifier")
    _reject_secret(value, "error_code")
    return value


def _optional_message(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_ERROR_MESSAGE:
        raise RegistryValueError("error_message must be a short non-empty string")
    _reject_secret(value, "error_message")
    return value


def _metadata(
    value: Mapping[str, Any],
) -> tuple[tuple[str, str | int | bool | None], ...]:
    if not isinstance(value, Mapping) or len(value) > _MAX_META_ITEMS:
        raise RegistryValueError("result_metadata must be a mapping of at most 8 items")
    items: list[tuple[str, str | int | bool | None]] = []
    for key in value:
        if not isinstance(key, str) or not _META_KEY_RE.fullmatch(key):
            raise RegistryValueError("result_metadata keys must be short identifiers")
        item = value[key]
        if item is not None and not isinstance(item, (str, int, bool)):
            raise RegistryValueError("result_metadata values must be small scalars")
        if isinstance(item, str):
            if len(item) > _MAX_META_TEXT:
                raise RegistryValueError("result_metadata text is too long")
            _reject_secret(item, "result_metadata")
        if isinstance(item, bool):
            stored: str | int | bool | None = item
        elif isinstance(item, int):
            stored = item
        else:
            stored = item
        items.append((key, stored))
    return tuple(items)


def _reject_secret(value: str, field: str) -> None:
    if _SECRET_RE.search(value):
        raise RegistryValueError(f"{field} must not contain a credential")
