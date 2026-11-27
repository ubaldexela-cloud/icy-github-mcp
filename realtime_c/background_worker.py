"""Single background worker for one Phase A task registry.

Phase B only. This module schedules work. ``TaskRegistry`` remains the only
owner of task identity and lifecycle state. The worker does not import the
voice engine, the tool harness, MCP clients, or audio components, and it
does not speak, record, or store executor return values.

Threading model
---------------
``start`` creates one non-daemon thread named ``icy-background-task``.
Importing this module does not start that thread. A second ``start`` while
the thread is alive does nothing. ``start`` after ``shutdown`` raises
``WorkerStopped``; construct a new worker to run again.

The thread is not a daemon. A daemon thread would let the process exit
while a registry task was still running and would hide an incomplete
shutdown. Shutdown joins this thread for a caller-supplied timeout and
reports failure when the thread is still alive.

Queue
-----
The queue holds waiting tasks only. The running task does not occupy a
waiting slot. The default waiting capacity is 2, so the worker has at most
one executing task and two waiting tasks. A full queue raises ``QueueFull``
and moves the rejected task from ``queued`` to ``failed`` with error code
``queue_full``. Accepted tasks are left as they are.

Lock order
----------
The worker lock is the lock inside ``self._condition``. Registry methods
take the registry lock only while a public call is on the stack, and the
registry never calls the worker. Code that needs both acquires the worker
lock first, calls a public registry method, then releases the worker lock.
The worker lock is not held while an executor runs, while a completion
callback runs, or while ``shutdown`` joins the thread.

Cancellation and timeout
------------------------
Each submitted task gets its own ``CancellationToken``. Cancelling one task
does not set any other task's token. A task that is still waiting is
removed from the queue and moved ``queued`` -> ``cancel_requested`` ->
``cancelled`` without calling its executor. A task that has entered its
executor is moved to ``cancel_requested`` and signalled. It becomes
``cancelled`` only after that executor returns. A late return value is
discarded. This cannot forcibly stop a blocked Python thread. Until a
non-cooperative executor returns, the single worker stays occupied and the
task stays unfinished.

A timeout is a deadline on the execution context. The worker applies
``timed_out`` only after the executor call has returned and the deadline
has passed. It does not start a second task to work around a blocked call.
"""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import MappingProxyType

from realtime_c.task_registry import (
    TERMINAL_STATES,
    InvalidTransition,
    RegistryValueError,
    TaskRegistry,
    TaskSnapshot,
    TaskState,
)

DEFAULT_QUEUE_CAPACITY = 2
THREAD_NAME = "icy-background-task"

Executor = Callable[["ExecutionContext"], object]
TerminalCallback = Callable[["Completion"], None]


class WorkerError(Exception):
    """Base class for worker failures that are not registry failures."""


class WorkerNotRunning(WorkerError):
    """Submit was refused because the worker is stopped or shutting down."""

    def __init__(self, task_id: str) -> None:
        self.task_id = task_id
        super().__init__("worker is not accepting work")


class WorkerStopped(WorkerError):
    """This worker has shut down and cannot start another thread."""


class QueueFull(WorkerError):
    """The waiting queue is at capacity. No existing task was discarded."""

    def __init__(self, task_id: str) -> None:
        self.task_id = task_id
        super().__init__("waiting queue is full")


class SubmissionRejected(WorkerError):
    """The task was not admitted, and its registry state was left unchanged."""

    def __init__(self, task_id: str, reason: str) -> None:
        self.task_id = task_id
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class SubmitResult:
    """Proof that a task was admitted. The executor has not necessarily run."""

    task_id: str
    operation_id: str
    state: str


@dataclass(frozen=True)
class WorkerStatus:
    """Immutable worker view. It is not a copy of registry task state.

    ``running`` means the worker thread is alive, including when it is
    blocked inside a non-cooperative executor. ``stopped`` is true only
    when that thread is not alive. ``accepting`` is false after shutdown
    begins. ``incomplete_shutdown`` means shutdown was requested and the
    thread is still alive.
    """

    running: bool
    stopped: bool
    accepting: bool
    shutdown_requested: bool
    incomplete_shutdown: bool
    current_task_id: str | None
    queued_count: int
    queue_capacity: int
    thread_ident: int | None


@dataclass(frozen=True)
class ShutdownReport:
    """Result of one shutdown attempt.

    ``clean`` is true only when the worker thread is not alive after the
    bounded join. A blocked executor produces ``clean`` false and
    ``thread_alive`` true. ``current_task_id`` is the task still inside
    the executor after the join, when one remains.
    """

    clean: bool
    thread_alive: bool
    current_task_id: str | None
    cancelled_waiting_ids: tuple[str, ...]


@dataclass(frozen=True)
class Completion:
    """Terminal observation for one task. It has no executor return value.

    The registry snapshot is authoritative. This record is what the worker
    published after a successful registry transition. Callbacks receive the
    same fields and must not be used to change lifecycle state.
    """

    task_id: str
    operation_id: str
    state: str
    error_code: str | None
    error_message: str | None


class CancellationToken:
    """Cooperative cancel signal for exactly one task.

    ``wait`` returns when ``cancel`` is called. It does not stop a thread
    that never calls ``wait`` or ``is_cancelled``, and it does not cancel a
    remote request that has already been sent.
    """

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)


class ExecutionContext:
    """What an executor is allowed to see for one admission.

    ``arguments`` is a shallow read-only copy. The context does not carry
    conversation text, audio, credentials, or a registry handle. Returning
    a value does not publish it. Raising an exception fails the task with
    the exception class name only.
    """

    def __init__(
        self,
        task_id: str,
        operation_id: str,
        arguments: Mapping[str, object],
        cancellation: CancellationToken,
        deadline: datetime | None,
        clock: Callable[[], datetime],
    ) -> None:
        self.task_id = task_id
        self.operation_id = operation_id
        self.arguments = arguments
        self.cancellation = cancellation
        self.deadline = deadline
        self._clock = clock

    def cancelled(self) -> bool:
        return self.cancellation.is_cancelled()

    def wait_for_cancel(self, timeout: float | None = None) -> bool:
        """Block until this task is cancelled. Returns true if it was."""
        return self.cancellation.wait(timeout)

    def deadline_exceeded(self) -> bool:
        if self.deadline is None:
            return False
        return _aware_now(self._clock) >= self.deadline


class _Job:
    __slots__ = (
        "task_id",
        "operation_id",
        "executor",
        "arguments",
        "token",
        "deadline",
        "settled",
    )

    def __init__(
        self,
        task_id: str,
        operation_id: str,
        executor: Executor,
        arguments: Mapping[str, object],
        token: CancellationToken,
        deadline: datetime | None,
    ) -> None:
        self.task_id = task_id
        self.operation_id = operation_id
        self.executor = executor
        self.arguments = arguments
        self.token = token
        self.deadline = deadline
        self.settled = False


class _Claim:
    __slots__ = ("job", "completion", "stop")

    def __init__(
        self,
        job: _Job | None = None,
        completion: Completion | None = None,
        stop: bool = False,
    ) -> None:
        self.job = job
        self.completion = completion
        self.stop = stop


class BackgroundTaskWorker:
    """One worker thread bound to one ``TaskRegistry``.

    The caller creates the registry record and only then calls ``submit``
    with that task id. The worker does not create a second id. After
    admission, lifecycle changes go through the registry's public
    transition methods.
    """

    def __init__(
        self,
        registry: TaskRegistry,
        *,
        queue_capacity: int = DEFAULT_QUEUE_CAPACITY,
        on_terminal: TerminalCallback | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(registry, TaskRegistry):
            raise TypeError("registry must be a TaskRegistry")
        if isinstance(queue_capacity, bool) or not isinstance(queue_capacity, int):
            raise TypeError("queue_capacity must be an integer")
        if queue_capacity < 1:
            raise ValueError("queue_capacity must be at least 1")
        if on_terminal is not None and not callable(on_terminal):
            raise TypeError("on_terminal must be callable")
        self._registry = registry
        self._capacity = queue_capacity
        self._on_terminal = on_terminal
        self._clock = clock or _utc_now
        self._condition = threading.Condition()
        self._waiting: deque[_Job] = deque()
        self._waiting_ids: set[str] = set()
        self._current: _Job | None = None
        self._executor_started = False
        self._shutdown = False
        self._thread: threading.Thread | None = None
        self._completions: dict[str, Completion] = {}

    def start(self) -> None:
        """Start the single worker thread.

        Repeated calls do not create another thread. After ``shutdown``,
        this raises ``WorkerStopped``.
        """
        with self._condition:
            if self._shutdown:
                raise WorkerStopped("worker cannot start after shutdown")
            if self._thread is not None and self._thread.is_alive():
                return
            thread = threading.Thread(
                target=self._loop,
                name=THREAD_NAME,
                daemon=False,
            )
            self._thread = thread
            thread.start()

    def submit(
        self,
        task_id: str,
        tool_name: str,
        executor: Executor,
        *,
        arguments: Mapping[str, object] | None = None,
        timeout: float | None = None,
        operation_id: str | None = None,
    ) -> SubmitResult:
        """Admit an existing queued task and return without running it.

        The task must already exist and be ``queued``. The executor is
        called later on the worker thread. ``timeout`` is a deadline in
        seconds, measured with this worker's clock. It does not interrupt
        a blocked executor.

        Queue refusal and refusal while the worker is not accepting move
        that task to ``failed`` so it is not left ``queued``. A duplicate
        admission or an ineligible state raises ``SubmissionRejected`` and
        does not change the task.
        """
        if not callable(executor):
            raise TypeError("executor must be callable")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            raise TypeError("arguments must be a mapping")
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout < 0
        ):
            raise ValueError("timeout must be a non-negative number of seconds")
        copied = MappingProxyType(dict(arguments))
        with self._condition:
            snapshot = self._registry.get(task_id)
            if snapshot.state != TaskState.QUEUED:
                raise SubmissionRejected(
                    task_id,
                    f"task is {snapshot.state} and cannot be submitted",
                )
            if task_id in self._waiting_ids or (
                self._current is not None and self._current.task_id == task_id
            ):
                raise SubmissionRejected(task_id, "task is already submitted")
            accepting = (
                self._thread is not None
                and self._thread.is_alive()
                and not self._shutdown
            )
            if not accepting:
                self._registry.transition(
                    task_id,
                    TaskState.FAILED,
                    error_code="worker_not_running",
                    error_message="worker is not accepting work",
                )
                raise WorkerNotRunning(task_id)
            if len(self._waiting) >= self._capacity:
                self._registry.transition(
                    task_id,
                    TaskState.FAILED,
                    error_code="queue_full",
                    error_message="waiting queue is full",
                )
                raise QueueFull(task_id)
            operation = self._registry.register_operation(
                task_id,
                tool_name,
                operation_id,
            )
            deadline = None
            if timeout is not None:
                deadline = _aware_now(self._clock) + timedelta(seconds=float(timeout))
            job = _Job(
                task_id,
                operation.operation_id,
                executor,
                copied,
                CancellationToken(),
                deadline,
            )
            self._waiting.append(job)
            self._waiting_ids.add(task_id)
            self._condition.notify()
            return SubmitResult(task_id, operation.operation_id, TaskState.QUEUED.value)

    def status(self) -> WorkerStatus:
        """Return a frozen status snapshot. The queue object is not exposed."""
        with self._condition:
            thread = self._thread
            alive = thread is not None and thread.is_alive()
            current = None if self._current is None else self._current.task_id
            return WorkerStatus(
                running=alive,
                stopped=not alive,
                accepting=alive and not self._shutdown,
                shutdown_requested=self._shutdown,
                incomplete_shutdown=self._shutdown and alive,
                current_task_id=current,
                queued_count=len(self._waiting),
                queue_capacity=self._capacity,
                thread_ident=thread.ident if alive else None,
            )

    def cancel(self, task_id: str) -> TaskSnapshot:
        """Request cancellation of one task.

        A waiting task becomes ``cancelled`` before its executor runs. A
        running task becomes ``cancel_requested`` until its executor
        returns, and only that task's token is set. Terminal tasks raise
        ``InvalidTransition``.
        """
        pending: Completion | None = None
        with self._condition:
            self._registry.get(task_id)
            if task_id in self._waiting_ids:
                target: _Job | None = None
                kept: deque[_Job] = deque()
                for queued in self._waiting:
                    if queued.task_id == task_id and target is None:
                        target = queued
                    else:
                        kept.append(queued)
                self._waiting = kept
                self._waiting_ids.discard(task_id)
                if target is not None:
                    target.token.cancel()
                    pending = self._to_cancelled_locked(target)
                snapshot = self._registry.get(task_id)
                self._condition.notify_all()
            elif self._current is not None and self._current.task_id == task_id:
                job = self._current
                job.token.cancel()
                snapshot = self._registry.get(task_id)
                if snapshot.state == TaskState.RUNNING:
                    snapshot = self._registry.request_cancel(task_id)
                if not self._executor_started:
                    pending = self._to_cancelled_locked(job)
                    if self._current is job:
                        self._current = None
                        self._executor_started = False
                    snapshot = self._registry.get(task_id)
            else:
                snapshot = self._registry.get(task_id)
                if snapshot.state == TaskState.QUEUED:
                    pending = self._to_cancelled_locked(_placeholder_job(task_id))
                    snapshot = self._registry.get(task_id)
                elif snapshot.state == TaskState.CANCEL_REQUESTED:
                    pass
                elif snapshot.state == TaskState.RUNNING:
                    snapshot = self._registry.request_cancel(task_id)
                else:
                    snapshot = self._registry.request_cancel(task_id)
        if pending is not None:
            self._emit(pending)
        return snapshot

    def completion(self, task_id: str) -> Completion | None:
        """Return the worker's published terminal record, if it has one.

        This is not registry state. A missing record means the worker has
        not published a terminal outcome for this id.
        """
        with self._condition:
            return self._completions.get(task_id)

    def shutdown(self, timeout: float = 5.0) -> ShutdownReport:
        """Stop admitting work, cancel waiting tasks, and join once.

        Waiting tasks are cancelled and are not drained. The current task
        is signalled. When ``timeout`` expires first, the report is not
        clean and the blocked task is left unfinished. Calling shutdown
        again joins again and is safe.
        """
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout < 0:
            raise ValueError("timeout must be a non-negative number of seconds")
        pending: list[Completion] = []
        cancelled: list[str] = []
        with self._condition:
            self._shutdown = True
            waiting = list(self._waiting)
            self._waiting.clear()
            self._waiting_ids.clear()
            for job in waiting:
                cancelled.append(job.task_id)
                completion = self._to_cancelled_locked(job)
                if completion is not None:
                    pending.append(completion)
            current = self._current
            if current is not None:
                current.token.cancel()
                snapshot = self._registry.get(current.task_id)
                if snapshot.state == TaskState.RUNNING:
                    self._registry.request_cancel(current.task_id)
                if not self._executor_started:
                    completion = self._to_cancelled_locked(current)
                    if completion is not None:
                        pending.append(completion)
                    self._current = None
                    self._executor_started = False
            self._condition.notify_all()
            thread = self._thread
        for completion in pending:
            self._emit(completion)
        if thread is not None:
            thread.join(timeout)
        alive = thread is not None and thread.is_alive()
        with self._condition:
            if not alive:
                self._thread = None
            current_id = None if self._current is None else self._current.task_id
        return ShutdownReport(
            clean=not alive,
            thread_alive=alive,
            current_task_id=current_id,
            cancelled_waiting_ids=tuple(cancelled),
        )

    def _loop(self) -> None:
        while True:
            try:
                claimed = self._claim()
            except Exception:
                continue
            if claimed.stop:
                return
            if claimed.completion is not None:
                self._emit(claimed.completion)
                continue
            if claimed.job is None:
                continue
            try:
                self._execute(claimed.job)
            except Exception:
                self._fail_safe(claimed.job)

    def _claim(self) -> _Claim:
        with self._condition:
            while not self._waiting and not self._shutdown:
                self._condition.wait()
            if not self._waiting:
                return _Claim(stop=True)
            job = self._waiting.popleft()
            self._waiting_ids.discard(job.task_id)
            try:
                snapshot = self._registry.get(job.task_id)
            except Exception:
                completion = self._fail_unclaimed_locked(job)
                return _Claim(completion=completion)
            if snapshot.state in TERMINAL_STATES:
                job.settled = True
                return _Claim()
            if snapshot.state == TaskState.CANCEL_REQUESTED:
                completion = self._to_cancelled_locked(job)
                return _Claim(completion=completion)
            if snapshot.state != TaskState.QUEUED:
                return _Claim()
            try:
                self._registry.transition(job.task_id, TaskState.RUNNING)
                self._registry.note_dispatched(
                    job.task_id,
                    job.operation_id,
                    interruptible=False,
                )
            except Exception:
                completion = self._fail_unclaimed_locked(job)
                return _Claim(completion=completion)
            self._current = job
            self._executor_started = False
        return self._release_or_run(job)

    def _fail_unclaimed_locked(self, job: _Job) -> Completion | None:
        """Record failure for a popped job that cannot be started."""
        if self._current is job:
            self._current = None
            self._executor_started = False
        try:
            snapshot = self._registry.get(job.task_id)
        except Exception:
            job.settled = True
            return None
        if snapshot.state in TERMINAL_STATES:
            job.settled = True
            return None
        if snapshot.state == TaskState.CANCEL_REQUESTED:
            return self._to_cancelled_locked(job)
        return self._to_terminal_locked(
            job,
            TaskState.FAILED,
            "executor_failed",
            "worker_error",
        )

    def _release_or_run(self, job: _Job) -> _Claim:
        """Admit the executor only if cancellation has not already won."""
        with self._condition:
            if job.settled:
                if self._current is job:
                    self._current = None
                    self._executor_started = False
                return _Claim()
            if job.token.is_cancelled() or self._shutdown:
                completion = self._to_cancelled_locked(job)
                if self._current is job:
                    self._current = None
                    self._executor_started = False
                return _Claim(completion=completion)
            self._executor_started = True
            return _Claim(job=job)

    def _execute(self, job: _Job) -> None:
        with self._condition:
            if job.settled or not self._executor_started:
                return
        context = ExecutionContext(
            job.task_id,
            job.operation_id,
            job.arguments,
            job.token,
            job.deadline,
            self._clock,
        )
        error: Exception | None = None
        try:
            job.executor(context)
        except Exception as exc:
            error = exc
        completion = self._finish(job, error)
        if completion is not None:
            self._emit(completion)

    def _finish(self, job: _Job, error: Exception | None) -> Completion | None:
        with self._condition:
            if job.settled:
                if self._current is job:
                    self._current = None
                    self._executor_started = False
                return None
            try:
                snapshot = self._registry.get(job.task_id)
            except Exception:
                job.settled = True
                if self._current is job:
                    self._current = None
                    self._executor_started = False
                return None
            if snapshot.state in TERMINAL_STATES:
                job.settled = True
                completion = None
            elif (
                job.token.is_cancelled()
                or snapshot.state == TaskState.CANCEL_REQUESTED
                or self._shutdown
            ):
                completion = self._to_cancelled_locked(job)
            elif job.deadline is not None and _aware_now(self._clock) >= job.deadline:
                completion = self._to_terminal_locked(
                    job,
                    TaskState.TIMED_OUT,
                    "execution_timeout",
                    "execution deadline exceeded",
                )
            elif error is not None:
                completion = self._to_terminal_locked(
                    job,
                    TaskState.FAILED,
                    "executor_failed",
                    _exception_name(error),
                )
            else:
                completion = self._to_terminal_locked(
                    job,
                    TaskState.COMPLETED,
                    None,
                    None,
                )
            if self._current is job:
                self._current = None
                self._executor_started = False
            return completion

    def _to_cancelled_locked(self, job: _Job) -> Completion | None:
        if job.settled:
            return None
        snapshot = self._registry.get(job.task_id)
        if snapshot.state in TERMINAL_STATES:
            job.settled = True
            return None
        if snapshot.state in (TaskState.QUEUED, TaskState.RUNNING):
            self._registry.request_cancel(job.task_id)
        snapshot = self._registry.get(job.task_id)
        if snapshot.state != TaskState.CANCEL_REQUESTED:
            job.settled = True
            return None
        return self._to_terminal_locked(job, TaskState.CANCELLED, None, None)

    def _to_terminal_locked(
        self,
        job: _Job,
        state: TaskState,
        error_code: str | None,
        error_message: str | None,
    ) -> Completion | None:
        if job.settled:
            return None
        try:
            snapshot = self._registry.transition(
                job.task_id,
                state,
                error_code=error_code,
                error_message=error_message,
            )
        except RegistryValueError:
            if state not in (TaskState.FAILED, TaskState.TIMED_OUT):
                raise
            snapshot = self._registry.transition(
                job.task_id,
                state,
                error_code=error_code or "executor_failed",
                error_message="executor_failed",
            )
        except InvalidTransition:
            job.settled = True
            return None
        job.settled = True
        completion = _completion_from(job.task_id, job.operation_id, snapshot)
        self._completions[job.task_id] = completion
        return completion

    def _fail_safe(self, job: _Job) -> None:
        completion: Completion | None = None
        with self._condition:
            if not job.settled:
                try:
                    snapshot = self._registry.get(job.task_id)
                    if snapshot.state == TaskState.RUNNING:
                        completion = self._to_terminal_locked(
                            job,
                            TaskState.FAILED,
                            "executor_failed",
                            "worker_error",
                        )
                    elif snapshot.state == TaskState.CANCEL_REQUESTED:
                        completion = self._to_terminal_locked(
                            job,
                            TaskState.CANCELLED,
                            None,
                            None,
                        )
                except Exception:
                    job.settled = True
            if self._current is job:
                self._current = None
                self._executor_started = False
        if completion is not None:
            self._emit(completion)

    def _emit(self, completion: Completion) -> None:
        callback = self._on_terminal
        if callback is None:
            return
        try:
            callback(completion)
        except Exception:
            return


def _placeholder_job(task_id: str) -> _Job:
    return _Job(task_id, "", _noop, MappingProxyType({}), CancellationToken(), None)


def _noop(_context: ExecutionContext) -> None:
    return None


def _completion_from(task_id: str, operation_id: str, snapshot: TaskSnapshot) -> Completion:
    return Completion(
        task_id,
        operation_id,
        snapshot.state,
        snapshot.error_code,
        snapshot.error_message,
    )


def _exception_name(exc: BaseException) -> str:
    name = type(exc).__name__
    if name.isidentifier() and len(name) <= 64:
        return name
    return "Exception"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware_now(clock: Callable[[], datetime]) -> datetime:
    now = clock()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise WorkerError("clock must return a timezone-aware datetime")
    return now.astimezone(timezone.utc)
