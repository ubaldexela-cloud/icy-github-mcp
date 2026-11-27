"""Background adapter for one read-only repository lookup.

The adapter schedules ``github_get_repository`` on an injected
``BackgroundTaskWorker``. It does not import the GitHub MCP client, read
credentials, open a network connection, or speak.

``GithubClientRepositoryReader`` is the worker-only bridge to an injected
client. It calls that client's ``call`` and, when the client retains the
read, ``take_repository_read``. The client keeps its event loop, session,
transport, and child process. This reader does not start or close it.

The worker registers the operation during ``submit`` and marks it
dispatched, with ``interruptible`` false, before the executor runs. This
adapter does not register that operation a second time. ``note_finished``
is called only from the executor, and only for an outcome this process
actually observed:

- ``returned`` when the reader call comes back, including a failure or a
  payload that the result store rejects.
- ``abandoned`` when the local wait stops before the reader comes back.
  A non-interruptible abandoned operation keeps ``remote_may_still_run``.
- A later ``observe_return`` records that an abandoned call was seen to
  finish. It does not store a payload and does not complete the task.

A successful payload is stored before the executor returns. The worker
marks the task completed only after that return. A store rejection or a
reader failure raises, so the task is not completed. A cancellation that
is already set when the reader comes back does not store the payload and
does not complete the task. Local ``cancelled`` means the executor
stopped. It does not mean a remote call was cancelled.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from dataclasses import dataclass

from realtime_c.background_worker import (
    BackgroundTaskWorker,
    ExecutionContext,
    QueueFull,
    ShutdownReport,
    SubmissionRejected,
    WorkerNotRunning,
)
from realtime_c.task_registry import TaskRegistry, TaskSnapshot
from realtime_c.task_result_store import ResultRecord, TaskResultStore

TOOL_NAME = "github_get_repository"
_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,60}$")
_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_SECRET_RE = re.compile(
    r"(ghp_[A-Za-z0-9]|github_pat_|bearer\s+\S|sk-[A-Za-z0-9])",
    re.IGNORECASE,
)


class AdapterError(Exception):
    """Base class for adapter failures. Messages do not contain payloads."""


class AdapterRejected(AdapterError):
    """A conversation id or repository argument was rejected."""


class AdapterNotFound(AdapterError):
    """No task in this conversation matches the requested id."""


class RepositoryReadFailed(AdapterError):
    """The repository reader failed. The message has no payload."""


class ResultStoreFailed(AdapterError):
    """The result store rejected the payload. The task must not complete."""


class LocalWaitAbandoned(AdapterError):
    """The local wait stopped before the reader returned a payload."""


class SessionBusy(AdapterError):
    """The one session is already inside a call."""


class SessionOwnerMismatch(AdapterError):
    """A thread other than the bound worker tried to use the session."""


@dataclass(frozen=True)
class SessionCloseResult:
    """What one session-close attempt actually did.

    ``skipped`` means this reader has no session to close. ``in_use`` means
    the close was refused because a call is still inside the session.
    ``error`` is an exception class name, never a payload.
    """

    closed: bool
    error: str | None = None
    in_use: bool = False
    already_closed: bool = False
    skipped: bool = False


class ExclusiveMcpSession:
    """One MCP session. The first successful call binds the worker thread.

    A second call, from any thread, cannot enter while a call is active.
    ``close_session`` does not call the wrapped session while a call is
    active, and a repeated close does not open another session.
    """

    def __init__(self, session: object) -> None:
        if not hasattr(session, "call"):
            raise TypeError("session must provide call")
        self._session = session
        self._lock = threading.Lock()
        self._in_use = 0
        self._owner: int | None = None
        self._opened = False
        self._closed = False
        self.session_id = id(session)
        self.max_in_use = 0
        self.call_thread_ids: list[int] = []
        self.order: list[str] = []

    def open_session(self) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("session is closed")
            if self._opened:
                return
            self._opened = True
            self.order.append("open")

    def read_repository(
        self,
        owner: str,
        repo: str,
        *,
        cancelled: Callable[[], bool],
        wait_for_cancel: Callable[[float | None], bool],
    ) -> str:
        ident = threading.get_ident()
        with self._lock:
            if self._closed or not self._opened:
                raise RepositoryReadFailed("repository read failed")
            if self._in_use:
                raise SessionBusy("session is already in use")
            if self._owner is not None and self._owner != ident:
                raise SessionOwnerMismatch("session is owned by the worker thread")
            self._owner = ident
            self._in_use = 1
            self.max_in_use = max(self.max_in_use, self._in_use)
            self.call_thread_ids.append(ident)
            self.order.append(f"enter:{repo}")
        try:
            payload = self._session.call(
                owner,
                repo,
                cancelled=cancelled,
                wait_for_cancel=wait_for_cancel,
            )
        finally:
            with self._lock:
                self._in_use = 0
                self.order.append(f"exit:{repo}")
        if not isinstance(payload, str):
            raise RepositoryReadFailed("repository read failed")
        return payload

    def close_session(self) -> SessionCloseResult:
        with self._lock:
            if self._in_use:
                self.order.append("close_refused")
                return SessionCloseResult(closed=False, in_use=True)
            if self._closed:
                self.order.append("close_repeat")
                return SessionCloseResult(closed=True, already_closed=True)
            self._closed = True
            session = self._session
        try:
            closer = getattr(session, "close", None)
            if callable(closer):
                closer()
        except Exception as exc:
            with self._lock:
                self._closed = False
                self.order.append("close_error")
            return SessionCloseResult(closed=False, error=type(exc).__name__)
        with self._lock:
            self.order.append("close")
        return SessionCloseResult(closed=True)


class _ClientCancelView:
    """Attributes ``GithubMcpClient.call`` reads. This is not a second client."""

    __slots__ = ("cancel_event", "call_id", "pre_cancelled_at_entry")

    def __init__(self, cancel_event: threading.Event) -> None:
        self.cancel_event = cancel_event
        self.call_id = ""
        self.pre_cancelled_at_entry = cancel_event.is_set()


class GithubClientRepositoryReader:
    """Repository reads for one injected client, only from its worker thread.

    ``worker.status().thread_ident`` is the worker's own thread. Request
    arguments cannot replace it. A second call cannot enter while the
    first is inside ``call`` or ``take_repository_read``. Closing the
    client is intentionally absent; shutdown wiring belongs to a later phase.
    """

    def __init__(self, client: object, worker: BackgroundTaskWorker) -> None:
        if not isinstance(worker, BackgroundTaskWorker):
            raise TypeError("worker must be a BackgroundTaskWorker")
        if not callable(getattr(client, "call", None)):
            raise TypeError("client must provide call")
        if not callable(getattr(client, "take_repository_read", None)):
            raise TypeError("client must provide take_repository_read")
        self._client = client
        self._worker = worker
        self._lock = threading.Lock()
        self._in_use = False

    def read_repository(
        self,
        owner: str,
        repo: str,
        *,
        cancelled: Callable[[], bool],
        wait_for_cancel: Callable[[float | None], bool],
    ) -> str:
        self._require_worker()
        with self._lock:
            if self._in_use:
                raise SessionBusy("session is already in use")
            self._in_use = True
        try:
            return self._invoke(owner, repo, cancelled, wait_for_cancel)
        finally:
            with self._lock:
                self._in_use = False

    def _require_worker(self) -> None:
        ident = self._worker.status().thread_ident
        if ident is None or ident != threading.get_ident():
            raise SessionOwnerMismatch("session is owned by the worker thread")

    def _invoke(
        self,
        owner: str,
        repo: str,
        cancelled: Callable[[], bool],
        wait_for_cancel: Callable[[float | None], bool],
    ) -> str:
        cancel_event = threading.Event()
        if cancelled() or wait_for_cancel(0):
            cancel_event.set()
        stop = threading.Event()
        relay = threading.Thread(
            target=_relay_cancel,
            name="icy-github-read-cancel",
            args=(cancelled, cancel_event, stop),
            daemon=True,
        )
        relay.start()
        try:
            token = _ClientCancelView(cancel_event)
            try:
                text = self._client.call(
                    TOOL_NAME,
                    {"owner": owner, "repo": repo},
                    token,
                )
            except Exception as exc:
                _reraise_client_failure(exc)
            if not isinstance(text, str):
                raise RepositoryReadFailed("repository read failed")
            if _is_retained_text(text):
                try:
                    text = self._client.take_repository_read(cancel_event)
                except Exception as exc:
                    _reraise_client_failure(exc)
                if not isinstance(text, str):
                    raise RepositoryReadFailed("repository read failed")
            return _interpret_client_text(text)
        finally:
            stop.set()
            relay.join(1.0)


class RepositoryReader:
    """Injected reader. Tests supply a fake. Production GitHub is not used."""

    def read_repository(
        self,
        owner: str,
        repo: str,
        *,
        cancelled: Callable[[], bool],
        wait_for_cancel: Callable[[float | None], bool],
    ) -> str:
        raise NotImplementedError


@dataclass(frozen=True)
class RepositoryTaskAck:
    """Identifiers and status for one admission. It has no repository body."""

    task_id: str
    operation_id: str
    conversation_id: str
    state: str
    duplicate: bool


class BackgroundGithubAdapter:
    """Submit repository reads to one worker and store text results."""

    def __init__(
        self,
        registry: TaskRegistry,
        worker: BackgroundTaskWorker,
        results: TaskResultStore,
        reader: RepositoryReader,
    ) -> None:
        if not isinstance(registry, TaskRegistry):
            raise TypeError("registry must be a TaskRegistry")
        if not isinstance(worker, BackgroundTaskWorker):
            raise TypeError("worker must be a BackgroundTaskWorker")
        if not isinstance(results, TaskResultStore):
            raise TypeError("results must be a TaskResultStore")
        if not hasattr(reader, "read_repository"):
            raise TypeError("reader must provide read_repository")
        self._registry = registry
        self._worker = worker
        self._results = results
        self._reader = reader
        self._submit_lock = threading.Lock()
        self._startup_cleanup_error: str | None = None

    @property
    def startup_cleanup_error(self) -> str | None:
        """Exception class from session cleanup after a failed start, if any."""
        return self._startup_cleanup_error

    def start(self) -> None:
        """Start the injected worker. Importing this module does not.

        A reader with ``open_session`` is opened first. If the worker does
        not stay up, that session is closed and a started thread is joined.
        """
        opened = False
        try:
            opened = self._open_reader_session()
            self._worker.start()
        except Exception:
            self._stop_partial_worker()
            if opened:
                self._startup_cleanup_error = self._close_reader_session_best_effort()
            raise

    def shutdown(self, timeout: float = 5.0) -> ShutdownReport:
        """Stop the worker and return its report without rewriting it."""
        return self._worker.shutdown(timeout)

    def close_owned_session(self, report: ShutdownReport) -> SessionCloseResult:
        """Close the reader session only after the worker has stopped.

        A reader with no session is skipped. An alive worker does not reach
        ``close_session``. The worker report is not changed.
        """
        closer = getattr(self._reader, "close_session", None)
        if not callable(closer):
            return SessionCloseResult(closed=False, skipped=True)
        if not report.clean or report.thread_alive:
            return SessionCloseResult(closed=False, in_use=True)
        try:
            result = closer()
        except Exception as exc:
            return SessionCloseResult(closed=False, error=type(exc).__name__)
        if not isinstance(result, SessionCloseResult):
            return SessionCloseResult(closed=False, error="SessionCloseResult")
        return result

    def _open_reader_session(self) -> bool:
        opener = getattr(self._reader, "open_session", None)
        if not callable(opener):
            return False
        opener()
        return True

    def _stop_partial_worker(self) -> None:
        try:
            status = self._worker.status()
        except Exception:
            return
        if not status.running:
            return
        try:
            self._worker.shutdown(timeout=2.0)
        except Exception:
            return

    def _close_reader_session_best_effort(self) -> str | None:
        closer = getattr(self._reader, "close_session", None)
        if not callable(closer):
            return None
        try:
            result = closer()
        except Exception as exc:
            return type(exc).__name__
        if isinstance(result, SessionCloseResult) and result.error:
            return result.error
        return None

    def submit_repository_read(
        self,
        conversation_id: str,
        origin_turn_id: str,
        owner: str,
        repo: str,
    ) -> RepositoryTaskAck:
        """Create or reuse a task and return without waiting for the read."""
        conversation_id = _identifier(conversation_id, "conversation_id", _ID_RE)
        origin_turn_id = _identifier(origin_turn_id, "origin_turn_id", _ID_RE)
        owner = _identifier(owner, "owner", _NAME_RE)
        repo = _identifier(repo, "repo", _NAME_RE)
        dedup_key = f"repo:{owner}:{repo}"
        if len(dedup_key) > 128 or _SECRET_RE.search(dedup_key):
            raise AdapterRejected("repository arguments are not allowed")
        with self._submit_lock:
            task_id = self._registry.create(
                conversation_id,
                origin_turn_id,
                task_type=TOOL_NAME,
                deduplication_key=dedup_key,
            )
            snapshot = self._registry.get(task_id)
            if snapshot.conversation_id != conversation_id:
                raise AdapterNotFound("task not found")
            if snapshot.operations:
                operation = snapshot.operations[0]
                return RepositoryTaskAck(
                    task_id,
                    operation.operation_id,
                    conversation_id,
                    snapshot.state,
                    True,
                )
            try:
                admitted = self._worker.submit(
                    task_id,
                    TOOL_NAME,
                    self._execute,
                    arguments={
                        "owner": owner,
                        "repo": repo,
                        "conversation_id": conversation_id,
                    },
                )
            except SubmissionRejected:
                snapshot = self._registry.get(task_id)
                if not snapshot.operations:
                    raise
                operation = snapshot.operations[0]
                return RepositoryTaskAck(
                    task_id,
                    operation.operation_id,
                    conversation_id,
                    snapshot.state,
                    True,
                )
            return RepositoryTaskAck(
                admitted.task_id,
                admitted.operation_id,
                conversation_id,
                admitted.state,
                False,
            )

    def cancel(self, conversation_id: str, task_id: str) -> TaskSnapshot:
        """Cancel one task in this conversation. Other tasks stay as they are."""
        conversation_id = _identifier(conversation_id, "conversation_id", _ID_RE)
        task_id = _identifier(task_id, "task_id", _ID_RE)
        snapshot = self._owned(conversation_id, task_id)
        if snapshot.state in {"completed", "failed", "cancelled", "timed_out"}:
            return snapshot
        return self._worker.cancel(task_id)

    def observe_return(
        self,
        conversation_id: str,
        task_id: str,
        operation_id: str,
    ) -> TaskSnapshot:
        """Record that an abandoned read was later observed to finish.

        This does not store a payload and does not change task state.
        """
        conversation_id = _identifier(conversation_id, "conversation_id", _ID_RE)
        task_id = _identifier(task_id, "task_id", _ID_RE)
        operation_id = _identifier(operation_id, "operation_id", _ID_RE)
        self._owned(conversation_id, task_id)
        self._registry.note_finished(task_id, operation_id, outcome="returned")
        return self._registry.get(task_id)

    def get_result(
        self,
        conversation_id: str,
        task_id: str,
        operation_id: str,
    ) -> ResultRecord:
        """Return one stored result. Another conversation is not found."""
        conversation_id = _identifier(conversation_id, "conversation_id", _ID_RE)
        task_id = _identifier(task_id, "task_id", _ID_RE)
        operation_id = _identifier(operation_id, "operation_id", _ID_RE)
        self._owned(conversation_id, task_id)
        return self._results.get(conversation_id, task_id, operation_id)

    def _owned(self, conversation_id: str, task_id: str) -> TaskSnapshot:
        try:
            snapshot = self._registry.get(task_id)
        except Exception as exc:
            raise AdapterNotFound("task not found") from exc
        if snapshot.conversation_id != conversation_id:
            raise AdapterNotFound("task not found")
        return snapshot

    def _execute(self, context: ExecutionContext) -> None:
        """Run on the worker thread. The caller of submit is not this thread."""
        owner = context.arguments.get("owner")
        repo = context.arguments.get("repo")
        conversation_id = context.arguments.get("conversation_id")
        if not isinstance(owner, str) or not isinstance(repo, str) or not isinstance(conversation_id, str):
            raise RepositoryReadFailed("repository read failed")
        if context.cancelled():
            self._registry.note_finished(
                context.task_id,
                context.operation_id,
                outcome="abandoned",
            )
            return
        try:
            payload = self._reader.read_repository(
                owner,
                repo,
                cancelled=context.cancelled,
                wait_for_cancel=context.wait_for_cancel,
            )
        except LocalWaitAbandoned:
            self._registry.note_finished(
                context.task_id,
                context.operation_id,
                outcome="abandoned",
            )
            if context.cancelled():
                return
            raise RepositoryReadFailed("repository read failed") from None
        except RepositoryReadFailed:
            self._registry.note_finished(
                context.task_id,
                context.operation_id,
                outcome="returned",
            )
            raise
        except Exception:
            self._registry.note_finished(
                context.task_id,
                context.operation_id,
                outcome="returned",
            )
            raise RepositoryReadFailed("repository read failed") from None
        if not isinstance(payload, str):
            self._registry.note_finished(
                context.task_id,
                context.operation_id,
                outcome="returned",
            )
            raise RepositoryReadFailed("repository read failed") from None
        if context.cancelled():
            self._registry.note_finished(
                context.task_id,
                context.operation_id,
                outcome="returned",
            )
            return
        try:
            self._results.put(
                conversation_id,
                context.task_id,
                context.operation_id,
                payload,
            )
        except Exception:
            self._registry.note_finished(
                context.task_id,
                context.operation_id,
                outcome="returned",
            )
            raise ResultStoreFailed("result was rejected") from None
        self._registry.note_finished(
            context.task_id,
            context.operation_id,
            outcome="returned",
        )


def _relay_cancel(
    cancelled: Callable[[], bool],
    cancel_event: threading.Event,
    stop: threading.Event,
) -> None:
    """Copy the worker token onto the event the client already polls."""
    while not stop.is_set():
        if cancelled():
            cancel_event.set()
            return
        if stop.wait(0.02):
            return


def _reraise_client_failure(exc: Exception) -> None:
    if type(exc).__name__ == "GithubCallCancelled":
        raise LocalWaitAbandoned("repository read abandoned") from None
    raise RepositoryReadFailed("repository read failed") from None


def _json_dict(text: str) -> dict | None:
    try:
        value = _parse_json(text)
    except ValueError:
        return None
    if isinstance(value, dict):
        return value
    return None


def _parse_json(text: str) -> object:
    """Parse one JSON value. The adapter cannot import ``json``."""
    value, index = _parse_json_value(text, 0)
    index = _skip_json(text, index)
    if index != len(text):
        raise ValueError("trailing json")
    return value


def _skip_json(text: str, index: int) -> int:
    while index < len(text) and text[index] in " \t\r\n":
        index += 1
    return index


def _parse_json_value(text: str, index: int) -> tuple[object, int]:
    index = _skip_json(text, index)
    if index >= len(text):
        raise ValueError("truncated json")
    char = text[index]
    if char == "{":
        return _parse_json_object(text, index)
    if char == "[":
        return _parse_json_array(text, index)
    if char == '"':
        return _parse_json_string(text, index)
    if text.startswith("true", index):
        return True, index + 4
    if text.startswith("false", index):
        return False, index + 5
    if text.startswith("null", index):
        return None, index + 4
    if char == "-" or char.isdigit():
        return _parse_json_number(text, index)
    raise ValueError("invalid json")


def _parse_json_object(text: str, index: int) -> tuple[dict[str, object], int]:
    index += 1
    result: dict[str, object] = {}
    index = _skip_json(text, index)
    if index < len(text) and text[index] == "}":
        return result, index + 1
    while index < len(text):
        index = _skip_json(text, index)
        key, index = _parse_json_string(text, index)
        index = _skip_json(text, index)
        if index >= len(text) or text[index] != ":":
            raise ValueError("invalid json")
        value, index = _parse_json_value(text, index + 1)
        if not isinstance(key, str):
            raise ValueError("invalid json")
        result[key] = value
        index = _skip_json(text, index)
        if index >= len(text):
            raise ValueError("truncated json")
        if text[index] == "}":
            return result, index + 1
        if text[index] != ",":
            raise ValueError("invalid json")
        index += 1
    raise ValueError("truncated json")


def _parse_json_array(text: str, index: int) -> tuple[list[object], int]:
    index += 1
    result: list[object] = []
    index = _skip_json(text, index)
    if index < len(text) and text[index] == "]":
        return result, index + 1
    while index < len(text):
        value, index = _parse_json_value(text, index)
        result.append(value)
        index = _skip_json(text, index)
        if index >= len(text):
            raise ValueError("truncated json")
        if text[index] == "]":
            return result, index + 1
        if text[index] != ",":
            raise ValueError("invalid json")
        index += 1
    raise ValueError("truncated json")


def _parse_json_string(text: str, index: int) -> tuple[str, int]:
    if index >= len(text) or text[index] != '"':
        raise ValueError("invalid json")
    index += 1
    chars: list[str] = []
    while index < len(text):
        char = text[index]
        if char == '"':
            return "".join(chars), index + 1
        if char == "\\":
            index += 1
            if index >= len(text):
                raise ValueError("truncated json")
            escaped = text[index]
            mapping = {
                '"': '"',
                "\\": "\\",
                "/": "/",
                "b": "\b",
                "f": "\f",
                "n": "\n",
                "r": "\r",
                "t": "\t",
            }
            if escaped in mapping:
                chars.append(mapping[escaped])
                index += 1
                continue
            if escaped == "u":
                digits = text[index + 1:index + 5]
                if len(digits) != 4 or any(item not in "0123456789abcdefABCDEF" for item in digits):
                    raise ValueError("invalid json")
                chars.append(chr(int(digits, 16)))
                index += 5
                continue
            raise ValueError("invalid json")
        if ord(char) < 32:
            raise ValueError("invalid json")
        chars.append(char)
        index += 1
    raise ValueError("truncated json")


def _parse_json_number(text: str, index: int) -> tuple[int | float, int]:
    start = index
    if text[index] == "-":
        index += 1
    if index >= len(text) or not text[index].isdigit():
        raise ValueError("invalid json")
    if text[index] == "0":
        index += 1
    else:
        while index < len(text) and text[index].isdigit():
            index += 1
    if index < len(text) and text[index] == ".":
        index += 1
        if index >= len(text) or not text[index].isdigit():
            raise ValueError("invalid json")
        while index < len(text) and text[index].isdigit():
            index += 1
    if index < len(text) and text[index] in "eE":
        index += 1
        if index < len(text) and text[index] in "+-":
            index += 1
        if index >= len(text) or not text[index].isdigit():
            raise ValueError("invalid json")
        while index < len(text) and text[index].isdigit():
            index += 1
    token = text[start:index]
    if any(item in token for item in ".eE"):
        return float(token), index
    return int(token), index


def _is_retained_text(text: str) -> bool:
    value = _json_dict(text)
    return value is not None and value.get("status") == "github_read_retained"


def _is_local_abandon_envelope(value: dict) -> bool:
    """True only for a client envelope that stopped the local wait.

    The hard-deadline timeout and an in-flight unavailable result both set
    ``write_attempted`` and do not carry ``detail``. A disabled or pre-dispatch
    refusal has neither of those shapes. A finished tool body, including a
    completed network timeout, also lacks ``write_attempted``.
    """
    if value.get("write_attempted") is not False or "detail" in value:
        return False
    return value.get("error") in {"network_timeout", "github_unavailable"}


_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def _failure_code(value: dict) -> str:
    code = value.get("error")
    if (
        isinstance(code, str)
        and _CODE_RE.fullmatch(code) is not None
        and _SECRET_RE.search(code) is None
    ):
        return code
    return "repository read failed"


def _interpret_client_text(text: str) -> str:
    value = _json_dict(text)
    if value is None:
        if text.lstrip().startswith(("{", "[")):
            raise RepositoryReadFailed("repository read failed")
        return text
    if _is_local_abandon_envelope(value):
        raise LocalWaitAbandoned("repository read abandoned")
    if value.get("status") == "github_read_retained" or value.get("ok") is False or "error" in value:
        raise RepositoryReadFailed(_failure_code(value))
    return text


def _identifier(value: object, field: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str):
        raise AdapterRejected(f"{field} must be a string")
    if value.strip() != value or pattern.fullmatch(value) is None:
        raise AdapterRejected(f"{field} must be a short identifier without spaces")
    if _SECRET_RE.search(value):
        raise AdapterRejected(f"{field} must not contain a credential")
    return value


__all__ = [
    "TOOL_NAME",
    "AdapterError",
    "AdapterNotFound",
    "AdapterRejected",
    "BackgroundGithubAdapter",
    "LocalWaitAbandoned",
    "QueueFull",
    "ExclusiveMcpSession",
    "GithubClientRepositoryReader",
    "RepositoryReadFailed",
    "RepositoryReader",
    "RepositoryTaskAck",
    "ResultStoreFailed",
    "SessionBusy",
    "SessionCloseResult",
    "SessionOwnerMismatch",
    "WorkerNotRunning",
]
