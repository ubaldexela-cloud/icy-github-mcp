"""Optional MCP client for the isolated GitHub publish server.

The committed config stays disabled. This module does not read a PAT and
does not create the grant HMAC key file. A publication session key stays in
memory and is given to the child through a one-read approval-directory file.
Close deletes that file only. Replay ledgers are left in place.
The voice engine is not imported.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import stat
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio

from realtime_c.github_approval import (
    JOURNAL_PERSIST_DEADLINE_S,
    WORKER_GATE_LOCK_TIMEOUT_S,
    WRITE_TOOL_NAMES,
    TrackedLock,
    VoiceThreadGateForbiddenError,
    authorize_and_consume,
    direct_write_decision,
    job_call_meta,
    load_github_policy,
    policy_tool_error,
    _open_nofollow,
    prepare_private_directory,
    restrict_private_path,
    register_voice_thread,
    track_state_lock,
    unregister_voice_thread,
)
from realtime_c.redaction import RedactingLogFilter, redact_text

_LOG = logging.getLogger("realtime_c.github_mcp")
if not any(isinstance(item, RedactingLogFilter) for item in _LOG.filters):
    _LOG.addFilter(RedactingLogFilter())

from mcp_servers.github_reads import EXECUTE_TOOL_NAME, READ_CAPABILITY_TOOLS

GITHUB_TOOL_NAMES = (
    "github_prepare_publish",
    "github_create_repository",
    "github_create_file",
    "github_commit_files",
    "github_get_repository",
    "github_get_job_status",
    *READ_CAPABILITY_TOOLS,
    EXECUTE_TOOL_NAME,
)

_DEFAULT_TIMEOUT_S = 45.0
STARTUP_TIMEOUT_S = 10.0
INIT_RETRY_COOLDOWN_S = 15.0
MAX_AUTO_INIT_RETRIES = 5
SUPERVISOR_MAX_SPAWNS = 3
SUPERVISOR_WINDOW_S = 60.0
CHILD_TERM_GRACE_S = 1.0
CHILD_KILL_REAP_S = 0.5
SHUTDOWN_JOIN_S = 3.50
READ_CHUNK_BYTES = 65_536
MAX_STDOUT_FRAME_BYTES = 2_097_152
MAX_STDERR_LINE_BYTES = 8_192


def redact_child_stderr(line: bytes) -> str:
    """Redact a full child stderr line, then apply the byte cap."""
    text = redact_text(line.decode("utf-8", errors="replace"), max_len=None)
    if len(text) > MAX_STDERR_LINE_BYTES:
        return text[:MAX_STDERR_LINE_BYTES]
    return text


FOREGROUND_WAIT_S = 1.20
_FOREGROUND_SLICE_S = 0.025


class GithubCallCancelled(Exception):
    """The voice thread aborted this call before GitHub dispatch."""


@dataclass(frozen=True)
class TurnCallToken:
    """One foreground call. The worker loop never receives this object."""

    turn_id: str
    call_id: str
    cancel_event: threading.Event
    pre_cancelled_at_entry: bool


WORKER_READ_TIMEOUT_S = 10.0
WORKER_WRITE_TIMEOUT_S = 15.0

_POSIX_ENV_KEYS = (
    "PATH",
    "LANG",
    "LC_ALL",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
)
_WINDOWS_ENV_KEYS = (
    "PATH",
    "SYSTEMROOT",
    "WINDIR",
    "PATHEXT",
    "COMSPEC",
    "TEMP",
    "TMP",
)
_DENIED_CHILD_ENV = frozenset({
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "SSH_AUTH_SOCK",
    "OPENAI_API_KEY",
    "LLM_API_KEY",
    "TTS_API_KEY",
    "ASR_API_KEY",
    "GITHUB_TOKEN",
    "GITHUB_MCP_TOKEN",
    "GH_TOKEN",
    "GITHUB_GRANT_HMAC_KEY",
})


class ProtocolOversizedFrameError(Exception):
    """Stdout produced a frame above the 2 MiB cap."""


@dataclass
class CloseReport:
    clean: bool
    worker_joined: bool
    child_reaped: bool
    transport_closed: bool
    gate_io_active: bool
    unresolved_job_id: str | None


def build_github_child_env(root: Path, secret_rel: str = ".env.github") -> dict[str, str]:
    """Allowlist for the GitHub child. Parent secrets are not copied."""
    env: dict[str, str] = {
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUNBUFFERED": "1",
        "GITHUB_MCP_ROOT": str(root),
        "GITHUB_MCP_SECRET_FILE": secret_rel,
        "GITHUB_MCP_APPROVAL_DIR": str(root / "realtime_c" / "logs" / "github_approvals"),
    }
    if os.environ.get("PYTHONPATH"):
        env["PYTHONPATH"] = os.environ["PYTHONPATH"]
    allowed = _WINDOWS_ENV_KEYS if os.name == "nt" else _POSIX_ENV_KEYS
    for key in allowed:
        if key in _DENIED_CHILD_ENV:
            continue
        value = os.environ.get(key)
        if value:
            env[key] = value
    for key in _DENIED_CHILD_ENV:
        env.pop(key, None)
    return env


def take_stdout_frames(buf: bytearray) -> tuple[list[bytes], str | None]:
    """Pop complete newline frames. Oversized input clears the buffer."""
    frames: list[bytes] = []
    while True:
        nl = buf.find(b"\n")
        if nl == -1:
            if len(buf) > MAX_STDOUT_FRAME_BYTES:
                buf.clear()
                return frames, "stdout_frame_exceeded_2mib"
            return frames, None
        if nl > MAX_STDOUT_FRAME_BYTES:
            del buf[: nl + 1]
            return frames, "stdout_frame_exceeded_2mib"
        frame = bytes(buf[:nl]).rstrip(b"\r")
        del buf[: nl + 1]
        if frame:
            frames.append(frame)


class GithubMcpClient:
    """Persistent owned-stdio session. Disabled configs never start it."""

    STARTUP_TIMEOUT_S = STARTUP_TIMEOUT_S
    INIT_RETRY_COOLDOWN_S = INIT_RETRY_COOLDOWN_S
    supports_turn_token = True

    def __init__(
        self,
        root: Path,
        timeout: float = _DEFAULT_TIMEOUT_S,
        *,
        command: list[str] | None = None,
    ) -> None:
        self.root = root
        self.timeout = timeout
        self.foreground_wait_s = FOREGROUND_WAIT_S
        self.command = command
        self._handoff_key = secrets.token_bytes(32)
        self._handoff_key_path: Path | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.ready = threading.Event()
        self.error: BaseException | None = None
        self.schemas: dict[str, dict[str, Any]] = {}
        self._session: Any = None
        self._stopped: asyncio.Event | None = None
        self._started = False
        self._closed = False
        self._disabled = False
        self._close_requested = threading.Event()
        self._schemas_cached = False
        self._session_healthy = False
        self._closing = False
        self._child_proc: asyncio.subprocess.Process | None = None
        self._child_pid: int | None = None
        self._spawn_count = 0
        self._spawn_timestamps: deque[float] = deque()
        self._read_stream_send: Any = None
        self._write_stream_send: Any = None
        self._main_task: asyncio.Task[None] | None = None
        self._on_status: Callable[[dict[str, Any]], None] | None = None
        self._state_lock = TrackedLock()
        track_state_lock(self._state_lock)
        self._gate_io_stalled = False
        self._active_job: str | None = None
        self._pending_aborted_prepared_cleanup: list[tuple[str, str, str]] = []
        self._abort_persist = threading.Event()
        self._voice_thread_ident: int | None = None
        self._gate_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="Thread-GateIO")
        self._gate_executor_closed = False
        self._pipe_write_started = False
        self.last_startup_error = ""
        self._read_lock = threading.Lock()
        self._read_future: Any = None
        self._read_taken = False
        self._read_abandoned = False
        self._read_deadline = 0.0
        self._publication_worker: Any = None
        self._thread = threading.Thread(
            target=self._thread_main,
            name="github-mcp-worker",
            daemon=True,
        )

    @property
    def enabled(self) -> bool:
        with self._state_lock:
            return self._started and not self._disabled and not self._closed

    def _in_supervisor_backoff_locked(self, now_mono: float | None = None) -> bool:
        if self._session_healthy and self._child_proc is not None:
            return False
        now = time.monotonic() if now_mono is None else now_mono
        while self._spawn_timestamps and (now - self._spawn_timestamps[0]) >= SUPERVISOR_WINDOW_S:
            self._spawn_timestamps.popleft()
        return len(self._spawn_timestamps) >= SUPERVISOR_MAX_SPAWNS

    @property
    def available(self) -> bool:
        with self._state_lock:
            return (
                self._started
                and not self._disabled
                and not self._closed
                and self._schemas_cached
                and not self._in_supervisor_backoff_locked()
            )

    def start(self, wait: bool = False, on_status: Callable[[dict[str, Any]], None] | None = None) -> None:
        """Return immediately unless a test passes wait=True. Disabled configs spawn nothing."""
        if self._started:
            return
        self._on_status = on_status
        self._started = True
        cfg = self._load_config()
        if cfg.get("enabled") is not True:
            self._disabled = True
            self.error = RuntimeError("github_mcp_disabled")
            self.ready.set()
            self._emit({"event": "github_mcp_disabled", "message": "disabled"})
            return
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._thread_main,
            name="github-mcp-worker",
            daemon=True,
        )
        self._thread.start()
        if wait:
            self.ready.wait(timeout=30)

    def bind_publication_worker(self, worker: Any) -> None:
        """Let only this background worker dispatch publication tools."""
        self._publication_worker = worker

    def _publication_caller_allowed(self) -> bool:
        worker = self._publication_worker
        if worker is None:
            return False
        status = worker.status()
        ident = getattr(status, "thread_ident", None)
        return ident is not None and ident == threading.get_ident()

    def call(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        token: TurnCallToken | None = None,
        job_id: str | None = None,
        wait_s: float | None = None,
    ) -> str:
        if token is not None and token.pre_cancelled_at_entry:
            raise GithubCallCancelled(token.call_id)
        if self._disabled or not self._started:
            return json.dumps({
                "ok": False,
                "error": "github_mcp_disabled" if self._disabled else "github_unavailable",
                "spoken_status": "GitHub publishing is disabled.",
            })
        if self._closed or (self.error is not None and not self._schemas_cached):
            return json.dumps({
                "ok": False,
                "error": "github_unavailable",
                "spoken_status": "GitHub publishing is unavailable.",
                "detail": redact_text(self.error or "GitHub MCP is not running", max_len=200),
            })
        with self._state_lock:
            stalled = self._gate_io_stalled
            busy = self._active_job is not None
        if stalled or busy:
            return json.dumps({
                "ok": False,
                "error": "github_worker_busy",
                "reason": "journal_io_stalled" if stalled else "worker_busy",
                "spoken_status": "GitHub publishing is busy.",
            })
        if not self._schemas_cached or self._session is None or self.loop is None:
            return json.dumps({
                "ok": False,
                "error": "github_mcp_starting",
                "spoken_status": "GitHub publishing is still starting.",
            })
        if name in WRITE_TOOL_NAMES and not self._publication_caller_allowed():
            return json.dumps(direct_write_decision(self.root, name, arguments or {}))
        if name == "github_get_repository":
            return self._repository_read(name, arguments or {}, token, job_id)
        dispatched = threading.Event()
        future = asyncio.run_coroutine_threadsafe(
            self._call(name, arguments or {}, job_id=job_id, on_dispatch=dispatched.set),
            self.loop,
        )
        return self._wait_foreground(future, token, dispatched, wait_s)

    def _read_busy_json(self) -> str:
        return json.dumps({
            "ok": False,
            "error": "github_read_busy",
            "spoken_status": "A GitHub repository read is already running.",
            "write_attempted": False,
        })

    def _read_timeout_json(self) -> str:
        return json.dumps({
            "ok": False,
            "error": "network_timeout",
            "spoken_status": "GitHub timed out while reading the repository.",
            "write_attempted": False,
        })

    def _read_failed_json(self, exc: BaseException) -> str:
        return json.dumps({
            "ok": False,
            "error": "github_call_failed",
            "spoken_status": "The GitHub request failed.",
            "detail": redact_text(exc, max_len=200),
            "write_attempted": False,
        })

    def _read_consumed_json(self) -> str:
        return json.dumps({
            "ok": False,
            "error": "github_read_consumed",
            "spoken_status": "That GitHub read was already delivered.",
            "write_attempted": False,
        })

    def _read_retained_json(self) -> str:
        return json.dumps({
            "ok": False,
            "status": "github_read_retained",
            "spoken_status": "",
            "write_attempted": False,
            "outcome_uncertain": False,
        })

    def _read_done(self, future: Any) -> None:
        """Drop an abandoned or already delivered read. Do not store the payload."""
        with self._read_lock:
            if self._read_future is future and (self._read_abandoned or self._read_taken):
                self._read_future = None
        if not future.done():
            return
        try:
            future.exception()
        except BaseException:
            return

    def _abandon_read(self, future: Any, *, cancel: bool = False) -> None:
        """Drop ownership. Cancel only the local wait; a sent GET can still finish."""
        with self._read_lock:
            if self._read_future is future:
                self._read_abandoned = True
                if future.done():
                    self._read_future = None
        if cancel and not future.done():
            future.cancel()

    def _claim_read_result(self, future: Any, text: str) -> str | None:
        """Return the payload once. A second claim does not repeat it."""
        with self._read_lock:
            if self._read_future is not future or self._read_taken or self._read_abandoned:
                return None
            self._read_taken = True
            self._read_future = None
        return text

    def _repository_read(
        self,
        name: str,
        arguments: dict[str, Any],
        token: TurnCallToken | None,
        job_id: str | None,
    ) -> str:
        """One repository read. The voice wait stays 1.20s; a slower read stays owned."""
        if token is not None and token.cancel_event.is_set():
            raise GithubCallCancelled(token.call_id)
        loop = self.loop
        if loop is None:
            return json.dumps({
                "ok": False,
                "error": "github_mcp_starting",
                "spoken_status": "GitHub publishing is still starting.",
            })
        with self._read_lock:
            if self._read_future is not None:
                return self._read_busy_json()
            dispatched = threading.Event()
            future = asyncio.run_coroutine_threadsafe(
                self._call(name, arguments, job_id=job_id, on_dispatch=dispatched.set),
                loop,
            )
            self._read_future = future
            self._read_taken = False
            self._read_abandoned = False
            self._read_deadline = time.monotonic() + float(self.timeout)
            future.add_done_callback(self._read_done)
        try:
            text = self._poll_read(
                future,
                token,
                dispatched,
                time.monotonic() + self.foreground_wait_s,
            )
        except GithubCallCancelled:
            self._abandon_read(future, cancel=True)
            raise
        if text is not None:
            return text
        return self._read_retained_json()

    def take_repository_read(self, cancel_event: Any = None) -> str:
        """Consume the retained read once, or reject a second delivery."""
        with self._read_lock:
            future = self._read_future
            taken = self._read_taken
            abandoned = self._read_abandoned
            deadline = self._read_deadline
        if future is None or taken or abandoned:
            return self._read_consumed_json()
        token = None
        if cancel_event is not None:
            token = TurnCallToken("", "", cancel_event, bool(cancel_event.is_set()))
            if token.pre_cancelled_at_entry:
                self._abandon_read(future, cancel=True)
                raise GithubCallCancelled(token.call_id)
        dispatched = threading.Event()
        dispatched.set()
        try:
            text = self._poll_read(future, token, dispatched, deadline)
        except GithubCallCancelled:
            self._abandon_read(future, cancel=True)
            raise
        if text is None:
            self._abandon_read(future, cancel=True)
            return self._read_timeout_json()
        return text

    def _poll_read(
        self,
        future: Any,
        token: TurnCallToken | None,
        dispatched: threading.Event,
        soft_deadline: float,
    ) -> str | None:
        """Wait until the payload, cancel, hard timeout, or the soft deadline."""
        while True:
            if self._closed:
                self._abandon_read(future, cancel=True)
                return json.dumps({
                    "ok": False,
                    "error": "github_unavailable",
                    "spoken_status": "GitHub publishing is unavailable.",
                    "write_attempted": False,
                })
            if token is not None and token.cancel_event.is_set():
                self._abandon_read(future, cancel=True)
                raise GithubCallCancelled(token.call_id)
            now = time.monotonic()
            if now >= self._read_deadline and not future.done():
                self._abandon_read(future, cancel=True)
                return self._read_timeout_json()
            if now >= soft_deadline and not future.done():
                return None
            remaining = min(_FOREGROUND_SLICE_S, soft_deadline - now, self._read_deadline - now)
            if remaining <= 0:
                if future.done():
                    remaining = _FOREGROUND_SLICE_S
                else:
                    return None
            try:
                text = future.result(timeout=remaining)
            except TimeoutError:
                continue
            except GithubCallCancelled:
                raise
            except asyncio.CancelledError:
                self._abandon_read(future, cancel=True)
                return json.dumps({
                    "ok": False,
                    "error": "github_unavailable",
                    "spoken_status": "GitHub publishing is unavailable.",
                    "write_attempted": False,
                })
            except Exception as exc:  # noqa: BLE001
                claimed = self._claim_read_result(future, "")
                if claimed is None:
                    return self._read_consumed_json()
                return self._read_failed_json(exc)
            if token is not None and token.cancel_event.is_set():
                self._abandon_read(future, cancel=True)
                raise GithubCallCancelled(token.call_id)
            claimed = self._claim_read_result(future, text)
            if claimed is None:
                return self._read_consumed_json()
            return claimed

    def _wait_foreground(
        self,
        future: Any,
        token: TurnCallToken | None,
        dispatched: threading.Event,
        wait_s: float | None = None,
    ) -> str:
        """Wait on this thread only. A late cancel does not cancel a dispatched call."""
        limit = self.foreground_wait_s if wait_s is None else wait_s
        deadline = time.monotonic() + limit
        while True:
            if token is not None and token.cancel_event.is_set() and not dispatched.is_set():
                future.cancel()
                raise GithubCallCancelled(token.call_id)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                return future.result(timeout=min(_FOREGROUND_SLICE_S, remaining))
            except TimeoutError:
                continue
            except GithubCallCancelled:
                raise
            except Exception as exc:  # noqa: BLE001
                return json.dumps({
                    "ok": False,
                    "error": "github_call_failed",
                    "spoken_status": "The GitHub request failed.",
                    "detail": redact_text(exc, max_len=200),
                })
        if future.done() and not future.cancelled():
            try:
                return future.result()
            except GithubCallCancelled:
                raise
            except Exception as exc:  # noqa: BLE001
                return json.dumps({
                    "ok": False,
                    "error": "github_call_failed",
                    "spoken_status": "The GitHub request failed.",
                    "detail": redact_text(exc, max_len=200),
                })
        return json.dumps({
            "ok": False,
            "status": "in_progress",
            "committed_confirmed": False,
            "spoken_status": "The GitHub request is still running in the background.",
            "outcome_uncertain": False,
            "write_attempted": False,
        })

    @property
    def publication_handoff_key(self) -> bytes:
        """Session key for one MCP client. This is not a GitHub credential."""
        return self._handoff_key

    def _write_handoff_key_file(self) -> Path:
        directory = self.root / "realtime_c" / "logs" / "github_approvals"
        prepare_private_directory(directory)
        path = directory / f"handoff-{secrets.token_hex(16)}.key"
        fd = _open_nofollow(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(fd, self._handoff_key)
            os.fsync(fd)
        except OSError:
            os.close(fd)
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
        os.close(fd)
        try:
            restrict_private_path(path)
        except OSError:
            self._handoff_key_path = path
            self._delete_handoff_key_file()
            raise
        self._handoff_key_path = path
        return path

    def _delete_handoff_key_file(self) -> None:
        path = self._handoff_key_path
        self._handoff_key_path = None
        if path is None:
            return
        try:
            info = path.lstat()
            from realtime_c.github_approval import _is_reparse_point

            if _is_reparse_point(info) or not stat.S_ISREG(info.st_mode):
                return
            os.unlink(path)
        except OSError:
            return

    def close(self) -> CloseReport:
        """Ask the client loop to stop, then join its thread.

        The calling thread does not create a shutdown coroutine. The loop
        callback sets the stop event and cancels the main task. Stream close
        and child termination stay in ``_one_session``.
        """
        self._delete_handoff_key_file()
        self._closed = True
        self._closing = True
        self._close_requested.set()
        with self._read_lock:
            read_future = self._read_future
            if read_future is not None:
                self._read_abandoned = True
        if read_future is not None and not read_future.done():
            read_future.cancel()
        if self._voice_thread_ident is not None:
            unregister_voice_thread(self._voice_thread_ident)
            self._voice_thread_ident = None
        if not self._gate_executor_closed:
            self._gate_executor.shutdown(wait=False, cancel_futures=True)
            self._gate_executor_closed = True
        stalled = self._gate_io_stalled
        if not self._started or self._disabled or self.loop is None or not self._thread.is_alive():
            return CloseReport(not stalled, True, self._child_pid is None, True, stalled, None)
        loop = self.loop

        def _request_loop_stop() -> None:
            stopped = self._stopped
            if stopped is not None:
                stopped.set()
            task = self._main_task
            if task is not None and not task.done():
                task.cancel()

        try:
            loop.call_soon_threadsafe(_request_loop_stop)
        except RuntimeError:
            pass
        self._thread.join(timeout=SHUTDOWN_JOIN_S)
        joined = not self._thread.is_alive()
        self._recover_after_shutdown()
        reaped = self._child_proc is None
        stalled = self._gate_io_stalled
        return CloseReport(joined and reaped and not stalled, joined, reaped, True, stalled, None)

    def _recover_after_shutdown(self) -> None:
        """Enabled workers only. A disabled close never opens the approval journal."""
        if self._disabled or not self._started:
            return
        approval_dir = self.root / "realtime_c" / "logs" / "github_approvals"
        if not (approval_dir / "write_journal.json").is_file():
            return
        from realtime_c.github_approval import reconcile_startup_journal

        reconcile_startup_journal(
            approval_dir,
            now_mono=time.monotonic(),
            now_wall=time.time(),
            pipe_write_started=self._pipe_write_started,
        )

    def bind_voice_thread(self) -> None:
        """The bound thread may call the client. It must not take FileGateLock."""
        self._voice_thread_ident = threading.get_ident()
        register_voice_thread(self._voice_thread_ident)

    def mark_gate_io_stalled(self, job_id: str) -> None:
        """A persist deadline expired. The gate thread still owns the lock."""
        with self._state_lock:
            self._active_job = job_id
            self._gate_io_stalled = True

    def clear_gate_io_stall(self) -> None:
        from realtime_c.github_approval import gate_lock_held_by_current_thread

        if gate_lock_held_by_current_thread():
            raise RuntimeError("gate stall cleared while FileGateLock is held")
        with self._state_lock:
            self._gate_io_stalled = False
            self._active_job = None

    def run_gate_admission(
        self,
        approval_dir: Path,
        *,
        proposal_id: str,
        job_id: str,
        raw_key_32b: bytes,
        boot_id: str,
        now_mono: float,
        now_wall: float,
        deadline_s: float = JOURNAL_PERSIST_DEADLINE_S,
    ) -> dict[str, Any]:
        """Run TX-3 then TX-4 on Thread-GateIO. The voice thread cannot enter.

        On persist timeout the worker sets the stall flag and leaves the gate
        thread holding FileGateLock. That thread clears the stall only after
        the lock is released, and abort_check skips os.replace.
        """
        if threading.get_ident() == self._voice_thread_ident:
            raise VoiceThreadGateForbiddenError("voice thread cannot admit a grant")
        self._abort_persist.clear()

        def _admit() -> dict[str, Any]:
            try:
                return authorize_and_consume(
                    approval_dir,
                    proposal_id=proposal_id,
                    job_id=job_id,
                    raw_key_32b=raw_key_32b,
                    boot_id=boot_id,
                    now_mono=now_mono,
                    now_wall=now_wall,
                    pending=self._pending_aborted_prepared_cleanup,
                    abort_check=self._abort_persist.is_set,
                    timeout_s=WORKER_GATE_LOCK_TIMEOUT_S,
                )
            finally:
                self.clear_gate_io_stall()

        future = self._gate_executor.submit(_admit)
        try:
            return future.result(timeout=deadline_s)
        except TimeoutError:
            self._abort_persist.set()
            self.mark_gate_io_stalled(job_id)
            raise

    def _emit(self, event: dict[str, Any]) -> None:
        if self._on_status is None:
            return
        try:
            self._on_status(event)
        except Exception:
            return

    def _load_config(self) -> dict[str, Any]:
        """Missing, unreadable, or non-true enabled stays disabled."""
        path = self.root / "config" / "github_mcp.json"
        if not path.is_file():
            return {"enabled": False}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {"enabled": False}
        if not isinstance(data, dict):
            return {"enabled": False}
        if data.get("enabled") is not True:
            out = dict(data)
            out["enabled"] = False
            return out
        return data

    def _thread_main(self) -> None:
        assert self.loop is not None
        asyncio.set_event_loop(self.loop)
        if self._closing:
            self.ready.set()
            try:
                self.loop.close()
            except Exception:
                pass
            return
        try:
            self._main_task = self.loop.create_task(self._main())
            self.loop.run_until_complete(self._main_task)
        except asyncio.CancelledError:
            pass
        finally:
            if not self.ready.is_set():
                self.ready.set()
            try:
                self.loop.close()
            except Exception:
                pass

    async def _main(self) -> None:
        self._stopped = asyncio.Event()
        approval_dir = self.root / "realtime_c" / "logs" / "github_approvals"
        if (approval_dir / "write_journal.json").is_file():
            from realtime_c.github_approval import reconcile_startup_journal

            reconcile_startup_journal(
                approval_dir,
                now_mono=time.monotonic(),
                now_wall=time.time(),
            )
        attempts = 0
        while not self._closing and attempts < MAX_AUTO_INIT_RETRIES:
            with self._state_lock:
                if self._in_supervisor_backoff_locked():
                    break
            attempts += 1
            clean = await self._one_session()
            if clean or self._closing:
                break
            if attempts >= MAX_AUTO_INIT_RETRIES:
                break
            try:
                await asyncio.wait_for(self._stopped.wait(), timeout=self.INIT_RETRY_COOLDOWN_S)
                break
            except asyncio.TimeoutError:
                continue
        self.ready.set()

    async def _one_session(self) -> bool:
        proc: asyncio.subprocess.Process | None = None
        pumps: list[asyncio.Task[None]] = []
        clean = False
        if self._closing:
            return False
        try:
            proc = await self._spawn_github_stdio()
            self._child_proc = proc
            self._child_pid = proc.pid
            read_w, read_s = anyio.create_memory_object_stream[Any](0)
            write_s, write_r = anyio.create_memory_object_stream[Any](0)
            self._read_stream_send = read_w
            self._write_stream_send = write_s
            pumps = [
                asyncio.create_task(self._stdout_pump_task(proc, read_w)),
                asyncio.create_task(self._stdin_pump_task(proc, write_r)),
                asyncio.create_task(self._stderr_pump_task(proc)),
            ]
            from mcp import ClientSession

            async with ClientSession(read_s, write_s) as session:
                try:
                    await asyncio.wait_for(session.initialize(), timeout=self.STARTUP_TIMEOUT_S)
                    listed = await asyncio.wait_for(session.list_tools(), timeout=self.STARTUP_TIMEOUT_S)
                except TimeoutError:
                    if proc.returncode is None:
                        proc.kill()
                    raise
                found: dict[str, dict[str, Any]] = {}
                for tool in listed.tools:
                    raw = getattr(tool, "inputSchema", None)
                    if raw is None:
                        raw = getattr(tool, "input_schema", None)
                    if hasattr(raw, "model_dump"):
                        raw = raw.model_dump(by_alias=True)
                    found[str(tool.name)] = raw if isinstance(raw, dict) else {}
                with self._state_lock:
                    self.schemas = found
                    self._schemas_cached = True
                    self._session_healthy = True
                    self._session = session
                    self.error = None
                self.ready.set()
                self._emit({"event": "github_mcp_ready", "tools": sorted(found)})
                await self._stopped.wait()
                clean = True
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            self.last_startup_error = redact_text(exc, max_len=300)
            if self.error is None and not self._closing:
                self.error = exc
            self._emit({
                "event": "github_mcp_unavailable",
                "phase": "startup",
                "message": self.last_startup_error,
            })
        finally:
            with self._state_lock:
                self._session = None
                self._session_healthy = False
            await self._close_transport_streams()
            for task in pumps:
                task.cancel()
            if pumps:
                await asyncio.gather(*pumps, return_exceptions=True)
            if proc is not None:
                await self._terminate_child_proc(proc)
            self._child_proc = None
            self._child_pid = None
            self.ready.set()
        return clean

    async def _spawn_github_stdio(self) -> asyncio.subprocess.Process:
        secret_rel = ".env.github"
        cfg = self._load_config()
        raw_secret = cfg.get("secret_file")
        if isinstance(raw_secret, str) and raw_secret and not raw_secret.startswith(("/", "\\")) and ".." not in raw_secret:
            secret_rel = raw_secret
        command = self.command or [sys.executable, "-m", "mcp_servers.github_server"]
        key_path = self._write_handoff_key_file()
        env = build_github_child_env(self.root, secret_rel)
        env["GITHUB_MCP_HANDOFF_PATH"] = str(key_path)
        kwargs: dict[str, Any] = {
            "stdin": asyncio.subprocess.PIPE,
            "stdout": asyncio.subprocess.PIPE,
            "stderr": asyncio.subprocess.PIPE,
            "cwd": str(self.root),
            "env": env,
        }
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        with self._state_lock:
            self._spawn_count += 1
            self._spawn_timestamps.append(time.monotonic())
        try:
            return await asyncio.create_subprocess_exec(*command, **kwargs)
        except Exception:
            self._delete_handoff_key_file()
            raise

    async def _stdout_pump_task(self, proc: asyncio.subprocess.Process, writer: Any) -> None:
        import mcp_types as types
        from mcp.shared.message import SessionMessage

        buf = bytearray()
        assert proc.stdout is not None
        try:
            while True:
                chunk = await proc.stdout.read(READ_CHUNK_BYTES)
                if not chunk:
                    break
                buf.extend(chunk)
                frames, reason = take_stdout_frames(buf)
                if reason:
                    await writer.send(ProtocolOversizedFrameError("MCP stdout frame exceeded 2 MiB limit"))
                    break
                for frame in frames:
                    try:
                        text = frame.decode("utf-8")
                        message = types.jsonrpc_message_adapter.validate_json(text, by_name=False)
                    except (UnicodeError, ValueError) as exc:
                        await writer.send(exc)
                        return
                    await writer.send(SessionMessage(message=message))
        except asyncio.CancelledError:
            raise
        except Exception:
            return
        finally:
            try:
                await writer.aclose()
            except Exception:
                pass

    async def _stdin_pump_task(self, proc: asyncio.subprocess.Process, reader: Any) -> None:
        assert proc.stdin is not None
        try:
            async with reader:
                async for session_message in reader:
                    line = session_message.message.model_dump_json(by_alias=True, exclude_unset=True)
                    data = (line + "\n").encode("utf-8")
                    self.begin_pipe_write(proc.stdin, data)
                    await proc.stdin.drain()
        except asyncio.CancelledError:
            raise
        except Exception:
            return

    def begin_pipe_write(self, stdin: Any, data: bytes) -> None:
        """Latch the pipe only after the flag is visible, and only then write."""
        self._pipe_write_started = True
        stdin.write(data)

    async def _stderr_pump_task(self, proc: asyncio.subprocess.Process) -> None:
        assert proc.stderr is not None
        try:
            while True:
                line = await proc.stderr.readline()
                if not line:
                    break
                redacted = redact_child_stderr(line)
                if redacted:
                    _LOG.info("github child stderr: %s", redacted)
        except asyncio.CancelledError:
            raise
        except Exception:
            return

    async def _close_transport_streams(self) -> None:
        for stream in (self._write_stream_send, self._read_stream_send):
            if stream is None:
                continue
            try:
                await stream.aclose()
            except Exception:
                pass
        self._write_stream_send = None
        self._read_stream_send = None

    async def _terminate_child_proc(self, proc: asyncio.subprocess.Process) -> None:
        if proc.returncode is not None:
            return
        try:
            if os.name != "nt" and proc.pid:
                os.killpg(proc.pid, 15)
            else:
                proc.terminate()
        except (ProcessLookupError, OSError):
            return
        try:
            await asyncio.wait_for(proc.wait(), timeout=CHILD_TERM_GRACE_S)
            return
        except asyncio.TimeoutError:
            pass
        try:
            if os.name != "nt" and proc.pid:
                os.killpg(proc.pid, 9)
            else:
                proc.kill()
        except (ProcessLookupError, OSError):
            return
        try:
            await asyncio.wait_for(proc.wait(), timeout=CHILD_KILL_REAP_S)
        except asyncio.TimeoutError:
            return

    async def _call(
        self,
        name: str,
        arguments: dict[str, Any],
        job_id: str | None = None,
        on_dispatch: Callable[[], None] | None = None,
    ) -> str:
        denied = policy_tool_error(load_github_policy(self.root), name)
        if denied:
            return json.dumps({
                "ok": False,
                "error": denied,
                "spoken_status": "GitHub publishing is not allowed.",
                "write_attempted": False,
                "outcome_uncertain": False,
            })
        meta = job_call_meta(job_id)
        if on_dispatch is not None:
            on_dispatch()
        result = await self._session.call_tool(
            name,
            arguments=arguments,
            read_timeout_seconds=None if meta is not None else self.timeout,
            **({"meta": meta} if meta is not None else {}),
        )
        if getattr(result, "isError", False) or getattr(result, "is_error", False):
            text = _text(result) or "GitHub MCP tool returned an error"
            return json.dumps({
                "ok": False,
                "error": "github_tool_error",
                "spoken_status": "The GitHub tool returned an error.",
                "detail": redact_text(text, max_len=240),
            })
        return _text(result)


def _text(result: Any) -> str:
    parts = []
    for block in getattr(result, "content", []) or []:
        value = getattr(block, "text", None)
        if value:
            parts.append(str(value))
    return "".join(parts)
