"""Fake-only shutdown lifecycle tests for GithubMcpClient.close.

These tests never start mcp_servers.github_server, open a socket, or read a credential.
"""

from __future__ import annotations

import asyncio
import gc
import hashlib
import json
import logging
import socket
import tempfile
import threading
import time
import unittest
import warnings
from pathlib import Path
from unittest import mock

from realtime_c.github_mcp import GithubMcpClient

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "github_mcp.json"
_CONFIG_SHA = "fd5af162f322429a505b6116071ffc6c345014e64a871b737cba97d164e087e5"


class _LogCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


class _FakeChild:
    """In-process stand-in. terminate() and wait() are observable and do not spawn."""

    def __init__(self) -> None:
        self.pid = 0
        self.returncode: int | None = None
        self.stdout = None
        self.stdin = None
        self.stderr = None
        self.terminate_calls = 0
        self.kill_calls = 0
        self.wait_calls = 0

    def terminate(self) -> None:
        self.terminate_calls += 1

    def kill(self) -> None:
        self.kill_calls += 1
        self.returncode = -9

    async def wait(self) -> int:
        self.wait_calls += 1
        self.returncode = 0
        return 0


class ShutdownLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "config").mkdir()
        (self.root / "config" / "github_mcp.json").write_text(
            json.dumps({"enabled": True, "allow_reads": True, "allow_writes": False}),
            encoding="utf-8",
        )
        self._spawn_calls: list[str] = []

        async def _blocked_spawn(*args: object, **_kwargs: object) -> None:
            self._spawn_calls.append(" ".join(str(item) for item in args))
            raise AssertionError("spawn blocked")

        self._guards = [
            mock.patch.object(socket, "create_connection", side_effect=AssertionError("socket")),
            mock.patch.object(asyncio, "create_subprocess_exec", _blocked_spawn),
        ]
        for patcher in self._guards:
            patcher.start()
        self._clients: list[GithubMcpClient] = []

    def tearDown(self) -> None:
        for client in self._clients:
            try:
                if client._thread.is_alive():
                    client.close()
            except Exception:
                pass
        for patcher in reversed(self._guards):
            patcher.stop()
        self.tmp.cleanup()
        config = CONFIG.read_bytes()
        self.assertEqual(len(config), 1247)
        self.assertEqual(hashlib.sha256(config).hexdigest(), _CONFIG_SHA)

    def _client(self) -> GithubMcpClient:
        client = GithubMcpClient(self.root)
        self._clients.append(client)
        return client

    def _close_quietly(self, client: GithubMcpClient) -> tuple[list[str], list[str]]:
        capture = _LogCapture()
        logger = logging.getLogger("asyncio")
        previous = logger.level
        logger.setLevel(logging.DEBUG)
        logger.addHandler(capture)
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                client.close()
                gc.collect()
            warning_text = [f"{item.category.__name__}: {item.message}" for item in caught]
        finally:
            logger.removeHandler(capture)
            logger.setLevel(previous)
        return capture.messages, warning_text

    def _assert_quiet(self, logs: list[str], warning_text: list[str]) -> None:
        combined = "\n".join(logs + warning_text)
        self.assertNotIn("Task was destroyed but it is pending", combined)
        self.assertNotIn("was never awaited", combined)
        self.assertNotIn("_shutdown", combined)

    def _hold(self, client: GithubMcpClient, state: dict[str, object], child: _FakeChild | None) -> None:
        async def _session() -> bool:
            state["entered"] = True
            if child is not None:
                client._child_proc = child
                client._child_pid = child.pid
            entered = state.get("entered_event")
            if isinstance(entered, threading.Event):
                entered.set()
            try:
                await client._stopped.wait()
            finally:
                state["finally"] = True
                if child is not None:
                    await client._terminate_child_proc(child)
                client._child_proc = None
                client._child_pid = None
            return True

        client._one_session = _session  # type: ignore[method-assign]

    def test_01_close_immediately_after_start(self) -> None:
        client = self._client()
        client.start(wait=False)
        deadline = time.perf_counter() + 2
        while not client._thread.is_alive() and time.perf_counter() < deadline:
            time.sleep(0.01)
        self.assertTrue(client._thread.is_alive())
        self.assertFalse(client.ready.is_set())
        started = time.perf_counter()
        logs, warns = self._close_quietly(client)
        self.assertLess(time.perf_counter() - started, 3.0)
        self.assertFalse(client._thread.is_alive())
        self.assertTrue(client.loop is not None and client.loop.is_closed())
        self._assert_quiet(logs, warns)

    def test_02_close_before_the_session_is_ready(self) -> None:
        client = self._client()
        state: dict[str, object] = {"entered": False, "finally": False, "entered_event": threading.Event()}
        self._hold(client, state, None)
        client.start(wait=False)
        self.assertTrue(state["entered_event"].wait(2))  # type: ignore[union-attr]
        self.assertFalse(client.ready.is_set())
        logs, warns = self._close_quietly(client)
        self.assertTrue(state["finally"])
        self.assertFalse(client._thread.is_alive())
        self._assert_quiet(logs, warns)

    def test_03_close_while_initialization_is_pending(self) -> None:
        client = self._client()
        state: dict[str, object] = {"entered": False, "finally": False, "entered_event": threading.Event()}
        self._hold(client, state, None)
        client.start(wait=False)
        self.assertTrue(state["entered_event"].wait(2))  # type: ignore[union-attr]
        self.assertFalse(client._schemas_cached)
        logs, warns = self._close_quietly(client)
        self.assertTrue(state["finally"])
        self.assertFalse(client._thread.is_alive())
        self._assert_quiet(logs, warns)

    def test_04_close_after_successful_initialization(self) -> None:
        client = self._client()
        state: dict[str, object] = {"entered": False, "finally": False, "entered_event": threading.Event()}

        async def _ready_session() -> bool:
            client._schemas_cached = True
            client._session_healthy = True
            client._session = object()
            client.ready.set()
            state["entered_event"].set()  # type: ignore[union-attr]
            try:
                await client._stopped.wait()
            finally:
                state["finally"] = True
                client._session = None
                client._session_healthy = False
            return True

        client._one_session = _ready_session  # type: ignore[method-assign]
        client.start(wait=True)
        self.assertTrue(client.ready.is_set())
        self.assertIsNotNone(client._main_task)
        self.assertFalse(client._main_task.done())  # type: ignore[union-attr]
        logs, warns = self._close_quietly(client)
        self.assertTrue(state["finally"])
        self.assertFalse(client._thread.is_alive())
        self.assertTrue(client.loop.is_closed())
        self._assert_quiet(logs, warns)

    def test_05_close_after_startup_failure(self) -> None:
        client = self._client()
        client.INIT_RETRY_COOLDOWN_S = 30.0
        failed = threading.Event()

        async def _fail() -> bool:
            client.error = RuntimeError("startup failed")
            client.ready.set()
            failed.set()
            return False

        client._one_session = _fail  # type: ignore[method-assign]
        client.start(wait=False)
        self.assertTrue(failed.wait(2))
        started = time.perf_counter()
        logs, warns = self._close_quietly(client)
        self.assertLess(time.perf_counter() - started, 2.0)
        self.assertFalse(client._thread.is_alive())
        self._assert_quiet(logs, warns)

    def test_06_repeated_close_is_idempotent(self) -> None:
        client = self._client()
        state: dict[str, object] = {"entered": False, "finally": False, "entered_event": threading.Event()}
        self._hold(client, state, None)
        client.start(wait=False)
        self.assertTrue(state["entered_event"].wait(2))  # type: ignore[union-attr]
        logs, warns = self._close_quietly(client)
        second = client.close()
        third = client.close()
        self.assertTrue(second.worker_joined)
        self.assertTrue(third.worker_joined)
        self.assertTrue(second.child_reaped)
        self.assertTrue(third.child_reaped)
        self.assertFalse(client._thread.is_alive())
        self._assert_quiet(logs, warns)

    def test_07_close_while_the_main_task_is_running(self) -> None:
        client = self._client()
        state: dict[str, object] = {"entered_event": threading.Event(), "finally": False}
        self._hold(client, state, None)
        client.start(wait=False)
        self.assertTrue(state["entered_event"].wait(2))  # type: ignore[union-attr]
        task = client._main_task
        self.assertIsNotNone(task)
        self.assertFalse(task.done())  # type: ignore[union-attr]
        logs, warns = self._close_quietly(client)
        self.assertTrue(task.done())  # type: ignore[union-attr]
        self.assertTrue(state["finally"])
        self._assert_quiet(logs, warns)

    def test_08_close_requests_and_awaits_fake_child_termination(self) -> None:
        client = self._client()
        child = _FakeChild()
        state: dict[str, object] = {"entered_event": threading.Event(), "finally": False}
        self._hold(client, state, child)
        client.start(wait=False)
        self.assertTrue(state["entered_event"].wait(2))  # type: ignore[union-attr]
        self.assertIs(client._child_proc, child)
        logs, warns = self._close_quietly(client)
        self.assertGreaterEqual(child.terminate_calls, 1)
        self.assertGreaterEqual(child.wait_calls, 1)
        self.assertIsNone(client._child_proc)
        self.assertFalse(client._thread.is_alive())
        self._assert_quiet(logs, warns)

    def test_09_cancellation_runs_session_cleanup(self) -> None:
        client = self._client()
        child = _FakeChild()
        state: dict[str, object] = {"entered_event": threading.Event(), "finally": False}
        self._hold(client, state, child)
        client.start(wait=False)
        self.assertTrue(state["entered_event"].wait(2))  # type: ignore[union-attr]
        logs, warns = self._close_quietly(client)
        self.assertTrue(state["finally"])
        self.assertGreaterEqual(child.wait_calls, 1)
        self.assertIsNone(client._session)
        self.assertTrue(client.loop.is_closed())
        self._assert_quiet(logs, warns)

    def test_10_thread_joins_and_the_loop_terminates(self) -> None:
        client = self._client()
        state: dict[str, object] = {"entered_event": threading.Event(), "finally": False}
        self._hold(client, state, None)
        client.start(wait=False)
        self.assertTrue(state["entered_event"].wait(2))  # type: ignore[union-attr]
        loop = client.loop
        self.assertIsNotNone(loop)
        self.assertFalse(loop.is_closed())
        report_logs = self._close_quietly(client)
        report = client.close()
        self.assertTrue(report.worker_joined)
        self.assertFalse(client._thread.is_alive())
        self.assertTrue(loop.is_closed())
        self._assert_quiet(*report_logs)


if __name__ == "__main__":
    unittest.main()
