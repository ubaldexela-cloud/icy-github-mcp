"""C7 simulated GitHub client adapter. No real client, process, credential, or network."""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
import threading
import unittest
from pathlib import Path

from realtime_c.background_github_adapter import (
    TOOL_NAME,
    AdapterNotFound,
    BackgroundGithubAdapter,
    GithubClientRepositoryReader,
    LocalWaitAbandoned,
    RepositoryReadFailed,
    SessionBusy,
    SessionOwnerMismatch,
)
from realtime_c.background_worker import THREAD_NAME, BackgroundTaskWorker, QueueFull
from realtime_c.task_registry import TaskRegistry
from realtime_c.task_result_store import ResultNotFound, TaskResultStore


ROOT = Path(__file__).resolve().parents[1]
ADAPTER_PATH = ROOT / "realtime_c" / "background_github_adapter.py"
CONFIG_PATH = ROOT / "config" / "github_mcp.json"
CONFIG_SHA256 = "fd5af162f322429a505b6116071ffc6c345014e64a871b737cba97d164e087e5"
OWNER = "ubaldexela-cloud"
SECRET = "ghp_testonly"
SUCCESS = json.dumps({
    "ok": True,
    "full_name": "ubaldexela-cloud/mnist-einops-cnn",
    "owner": OWNER,
    "name": "mnist-einops-cnn",
    "private": False,
})
RETAINED = json.dumps({
    "ok": False,
    "status": "github_read_retained",
    "spoken_status": "",
    "write_attempted": False,
    "outcome_uncertain": False,
})


class GithubCallCancelled(Exception):
    """Same class name the production client raises. This object is local."""


def _envelope(error: str, *, spoken: str, detail: str | None = None, write_attempted: bool | None = None) -> str:
    body: dict[str, object] = {
        "ok": False,
        "error": error,
        "spoken_status": spoken,
    }
    if detail is not None:
        body["detail"] = detail
    if write_attempted is not None:
        body["write_attempted"] = write_attempted
    return json.dumps(body)


class CompletionGate:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: dict[str, threading.Event] = {}

    def callback(self, completion: object) -> None:
        task_id = getattr(completion, "task_id", "")
        with self._lock:
            event = self._events.get(task_id)
            if event is None:
                event = threading.Event()
                self._events[task_id] = event
            event.set()

    def wait(self, task_id: str, timeout: float = 2) -> bool:
        with self._lock:
            event = self._events.get(task_id)
            if event is None:
                event = threading.Event()
                self._events[task_id] = event
        return event.wait(timeout)


class SimulatedGithubClient:
    """The production client's repository-read surface, with no I/O."""

    def __init__(self) -> None:
        self.fixed_response: str | None = None
        self.fail_submit: BaseException | None = None
        self.results: dict[str, str] = {}
        self.gates: dict[str, asyncio.Event] = {}
        self.entered: dict[str, threading.Event] = {}
        self.ignore_cancel = False
        self.timeout_on_take = False
        self.loop: asyncio.AbstractEventLoop | None = None
        self.thread: threading.Thread | None = None
        self.loop_count = 0
        self.start_count = 0
        self.close_count = 0
        self.calls: list[tuple[str, dict[str, object], object, int, bool]] = []
        self.take_callers: list[int] = []
        self.session_idents: list[int] = []
        self.session_order: list[str] = []
        self.active = 0
        self.max_active = 0
        self.future_ids: list[int] = []
        self.take_future_ids: list[int] = []
        self.remote_still_running = False
        self.reenter_reader: GithubClientRepositoryReader | None = None
        self.reentry_error: BaseException | None = None
        self._did_reenter = False
        self._future: asyncio.Future[str] | None = None
        self._taken = False
        self._abandoned = False
        self._lock = threading.Lock()

    @property
    def session(self) -> object:
        raise AssertionError("session")

    @property
    def _session(self) -> object:
        raise AssertionError("_session")

    def start(self, *_args: object, **_kwargs: object) -> None:
        self.start_count += 1
        raise AssertionError("start")

    def close(self) -> None:
        self.close_count += 1
        raise AssertionError("close")

    def open_loop(self) -> None:
        if self.loop is not None:
            return
        self.loop_count += 1
        loop = asyncio.new_event_loop()
        ready = threading.Event()

        def run() -> None:
            asyncio.set_event_loop(loop)
            loop.call_soon(ready.set)
            loop.run_forever()

        self.loop = loop
        self.thread = threading.Thread(target=run, name="github-mcp-worker", daemon=True)
        self.thread.start()
        if not ready.wait(2):
            raise RuntimeError("simulated loop did not start")

    def add_gate(self, repo: str) -> threading.Event:
        self.open_loop()
        entered = threading.Event()
        self.entered[repo] = entered

        async def make() -> None:
            self.gates[repo] = asyncio.Event()

        assert self.loop is not None
        asyncio.run_coroutine_threadsafe(make(), self.loop).result(2)
        return entered

    def release(self, repo: str) -> None:
        gate = self.gates[repo]
        assert self.loop is not None
        self.loop.call_soon_threadsafe(gate.set)

    def release_all(self) -> None:
        loop = self.loop
        if loop is None:
            return

        def _set() -> None:
            for gate in list(self.gates.values()):
                gate.set()

        try:
            loop.call_soon_threadsafe(_set)
        except RuntimeError:
            return

    def stop_loop(self) -> None:
        loop = self.loop
        thread = self.thread
        if loop is None:
            return

        async def _drain() -> None:
            for gate in list(self.gates.values()):
                gate.set()
            current = asyncio.current_task()
            pending = [task for task in asyncio.all_tasks(loop) if task is not current]
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            loop.stop()

        try:
            asyncio.run_coroutine_threadsafe(_drain(), loop).result(2)
        except Exception:
            try:
                loop.call_soon_threadsafe(loop.stop)
            except RuntimeError:
                pass
        if thread is not None:
            thread.join(2)
        if not loop.is_closed():
            loop.close()
        self.thread = None
        self.loop = None

    def call(
        self,
        name: str,
        arguments: dict[str, object] | None = None,
        token: object = None,
        job_id: object = None,
    ) -> str:
        copied = dict(arguments or {})
        self.calls.append((name, copied, job_id, threading.get_ident(), token is not None))
        if self.reenter_reader is not None and not self._did_reenter:
            self._did_reenter = True
            try:
                self.reenter_reader.read_repository(
                    OWNER,
                    "reentry-repo",
                    cancelled=lambda: False,
                    wait_for_cancel=lambda timeout: False,
                )
            except SessionBusy as exc:
                self.reentry_error = exc
        if self.fail_submit is not None:
            raise self.fail_submit
        if token is not None and getattr(token, "pre_cancelled_at_entry", False):
            raise GithubCallCancelled()
        if self.fixed_response is not None:
            return self.fixed_response
        if self.loop is None:
            raise AssertionError("loop")
        repo = str(copied.get("repo", ""))
        future = asyncio.run_coroutine_threadsafe(self._on_loop(repo), self.loop)
        self.future_ids.append(id(future))
        self._future = future
        self._taken = False
        self._abandoned = False
        try:
            text = future.result(timeout=0)
        except TimeoutError:
            return RETAINED
        self._taken = True
        self._future = None
        return text

    async def _on_loop(self, repo: str) -> str:
        self.session_idents.append(threading.get_ident())
        self.session_order.append(repo)
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        entered = self.entered.get(repo)
        if entered is not None:
            entered.set()
        gate = self.gates.get(repo)
        if gate is not None:
            await gate.wait()
        with self._lock:
            self.active -= 1
        return self.results.get(repo, SUCCESS)

    def take_repository_read(self, cancel_event: threading.Event | None = None) -> str:
        self.take_callers.append(threading.get_ident())
        future = self._future
        if future is None or self._taken or self._abandoned:
            return _envelope(
                "github_read_consumed",
                spoken="That GitHub read was already delivered.",
                write_attempted=False,
            )
        self.take_future_ids.append(id(future))
        if self.timeout_on_take:
            self._abandoned = True
            self.remote_still_running = True
            return _envelope(
                "network_timeout",
                spoken=f"GitHub timed out {SECRET}",
                write_attempted=False,
            )
        while not future.done():
            if cancel_event is not None and cancel_event.is_set() and not self.ignore_cancel:
                self._abandoned = True
                self.remote_still_running = True
                future.cancel()
                raise GithubCallCancelled()
            try:
                text = future.result(timeout=0.01)
            except TimeoutError:
                continue
            except asyncio.CancelledError:
                self._abandoned = True
                self.remote_still_running = True
                return _envelope(
                    "github_unavailable",
                    spoken="GitHub publishing is unavailable.",
                    write_attempted=False,
                )
            self._taken = True
            self._future = None
            return text
        self._taken = True
        self._future = None
        return future.result()


class LocalClock:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def call(self, name: str, arguments: dict | None = None, token: object = None) -> str:
        del arguments, token
        self.calls.append(name)
        return json.dumps({"ok": True, "spoken": "3:45 PM"})


class C7RealClientAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = TaskRegistry()
        self.store = TaskResultStore()
        self.gate = CompletionGate()
        self.worker = BackgroundTaskWorker(self.registry, on_terminal=self.gate.callback)
        self.client = SimulatedGithubClient()
        self.reader = GithubClientRepositoryReader(self.client, self.worker)
        self.adapter = BackgroundGithubAdapter(
            self.registry,
            self.worker,
            self.store,
            self.reader,
        )
        self.turns = 0

    def tearDown(self) -> None:
        self.client.ignore_cancel = False
        self.client.timeout_on_take = False
        self.client.fail_submit = None
        self.client.release_all()
        self.worker.shutdown(timeout=2)
        self.client.stop_loop()

    def turn(self) -> str:
        self.turns += 1
        return f"turn-{self.turns}"

    def submit(self, repo: str, conversation: str = "conv-a"):
        self.adapter.start()
        return self.adapter.submit_repository_read(conversation, self.turn(), OWNER, repo)

    def test_c7_1_supported_client_interface(self) -> None:
        source = ADAPTER_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        modules: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
        banned = ("github_mcp", "socket", "httpx", "urllib", "asyncio", "mcp")
        self.assertFalse(any(name == item or name.startswith(f"{item}.") for name in modules for item in banned))
        self.assertNotIn("CredRead", source)
        reader_source = inspect.getsource(GithubClientRepositoryReader)
        self.assertNotIn("_session", reader_source)
        self.assertNotIn("call_tool", reader_source)
        self.assertNotIn("asyncio", reader_source)
        self.assertNotIn("new_event_loop", reader_source)
        self.assertNotIn("close(", reader_source)
        self.client.fixed_response = SUCCESS
        ack = self.submit("mnist-einops-cnn")
        self.assertTrue(self.gate.wait(ack.task_id))
        self.assertEqual(len(self.client.calls), 1)
        name, arguments, job_id, caller, saw_token = self.client.calls[0]
        self.assertEqual(name, TOOL_NAME)
        self.assertEqual(arguments, {"owner": OWNER, "repo": "mnist-einops-cnn"})
        self.assertIsNone(job_id)
        self.assertTrue(saw_token)
        self.assertEqual(caller, self.worker.status().thread_ident)
        self.assertEqual(self.client.take_callers, [])
        self.assertEqual(self.client.loop_count, 0)
        self.assertEqual(self.client.session_idents, [])
        self.assertEqual(self.client.start_count, 0)
        self.assertEqual(self.client.close_count, 0)
        finished = self.registry.get(ack.task_id)
        self.assertEqual(finished.state, "completed")
        self.assertEqual(finished.conversation_id, "conv-a")
        self.assertFalse(finished.remote_may_still_run)
        self.assertEqual(finished.operations[0].state, "returned")
        stored = self.adapter.get_result("conv-a", ack.task_id, ack.operation_id)
        self.assertEqual(stored.payload, SUCCESS)
        self.assertEqual(stored.task_id, ack.task_id)
        self.assertEqual(stored.conversation_id, "conv-a")
        with self.assertRaises(AdapterNotFound):
            self.adapter.get_result("conv-b", ack.task_id, ack.operation_id)

    def test_c7_2_worker_only_invocation(self) -> None:
        with self.assertRaises(SessionOwnerMismatch):
            self.reader.read_repository(
                OWNER,
                "mnist-einops-cnn",
                cancelled=lambda: False,
                wait_for_cancel=lambda timeout: False,
            )
        self.assertEqual(self.client.calls, [])
        self.adapter.start()
        voice = threading.get_ident()
        worker_ident = self.worker.status().thread_ident
        self.assertIsNotNone(worker_ident)
        self.assertNotEqual(worker_ident, voice)
        with self.assertRaises(SessionOwnerMismatch):
            self.reader.read_repository(
                str(worker_ident),
                "mnist-einops-cnn",
                cancelled=lambda: False,
                wait_for_cancel=lambda timeout: False,
            )
        refused = threading.Event()
        errors: list[BaseException] = []

        def spoof() -> None:
            threading.current_thread().name = THREAD_NAME
            try:
                self.reader.read_repository(
                    OWNER,
                    "mnist-einops-cnn",
                    cancelled=lambda: False,
                    wait_for_cancel=lambda timeout: False,
                )
            except BaseException as exc:  # noqa: BLE001 - the test asserts the type
                errors.append(exc)
            refused.set()

        threading.Thread(target=spoof, name=THREAD_NAME).start()
        self.assertTrue(refused.wait(2))
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], SessionOwnerMismatch)
        self.assertEqual(self.client.calls, [])
        self.client.fixed_response = SUCCESS
        self.client.reenter_reader = self.reader
        ack = self.adapter.submit_repository_read("conv-a", self.turn(), OWNER, "mnist-einops-cnn")
        self.assertTrue(self.gate.wait(ack.task_id))
        self.assertIsInstance(self.client.reentry_error, SessionBusy)
        self.assertEqual(len(self.client.calls), 1)
        self.assertEqual(self.client.calls[0][3], worker_ident)
        self.assertNotEqual(self.client.calls[0][3], voice)
        self.assertEqual(self.registry.get(ack.task_id).state, "completed")

    def test_c7_3_serialization_and_queue(self) -> None:
        repos = ("repo-a", "repo-b", "repo-c")
        entered = {repo: self.client.add_gate(repo) for repo in repos}
        self.client.results = {
            "repo-a": json.dumps({"ok": True, "name": "repo-a"}),
            "repo-b": json.dumps({"ok": True, "name": "repo-b"}),
            "repo-c": json.dumps({"ok": True, "name": "repo-c"}),
        }
        conversations = {"repo-a": "conv-a", "repo-b": "conv-b", "repo-c": "conv-a"}
        self.adapter.start()
        first = self.adapter.submit_repository_read("conv-a", self.turn(), OWNER, "repo-a")
        self.assertTrue(entered["repo-a"].wait(2))
        second = self.adapter.submit_repository_read("conv-b", self.turn(), OWNER, "repo-b")
        third = self.adapter.submit_repository_read("conv-a", self.turn(), OWNER, "repo-c")
        acks = [first, second, third]
        self.assertEqual(self.worker.status().queue_capacity, 2)
        self.assertEqual(self.worker.status().queued_count, 2)
        self.assertEqual(len(self.client.calls), 1)
        self.assertEqual(self.client.max_active, 1)
        with self.assertRaises(QueueFull) as overflow:
            self.adapter.submit_repository_read("conv-a", self.turn(), OWNER, "repo-d")
        rejected = self.registry.get(overflow.exception.task_id)
        self.assertEqual(rejected.state, "failed")
        self.assertEqual(rejected.error_code, "queue_full")
        self.assertEqual(self.worker.status().queued_count, 2)
        self.assertEqual([ack.conversation_id for ack in acks], ["conv-a", "conv-b", "conv-a"])
        self.client.release("repo-a")
        self.assertTrue(entered["repo-b"].wait(2))
        self.assertEqual(self.client.session_order, ["repo-a", "repo-b"])
        self.assertEqual(self.client.max_active, 1)
        self.client.release("repo-b")
        self.assertTrue(entered["repo-c"].wait(2))
        self.client.release("repo-c")
        for ack in acks:
            self.assertTrue(self.gate.wait(ack.task_id), ack.task_id)
        self.assertEqual(self.client.session_order, ["repo-a", "repo-b", "repo-c"])
        self.assertEqual(self.client.max_active, 1)
        self.assertNotIn("repo-d", self.client.session_order)
        self.assertEqual(len(set(self.client.future_ids)), 3)
        for ack, repo in zip(acks, repos):
            stored = self.adapter.get_result(ack.conversation_id, ack.task_id, ack.operation_id)
            self.assertEqual(json.loads(stored.payload)["name"], repo)
            self.assertEqual(stored.conversation_id, conversations[repo])
            other = "conv-b" if ack.conversation_id == "conv-a" else "conv-a"
            with self.assertRaises(AdapterNotFound):
                self.adapter.get_result(other, ack.task_id, ack.operation_id)
        self.assertEqual(self.registry.get(acks[0].task_id).state, "completed")
        self.assertEqual(self.registry.get(acks[1].task_id).conversation_id, "conv-b")

    def test_c7_4_thread_safe_client_submission(self) -> None:
        entered = self.client.add_gate("mnist-einops-cnn")
        self.client.results["mnist-einops-cnn"] = SUCCESS
        ack = self.submit("mnist-einops-cnn")
        self.assertTrue(entered.wait(2))
        self.assertEqual(self.client.session_idents, [self.client.thread.ident])
        self.assertEqual(self.client.calls[0][3], self.worker.status().thread_ident)
        self.assertNotIn(self.worker.status().thread_ident, self.client.session_idents)
        self.assertEqual(self.client.loop_count, 1)
        self.assertEqual(self.client.take_callers, [self.worker.status().thread_ident])
        self.assertEqual(
            len([item for item in threading.enumerate() if item.name == "github-mcp-worker"]),
            1,
        )
        self.client.release("mnist-einops-cnn")
        self.assertTrue(self.gate.wait(ack.task_id))
        self.assertEqual(self.adapter.get_result("conv-a", ack.task_id, ack.operation_id).payload, SUCCESS)
        self.assertFalse(any(item.name == "icy-github-read-cancel" for item in threading.enumerate()))

    def test_c7_5_client_exception_handling(self) -> None:
        cases = {
            "not-found": (
                _envelope("repository_not_found", spoken="That repository was not found."),
                "repository_not_found",
                False,
            ),
            "not-allowed": (
                _envelope("repo_not_allowlisted", spoken="That repository is not allowed."),
                "repo_not_allowlisted",
                False,
            ),
            "tool-error": (
                _envelope(
                    "github_call_failed",
                    spoken="The GitHub request failed.",
                    detail=SECRET,
                    write_attempted=False,
                ),
                "github_call_failed",
                False,
            ),
            "transport": (
                _envelope("network_error", spoken="GitHub could not be reached while reading the repository."),
                "network_error",
                False,
            ),
            "closed": (
                _envelope(
                    "github_unavailable",
                    spoken="GitHub publishing is unavailable.",
                    detail="GitHub MCP is not running",
                ),
                "github_unavailable",
                False,
            ),
            "server-timeout": (
                _envelope("network_timeout", spoken="GitHub timed out while reading the repository."),
                "network_timeout",
                False,
            ),
            "local-timeout": (
                _envelope(
                    "network_timeout",
                    spoken=f"GitHub timed out {SECRET}",
                    write_attempted=False,
                ),
                "abandoned",
                True,
            ),
            "cancelled-future": (
                _envelope(
                    "github_unavailable",
                    spoken="GitHub publishing is unavailable.",
                    write_attempted=False,
                ),
                "abandoned",
                True,
            ),
        }
        for repo, (response, expected, abandoned) in cases.items():
            self.client.fixed_response = response
            self.client.fail_submit = None
            probe = self._read_on_worker()
            self.assertNotIn(SECRET, str(probe))
            if abandoned:
                self.assertIsInstance(probe, LocalWaitAbandoned)
            else:
                self.assertIsInstance(probe, RepositoryReadFailed)
                self.assertEqual(str(probe), expected)
            ack = self.adapter.submit_repository_read("conv-a", self.turn(), OWNER, repo)
            self.assertTrue(self.gate.wait(ack.task_id), repo)
            snapshot = self.registry.get(ack.task_id)
            self.assertNotIn(SECRET, repr(snapshot))
            self.assertNotIn(SECRET, snapshot.error_message or "")
            self.assertEqual(snapshot.state, "failed")
            with self.assertRaises(ResultNotFound):
                self.adapter.get_result("conv-a", ack.task_id, ack.operation_id)
            if abandoned:
                self.assertEqual(snapshot.operations[0].state, "abandoned")
                self.assertTrue(snapshot.remote_may_still_run)
            else:
                self.assertEqual(snapshot.operations[0].state, "returned")
                self.assertFalse(snapshot.remote_may_still_run)
                self.assertEqual(snapshot.error_message, "RepositoryReadFailed")

        self.client.fixed_response = None
        self.client.fail_submit = RuntimeError(SECRET)
        probe = self._read_on_worker()
        self.assertIsInstance(probe, RepositoryReadFailed)
        self.assertEqual(str(probe), "repository read failed")
        self.assertNotIn(SECRET, str(probe))
        submit_ack = self.adapter.submit_repository_read("conv-a", self.turn(), OWNER, "submit-failed")
        self.assertTrue(self.gate.wait(submit_ack.task_id))
        submit_snapshot = self.registry.get(submit_ack.task_id)
        self.assertEqual(submit_snapshot.state, "failed")
        self.assertEqual(submit_snapshot.operations[0].state, "returned")
        self.assertFalse(submit_snapshot.remote_may_still_run)
        self.assertNotIn(SECRET, repr(submit_snapshot))
        self.client.fail_submit = None

        self.client.fixed_response = None
        self.client.fail_submit = GithubCallCancelled(SECRET)
        probe = self._read_on_worker()
        self.assertIsInstance(probe, LocalWaitAbandoned)
        self.assertNotIn(SECRET, str(probe))
        self.client.fail_submit = None

        entered = self.client.add_gate("live-cancel")
        self.client.results["live-cancel"] = SUCCESS
        self.client.results["still-running"] = json.dumps({"ok": True, "name": "still-running"})
        held = self.adapter.submit_repository_read("conv-a", self.turn(), OWNER, "live-cancel")
        self.assertTrue(entered.wait(2))
        other = self.adapter.submit_repository_read("conv-b", self.turn(), OWNER, "still-running")
        self.adapter.cancel("conv-a", held.task_id)
        self.assertTrue(self.gate.wait(held.task_id))
        cancelled = self.registry.get(held.task_id)
        self.assertEqual(cancelled.state, "cancelled")
        self.assertEqual(cancelled.operations[0].state, "abandoned")
        self.assertTrue(cancelled.remote_may_still_run)
        self.assertTrue(self.client.remote_still_running)
        with self.assertRaises(ResultNotFound):
            self.adapter.get_result("conv-a", held.task_id, held.operation_id)
        self.assertTrue(self.gate.wait(other.task_id))
        self.assertEqual(self.registry.get(other.task_id).state, "completed")
        self.assertEqual(self.registry.get(other.task_id).conversation_id, "conv-b")
        stored = self.adapter.get_result("conv-b", other.task_id, other.operation_id)
        self.assertEqual(json.loads(stored.payload)["name"], "still-running")
        self.assertEqual(self.client.close_count, 0)

    def test_c7_6_noncooperative_operation(self) -> None:
        entered = self.client.add_gate("blocked-repo")
        self.client.ignore_cancel = True
        self.client.results["blocked-repo"] = SUCCESS
        ack = self.submit("blocked-repo")
        self.assertTrue(entered.wait(2))
        self.adapter.cancel("conv-a", ack.task_id)
        report = self.worker.shutdown(timeout=0.2)
        self.assertFalse(report.clean)
        self.assertTrue(report.thread_alive)
        self.assertEqual(report.current_task_id, ack.task_id)
        snapshot = self.registry.get(ack.task_id)
        self.assertNotEqual(snapshot.operations[0].state, "returned")
        self.assertTrue(snapshot.remote_may_still_run)
        self.assertNotIn(snapshot.state, {"completed", "failed", "cancelled", "timed_out"})
        with self.assertRaises(ResultNotFound):
            self.adapter.get_result("conv-a", ack.task_id, ack.operation_id)
        closed = self.adapter.close_owned_session(report)
        self.assertFalse(closed.closed)
        self.assertEqual(self.client.close_count, 0)
        self.assertEqual(self.client.start_count, 0)
        self.assertEqual(self.client.active, 1)
        self.assertFalse(hasattr(self.reader, "close_session"))

    def test_c7_7_disabled_and_unavailable_client(self) -> None:
        import hashlib

        payload = CONFIG_PATH.read_bytes()
        self.assertEqual(len(payload), 1247)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), CONFIG_SHA256)
        policy = json.loads(payload.decode("utf-8"))
        self.assertIs(policy["enabled"], False)
        self.assertEqual(policy["allowed_owner"], OWNER)
        self.assertEqual(policy["allowed_repos"], ["mnist-einops-cnn"])
        self.assertIs(policy["allow_writes"], False)
        self.assertIs(policy["allow_repo_creation"], False)
        clock = LocalClock()
        disabled = _envelope("github_mcp_disabled", spoken="GitHub publishing is disabled.")
        starting = _envelope("github_mcp_starting", spoken="GitHub publishing is still starting.")
        for repo, response in (("disabled-repo", disabled), ("starting-repo", starting)):
            self.client.fixed_response = response
            ack = self.submit(repo)
            self.assertTrue(self.gate.wait(ack.task_id))
            snapshot = self.registry.get(ack.task_id)
            self.assertEqual(snapshot.state, "failed")
            self.assertEqual(snapshot.operations[0].state, "returned")
            self.assertFalse(snapshot.remote_may_still_run)
            self.assertEqual(snapshot.error_message, "RepositoryReadFailed")
        self.assertEqual(self.client.start_count, 0)
        self.assertEqual(self.client.close_count, 0)
        self.assertEqual(self.client.loop_count, 0)
        self.assertIsNone(self.client.thread)
        self.assertEqual(clock.call("get_local_time"), json.dumps({"ok": True, "spoken": "3:45 PM"}))
        self.assertEqual(clock.calls, ["get_local_time"])
        self.assertEqual(self.client.start_count, 0)

    def test_c7_8_repeated_calls_and_recovery(self) -> None:
        self.client.fixed_response = _envelope(
            "repository_not_found",
            spoken="That repository was not found.",
        )
        failed = self.submit("first-repo")
        self.assertTrue(self.gate.wait(failed.task_id))
        self.assertEqual(self.registry.get(failed.task_id).state, "failed")
        self.client.fixed_response = None
        entered = self.client.add_gate("second-repo")
        self.client.results["second-repo"] = json.dumps({"ok": True, "name": "second-repo"})
        self.client.results["third-repo"] = json.dumps({"ok": True, "name": "third-repo"})
        second = self.adapter.submit_repository_read("conv-a", self.turn(), OWNER, "second-repo")
        self.assertTrue(entered.wait(2))
        held_calls = len(self.client.calls)
        duplicate = self.adapter.submit_repository_read("conv-a", self.turn(), OWNER, "second-repo")
        self.assertTrue(duplicate.duplicate)
        self.assertEqual(duplicate.task_id, second.task_id)
        self.assertEqual(len(self.client.calls), held_calls)
        self.client.release("second-repo")
        self.assertTrue(self.gate.wait(second.task_id))
        self.assertEqual(
            json.loads(self.adapter.get_result("conv-a", second.task_id, second.operation_id).payload)["name"],
            "second-repo",
        )
        third_entered = self.client.add_gate("third-repo")
        third = self.adapter.submit_repository_read("conv-b", self.turn(), OWNER, "third-repo")
        self.assertTrue(third_entered.wait(2))
        self.assertEqual(len(set(self.client.future_ids)), len(self.client.future_ids))
        self.assertGreaterEqual(len(self.client.future_ids), 2)
        self.assertNotEqual(self.client.future_ids[-1], self.client.future_ids[-2])
        self.client.release("third-repo")
        self.assertTrue(self.gate.wait(third.task_id))
        self.assertEqual(
            json.loads(self.adapter.get_result("conv-b", third.task_id, third.operation_id).payload)["name"],
            "third-repo",
        )
        self.assertEqual(self.client.max_active, 1)

    def _read_on_worker(self) -> BaseException:
        task_id = self.registry.create("conv-probe", self.turn(), task_type="probe")
        box: dict[str, BaseException] = {}

        def executor(context: object) -> None:
            try:
                self.reader.read_repository(
                    OWNER,
                    "probe-repo",
                    cancelled=context.cancelled,  # type: ignore[attr-defined]
                    wait_for_cancel=context.wait_for_cancel,  # type: ignore[attr-defined]
                )
            except Exception as exc:  # noqa: BLE001 - the probe reports the reader exception
                box["error"] = exc

        self.adapter.start()
        self.worker.submit(task_id, "probe", executor)
        self.assertTrue(self.gate.wait(task_id))
        return box["error"]


if __name__ == "__main__":
    unittest.main()
