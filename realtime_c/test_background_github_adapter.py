"""Offline tests for the background repository adapter.

Synchronization uses threading events. A ``wait`` timeout only fails a
test that never reaches the expected signal. The reader is a fake. No
voice, MCP, credential, or network access.
"""

from __future__ import annotations

import ast
import threading
import unittest
from pathlib import Path

from realtime_c.background_github_adapter import (
    TOOL_NAME,
    AdapterNotFound,
    AdapterRejected,
    BackgroundGithubAdapter,
    LocalWaitAbandoned,
    RepositoryReadFailed,
)
from realtime_c.background_worker import (
    THREAD_NAME,
    BackgroundTaskWorker,
    QueueFull,
    WorkerNotRunning,
)
from realtime_c.task_registry import TaskRegistry
from realtime_c.task_result_store import ResultMismatch, ResultNotFound, TaskResultStore


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


class FakeReader:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, int, str]] = []
        self._handlers: dict[str, object] = {}

    def when(self, repo: str, handler: object) -> None:
        self._handlers[repo] = handler

    def read_repository(self, owner: str, repo: str, *, cancelled, wait_for_cancel):
        self.calls.append((owner, repo, threading.get_ident(), threading.current_thread().name))
        handler = self._handlers.get(repo)
        if handler is None:
            return "repository is public"
        return handler(owner, repo, cancelled, wait_for_cancel)


class WatchingStore(TaskResultStore):
    def __init__(self, registry: TaskRegistry) -> None:
        super().__init__()
        self.registry = registry
        self.stored_before_completion = False

    def put(self, conversation_id: str, task_id: str, operation_id: str, payload: str):
        if self.registry.get(task_id).state == "completed":
            raise AssertionError("result stored after completion")
        self.stored_before_completion = True
        return super().put(conversation_id, task_id, operation_id, payload)


class AdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.releases: list[threading.Event] = []
        self.messages: list[str] = []
        self.registry = TaskRegistry()
        self.reader = FakeReader()
        self.store: TaskResultStore = TaskResultStore()
        self.gate = CompletionGate()
        self.worker = BackgroundTaskWorker(
            self.registry,
            on_terminal=self.gate.callback,
        )
        self.adapter = BackgroundGithubAdapter(
            self.registry,
            self.worker,
            self.store,
            self.reader,
        )

    def tearDown(self) -> None:
        for event in self.releases:
            event.set()
        self.worker.shutdown(timeout=2)

    def release_later(self) -> threading.Event:
        event = threading.Event()
        self.releases.append(event)
        return event

    def use_store(self, store: TaskResultStore) -> None:
        self.store = store
        self.adapter = BackgroundGithubAdapter(
            self.registry,
            self.worker,
            self.store,
            self.reader,
        )

    def submit_async(self, **kwargs: str):
        done = threading.Event()
        box: dict[str, object] = {}

        def run() -> None:
            try:
                box["ack"] = self.adapter.submit_repository_read(**kwargs)
            except Exception as exc:  # noqa: BLE001 - the test asserts on it
                box["error"] = exc
            finally:
                done.set()

        threading.Thread(target=run).start()
        return done, box

    def test_01_submit_returns_before_the_read_and_stores_the_result(self) -> None:
        entered = threading.Event()
        release = self.release_later()
        caller = threading.get_ident()

        def block(owner: str, repo: str, cancelled, wait_for_cancel) -> str:
            del owner, repo, cancelled, wait_for_cancel
            entered.set()
            self.assertTrue(release.wait(2), "reader was not released")
            return "repository is public"

        self.reader.when("mnist-einops-cnn", block)
        watching = WatchingStore(self.registry)
        self.use_store(watching)
        self.adapter.start()
        done, box = self.submit_async(
            conversation_id="conv-a",
            origin_turn_id="turn-1",
            owner="ubaldexela-cloud",
            repo="mnist-einops-cnn",
        )
        self.assertTrue(done.wait(2), "submit waited for the repository read")
        self.assertTrue(entered.wait(2), "reader did not start")
        self.assertNotIn("error", box)
        ack = box["ack"]
        self.assertFalse(release.is_set())
        self.assertEqual(ack.conversation_id, "conv-a")
        self.assertFalse(ack.duplicate)
        self.assertEqual(ack.state, "queued")
        self.assertNotIn("repository is public", repr(ack))
        snapshot = self.registry.get(ack.task_id)
        self.assertEqual(snapshot.conversation_id, "conv-a")
        self.assertEqual(snapshot.origin_turn_id, "turn-1")
        self.assertEqual(snapshot.task_type, TOOL_NAME)
        self.assertEqual(len(snapshot.operations), 1)
        operation = snapshot.operations[0]
        self.assertEqual(operation.operation_id, ack.operation_id)
        self.assertEqual(operation.tool_name, TOOL_NAME)
        self.assertEqual(self.reader.calls[0][3], THREAD_NAME)
        self.assertNotEqual(self.reader.calls[0][2], caller)
        release.set()
        self.assertTrue(self.gate.wait(ack.task_id), "task did not finish")
        finished = self.registry.get(ack.task_id)
        self.assertEqual(finished.state, "completed")
        self.assertFalse(finished.remote_may_still_run)
        self.assertEqual(finished.operations[0].state, "returned")
        self.assertTrue(watching.stored_before_completion)
        stored = self.adapter.get_result("conv-a", ack.task_id, ack.operation_id)
        self.assertEqual(stored.payload, "repository is public")
        self.assertEqual(stored.conversation_id, "conv-a")
        with self.assertRaises(ResultMismatch):
            self.store.get("conv-a", ack.task_id, "op-other")
        with self.assertRaises(AdapterNotFound):
            self.adapter.get_result("conv-b", ack.task_id, ack.operation_id)
        with self.assertRaises(ResultNotFound):
            self.store.get("conv-b", ack.task_id, ack.operation_id)
        self.assertEqual(self.messages, [])

    def test_02_duplicate_submission_does_not_read_twice(self) -> None:
        entered = threading.Event()
        release = self.release_later()

        def block(owner: str, repo: str, cancelled, wait_for_cancel) -> str:
            del owner, repo, cancelled, wait_for_cancel
            entered.set()
            self.assertTrue(release.wait(2))
            return "repository is public"

        self.reader.when("mnist-einops-cnn", block)
        self.adapter.start()
        first_done, first_box = self.submit_async(
            conversation_id="conv-a",
            origin_turn_id="turn-1",
            owner="ubaldexela-cloud",
            repo="mnist-einops-cnn",
        )
        self.assertTrue(entered.wait(2))
        self.assertTrue(first_done.wait(2))
        second = self.adapter.submit_repository_read(
            "conv-a",
            "turn-2",
            "ubaldexela-cloud",
            "mnist-einops-cnn",
        )
        other = self.adapter.submit_repository_read(
            "conv-b",
            "turn-1",
            "ubaldexela-cloud",
            "mnist-einops-cnn",
        )
        self.assertEqual(second.task_id, first_box["ack"].task_id)
        self.assertTrue(second.duplicate)
        self.assertEqual(second.operation_id, first_box["ack"].operation_id)
        self.assertNotEqual(other.task_id, second.task_id)
        self.assertFalse(other.duplicate)
        self.assertEqual(
            [call[0:2] for call in self.reader.calls],
            [("ubaldexela-cloud", "mnist-einops-cnn")],
        )
        release.set()
        self.assertTrue(self.gate.wait(second.task_id))
        self.assertTrue(self.gate.wait(other.task_id))
        self.assertEqual(len(self.reader.calls), 2)

    def test_03_queue_full_and_worker_not_running(self) -> None:
        self.worker.shutdown(timeout=2)
        self.worker = BackgroundTaskWorker(
            self.registry,
            queue_capacity=2,
            on_terminal=self.gate.callback,
        )
        self.adapter = BackgroundGithubAdapter(
            self.registry,
            self.worker,
            self.store,
            self.reader,
        )
        with self.assertRaises(WorkerNotRunning) as stopped:
            self.adapter.submit_repository_read(
                "conv-a",
                "turn-1",
                "ubaldexela-cloud",
                "not-running",
            )
        failed = self.registry.get(stopped.exception.task_id)
        self.assertEqual(failed.state, "failed")
        self.assertEqual(failed.error_code, "worker_not_running")
        self.assertNotIn("ghp_", failed.error_message or "")
        self.adapter.start()
        entered = threading.Event()
        release = self.release_later()

        def block(owner: str, repo: str, cancelled, wait_for_cancel) -> str:
            del owner, repo, cancelled, wait_for_cancel
            entered.set()
            self.assertTrue(release.wait(2))
            return "holding"

        self.reader.when("hold-repo", block)
        hold_done, hold_box = self.submit_async(
            conversation_id="conv-a",
            origin_turn_id="turn-2",
            owner="ubaldexela-cloud",
            repo="hold-repo",
        )
        self.assertTrue(entered.wait(2))
        self.assertTrue(hold_done.wait(2))
        first = self.adapter.submit_repository_read("conv-a", "turn-3", "ubaldexela-cloud", "wait-one")
        second = self.adapter.submit_repository_read("conv-a", "turn-4", "ubaldexela-cloud", "wait-two")
        with self.assertRaises(QueueFull) as full:
            self.adapter.submit_repository_read("conv-a", "turn-5", "ubaldexela-cloud", "wait-three")
        rejected = self.registry.get(full.exception.task_id)
        self.assertEqual(rejected.state, "failed")
        self.assertEqual(rejected.error_code, "queue_full")
        self.assertEqual(self.registry.get(first.task_id).state, "queued")
        self.assertEqual(self.registry.get(second.task_id).state, "queued")
        release.set()
        self.assertTrue(self.gate.wait(hold_box["ack"].task_id))
        self.assertTrue(self.gate.wait(first.task_id))
        self.assertTrue(self.gate.wait(second.task_id))
        self.assertEqual(self.registry.get(first.task_id).state, "completed")
        self.assertEqual(self.registry.get(rejected.task_id).state, "failed")

    def test_04_invalid_arguments_create_no_task(self) -> None:
        self.adapter.start()
        secret = "ghp_" + ("A" * 16)
        with self.assertRaises(AdapterRejected) as rejected:
            self.adapter.submit_repository_read("conv-a", "turn-1", "bad owner", "mnist-einops-cnn")
        self.assertNotIn("bad owner", str(rejected.exception))
        with self.assertRaises(AdapterRejected) as secret_error:
            self.adapter.submit_repository_read("conv-a", "turn-1", secret, "mnist-einops-cnn")
        self.assertNotIn(secret, str(secret_error.exception))
        self.assertNotIn("ghp_", str(secret_error.exception))
        with self.assertRaises(AdapterRejected):
            self.adapter.submit_repository_read("", "turn-1", "ubaldexela-cloud", "mnist-einops-cnn")
        self.assertEqual(self.registry.list_tasks(), ())
        self.assertEqual(self.reader.calls, [])

    def test_05_cancel_before_dispatch_skips_the_reader(self) -> None:
        entered = threading.Event()
        release = self.release_later()

        def block(owner: str, repo: str, cancelled, wait_for_cancel) -> str:
            del owner, repo, cancelled, wait_for_cancel
            entered.set()
            self.assertTrue(release.wait(2))
            return "holding"

        self.reader.when("hold-repo", block)
        self.adapter.start()
        hold_done, hold_box = self.submit_async(
            conversation_id="conv-a",
            origin_turn_id="turn-1",
            owner="ubaldexela-cloud",
            repo="hold-repo",
        )
        self.assertTrue(entered.wait(2))
        self.assertTrue(hold_done.wait(2))
        waiting = self.adapter.submit_repository_read(
            "conv-a",
            "turn-2",
            "ubaldexela-cloud",
            "wait-repo",
        )
        cancelled = self.adapter.cancel("conv-a", waiting.task_id)
        self.assertEqual(cancelled.state, "cancelled")
        self.assertFalse(cancelled.remote_may_still_run)
        self.assertFalse(cancelled.operations[0].dispatched)
        self.assertEqual([call[1] for call in self.reader.calls], ["hold-repo"])
        release.set()
        self.assertTrue(self.gate.wait(hold_box["ack"].task_id))

    def test_06_cancel_during_execution_is_isolated(self) -> None:
        entered = threading.Event()
        other_entered = threading.Event()
        other_release = self.release_later()

        def abandon(owner: str, repo: str, cancelled, wait_for_cancel) -> str:
            del owner, repo, cancelled
            entered.set()
            self.assertTrue(wait_for_cancel(2), "cancel was not signalled")
            raise LocalWaitAbandoned("stopped")

        def other(owner: str, repo: str, cancelled, wait_for_cancel) -> str:
            del owner, repo, cancelled, wait_for_cancel
            other_entered.set()
            self.assertTrue(other_release.wait(2))
            return "other repository is public"

        self.reader.when("target-repo", abandon)
        self.reader.when("other-repo", other)
        self.adapter.start()
        target_done, target_box = self.submit_async(
            conversation_id="conv-a",
            origin_turn_id="turn-1",
            owner="ubaldexela-cloud",
            repo="target-repo",
        )
        self.assertTrue(entered.wait(2))
        self.assertTrue(target_done.wait(2))
        other_ack = self.adapter.submit_repository_read(
            "conv-a",
            "turn-2",
            "ubaldexela-cloud",
            "other-repo",
        )
        snapshot = self.adapter.cancel("conv-a", target_box["ack"].task_id)
        self.assertEqual(snapshot.state, "cancel_requested")
        self.assertTrue(self.gate.wait(target_box["ack"].task_id))
        abandoned = self.registry.get(target_box["ack"].task_id)
        self.assertEqual(abandoned.state, "cancelled")
        self.assertEqual(abandoned.operations[0].state, "abandoned")
        self.assertTrue(abandoned.remote_may_still_run)
        with self.assertRaises(ResultNotFound):
            self.store.get("conv-a", abandoned.task_id, abandoned.operations[0].operation_id)
        self.assertTrue(other_entered.wait(2))
        self.assertEqual(self.registry.get(other_ack.task_id).state, "running")
        other_release.set()
        self.assertTrue(self.gate.wait(other_ack.task_id))
        self.assertEqual(self.registry.get(other_ack.task_id).state, "completed")
        self.assertEqual(
            self.adapter.get_result("conv-a", other_ack.task_id, other_ack.operation_id).payload,
            "other repository is public",
        )
        observed = self.adapter.observe_return(
            "conv-a",
            abandoned.task_id,
            abandoned.operations[0].operation_id,
        )
        self.assertEqual(observed.state, "cancelled")
        self.assertFalse(observed.remote_may_still_run)
        self.assertEqual(observed.operations[0].state, "returned")
        with self.assertRaises(ResultNotFound):
            self.store.get("conv-a", abandoned.task_id, abandoned.operations[0].operation_id)
        with self.assertRaises(AdapterNotFound):
            self.adapter.cancel("conv-b", other_ack.task_id)

    def test_07_late_payload_after_cancel_is_not_stored(self) -> None:
        entered = threading.Event()

        def late(owner: str, repo: str, cancelled, wait_for_cancel) -> str:
            del owner, repo, cancelled
            entered.set()
            self.assertTrue(wait_for_cancel(2))
            return "late repository body"

        self.reader.when("late-repo", late)
        self.adapter.start()
        done, box = self.submit_async(
            conversation_id="conv-a",
            origin_turn_id="turn-1",
            owner="ubaldexela-cloud",
            repo="late-repo",
        )
        self.assertTrue(entered.wait(2))
        self.assertTrue(done.wait(2))
        self.adapter.cancel("conv-a", box["ack"].task_id)
        self.assertTrue(self.gate.wait(box["ack"].task_id))
        finished = self.registry.get(box["ack"].task_id)
        self.assertEqual(finished.state, "cancelled")
        self.assertNotEqual(finished.state, "completed")
        self.assertEqual(finished.operations[0].state, "returned")
        self.assertFalse(finished.remote_may_still_run)
        with self.assertRaises(ResultNotFound):
            self.store.get("conv-a", finished.task_id, finished.operations[0].operation_id)
        self.assertNotIn("late repository body", str(finished.error_message))
        self.assertEqual(self.messages, [])

    def test_08_reader_and_store_failures_do_not_complete(self) -> None:
        secret = "ghp_" + ("B" * 16)

        def explode(owner: str, repo: str, cancelled, wait_for_cancel) -> str:
            del owner, repo, cancelled, wait_for_cancel
            raise RuntimeError(secret)

        def leak(owner: str, repo: str, cancelled, wait_for_cancel) -> str:
            del owner, repo, cancelled, wait_for_cancel
            return "prefix " + secret

        self.reader.when("explode-repo", explode)
        self.reader.when("leak-repo", leak)
        self.adapter.start()
        exploded = self.adapter.submit_repository_read(
            "conv-a",
            "turn-1",
            "ubaldexela-cloud",
            "explode-repo",
        )
        self.assertTrue(self.gate.wait(exploded.task_id))
        failed = self.registry.get(exploded.task_id)
        self.assertEqual(failed.state, "failed")
        self.assertEqual(failed.error_code, "executor_failed")
        self.assertEqual(failed.error_message, "RepositoryReadFailed")
        self.assertNotIn(secret, failed.error_message or "")
        self.assertNotIn("ghp_", failed.error_message or "")
        self.assertEqual(failed.operations[0].state, "returned")
        leaked = self.adapter.submit_repository_read(
            "conv-a",
            "turn-2",
            "ubaldexela-cloud",
            "leak-repo",
        )
        self.assertTrue(self.gate.wait(leaked.task_id))
        rejected = self.registry.get(leaked.task_id)
        self.assertEqual(rejected.state, "failed")
        self.assertNotEqual(rejected.state, "completed")
        self.assertEqual(rejected.error_message, "ResultStoreFailed")
        self.assertNotIn(secret, rejected.error_message or "")
        self.assertNotIn("ghp_", rejected.error_message or "")
        self.assertEqual(self.store.status().count, 0)
        self.assertEqual(self.messages, [])

    def test_09_shutdown_reports_queued_and_noncooperative_work_truthfully(self) -> None:
        entered = threading.Event()
        release = self.release_later()

        def cooperative(owner: str, repo: str, cancelled, wait_for_cancel) -> str:
            del owner, repo, cancelled
            entered.set()
            self.assertTrue(wait_for_cancel(2))
            raise LocalWaitAbandoned("stopped")

        self.reader.when("hold-repo", cooperative)
        self.adapter.start()
        hold_done, hold_box = self.submit_async(
            conversation_id="conv-a",
            origin_turn_id="turn-1",
            owner="ubaldexela-cloud",
            repo="hold-repo",
        )
        self.assertTrue(entered.wait(2))
        self.assertTrue(hold_done.wait(2))
        queued = self.adapter.submit_repository_read(
            "conv-a",
            "turn-2",
            "ubaldexela-cloud",
            "queued-repo",
        )
        report = self.adapter.shutdown(timeout=2)
        self.assertTrue(report.clean)
        self.assertFalse(report.thread_alive)
        self.assertIn(queued.task_id, report.cancelled_waiting_ids)
        queued_snapshot = self.registry.get(queued.task_id)
        self.assertEqual(queued_snapshot.state, "cancelled")
        self.assertFalse(queued_snapshot.operations[0].dispatched)
        self.assertFalse(queued_snapshot.remote_may_still_run)
        held = self.registry.get(hold_box["ack"].task_id)
        self.assertEqual(held.state, "cancelled")
        self.assertEqual(held.operations[0].state, "abandoned")
        self.assertTrue(held.remote_may_still_run)
        self.assertEqual([call[1] for call in self.reader.calls], ["hold-repo"])

        self.worker = BackgroundTaskWorker(self.registry, on_terminal=self.gate.callback)
        self.adapter = BackgroundGithubAdapter(
            self.registry,
            self.worker,
            self.store,
            self.reader,
        )
        stuck = threading.Event()

        def stubborn(owner: str, repo: str, cancelled, wait_for_cancel) -> str:
            del owner, repo, cancelled, wait_for_cancel
            stuck.set()
            self.assertTrue(release.wait(2))
            return "late repository body"

        self.reader.when("stuck-repo", stubborn)
        self.adapter.start()
        stuck_done, stuck_box = self.submit_async(
            conversation_id="conv-a",
            origin_turn_id="turn-3",
            owner="ubaldexela-cloud",
            repo="stuck-repo",
        )
        self.assertTrue(stuck.wait(2))
        self.assertTrue(stuck_done.wait(2))
        incomplete = self.adapter.shutdown(timeout=0.2)
        self.assertFalse(incomplete.clean)
        self.assertTrue(incomplete.thread_alive)
        self.assertEqual(incomplete.current_task_id, stuck_box["ack"].task_id)
        during = self.registry.get(stuck_box["ack"].task_id)
        self.assertEqual(during.state, "cancel_requested")
        self.assertNotEqual(during.state, "cancelled")
        self.assertTrue(during.remote_may_still_run)
        release.set()
        finished = self.adapter.shutdown(timeout=2)
        self.assertTrue(finished.clean)
        self.assertFalse(finished.thread_alive)
        after = self.registry.get(stuck_box["ack"].task_id)
        self.assertEqual(after.state, "cancelled")
        with self.assertRaises(ResultNotFound):
            self.store.get("conv-a", after.task_id, after.operations[0].operation_id)

    def test_10_module_does_not_touch_github_or_the_voice_path(self) -> None:
        source = Path(
            __import__(
                "realtime_c.background_github_adapter",
                fromlist=["background_github_adapter"],
            ).__file__
        ).read_text(encoding="utf-8")
        modules: list[str] = []
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
        allowed = {
            "__future__",
            "re",
            "threading",
            "collections.abc",
            "dataclasses",
            "realtime_c.background_worker",
            "realtime_c.task_registry",
            "realtime_c.task_result_store",
        }
        self.assertLessEqual(set(modules), allowed)
        names = {item.name for item in threading.enumerate()}
        self.assertNotIn("github-mcp-worker", names)
        self.assertNotIn("realtime-mcp-tools", names)
        self.assertNotIn(THREAD_NAME, names)
        self.assertFalse(any(isinstance(item, RepositoryReadFailed) for item in self.messages))


if __name__ == "__main__":
    unittest.main()
