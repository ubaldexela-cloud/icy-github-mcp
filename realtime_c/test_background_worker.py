"""Offline tests for the single background worker.

Synchronization uses threading events. Timeouts on ``wait`` only fail a
test that never reaches the expected signal. No voice, MCP, or network.
"""

from __future__ import annotations

import ast
import io
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from realtime_c.background_worker import (
    THREAD_NAME,
    BackgroundTaskWorker,
    Completion,
    QueueFull,
    WorkerNotRunning,
    WorkerStopped,
)
from realtime_c.task_registry import (
    InvalidTransition,
    TaskNotFound,
    TaskRegistry,
    TaskState,
)


class _Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)


class BackgroundWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = _Clock()
        self.registry = TaskRegistry(clock=self.clock)
        self.worker: BackgroundTaskWorker | None = None
        self.releases: list[threading.Event] = []

    def tearDown(self) -> None:
        for event in self.releases:
            event.set()
        if self.worker is not None:
            self.worker.shutdown(timeout=2)

    def make_worker(self, **kwargs: object) -> BackgroundTaskWorker:
        self.worker = BackgroundTaskWorker(self.registry, clock=self.clock, **kwargs)
        return self.worker

    def task(self, name: str = "conv") -> str:
        return self.registry.create(name, "turn")

    def wait(self, event: threading.Event, message: str) -> None:
        self.assertTrue(event.wait(2), message)

    def release_later(self) -> threading.Event:
        event = threading.Event()
        self.releases.append(event)
        return event

    def test_01_explicit_startup(self) -> None:
        source = Path(
            __import__("realtime_c.background_worker", fromlist=["background_worker"]).__file__
        ).read_text(encoding="utf-8")
        modules: list[str] = []
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
        allowed = {
            "__future__",
            "threading",
            "collections",
            "collections.abc",
            "dataclasses",
            "datetime",
            "types",
            "realtime_c.task_registry",
        }
        self.assertLessEqual(set(modules), allowed)
        self.assertEqual(
            [item.name for item in threading.enumerate() if item.name == THREAD_NAME],
            [],
        )
        worker = self.make_worker()
        self.assertTrue(worker.status().stopped)
        self.assertFalse(worker.status().running)
        self.assertIsNone(worker.status().thread_ident)
        worker.start()
        first = worker.status().thread_ident
        worker.start()
        named = [item for item in threading.enumerate() if item.name == THREAD_NAME]
        self.assertEqual(len(named), 1)
        self.assertFalse(named[0].daemon)
        self.assertEqual(worker.status().thread_ident, first)
        self.assertTrue(worker.status().running)
        self.assertFalse(worker.status().stopped)
        self.assertEqual(worker.status().queue_capacity, 2)

    def test_02_execution_is_off_the_caller_thread(self) -> None:
        worker = self.make_worker()
        worker.start()
        caller = threading.get_ident()
        seen: dict[str, object] = {}
        entered = threading.Event()

        def executor(context: object) -> None:
            seen["ident"] = threading.get_ident()
            seen["name"] = threading.current_thread().name
            entered.set()

        task_id = self.task()
        worker.submit(task_id, "probe", executor)
        self.wait(entered, "executor did not start")
        self.assertNotEqual(seen["ident"], caller)
        self.assertEqual(seen["name"], THREAD_NAME)
        self.assertEqual(seen["ident"], worker.status().thread_ident)

    def test_03_submission_returns_while_executor_is_blocked(self) -> None:
        worker = self.make_worker()
        worker.start()
        entered = threading.Event()
        release = self.release_later()

        def executor(context: object) -> None:
            entered.set()
            release.wait()

        task_id = self.task()
        result = worker.submit(task_id, "blocked", executor)
        self.assertEqual(result.task_id, task_id)
        self.assertEqual(result.state, TaskState.QUEUED.value)
        self.wait(entered, "executor did not reach its block")
        self.assertFalse(release.is_set())
        self.assertEqual(worker.status().current_task_id, task_id)
        self.assertEqual(self.registry.get(task_id).state, TaskState.RUNNING)
        release.set()

    def test_04_registry_lifecycle(self) -> None:
        finished = threading.Event()
        worker = self.make_worker(on_terminal=lambda _item: finished.set())
        worker.start()
        entered = threading.Event()
        release = self.release_later()
        seen: list[str] = []

        def executor(context: object) -> str:
            seen.append(self.registry.get(context.task_id).state)
            self.assertEqual(context.arguments["marker"], "safe")
            entered.set()
            release.wait()
            return "raw-result-is-not-stored"

        task_id = self.task()
        self.assertEqual(self.registry.get(task_id).state, TaskState.QUEUED)
        worker.submit(task_id, "read_note", executor, arguments={"marker": "safe"})
        self.wait(entered, "task did not enter running")
        running = self.registry.get(task_id)
        self.assertEqual(running.state, TaskState.RUNNING)
        self.assertEqual(seen, [TaskState.RUNNING.value])
        self.assertEqual(running.task_id, task_id)
        self.assertEqual(running.result_metadata, ())
        self.assertTrue(running.operations[0].dispatched)
        self.assertFalse(running.operations[0].interruptible)
        release.set()
        self.wait(finished, "task did not finish")
        completed = self.registry.get(task_id)
        self.assertEqual(completed.state, TaskState.COMPLETED)
        self.assertIsNone(completed.error_code)
        self.assertEqual(completed.result_metadata, ())
        published = worker.completion(task_id)
        self.assertIsNotNone(published)
        assert published is not None
        self.assertEqual(published.state, TaskState.COMPLETED.value)
        self.assertNotIn("result", Completion.__dataclass_fields__)

    def test_05_sequential_fifo_execution(self) -> None:
        worker = self.make_worker()
        worker.start()
        order: list[str] = []
        first_in = threading.Event()
        second_in = threading.Event()
        third_in = threading.Event()
        release_first = self.release_later()
        release_second = self.release_later()
        release_third = self.release_later()

        def make(name: str, entered: threading.Event, release: threading.Event):
            def executor(context: object) -> None:
                order.append(name)
                entered.set()
                release.wait()

            return executor

        first = self.task("a")
        second = self.task("b")
        third = self.task("c")
        worker.submit(first, "op", make("a", first_in, release_first))
        self.wait(first_in, "first task did not start")
        worker.submit(second, "op", make("b", second_in, release_second))
        worker.submit(third, "op", make("c", third_in, release_third))
        self.assertFalse(second_in.is_set())
        self.assertEqual(worker.status().current_task_id, first)
        self.assertEqual(worker.status().queued_count, 2)
        self.assertEqual(self.registry.get(second).state, TaskState.QUEUED)
        release_first.set()
        self.wait(second_in, "second task did not start")
        self.assertFalse(third_in.is_set())
        self.assertEqual(order, ["a", "b"])
        self.assertEqual(worker.status().current_task_id, second)
        self.assertEqual(worker.status().queued_count, 1)
        release_second.set()
        self.wait(third_in, "third task did not start")
        self.assertEqual(order, ["a", "b", "c"])
        self.assertEqual(worker.status().current_task_id, third)
        release_third.set()

    def test_06_bounded_queue_rejects_without_discarding(self) -> None:
        finished: list[str] = []
        done = threading.Event()

        def on_terminal(item: Completion) -> None:
            if item.state == TaskState.COMPLETED.value:
                finished.append(item.task_id)
                if len(finished) == 3:
                    done.set()

        worker = self.make_worker(on_terminal=on_terminal)
        worker.start()
        ran: list[str] = []
        entered = threading.Event()
        release = self.release_later()

        def make(name: str, block: bool = False):
            def executor(context: object) -> None:
                ran.append(name)
                if block:
                    entered.set()
                    release.wait()

            return executor

        first = self.task("1")
        second = self.task("2")
        third = self.task("3")
        fourth = self.task("4")
        worker.submit(first, "op", make("1", block=True))
        self.wait(entered, "running task did not start")
        worker.submit(second, "op", make("2"))
        worker.submit(third, "op", make("3"))
        with self.assertRaises(QueueFull) as raised:
            worker.submit(fourth, "op", make("4"))
        self.assertEqual(raised.exception.task_id, fourth)
        self.assertEqual(self.registry.get(fourth).state, TaskState.FAILED)
        self.assertEqual(self.registry.get(fourth).error_code, "queue_full")
        self.assertEqual(self.registry.get(first).state, TaskState.RUNNING)
        self.assertEqual(self.registry.get(second).state, TaskState.QUEUED)
        self.assertEqual(self.registry.get(third).state, TaskState.QUEUED)
        self.assertEqual(worker.status().current_task_id, first)
        self.assertEqual(worker.status().queued_count, 2)
        self.assertEqual(ran, ["1"])
        release.set()
        self.wait(done, "queued tasks did not finish")
        self.assertEqual(ran, ["1", "2", "3"])
        self.assertEqual(self.registry.get(fourth).state, TaskState.FAILED)
        self.assertEqual(self.registry.get(first).task_id, first)
        self.assertEqual(self.registry.get(second).task_id, second)

    def test_07_cancel_waiting_task_before_execution(self) -> None:
        terminal: set[str] = set()
        expected: set[str] = set()
        ready = threading.Event()

        def on_terminal(item: Completion) -> None:
            terminal.add(item.task_id)
            if expected and expected <= terminal:
                ready.set()

        worker = self.make_worker(on_terminal=on_terminal)
        worker.start()
        entered = threading.Event()
        release = self.release_later()
        ran: list[str] = []

        def blocker(context: object) -> None:
            ran.append("blocker")
            entered.set()
            release.wait()

        def victim(context: object) -> None:
            ran.append("victim")

        def other(context: object) -> None:
            ran.append("other")

        holding = self.task("hold")
        cancelled = self.task("cancel")
        kept = self.task("keep")
        worker.submit(holding, "op", blocker)
        self.wait(entered, "blocker did not start")
        worker.submit(cancelled, "op", victim)
        worker.submit(kept, "op", other)
        snapshot = worker.cancel(cancelled)
        self.assertEqual(snapshot.state, TaskState.CANCELLED)
        self.assertNotIn("victim", ran)
        expected.update({holding, kept})
        release.set()
        self.wait(ready, "unrelated task did not finish")
        self.assertEqual(ran, ["blocker", "other"])
        self.assertEqual(self.registry.get(cancelled).state, TaskState.CANCELLED)
        self.assertEqual(self.registry.get(kept).state, TaskState.COMPLETED)
        self.assertEqual(self.registry.get(holding).state, TaskState.COMPLETED)

    def test_08_cooperative_running_cancel(self) -> None:
        finished = threading.Event()
        worker = self.make_worker(on_terminal=lambda item: finished.set())
        worker.start()
        entered = threading.Event()

        def executor(context: object) -> str:
            entered.set()
            context.wait_for_cancel()
            return "ignored-result"

        task_id = self.task()
        worker.submit(task_id, "op", executor)
        self.wait(entered, "task did not start")
        requested = worker.cancel(task_id)
        self.assertEqual(requested.state, TaskState.CANCEL_REQUESTED)
        self.wait(finished, "cancel did not finish")
        self.assertEqual(self.registry.get(task_id).state, TaskState.CANCELLED)
        published = worker.completion(task_id)
        self.assertIsNotNone(published)
        assert published is not None
        self.assertEqual(published.state, TaskState.CANCELLED.value)

    def test_09_cancel_is_isolated_to_one_task(self) -> None:
        watch: dict[str, str | None] = {"id": None}
        other_done = threading.Event()

        def on_terminal(item: Completion) -> None:
            if item.task_id == watch["id"]:
                other_done.set()

        worker = self.make_worker(on_terminal=on_terminal)
        worker.start()
        entered = threading.Event()
        other_entered = threading.Event()
        release = self.release_later()

        def first(context: object) -> str:
            entered.set()
            context.wait_for_cancel()
            return "late"

        def second(context: object) -> None:
            self.assertFalse(context.cancelled())
            other_entered.set()
            release.wait()

        task_a = self.task("a")
        task_b = self.task("b")
        watch["id"] = task_b
        worker.submit(task_a, "op", first)
        self.wait(entered, "task A did not start")
        worker.submit(task_b, "op", second)
        self.assertEqual(self.registry.get(task_b).state, TaskState.QUEUED)
        worker.cancel(task_a)
        self.wait(other_entered, "task B did not start")
        self.assertEqual(self.registry.get(task_a).state, TaskState.CANCELLED)
        self.assertEqual(self.registry.get(task_b).state, TaskState.RUNNING)
        self.assertFalse(worker.completion(task_b) and worker.completion(task_b).state == TaskState.CANCELLED.value)
        release.set()
        self.wait(other_done, "task B did not complete")
        self.assertEqual(self.registry.get(task_b).state, TaskState.COMPLETED)
        self.assertEqual(self.registry.get(task_a).state, TaskState.CANCELLED)

    def test_10_late_result_after_cancel_is_not_success(self) -> None:
        published: list[str] = []
        finished = threading.Event()

        def on_terminal(item: Completion) -> None:
            if item.state == TaskState.COMPLETED.value:
                published.append(item.task_id)
            finished.set()

        worker = self.make_worker(on_terminal=on_terminal)
        worker.start()
        entered = threading.Event()
        sentinel = {"raw": "not-a-completion"}

        def executor(context: object) -> dict[str, str]:
            entered.set()
            context.wait_for_cancel()
            return sentinel

        task_id = self.task()
        worker.submit(task_id, "op", executor)
        self.wait(entered, "task did not start")
        worker.cancel(task_id)
        self.wait(finished, "terminal callback did not run")
        self.assertEqual(published, [])
        self.assertEqual(self.registry.get(task_id).state, TaskState.CANCELLED)
        record = worker.completion(task_id)
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.state, TaskState.CANCELLED.value)
        self.assertFalse(hasattr(record, "result"))

    def test_11_executor_exception_does_not_stop_the_worker(self) -> None:
        hooks: dict[str, threading.Event] = {}

        def on_terminal(item: Completion) -> None:
            event = hooks.get(item.task_id)
            if event is not None:
                event.set()

        worker = self.make_worker(on_terminal=on_terminal)
        worker.start()
        failed_done = threading.Event()
        later_done = threading.Event()

        def broken(context: object) -> None:
            raise RuntimeError("ghp_should_not_appear")

        def later(context: object) -> None:
            return None

        bad = self.task("bad")
        good = self.task("good")
        hooks[bad] = failed_done
        hooks[good] = later_done
        worker.submit(bad, "op", broken)
        worker.submit(good, "op", later)
        self.wait(failed_done, "failing task did not finish")
        self.wait(later_done, "later task did not run")
        failed = self.registry.get(bad)
        self.assertEqual(failed.state, TaskState.FAILED)
        self.assertEqual(failed.error_code, "executor_failed")
        self.assertEqual(failed.error_message, "RuntimeError")
        self.assertNotIn("ghp_", failed.error_message or "")
        self.assertEqual(self.registry.get(good).state, TaskState.COMPLETED)
        self.assertTrue(worker.status().running)
        self.assertFalse(worker.status().stopped)

    def test_12_timeout_is_distinct_from_a_blocked_thread(self) -> None:
        finished = threading.Event()
        worker = self.make_worker(on_terminal=lambda _item: finished.set())
        worker.start()
        entered = threading.Event()
        advanced = self.release_later()
        box: dict[str, bool] = {}

        def cooperative(context: object) -> str:
            entered.set()
            advanced.wait()
            box["exceeded"] = context.deadline_exceeded()
            return "late"

        cooperative_id = self.task("deadline")
        worker.submit(cooperative_id, "op", cooperative, timeout=5)
        self.wait(entered, "cooperative executor did not start")
        self.assertEqual(self.registry.get(cooperative_id).state, TaskState.RUNNING)
        self.clock.advance(5)
        advanced.set()
        self.wait(finished, "deadline task did not finish")
        self.assertTrue(box["exceeded"])
        timed = self.registry.get(cooperative_id)
        self.assertEqual(timed.state, TaskState.TIMED_OUT)
        self.assertEqual(timed.error_code, "execution_timeout")
        finished.clear()

        blocked_entered = threading.Event()
        release = self.release_later()

        def blocked(context: object) -> str:
            blocked_entered.set()
            release.wait()
            return "still-running"

        blocked_id = self.task("blocked")
        worker.submit(blocked_id, "op", blocked, timeout=5)
        self.wait(blocked_entered, "blocked executor did not start")
        self.clock.advance(5)
        self.assertEqual(self.registry.get(blocked_id).state, TaskState.RUNNING)
        status = worker.status()
        self.assertTrue(status.running)
        self.assertFalse(status.stopped)
        self.assertEqual(status.current_task_id, blocked_id)
        named = [item for item in threading.enumerate() if item.name == THREAD_NAME]
        self.assertEqual(len(named), 1)
        self.assertTrue(named[0].is_alive())
        self.assertFalse(finished.is_set())
        release.set()
        self.wait(finished, "returned blocked task did not time out")
        self.assertEqual(self.registry.get(blocked_id).state, TaskState.TIMED_OUT)

    def test_13_callback_failure_keeps_the_worker_usable(self) -> None:
        first_done = threading.Event()
        second_done = threading.Event()

        def on_terminal(item: Completion) -> None:
            try:
                if item.task_id == first:
                    raise RuntimeError("callback failed")
            finally:
                if item.task_id == first:
                    first_done.set()
                else:
                    second_done.set()

        worker = self.make_worker(on_terminal=on_terminal)
        worker.start()
        first = self.task("first")
        second = self.task("second")

        def ok(context: object) -> None:
            return None

        worker.submit(first, "op", ok)
        self.wait(first_done, "first callback did not finish")
        self.assertEqual(self.registry.get(first).state, TaskState.COMPLETED)
        worker.submit(second, "op", ok)
        self.wait(second_done, "worker did not accept the next task")
        self.assertEqual(self.registry.get(second).state, TaskState.COMPLETED)
        self.assertTrue(worker.status().running)

    def test_14_shutdown_with_empty_queue(self) -> None:
        worker = self.make_worker()
        worker.start()
        self.assertTrue(worker.status().accepting)
        report = worker.shutdown(timeout=2)
        self.assertTrue(report.clean)
        self.assertFalse(report.thread_alive)
        self.assertIsNone(report.current_task_id)
        self.assertEqual(report.cancelled_waiting_ids, ())
        status = worker.status()
        self.assertTrue(status.stopped)
        self.assertFalse(status.running)
        self.assertFalse(status.incomplete_shutdown)
        again = worker.shutdown(timeout=2)
        self.assertTrue(again.clean)
        with self.assertRaises(WorkerStopped):
            worker.start()

    def test_15_shutdown_cancels_tasks_that_have_not_started(self) -> None:
        worker = self.make_worker()
        worker.start()
        entered = threading.Event()
        ran: list[str] = []

        def running(context: object) -> None:
            entered.set()
            context.wait_for_cancel()

        def waiting(name: str):
            def executor(context: object) -> None:
                ran.append(name)

            return executor

        current = self.task("current")
        left = self.task("left")
        right = self.task("right")
        worker.submit(current, "op", running)
        self.wait(entered, "running task did not start")
        worker.submit(left, "op", waiting("left"))
        worker.submit(right, "op", waiting("right"))
        report = worker.shutdown(timeout=2)
        self.assertTrue(report.clean)
        self.assertFalse(report.thread_alive)
        self.assertEqual(set(report.cancelled_waiting_ids), {left, right})
        self.assertEqual(ran, [])
        self.assertEqual(self.registry.get(current).state, TaskState.CANCELLED)
        self.assertEqual(self.registry.get(left).state, TaskState.CANCELLED)
        self.assertEqual(self.registry.get(right).state, TaskState.CANCELLED)

    def test_16_shutdown_signals_a_cooperative_task(self) -> None:
        worker = self.make_worker()
        worker.start()
        entered = threading.Event()

        def executor(context: object) -> None:
            entered.set()
            context.wait_for_cancel()

        task_id = self.task()
        worker.submit(task_id, "op", executor)
        self.wait(entered, "task did not start")
        started = time.perf_counter()
        report = worker.shutdown(timeout=2)
        elapsed = time.perf_counter() - started
        self.assertTrue(report.clean)
        self.assertFalse(report.thread_alive)
        self.assertLess(elapsed, 2)
        self.assertEqual(self.registry.get(task_id).state, TaskState.CANCELLED)
        self.assertTrue(worker.status().stopped)

    def test_17_shutdown_reports_a_blocked_task_as_incomplete(self) -> None:
        worker = self.make_worker()
        worker.start()
        entered = threading.Event()
        release = self.release_later()

        def executor(context: object) -> None:
            entered.set()
            release.wait()

        blocked = self.task("blocked")
        worker.submit(blocked, "op", executor)
        self.wait(entered, "blocked task did not start")
        report = worker.shutdown(timeout=0.3)
        self.assertFalse(report.clean)
        self.assertTrue(report.thread_alive)
        self.assertEqual(report.current_task_id, blocked)
        status = worker.status()
        self.assertTrue(status.running)
        self.assertFalse(status.stopped)
        self.assertTrue(status.incomplete_shutdown)
        self.assertFalse(status.accepting)
        self.assertEqual(self.registry.get(blocked).state, TaskState.CANCEL_REQUESTED)
        rejected = self.task("rejected")
        with self.assertRaises(WorkerNotRunning) as raised:
            worker.submit(rejected, "op", executor)
        self.assertEqual(raised.exception.task_id, rejected)
        self.assertEqual(self.registry.get(rejected).state, TaskState.FAILED)
        self.assertEqual(self.registry.get(rejected).error_code, "worker_not_running")
        self.assertEqual(self.registry.get(blocked).state, TaskState.CANCEL_REQUESTED)
        release.set()
        follow = worker.shutdown(timeout=2)
        self.assertTrue(follow.clean)
        self.assertEqual(self.registry.get(blocked).state, TaskState.CANCELLED)

    def test_18_concurrent_submit_and_cancel(self) -> None:
        finished: dict[str, threading.Event] = {}
        finished_lock = threading.Lock()

        def on_terminal(item: Completion) -> None:
            with finished_lock:
                event = finished.get(item.task_id)
            if event is not None:
                event.set()

        worker = self.make_worker(on_terminal=on_terminal)
        worker.start()
        calls: list[str] = []
        call_lock = threading.Lock()

        def remember(context: object) -> str:
            with call_lock:
                calls.append(context.task_id)
            context.wait_for_cancel(0)
            return "value"

        for _trial in range(30):
            entered = threading.Event()
            release = self.release_later()

            def blocker(context: object, entered: threading.Event = entered, release: threading.Event = release) -> None:
                entered.set()
                release.wait()

            holder = self.task("holder")
            victim = self.task("victim")
            with finished_lock:
                finished[holder] = threading.Event()
                finished[victim] = threading.Event()
            worker.submit(holder, "hold", blocker)
            self.wait(entered, "holder did not start")
            worker.submit(victim, "victim", remember)
            gate = threading.Barrier(2)

            def release_holder() -> None:
                gate.wait()
                release.set()

            def cancel_victim() -> None:
                gate.wait()
                try:
                    worker.cancel(victim)
                except InvalidTransition:
                    return

            left = threading.Thread(target=release_holder)
            right = threading.Thread(target=cancel_victim)
            left.start()
            right.start()
            left.join(2)
            right.join(2)
            self.assertFalse(left.is_alive())
            self.assertFalse(right.is_alive())
            self.wait(finished[victim], "victim did not reach a terminal state")
            self.wait(finished[holder], "holder did not finish")
            self.assertEqual(self.registry.get(holder).state, TaskState.COMPLETED)
            self.assertLessEqual(calls.count(victim), 1)
            self.assertIn(
                self.registry.get(victim).state,
                {TaskState.CANCELLED, TaskState.COMPLETED},
            )
            if calls.count(victim) == 0:
                self.assertEqual(self.registry.get(victim).state, TaskState.CANCELLED)

        follow_done = threading.Event()
        follow = self.task("follow")
        with finished_lock:
            finished[follow] = follow_done

        def marker(context: object) -> None:
            return None

        worker.submit(follow, "op", marker)
        self.wait(follow_done, "worker did not survive the race")
        self.assertEqual(self.registry.get(follow).state, TaskState.COMPLETED)
        self.assertTrue(worker.status().running)

    def test_19_terminal_retention_still_comes_from_the_registry(self) -> None:
        self.registry = TaskRegistry(max_terminal=8, clock=self.clock)
        events: dict[str, threading.Event] = {}

        def on_terminal(item: Completion) -> None:
            event = events.get(item.task_id)
            if event is not None:
                event.set()

        worker = self.make_worker(on_terminal=on_terminal)
        worker.start()
        held = self.registry.create("held", "turn")
        completed: list[str] = []
        for index in range(9):
            task_id = self.registry.create(f"conv-{index}", "turn")
            finished = threading.Event()
            events[task_id] = finished
            completed.append(task_id)
            worker.submit(task_id, "op", lambda context: None)
            self.wait(finished, f"task {index} did not finish")
        with self.assertRaises(TaskNotFound):
            self.registry.get(completed[0])
        for task_id in completed[1:]:
            self.assertEqual(self.registry.get(task_id).state, TaskState.COMPLETED)
        self.assertEqual(self.registry.get(held).state, TaskState.QUEUED)
        self.assertNotIn(held, completed)

    def test_20_phase_a_registry_suite_still_passes(self) -> None:
        suite = unittest.defaultTestLoader.loadTestsFromName(
            "realtime_c.test_task_registry"
        )
        result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
        self.assertEqual(result.failures, [])
        self.assertEqual(result.errors, [])
        self.assertTrue(result.wasSuccessful())
        self.assertGreater(result.testsRun, 0)


if __name__ == "__main__":
    unittest.main()
