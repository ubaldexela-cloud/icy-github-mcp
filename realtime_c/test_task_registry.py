"""Offline tests for the in-memory task registry. No voice, MCP, or network."""

from __future__ import annotations

import threading
import unittest
from datetime import datetime, timedelta, timezone

from realtime_c.task_registry import (
    CapacityError,
    DuplicateOperation,
    InvalidTransition,
    OperationSnapshot,
    RegistryValueError,
    TaskNotFound,
    TaskRegistry,
    TaskSnapshot,
    TaskState,
)


class _Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)


class IdentityTests(unittest.TestCase):
    def test_unique_task_ids(self) -> None:
        registry = TaskRegistry()
        ids = [registry.create(f"conv-{index}", f"turn-{index}") for index in range(12)]
        self.assertEqual(len(set(ids)), 12)
        for task_id in ids:
            self.assertEqual(registry.get(task_id).task_id, task_id)

    def test_conversation_turn_and_task_ids_stay_distinct(self) -> None:
        registry = TaskRegistry()
        first = registry.create("conversation-a", "turn-a", task_type="read")
        second = registry.create("conversation-b", "turn-b", task_type="read")
        left = registry.get(first)
        right = registry.get(second)
        self.assertNotEqual(left.task_id, left.conversation_id)
        self.assertNotEqual(left.task_id, left.origin_turn_id)
        self.assertNotEqual(left.conversation_id, right.conversation_id)
        self.assertNotEqual(left.origin_turn_id, right.origin_turn_id)
        registry.transition(first, TaskState.RUNNING)
        again = registry.get(first)
        self.assertEqual(again.task_id, left.task_id)
        self.assertEqual(again.conversation_id, "conversation-a")
        self.assertEqual(again.origin_turn_id, "turn-a")
        self.assertEqual(again.task_type, "read")


class TransitionTests(unittest.TestCase):
    def test_every_documented_transition(self) -> None:
        cases = (
            (TaskState.QUEUED, TaskState.RUNNING),
            (TaskState.QUEUED, TaskState.CANCEL_REQUESTED),
            (TaskState.QUEUED, TaskState.CANCELLED),
            (TaskState.QUEUED, TaskState.FAILED),
            (TaskState.RUNNING, TaskState.CANCEL_REQUESTED),
            (TaskState.RUNNING, TaskState.COMPLETED),
            (TaskState.RUNNING, TaskState.FAILED),
            (TaskState.RUNNING, TaskState.TIMED_OUT),
            (TaskState.CANCEL_REQUESTED, TaskState.CANCELLED),
            (TaskState.CANCEL_REQUESTED, TaskState.FAILED),
            (TaskState.CANCEL_REQUESTED, TaskState.TIMED_OUT),
        )
        registry = TaskRegistry()
        for index, (start, end) in enumerate(cases):
            task_id = registry.create(f"conv-{index}", f"turn-{index}")
            if start == TaskState.RUNNING:
                registry.transition(task_id, TaskState.RUNNING)
            elif start == TaskState.CANCEL_REQUESTED:
                registry.transition(task_id, TaskState.RUNNING)
                registry.transition(task_id, TaskState.CANCEL_REQUESTED)
            kwargs = {}
            if end in {TaskState.FAILED, TaskState.TIMED_OUT}:
                kwargs = {"error_code": "tool_failed", "error_message": "the tool stopped"}
            snapshot = registry.transition(task_id, end, **kwargs)
            self.assertEqual(snapshot.state, end.value)

    def test_invalid_transitions_are_rejected(self) -> None:
        registry = TaskRegistry()
        completed = registry.create("conv", "turn-done")
        registry.transition(completed, TaskState.RUNNING)
        registry.transition(completed, TaskState.COMPLETED)
        with self.assertRaises(InvalidTransition):
            registry.transition(completed, TaskState.RUNNING)
        with self.assertRaises(InvalidTransition):
            registry.transition(completed, TaskState.CANCELLED)
        failed = registry.create("conv", "turn-failed")
        registry.transition(failed, TaskState.FAILED, error_code="boom")
        with self.assertRaises(InvalidTransition):
            registry.transition(failed, TaskState.QUEUED)
        running = registry.create("conv", "turn-run")
        registry.transition(running, TaskState.RUNNING)
        with self.assertRaises(InvalidTransition):
            registry.transition(running, TaskState.CANCELLED)
        with self.assertRaises(InvalidTransition):
            registry.transition(running, "not-a-state")
        self.assertEqual(registry.get(completed).state, TaskState.COMPLETED.value)
        self.assertEqual(registry.get(running).state, TaskState.RUNNING.value)


class CancellationTests(unittest.TestCase):
    def test_request_is_idempotent_and_does_not_finish_a_running_task(self) -> None:
        clock = _Clock()
        registry = TaskRegistry(clock=clock)
        task_id = registry.create("conv", "turn")
        registry.transition(task_id, TaskState.RUNNING)
        clock.advance(5)
        operation = registry.register_operation(task_id, "github_get_repository", "op-read")
        registry.note_dispatched(task_id, operation.operation_id, interruptible=False)
        clock.advance(5)
        first = registry.request_cancel(task_id)
        clock.advance(5)
        second = registry.request_cancel(task_id)
        self.assertEqual(first.state, TaskState.CANCEL_REQUESTED.value)
        self.assertEqual(second.state, TaskState.CANCEL_REQUESTED.value)
        self.assertEqual(second.cancel_requested_at, first.cancel_requested_at)
        self.assertIsNone(second.finished_at)
        self.assertTrue(second.remote_may_still_run)
        self.assertNotEqual(second.state, TaskState.CANCELLED.value)
        clock.advance(5)
        confirmed = registry.transition(task_id, TaskState.CANCELLED)
        self.assertEqual(confirmed.state, TaskState.CANCELLED.value)
        self.assertIsNotNone(confirmed.finished_at)
        self.assertTrue(confirmed.remote_may_still_run)


class OperationTests(unittest.TestCase):
    def test_an_operation_belongs_to_one_task(self) -> None:
        registry = TaskRegistry()
        first = registry.create("conv-a", "turn-a")
        second = registry.create("conv-b", "turn-b")
        operation = registry.register_operation(first, "search_web", "op-1")
        self.assertIsInstance(operation, OperationSnapshot)
        self.assertEqual(operation.task_id, first)
        with self.assertRaises(DuplicateOperation) as raised:
            registry.register_operation(second, "search_web", "op-1")
        self.assertEqual(raised.exception.task_id, first)
        self.assertEqual(registry.get(second).operations, ())
        self.assertEqual(registry.get(first).operations[0].operation_id, "op-1")


class OperationFinishTests(unittest.TestCase):
    def test_returned_clears_the_remote_flag_and_abandoned_keeps_it(self) -> None:
        clock = _Clock()
        registry = TaskRegistry(clock=clock)
        task_id = registry.create("conv", "turn")
        registry.transition(task_id, TaskState.RUNNING)
        first = registry.register_operation(task_id, "github_get_repository", "op-read")
        second = registry.register_operation(task_id, "github_get_repository", "op-other")
        registry.note_dispatched(task_id, first.operation_id, interruptible=False)
        registry.note_dispatched(task_id, second.operation_id, interruptible=False)
        dispatched = registry.get(task_id)
        self.assertTrue(dispatched.remote_may_still_run)
        self.assertEqual(dispatched.state, TaskState.RUNNING.value)
        self.assertTrue(dispatched.operations[0].dispatched)
        self.assertFalse(dispatched.operations[0].interruptible)
        self.assertEqual(dispatched.operations[0].state, "started")

        with self.assertRaises(RegistryValueError):
            registry.note_finished(task_id, "op-never", outcome="returned")
        quiet = registry.register_operation(task_id, "search_web", "op-quiet")
        with self.assertRaises(InvalidTransition):
            registry.note_finished(task_id, quiet.operation_id, outcome="returned")
        with self.assertRaises(TaskNotFound):
            registry.note_finished("missing-task", first.operation_id, outcome="returned")
        with self.assertRaises(RegistryValueError):
            registry.note_finished(task_id, "missing-op", outcome="returned")
        with self.assertRaises(RegistryValueError):
            registry.note_finished(task_id, first.operation_id, outcome="dropped")

        clock.advance(4)
        abandoned = registry.note_finished(task_id, second.operation_id, outcome="abandoned")
        self.assertEqual(abandoned.operation_id, "op-other")
        self.assertTrue(abandoned.dispatched)
        self.assertFalse(abandoned.interruptible)
        self.assertEqual(abandoned.state, "abandoned")
        self.assertEqual(abandoned.started_at, dispatched.operations[1].started_at)
        self.assertEqual(abandoned.finished_at, clock.now)
        self.assertTrue(registry.get(task_id).remote_may_still_run)
        self.assertEqual(registry.get(task_id).state, TaskState.RUNNING.value)
        clock.advance(2)
        abandoned_again = registry.note_finished(task_id, second.operation_id, outcome="abandoned")
        self.assertEqual(abandoned_again.finished_at, abandoned.finished_at)
        self.assertEqual(abandoned_again.state, "abandoned")

        clock.advance(3)
        returned = registry.note_finished(task_id, first.operation_id, outcome="returned")
        self.assertEqual(returned.operation_id, "op-read")
        self.assertTrue(returned.dispatched)
        self.assertEqual(returned.state, "returned")
        self.assertEqual(returned.started_at, dispatched.operations[0].started_at)
        self.assertEqual(returned.finished_at, clock.now)
        after_one = registry.get(task_id)
        self.assertTrue(after_one.remote_may_still_run)
        self.assertEqual(after_one.operations[1].state, "abandoned")
        self.assertEqual(after_one.operations[1].operation_id, "op-other")
        self.assertEqual(after_one.operations[2].state, "recorded")
        self.assertFalse(after_one.operations[2].dispatched)

        clock.advance(1)
        observed = registry.note_finished(task_id, second.operation_id, outcome="returned")
        self.assertEqual(observed.state, "returned")
        self.assertEqual(observed.finished_at, clock.now)
        self.assertTrue(observed.dispatched)
        cleared = registry.get(task_id)
        self.assertFalse(cleared.remote_may_still_run)
        self.assertEqual(cleared.state, TaskState.RUNNING.value)
        self.assertIsNone(cleared.finished_at)
        self.assertIsNone(cleared.error_code)
        clock.advance(6)
        repeated = registry.note_finished(task_id, first.operation_id, outcome="returned")
        self.assertEqual(repeated.finished_at, returned.finished_at)
        with self.assertRaises(InvalidTransition):
            registry.note_finished(task_id, first.operation_id, outcome="abandoned")
        with self.assertRaises(InvalidTransition):
            registry.transition(task_id, TaskState.CANCELLED)
        self.assertEqual(registry.get(task_id).state, TaskState.RUNNING.value)
        self.assertFalse(registry.get(task_id).remote_may_still_run)


class DedupTests(unittest.TestCase):
    def test_dedup_is_scoped_to_an_active_conversation(self) -> None:
        registry = TaskRegistry()
        first = registry.create("conv-a", "turn-1", deduplication_key="repo-read")
        again = registry.create("conv-a", "turn-2", deduplication_key="repo-read")
        other = registry.create("conv-b", "turn-1", deduplication_key="repo-read")
        fresh = registry.create("conv-a", "turn-3")
        self.assertEqual(again, first)
        self.assertEqual(registry.get(first).origin_turn_id, "turn-1")
        self.assertNotEqual(other, first)
        self.assertNotEqual(fresh, first)
        registry.transition(first, TaskState.RUNNING)
        registry.transition(first, TaskState.COMPLETED)
        restarted = registry.create("conv-a", "turn-4", deduplication_key="repo-read")
        self.assertNotEqual(restarted, first)
        self.assertEqual(registry.get(restarted).state, TaskState.QUEUED.value)


class RetentionTests(unittest.TestCase):
    def test_only_the_oldest_terminal_records_are_evicted(self) -> None:
        registry = TaskRegistry(max_terminal=8)
        active = registry.create("conv", "turn-active")
        holding = registry.create("conv", "turn-holding")
        registry.request_cancel(holding)
        finished: list[str] = []
        for index in range(9):
            task_id = registry.create("conv", f"turn-{index}")
            registry.transition(task_id, TaskState.RUNNING)
            registry.transition(task_id, TaskState.COMPLETED)
            finished.append(task_id)
        visible = {item.task_id for item in registry.list_tasks()}
        self.assertIn(active, visible)
        self.assertIn(holding, visible)
        self.assertNotIn(finished[0], visible)
        self.assertEqual(registry.get(active).state, TaskState.QUEUED.value)
        self.assertEqual(registry.get(holding).state, TaskState.CANCEL_REQUESTED.value)
        for task_id in finished[1:]:
            self.assertEqual(registry.get(task_id).state, TaskState.COMPLETED.value)
        with self.assertRaises(TaskNotFound):
            registry.get(finished[0])
        more = [registry.create("conv", f"later-{index}") for index in range(6)]
        self.assertNotIn(finished[0], more)
        self.assertEqual(len({finished[0], *finished, active, holding, *more}), 17)

    def test_active_capacity_does_not_discard_unfinished_tasks(self) -> None:
        registry = TaskRegistry(max_active=2)
        first = registry.create("conv", "turn-1")
        second = registry.create("conv", "turn-2")
        with self.assertRaises(CapacityError):
            registry.create("conv", "turn-3")
        self.assertEqual(registry.get(first).state, TaskState.QUEUED.value)
        self.assertEqual(registry.get(second).state, TaskState.QUEUED.value)
        self.assertEqual(len(registry.list_tasks()), 2)


class ConcurrencyTests(unittest.TestCase):
    def test_concurrent_create_and_transition(self) -> None:
        registry = TaskRegistry()
        start = threading.Barrier(6)
        errors: list[BaseException] = []
        ids: list[str] = []
        gate = threading.Lock()

        def create_one(index: int) -> None:
            start.wait()
            try:
                task_id = registry.create(f"conv-{index}", f"turn-{index}")
                with gate:
                    ids.append(task_id)
                registry.transition(task_id, TaskState.RUNNING)
                registry.transition(task_id, TaskState.COMPLETED)
            except Exception as exc:  # noqa: BLE001 - the assertion reports it
                errors.append(exc)

        threads = [threading.Thread(target=create_one, args=(index,)) for index in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertEqual(errors, [])
        self.assertEqual(len(set(ids)), 6)
        self.assertTrue(all(not thread.is_alive() for thread in threads))

        shared = registry.create("conv-shared", "turn-shared")
        registry.transition(shared, TaskState.RUNNING)
        before = registry.get(shared)
        race = threading.Barrier(2)
        outcomes: list[tuple[str, str]] = []

        def finish(state: str) -> None:
            race.wait()
            try:
                registry.transition(shared, state)
                outcomes.append(("ok", state))
            except InvalidTransition:
                outcomes.append(("rejected", state))

        racers = [
            threading.Thread(target=finish, args=("completed",)),
            threading.Thread(target=finish, args=("failed",)),
        ]
        for thread in racers:
            thread.start()
        for thread in racers:
            thread.join(timeout=5)
        self.assertEqual(sorted(kind for kind, _state in outcomes), ["ok", "rejected"])
        self.assertIn(registry.get(shared).state, {TaskState.COMPLETED.value, TaskState.FAILED.value})
        self.assertEqual(before.state, TaskState.RUNNING.value)
        self.assertEqual(before.task_id, shared)


class SnapshotTests(unittest.TestCase):
    def test_returned_snapshot_cannot_change_the_registry(self) -> None:
        registry = TaskRegistry()
        task_id = registry.create("conv", "turn", task_type="read")
        registry.register_operation(task_id, "search_web", "op-1")
        snapshot = registry.get(task_id)
        self.assertIsInstance(snapshot, TaskSnapshot)
        with self.assertRaises(AttributeError):
            snapshot.state = TaskState.COMPLETED.value  # type: ignore[misc]
        with self.assertRaises(TypeError):
            snapshot.operations[0] = snapshot.operations[0]  # type: ignore[index]
        with self.assertRaises(AttributeError):
            snapshot.operations[0].state = "finished"  # type: ignore[misc]
        self.assertEqual(registry.get(task_id).state, TaskState.QUEUED.value)
        self.assertEqual(registry.get(task_id).operations[0].state, "recorded")


class ErrorTests(unittest.TestCase):
    def test_unknown_duplicate_invalid_and_capacity_errors(self) -> None:
        registry = TaskRegistry(max_active=1)
        with self.assertRaises(TaskNotFound):
            registry.get("missing-task")
        task_id = registry.create("conv", "turn")
        registry.register_operation(task_id, "search_web", "op-1")
        with self.assertRaises(DuplicateOperation):
            registry.register_operation(task_id, "search_web", "op-1")
        with self.assertRaises(InvalidTransition):
            registry.transition(task_id, TaskState.COMPLETED)
        with self.assertRaises(CapacityError):
            registry.create("conv", "turn-extra")
        with self.assertRaises(RegistryValueError):
            registry.create("conv two", "turn")
        with self.assertRaises(RegistryValueError):
            registry.transition(
                task_id,
                TaskState.FAILED,
                error_message="leaked ghp_AAAAAAAAAAAAAAAAAAAAAA",  # synthetic-credential-fixture
            )


class TimeTests(unittest.TestCase):
    def test_timestamps_are_utc_and_follow_the_lifecycle(self) -> None:
        clock = _Clock()
        registry = TaskRegistry(clock=clock)
        task_id = registry.create("conv", "turn")
        created = registry.get(task_id)
        self.assertEqual(created.created_at, clock.now)
        self.assertEqual(created.created_at.tzinfo, timezone.utc)
        self.assertIsNone(created.started_at)
        self.assertIsNone(created.finished_at)
        clock.advance(10)
        running = registry.transition(task_id, TaskState.RUNNING)
        self.assertEqual(running.started_at, clock.now)
        self.assertEqual(running.created_at, created.created_at)
        self.assertEqual(running.updated_at, clock.now)
        clock.advance(3)
        cancelled = registry.request_cancel(task_id)
        self.assertEqual(cancelled.cancel_requested_at, clock.now)
        self.assertEqual(cancelled.started_at, running.started_at)
        clock.advance(4)
        finished = registry.transition(task_id, TaskState.CANCELLED)
        self.assertEqual(finished.finished_at, clock.now)
        self.assertEqual(finished.updated_at, clock.now)
        self.assertEqual(finished.cancel_requested_at, cancelled.cancel_requested_at)
        self.assertIsNotNone(finished.finished_at.utcoffset() if finished.finished_at else None)


if __name__ == "__main__":
    unittest.main()
