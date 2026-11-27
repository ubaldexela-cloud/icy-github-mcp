"""Offline tests for the task result store. No voice, MCP, or network."""

from __future__ import annotations

import logging
import threading
import unittest
from datetime import datetime, timezone

from realtime_c.task_result_store import (
    MAX_PAYLOAD_BYTES,
    ResultConflict,
    ResultMismatch,
    ResultNotFound,
    ResultRecord,
    ResultRejected,
    TaskResultStore,
)


class ResultStoreTests(unittest.TestCase):
    def test_store_and_retrieve(self) -> None:
        store = TaskResultStore()
        stored = store.put("conv", "item-1", "op-1", "repository is public")
        found = store.get("conv", "item-1", "op-1")
        self.assertEqual(found, stored)
        self.assertEqual(found.payload, "repository is public")
        self.assertEqual(found.conversation_id, "conv")
        self.assertEqual(found.task_id, "item-1")
        self.assertEqual(found.operation_id, "op-1")
        self.assertIsInstance(found, ResultRecord)
        self.assertEqual(store.status().count, 1)
        self.assertEqual(store.status().capacity, 8)

    def test_conversations_are_isolated(self) -> None:
        store = TaskResultStore()
        store.put("conv-a", "item-1", "op-1", "alpha")
        store.put("conv-b", "item-1", "op-1", "beta")
        self.assertEqual(store.get("conv-a", "item-1", "op-1").payload, "alpha")
        self.assertEqual(store.get("conv-b", "item-1", "op-1").payload, "beta")
        with self.assertRaises(ResultNotFound):
            store.get("conv-c", "item-1", "op-1")

    def test_wrong_task_is_not_found(self) -> None:
        store = TaskResultStore()
        store.put("conv", "item-1", "op-1", "alpha")
        with self.assertRaises(ResultNotFound):
            store.get("conv", "item-2", "op-1")

    def test_wrong_operation_is_a_mismatch(self) -> None:
        store = TaskResultStore()
        store.put("conv", "item-1", "op-1", "alpha")
        with self.assertRaises(ResultMismatch) as raised:
            store.get("conv", "item-1", "op-2")
        self.assertNotIn("alpha", str(raised.exception))

    def test_same_operation_and_payload_is_idempotent(self) -> None:
        store = TaskResultStore()
        first = store.put("conv", "item-1", "op-1", "alpha")
        second = store.put("conv", "item-1", "op-1", "alpha")
        self.assertEqual(second, first)
        self.assertEqual(second.stored_at, first.stored_at)
        self.assertEqual(store.status().count, 1)

    def test_different_payload_conflicts(self) -> None:
        store = TaskResultStore()
        store.put("conv", "item-1", "op-1", "alpha")
        with self.assertRaises(ResultConflict) as raised:
            store.put("conv", "item-1", "op-1", "beta")
        self.assertNotIn("alpha", str(raised.exception))
        self.assertNotIn("beta", str(raised.exception))
        self.assertEqual(store.get("conv", "item-1", "op-1").payload, "alpha")

    def test_second_operation_for_the_same_task_is_rejected(self) -> None:
        store = TaskResultStore()
        store.put("conv", "item-1", "op-1", "alpha")
        with self.assertRaises(ResultConflict):
            store.put("conv", "item-1", "op-2", "alpha")
        self.assertEqual(store.get("conv", "item-1", "op-1").payload, "alpha")
        self.assertEqual(store.status().count, 1)

    def test_empty_and_malformed_identifiers_are_rejected(self) -> None:
        store = TaskResultStore()
        with self.assertRaises(ResultRejected):
            store.put("", "item-1", "op-1", "alpha")
        with self.assertRaises(ResultRejected):
            store.put("conv", "bad id", "op-1", "alpha")
        with self.assertRaises(ResultRejected):
            store.put("conv", "item-1", "x" * 129, "alpha")
        with self.assertRaises(ResultRejected):
            store.put(1, "item-1", "op-1", "alpha")  # type: ignore[arg-type]
        self.assertEqual(store.status().count, 0)

    def test_non_string_payload_is_rejected(self) -> None:
        store = TaskResultStore()
        with self.assertRaises(ResultRejected) as raised:
            store.put("conv", "item-1", "op-1", {"raw": "value"})  # type: ignore[arg-type]
        self.assertNotIn("value", str(raised.exception))
        self.assertEqual(store.status().count, 0)

    def test_empty_payload_is_rejected_and_spaces_are_kept(self) -> None:
        store = TaskResultStore()
        with self.assertRaises(ResultRejected) as raised:
            store.put("conv", "item-1", "op-1", "")
        self.assertNotIn("item-1", str(raised.exception))
        stored = store.put("conv", "item-2", "op-2", " ")
        self.assertEqual(stored.payload, " ")
        self.assertEqual(store.get("conv", "item-2", "op-2").payload, " ")

    def test_payload_at_and_above_the_byte_limit(self) -> None:
        store = TaskResultStore()
        exact = "a" * MAX_PAYLOAD_BYTES
        self.assertEqual(len(exact.encode("utf-8")), 8192)
        stored = store.put("conv", "item-1", "op-1", exact)
        self.assertEqual(len(stored.payload.encode("utf-8")), 8192)
        over = "a" * (MAX_PAYLOAD_BYTES + 1)
        with self.assertRaises(ResultRejected) as raised:
            store.put("conv", "item-2", "op-2", over)
        self.assertNotIn(over[:40], str(raised.exception))
        self.assertEqual(store.status().count, 1)

    def test_utf8_byte_count_uses_encoded_size(self) -> None:
        store = TaskResultStore()
        exact = "é" * 4096
        self.assertEqual(len(exact), 4096)
        self.assertEqual(len(exact.encode("utf-8")), 8192)
        store.put("conv", "item-1", "op-1", exact)
        self.assertEqual(store.get("conv", "item-1", "op-1").payload, exact)
        over = exact + "x"
        self.assertEqual(len(over.encode("utf-8")), 8193)
        with self.assertRaises(ResultRejected):
            store.put("conv", "item-2", "op-2", over)

    def test_credential_like_payloads_are_rejected_without_echo(self) -> None:
        store = TaskResultStore()
        samples = (
            "prefix ghp_" + ("A" * 16),
            "github_pat_" + ("b" * 12),
            "Bearer secret-value",
            "sk-" + ("c" * 12),
        )
        logger = logging.getLogger("realtime_c.task_result_store")
        for index, sample in enumerate(samples):
            with self.assertNoLogs(logger, level="DEBUG"):
                with self.assertRaises(ResultRejected) as raised:
                    store.put("conv", f"item-{index}", "op-1", sample)
            message = str(raised.exception)
            self.assertNotIn(sample, message)
            self.assertNotIn("ghp_", message)
            self.assertNotIn("github_pat_", message)
            self.assertNotIn("secret-value", message)
            self.assertNotIn("sk-", message)
        self.assertEqual(store.status().count, 0)

    def test_capacity_evicts_the_oldest_insertion(self) -> None:
        store = TaskResultStore(capacity=2)
        store.put("conv", "item-a", "op-a", "alpha")
        store.put("conv", "item-b", "op-b", "beta")
        again = store.put("conv", "item-b", "op-b", "beta")
        self.assertEqual(again.payload, "beta")
        self.assertEqual(store.status().count, 2)
        store.put("conv", "item-c", "op-c", "gamma")
        with self.assertRaises(ResultNotFound):
            store.get("conv", "item-a", "op-a")
        self.assertEqual(store.get("conv", "item-b", "op-b").payload, "beta")
        self.assertEqual(store.get("conv", "item-c", "op-c").payload, "gamma")
        store.put("conv", "item-d", "op-d", "delta")
        with self.assertRaises(ResultNotFound):
            store.get("conv", "item-b", "op-b")
        self.assertEqual(store.get("conv", "item-c", "op-c").payload, "gamma")
        self.assertEqual(store.get("conv", "item-d", "op-d").payload, "delta")
        with self.assertRaises(ResultRejected):
            TaskResultStore(capacity=0)
        with self.assertRaises(ResultRejected):
            TaskResultStore(capacity=65)

    def test_remove_is_scoped_to_one_task_and_one_conversation(self) -> None:
        store = TaskResultStore()
        store.put("conv-a", "item-1", "op-1", "alpha")
        store.put("conv-a", "item-2", "op-2", "beta")
        store.put("conv-b", "item-1", "op-1", "gamma")
        self.assertTrue(store.remove("conv-a", "item-1"))
        self.assertFalse(store.remove("conv-a", "item-1"))
        with self.assertRaises(ResultNotFound):
            store.get("conv-a", "item-1", "op-1")
        self.assertEqual(store.get("conv-a", "item-2", "op-2").payload, "beta")
        self.assertEqual(store.get("conv-b", "item-1", "op-1").payload, "gamma")
        self.assertEqual(store.remove_conversation("conv-a"), 1)
        with self.assertRaises(ResultNotFound):
            store.get("conv-a", "item-2", "op-2")
        self.assertEqual(store.get("conv-b", "item-1", "op-1").payload, "gamma")
        self.assertEqual(store.remove_conversation("conv-a"), 0)

    def test_returned_record_cannot_change_the_store(self) -> None:
        store = TaskResultStore()
        stored = store.put("conv", "item-1", "op-1", "alpha")
        with self.assertRaises(AttributeError):
            stored.payload = "changed"  # type: ignore[misc]
        self.assertEqual(store.get("conv", "item-1", "op-1").payload, "alpha")
        self.assertEqual(stored.stored_at.tzinfo, timezone.utc)

    def test_concurrent_puts_and_gets_stay_consistent(self) -> None:
        store = TaskResultStore(capacity=16)
        start = threading.Barrier(8)
        errors: list[BaseException] = []

        def write_one(index: int) -> None:
            start.wait()
            try:
                store.put(f"conv-{index}", f"item-{index}", f"op-{index}", f"body-{index}")
                found = store.get(f"conv-{index}", f"item-{index}", f"op-{index}")
                if found.payload != f"body-{index}":
                    raise AssertionError(index)
            except Exception as exc:  # noqa: BLE001 - the assertion reports it
                errors.append(exc)

        threads = [threading.Thread(target=write_one, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertEqual(errors, [])
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(store.status().count, 8)

        shared = threading.Barrier(4)
        shared_errors: list[BaseException] = []

        def write_same() -> None:
            shared.wait()
            try:
                store.put("shared", "task", "op", "same-body")
            except Exception as exc:  # noqa: BLE001 - the assertion reports it
                shared_errors.append(exc)

        writers = [threading.Thread(target=write_same) for _index in range(4)]
        for thread in writers:
            thread.start()
        for thread in writers:
            thread.join(timeout=5)
        self.assertEqual(shared_errors, [])
        self.assertEqual(store.get("shared", "task", "op").payload, "same-body")

    def test_clock_timestamp_is_recorded(self) -> None:
        moment = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        store = TaskResultStore(clock=lambda: moment)
        stored = store.put("conv", "item-1", "op-1", "alpha")
        self.assertEqual(stored.stored_at, moment)


if __name__ == "__main__":
    unittest.main()
