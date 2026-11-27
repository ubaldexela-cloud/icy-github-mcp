"""Approval, replay, and fake-HTTP coverage for GitHub writes."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from realtime_c.github_approval import GithubPolicy
from realtime_c.github_operations import confirm_operation, execute_operation, prepare_operation


def _policy() -> GithubPolicy:
    return GithubPolicy(
        True, None, True, True, True, False, False, False, False,
        "ubaldexela-cloud", ("mnist-einops-cnn",),
    )


class _Response:
    def __init__(self, status: int, payload: dict[str, Any]) -> None:
        self.status_code = status
        self._payload = payload

    def json(self) -> dict[str, Any]:
        return self._payload


class _Client:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def request(self, method: str, url: str, headers: dict[str, str] | None = None, json: dict[str, Any] | None = None) -> _Response:
        del headers, json
        self.calls.append((method, url))
        if method == "GET" and url.endswith("/issues/7"):
            return _Response(200, {"id": 7, "number": 7, "state": "closed"})
        if method == "PATCH":
            return _Response(200, {"number": 7, "state": "closed"})
        if method == "POST" and url.endswith("/pulls"):
            return _Response(201, {"number": 4, "id": 4})
        if method == "GET" and "/pulls/" in url:
            return _Response(200, {"number": 4, "id": 4, "state": "open"})
        if method == "PUT":
            return _Response(201, {"content": {"sha": "abc"}})
        if method == "GET" and "/contents/" in url:
            return _Response(200, {"sha": "abc", "path": "README.md"})
        return _Response(500, {})


class OperationApprovalTests(unittest.TestCase):
    def test_approval_replay_and_verification(self) -> None:
        policy = _policy()
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "consumed.ledger"
            prepared = prepare_operation(policy, "close_issue", {"owner": "ubaldexela-cloud", "repo": "mnist-einops-cnn", "number": 7})
            self.assertTrue(prepared["ok"], prepared)
            mismatch = confirm_operation(prepared["authorization_id"], True, "0" * 64)
            self.assertEqual(mismatch["error"], "manifest_changed")
            rejected = confirm_operation(prepared["authorization_id"], False, prepared["fingerprint"])
            self.assertEqual(rejected["error"], "approval_rejected")
            prepared = prepare_operation(policy, "close_issue", {"owner": "ubaldexela-cloud", "repo": "mnist-einops-cnn", "number": 7})
            confirmed = confirm_operation(prepared["authorization_id"], True, prepared["fingerprint"])
            self.assertTrue(confirmed["ok"])
            client = _Client()
            done = execute_operation(
                prepared["authorization_id"],
                policy=policy,
                ledger=ledger,
                client=client,
                headers={"Authorization": "Bearer unit-test"},
            )
            self.assertTrue(done["verified"], done)
            self.assertIn(("PATCH", "https://api.github.com/repos/ubaldexela-cloud/mnist-einops-cnn/issues/7"), client.calls)
            self.assertEqual(sum(1 for method, _url in client.calls if method == "PATCH"), 1)
            again = execute_operation(
                prepared["authorization_id"],
                policy=policy,
                ledger=ledger,
                client=client,
                headers={"Authorization": "Bearer unit-test"},
            )
            self.assertEqual(again["error"], "approval_not_accepted")
            self.assertEqual(sum(1 for method, _url in client.calls if method == "PATCH"), 1)
            other = prepare_operation(policy, "update_file", {
                "owner": "other",
                "repo": "mnist-einops-cnn",
                "path": "README.md",
                "branch": "main",
                "content": "x",
                "message": "update",
            })
            self.assertEqual(other["error"], "owner_not_allowlisted")
            self.assertNotIn("unit-test", json.dumps(done))


if __name__ == "__main__":
    unittest.main()
