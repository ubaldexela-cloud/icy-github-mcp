"""Background execution for long-running Git operations. Fake HTTP is not required."""

from __future__ import annotations

import json
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from realtime_c import git_workspace
from realtime_c.background_github_adapter import BackgroundGithubAdapter, SessionCloseResult
from realtime_c.background_worker import BackgroundTaskWorker
from realtime_c.combined_tools import CombinedToolSession
from realtime_c.mcp_tools import TOOL_NAMES
from realtime_c.task_registry import TaskRegistry
from realtime_c.task_result_store import TaskResultStore


class _Tools:
    available = True
    schemas = {name: {"type": "object", "properties": {}} for name in TOOL_NAMES}
    calls: list[str] = []

    def call(self, name: str, arguments: dict | None = None) -> str:
        del arguments
        self.calls.append(name)
        return json.dumps({"ok": True, "tool": name})


class _Reader:
    def __init__(self) -> None:
        self.closed = 0

    def read_repository(self, owner: str, repo: str, *, cancelled, wait_for_cancel) -> str:
        del owner, repo, cancelled, wait_for_cancel
        raise AssertionError("repository read was not requested")

    def close_session(self) -> SessionCloseResult:
        self.closed += 1
        return SessionCloseResult(closed=True)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


class BackgroundJobTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.workspace = self.root / "work"
        self.workspace.mkdir()
        origin = self.root / "origin"
        origin.mkdir()
        _git(origin, "init", "-b", "main")
        _git(origin, "config", "user.email", "icy@example.com")
        _git(origin, "config", "user.name", "ICY")
        (origin / "README.md").write_text("c30\n", encoding="utf-8")
        _git(origin, "add", "README.md")
        _git(origin, "commit", "-m", "c30")
        self.origin = origin
        config = self.root / "config"
        config.mkdir()
        (config / "git_workspace.json").write_text(
            json.dumps({"workspace_root": str(self.workspace)}),
            encoding="utf-8",
        )
        (config / "github_mcp.json").write_text(json.dumps({
            "enabled": True,
            "allow_reads": True,
            "allow_writes": False,
            "allow_repo_creation": False,
            "allow_workflows": False,
            "allow_permissions": False,
            "allow_destructive": False,
            "allowed_owner": "ubaldexela-cloud",
            "allowed_repos": ["mnist-einops-cnn"],
        }), encoding="utf-8")
        _git(self.workspace, "init", "-b", "main")
        _git(self.workspace, "config", "user.email", "icy@example.com")
        _git(self.workspace, "config", "user.name", "ICY")
        (self.workspace / "README.md").write_text("local\n", encoding="utf-8")
        _git(self.workspace, "add", "README.md")
        _git(self.workspace, "commit", "-m", "local")
        self.registry = TaskRegistry()
        self.worker = BackgroundTaskWorker(self.registry)
        self.reader = _Reader()
        self.adapter = BackgroundGithubAdapter(self.registry, self.worker, TaskResultStore(), self.reader)
        self.adapter.start()
        self.tools = _Tools()
        self.tools.calls = []
        self.session = CombinedToolSession(
            self.tools,
            None,
            None,
            background=self.adapter,
            task_registry=self.registry,
            conversation_id="conv-a",
            project_root=self.root,
            github_policy_root=self.root,
        )
        self.release = threading.Event()
        self.release.set()
        self._original_clone = git_workspace.workspace_clone

    def tearDown(self) -> None:
        git_workspace.workspace_clone = self._original_clone
        self.release.set()
        self.worker.shutdown(timeout=5)
        self.tmp.cleanup()

    def _wait_result(self, task_id: str, timeout: float = 8.0) -> dict:
        deadline = time.time() + timeout
        last: dict = {}
        while time.time() < deadline:
            last = json.loads(self.session.call("icy_task_result", {"task_id": task_id}))
            if last.get("ok"):
                return last
            time.sleep(0.05)
        self.fail(f"result was not stored: {last}")

    def test_clone_returns_task_id_and_voice_stays_responsive(self) -> None:
        entered = threading.Event()
        self.release = threading.Event()
        voice = threading.get_ident()

        def blocked(workspace: Path, source: str, destination: str) -> dict:
            del workspace, source, destination
            self.assertNotEqual(threading.get_ident(), voice)
            entered.set()
            self.assertTrue(self.release.wait(5), "blocked clone was not released")
            return {"ok": True, "spoken_status": "Cloned.", "path": "held"}

        git_workspace.workspace_clone = blocked
        started = json.loads(self.session.call("git_clone", {"source": str(self.origin), "destination": "held"}))
        self.assertEqual(started["status"], "in_progress")
        self.assertTrue(started["task_id"])
        self.assertTrue(entered.wait(3), "clone did not reach the worker")
        other = json.loads(self.session.call("search_web", {"query": "weather"}))
        self.assertEqual(other["tool"], "search_web")
        self.assertEqual(self.tools.calls, ["search_web"])
        self.release.set()
        stored = self._wait_result(started["task_id"])
        body = json.loads(stored["result"])
        self.assertTrue(body["ok"], body)
        self.assertNotIn("ghp_", stored["result"])

    def test_real_clone_fetch_and_result(self) -> None:
        started = json.loads(self.session.call("git_clone", {
            "source": str(self.origin),
            "destination": "repo",
        }))
        self.assertEqual(started["status"], "in_progress")
        stored = self._wait_result(started["task_id"])
        body = json.loads(stored["result"])
        self.assertTrue(body["ok"], body)
        self.assertTrue((self.workspace / "repo" / "README.md").is_file())
        fetched = json.loads(self.session.call("git_fetch", {"path": "repo", "remote": "origin"}))
        self.assertEqual(fetched["status"], "in_progress")
        fetch_body = json.loads(self._wait_result(fetched["task_id"])["result"])
        self.assertTrue(fetch_body["ok"], fetch_body)
        pulled = json.loads(self.session.call("git_pull", {"path": "repo"}))
        self.assertEqual(pulled["status"], "in_progress")
        pull_body = json.loads(self._wait_result(pulled["task_id"])["result"])
        self.assertTrue(pull_body["ok"], pull_body)

    def test_cancel_does_not_claim_the_operation_stopped(self) -> None:
        entered = threading.Event()
        self.release = threading.Event()
        ran = []

        def blocked(workspace: Path, source: str, destination: str) -> dict:
            ran.append(destination)
            if destination == "slow":
                entered.set()
                self.release.wait(5)
            return self._original_clone(workspace, source, destination)

        git_workspace.workspace_clone = blocked
        slow = json.loads(self.session.call("git_clone", {"source": str(self.origin), "destination": "slow"}))
        self.assertTrue(entered.wait(3))
        queued = json.loads(self.session.call("git_clone", {"source": str(self.origin), "destination": "queued"}))
        cancelled = json.loads(self.session.call("icy_task_cancel", {"task_id": queued["task_id"]}))
        self.assertTrue(cancelled["ok"], cancelled)
        self.assertEqual(cancelled["state"], "cancelled")
        self.assertNotIn("stopped the remote", cancelled["spoken_status"].lower())
        self.release.set()
        self._wait_result(slow["task_id"])
        self.assertNotIn("queued", ran)
        other = CombinedToolSession(
            self.tools,
            None,
            None,
            background=self.adapter,
            task_registry=self.registry,
            conversation_id="conv-b",
            project_root=self.root,
        )
        hidden = json.loads(other.call("icy_task_result", {"task_id": slow["task_id"]}))
        self.assertEqual(hidden["error"], "task_not_found")

    def test_running_cancel_reports_the_operation_may_continue(self) -> None:
        entered = threading.Event()
        self.release = threading.Event()

        def blocked(workspace: Path, source: str, destination: str) -> dict:
            del workspace, source, destination
            entered.set()
            self.release.wait(5)
            return {"ok": True, "spoken_status": "finished after cancel", "path": destination}

        git_workspace.workspace_clone = blocked
        started = json.loads(self.session.call("git_clone", {"source": str(self.origin), "destination": "live"}))
        self.assertTrue(entered.wait(3))
        cancelled = json.loads(self.session.call("icy_task_cancel", {"task_id": started["task_id"]}))
        self.assertTrue(cancelled["ok"], cancelled)
        self.assertIn("may still be running", cancelled["spoken_status"])
        self.release.set()
        self._wait_result(started["task_id"])

    def test_failed_job_leaves_other_tools_usable(self) -> None:
        def broken(workspace: Path, source: str, destination: str) -> dict:
            del workspace, source, destination
            raise RuntimeError("clone failed in the test")

        git_workspace.workspace_clone = broken
        started = json.loads(self.session.call("git_clone", {"source": str(self.origin), "destination": "broken"}))
        stored = self._wait_result(started["task_id"])
        body = json.loads(stored["result"])
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"], "background_job_failed")
        self.assertTrue(body["remote_may_still_run"])
        git_workspace.workspace_clone = self._original_clone
        status = json.loads(self.session.call("git_status", {"path": "."}))
        self.assertTrue(status["ok"], status)
        local = json.loads(self.session.call("search_web", {"query": "still here"}))
        self.assertEqual(local["tool"], "search_web")

    def test_approved_local_branch_is_backgrounded(self) -> None:
        self.session.attach_operations(True)
        prepared = json.loads(self.session.call("github_prepare_operation", {
            "operation": "create_local_branch",
            "path": ".",
            "branch": "feature-c30",
        }))
        self.assertTrue(prepared["ok"], prepared)
        approved = json.loads(self.session.call("github_approve_operation", {
            "authorization_id": prepared["authorization_id"],
            "approved": True,
            "fingerprint": prepared["fingerprint"],
        }))
        self.assertEqual(approved["status"], "in_progress", approved)
        body = json.loads(self._wait_result(approved["task_id"])["result"])
        self.assertTrue(body["ok"], body)
        branch = json.loads(self.session.call("git_branch", {"path": "."}))
        self.assertEqual(branch.get("branch"), "feature-c30")
        replay = json.loads(self.session.call("github_approve_operation", {
            "authorization_id": prepared["authorization_id"],
            "approved": True,
            "fingerprint": prepared["fingerprint"],
        }))
        self.assertFalse(replay["ok"])
        self.assertNotEqual(replay.get("status"), "in_progress")

    def test_status_stays_available_while_a_mutation_holds_the_lock(self) -> None:
        started = threading.Event()
        release = threading.Event()

        def hold() -> None:
            self.assertIsNone(git_workspace._begin_mutation())
            started.set()
            release.wait(3)
            git_workspace._WORKSPACE_LOCK.release()

        thread = threading.Thread(target=hold)
        thread.start()
        self.assertTrue(started.wait(2))
        try:
            status = json.loads(self.session.call("git_status", {"path": "."}))
            self.assertTrue(status["ok"], status)
            busy = git_workspace.workspace_fetch(self.workspace, ".")
            self.assertEqual(busy["error"], "workspace_busy")
        finally:
            release.set()
            thread.join(3)

    def test_shutdown_refuses_to_close_the_session_while_the_worker_is_alive(self) -> None:
        entered = threading.Event()
        self.release = threading.Event()

        def blocked(workspace: Path, source: str, destination: str) -> dict:
            del workspace, source, destination
            entered.set()
            self.release.wait(5)
            return {"ok": True, "spoken_status": "done", "path": "shutdown"}

        git_workspace.workspace_clone = blocked
        self.session.call("git_clone", {"source": str(self.origin), "destination": "shutdown"})
        self.assertTrue(entered.wait(3))
        early = self.adapter.shutdown(timeout=0.2)
        self.assertFalse(early.clean)
        self.assertTrue(early.thread_alive)
        refused = self.adapter.close_owned_session(early)
        self.assertFalse(refused.closed)
        self.assertTrue(refused.in_use)
        self.assertEqual(self.reader.closed, 0)
        self.release.set()
        later = self.adapter.shutdown(timeout=5)
        self.assertTrue(later.clean, later)
        self.assertFalse(later.thread_alive)
        closed = self.adapter.close_owned_session(later)
        self.assertTrue(closed.closed)
        self.assertEqual(self.reader.closed, 1)


if __name__ == "__main__":
    unittest.main()
