"""Spoken GitHub workflows with a fake read bridge and a temporary repository."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from mcp_servers.github_reads import READ_CAPABILITY_TOOLS, run_read
from realtime_c.background_github_adapter import BackgroundGithubAdapter
from realtime_c.background_worker import BackgroundTaskWorker
from realtime_c.combined_tools import CombinedToolSession
from realtime_c.github_approval import load_github_policy
from realtime_c.github_voice import propose_tool
from realtime_c.mcp_tools import TOOL_NAMES
from realtime_c.task_registry import TaskRegistry
from realtime_c.task_result_store import TaskResultStore


class _Tools:
    available = True
    schemas = {name: {"type": "object", "properties": {}} for name in TOOL_NAMES}

    def call(self, name: str, arguments: dict | None = None) -> str:
        del arguments
        return json.dumps({"ok": True, "tool": name})


class _Github:
    enabled = True
    available = True
    supports_turn_token = True
    _schemas_cached = True
    schemas = {name: {"type": "object"} for name in ("github_get_repository", *READ_CAPABILITY_TOOLS, "github_execute_operation")}

    def call(self, name: str, arguments: dict | None = None, token: object = None, wait_s: float | None = None) -> str:
        del name, arguments, token, wait_s
        raise AssertionError("GitHub was called on the voice thread")


class _Reader:
    def read_repository(self, owner: str, repo: str, *, cancelled, wait_for_cancel) -> str:
        del owner, repo, cancelled, wait_for_cancel
        return json.dumps({"ok": True, "spoken_status": "Repository lookup finished."})

    def read_named(self, tool_name: str, arguments: dict, *, cancelled, wait_for_cancel) -> str:
        del cancelled, wait_for_cancel
        return json.dumps({
            "ok": True,
            "tool": tool_name,
            "arguments": {"owner": arguments.get("owner"), "repo": arguments.get("repo"), "path": arguments.get("path")},
            "spoken_status": "The GitHub read finished.",
        })


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


class GithubEndToEndTests(unittest.TestCase):
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
        (origin / "README.md").write_text("readme\n", encoding="utf-8")
        _git(origin, "add", "README.md")
        _git(origin, "commit", "-m", "readme")
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
        self.adapter = BackgroundGithubAdapter(self.registry, self.worker, TaskResultStore(), _Reader())
        self.adapter.start()
        self.session = CombinedToolSession(
            _Tools(),
            None,
            _Github(),  # type: ignore[arg-type]
            background=self.adapter,
            task_registry=self.registry,
            conversation_id="conv-e2e",
            project_root=self.root,
            github_policy_root=self.root,
        )
        self.session.attach_operations(True)

    def tearDown(self) -> None:
        self.worker.shutdown(timeout=5)
        self.tmp.cleanup()

    def _result(self, task_id: str) -> dict:
        import time

        deadline = time.time() + 8
        last = {}
        while time.time() < deadline:
            last = json.loads(self.session.call("icy_task_result", {"task_id": task_id}))
            if last.get("ok"):
                return json.loads(last["result"])
            time.sleep(0.05)
        self.fail(str(last))

    def test_spoken_workflows_and_security_boundaries(self) -> None:
        schemas = self.session.schemas
        for name in TOOL_NAMES:
            self.assertIn(name, schemas)
        phrases = {
            "Show me my repositories.": "github_list_repositories",
            "Read the README.": "github_read_file",
            "Show the latest commits.": "github_list_commits",
            "Check open pull requests.": "github_list_pull_requests",
            "Clone this repository into my workspace.": "git_clone",
            "Check the working tree.": "git_status",
            "Create a feature branch.": "github_prepare_operation",
            "Prepare a change to the README.": "github_prepare_operation",
            "Show me what will be committed.": "git_diff",
            "Approve this change.": "github_approve_operation",
            "Push the approved branch.": "github_prepare_operation",
            "Create a pull request.": "github_prepare_operation",
        }
        for utterance, expected in phrases.items():
            self.assertEqual(propose_tool(utterance, schemas), expected, utterance)

        commits = json.loads(self.session.call("github_list_commits", {"owner": "ubaldexela-cloud", "repo": "mnist-einops-cnn"}))
        self.assertEqual(commits["status"], "in_progress")
        body = self._result(commits["task_id"])
        self.assertTrue(body["ok"], body)
        self.assertNotIn("ghp_", json.dumps(body))
        other = CombinedToolSession(
            _Tools(),
            None,
            None,
            background=self.adapter,
            task_registry=self.registry,
            conversation_id="conv-other",
            project_root=self.root,
        )
        hidden = json.loads(other.call("icy_task_result", {"task_id": commits["task_id"]}))
        self.assertEqual(hidden["error"], "task_not_found")

        cloned = json.loads(self.session.call("git_clone", {"source": str(self.origin), "destination": "repo"}))
        self.assertEqual(cloned["status"], "in_progress")
        clone_body = self._result(cloned["task_id"])
        self.assertTrue(clone_body["ok"], clone_body)
        status = json.loads(self.session.call("git_status", {"path": "repo"}))
        self.assertTrue(status["clean"], status)
        escaped = json.loads(self.session.call("git_status", {"path": "../origin"}))
        self.assertFalse(escaped["ok"])
        self.assertIn(escaped["error"], {"path_outside_workspace", "symlink_rejected", "not_a_repository"})

        link = self.workspace / "linked"
        try:
            os.symlink(self.origin, link, target_is_directory=True)
        except OSError:
            link = None
        if link is not None:
            linked = json.loads(self.session.call("git_status", {"path": "linked"}))
            self.assertEqual(linked["error"], "symlink_rejected")

        denied = json.loads(self.session.call("github_execute_operation", {}))
        self.assertEqual(denied["error"], "approval_required")
        prepared = json.loads(self.session.call("github_prepare_operation", {
            "operation": "create_local_branch",
            "path": ".",
            "branch": "feature-e2e",
        }))
        self.assertTrue(prepared["ok"], prepared)
        self.assertIn("Nothing has been sent", prepared["spoken_status"])
        preview = json.loads(self.session.call("git_diff", {"path": "."}))
        self.assertTrue(preview["ok"], preview)
        approved = json.loads(self.session.call("github_approve_operation", {
            "authorization_id": prepared["authorization_id"],
            "approved": True,
            "fingerprint": prepared["fingerprint"],
        }))
        self.assertEqual(approved["status"], "in_progress")
        branch_body = self._result(approved["task_id"])
        self.assertTrue(branch_body["ok"], branch_body)
        replay = json.loads(self.session.call("github_approve_operation", {
            "authorization_id": prepared["authorization_id"],
            "approved": True,
            "fingerprint": prepared["fingerprint"],
        }))
        self.assertFalse(replay["ok"])

        class _Client:
            def __init__(self) -> None:
                self.calls = 0

            def request(self, *args, **kwargs):
                self.calls += 1
                raise AssertionError("workflow request was sent")

        client = _Client()
        token = "ghp_" + ("a" * 36)
        policy = load_github_policy(self.root)
        blocked = run_read(
            "github_list_workflows",
            {"owner": "ubaldexela-cloud", "repo": "mnist-einops-cnn"},
            headers={"Authorization": f"Bearer {token}"},
            client=client,
            policy=policy,
        )
        self.assertEqual(blocked["error"], "github_workflows_disabled")
        self.assertEqual(client.calls, 0)
        self.assertNotIn(token, json.dumps(blocked))
        collaborators = run_read(
            "github_list_collaborators",
            {"owner": "ubaldexela-cloud", "repo": "mnist-einops-cnn"},
            headers={"Authorization": f"Bearer {token}"},
            client=client,
            policy=policy,
        )
        self.assertEqual(collaborators["error"], "github_permissions_disabled")
        self.assertEqual(client.calls, 0)
        outside = run_read(
            "github_get_commit",
            {"owner": "someone-else", "repo": "mnist-einops-cnn", "sha": "abc"},
            headers={"Authorization": f"Bearer {token}"},
            client=client,
            policy=policy,
        )
        self.assertNotEqual(outside.get("error"), None)
        self.assertEqual(client.calls, 0)
        self.assertNotIn(token, json.dumps(outside))


if __name__ == "__main__":
    unittest.main()
