"""Voice-session integration with fake GitHub tools and a local workspace."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from realtime_c.combined_tools import CombinedToolSession
from realtime_c.github_voice import propose_tool
from realtime_c.mcp_tools import TOOL_NAMES


class _Tools:
    available = True
    schemas = {name: {"type": "object", "properties": {}} for name in TOOL_NAMES}

    def call(self, name: str, arguments: dict | None = None) -> str:
        return json.dumps({"ok": True, "tool": name})


class _Github:
    enabled = True
    available = True
    supports_turn_token = True
    _schemas_cached = True

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.schemas = {
            "github_get_repository": {"type": "object"},
            "github_list_repositories": {"type": "object"},
            "github_read_file": {"type": "object"},
            "github_list_commits": {"type": "object"},
            "github_list_pull_requests": {"type": "object"},
            "github_execute_operation": {"type": "object"},
        }

    def call(self, name: str, arguments: dict | None = None, token: Any = None, wait_s: float | None = None) -> str:
        del arguments, token, wait_s
        self.calls.append(name)
        return json.dumps({"ok": True, "tool": name})


class _Ack:
    def __init__(self) -> None:
        self.task_id = "task-read"
        self.operation_id = "op-read"
        self.state = "queued"
        self.duplicate = False


class _Background:
    def __init__(self) -> None:
        self.reads: list[str] = []

    def submit_named_read(self, conversation_id: str, origin: str, tool_name: str, arguments: dict[str, Any]):
        del conversation_id, origin, arguments
        self.reads.append(tool_name)
        return _Ack()


class VoiceIntegrationTests(unittest.TestCase):
    def test_selection_background_and_existing_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "config"
            config.mkdir()
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
            workspace = root / "work"
            workspace.mkdir()
            origin = root / "origin"
            origin.mkdir()
            subprocess.run(["git", "-C", str(origin), "init", "-b", "main"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(origin), "config", "user.email", "icy@example.com"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(origin), "config", "user.name", "ICY"], check=True, capture_output=True)
            (origin / "README.md").write_text("voice\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(origin), "add", "README.md"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(origin), "commit", "-m", "voice"], check=True, capture_output=True)
            (config / "git_workspace.json").write_text(json.dumps({"workspace_root": str(workspace)}), encoding="utf-8")
            github = _Github()
            background = _Background()
            session = CombinedToolSession(
                _Tools(),
                None,
                github,  # type: ignore[arg-type]
                github_policy_root=root,
                background=background,  # type: ignore[arg-type]
                project_root=root,
            )
            for name in TOOL_NAMES:
                self.assertIn(name, session.schemas)
            self.assertEqual(propose_tool("Show me my GitHub repositories.", session.schemas), "github_list_repositories")
            self.assertEqual(propose_tool("Show the latest commits.", session.schemas), "github_list_commits")
            self.assertEqual(propose_tool("Check whether there are open pull requests.", session.schemas), "github_list_pull_requests")
            self.assertIsNone(propose_tool("Create a pull request.", session.schemas))
            started = json.loads(session.call("github_list_commits", {"owner": "ubaldexela-cloud", "repo": "mnist-einops-cnn"}))
            self.assertEqual(started["status"], "in_progress")
            self.assertEqual(started["task_id"], "task-read")
            self.assertEqual(background.reads, ["github_list_commits"])
            self.assertEqual(github.calls, [])
            local = json.loads(session.call("search_web", {"query": "weather"}))
            self.assertEqual(local["tool"], "search_web")
            blocked = json.loads(session.call("github_execute_operation", {}))
            self.assertEqual(blocked["error"], "approval_required")
            self.assertEqual(github.calls, [])
            cloned = json.loads(session.call("git_clone", {"source": str(origin), "destination": "repo"}))
            self.assertTrue(cloned["ok"], cloned)
            status = json.loads(session.call("git_status", {"path": "repo"}))
            self.assertTrue(status["clean"], status)
            session.attach_operations(True)
            self.assertIn("github_prepare_operation", session.schemas)
            self.assertEqual(propose_tool("Create a pull request.", session.schemas), "github_prepare_operation")


if __name__ == "__main__":
    unittest.main()
