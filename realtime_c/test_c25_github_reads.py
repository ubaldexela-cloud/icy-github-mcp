"""Fake-HTTP coverage for GitHub read tools. No live GitHub call."""

from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from mcp_servers import github_reads
from mcp_servers import github_server as gh
from realtime_c.github_approval import GithubPolicy


def _policy(**overrides: Any) -> GithubPolicy:
    values: dict[str, Any] = {
        "ok": True,
        "error": None,
        "enabled": True,
        "allow_reads": True,
        "allow_writes": False,
        "allow_repo_creation": False,
        "allow_workflows": False,
        "allow_permissions": False,
        "allow_destructive": False,
        "allowed_owner": "ubaldexela-cloud",
        "allowed_repos": ("mnist-einops-cnn",),
    }
    values.update(overrides)
    return GithubPolicy(**values)


class _Response:
    def __init__(self, status: int, payload: Any, headers: dict[str, str] | None = None) -> None:
        self.status_code = status
        self._payload = payload
        self.headers = headers or {}
        if payload is None:
            self.content = b""
        else:
            self.content = json.dumps(payload).encode("utf-8")

    def json(self) -> Any:
        if self._payload is Ellipsis:
            raise ValueError("malformed")
        return self._payload


class _Client:
    def __init__(self, routes: list[tuple[str, _Response]]) -> None:
        self.routes = routes
        self.calls: list[dict[str, str]] = []

    def request(self, method: str, url: str, headers: dict[str, str] | None = None, json: Any = None) -> _Response:
        del headers, json
        if method != "GET":
            raise AssertionError(method)
        self.calls.append({"method": method, "url": url})
        matches = [(needle, response) for needle, response in self.routes if needle in url]
        if not matches:
            raise AssertionError(url)
        matches.sort(key=lambda item: len(item[0]), reverse=True)
        return matches[0][1]


class ReadOperationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = _policy()
        self.headers = {"Authorization": "Bearer unit-test"}

    def _run(self, operation: str, client: _Client, **arguments: Any) -> dict[str, Any]:
        return github_reads.run_read(
            operation,
            arguments,
            headers=self.headers,
            client=client,
            policy=self.policy,
        )

    def test_repository_list_is_filtered_and_paginated(self) -> None:
        page2 = f"{github_reads.GITHUB_API}/user/repos?page=2"
        client = _Client([
            (page2, _Response(200, [{"name": "mnist-einops-cnn", "full_name": "ubaldexela-cloud/mnist-einops-cnn", "private": False, "default_branch": "main", "owner": {"login": "ubaldexela-cloud"}}])),
            ("/user/repos", _Response(200, [
                {"name": "secret-repo", "full_name": "other/secret-repo", "private": True, "owner": {"login": "other"}},
                {"name": "mnist-einops-cnn", "full_name": "someone/mnist-einops-cnn", "private": False, "owner": {"login": "someone"}},
            ], {"link": f'<{page2}>; rel="next"'})),
        ])
        result = self._run("github_list_repositories", client)
        self.assertTrue(result["ok"], result)
        self.assertEqual([item["full_name"] for item in result["repositories"]], ["ubaldexela-cloud/mnist-einops-cnn"])
        self.assertEqual([item["method"] for item in client.calls], ["GET", "GET"])

    def test_missing_permission_rate_and_malformed(self) -> None:
        missing = self._run("github_list_branches", _Client([("/branches", _Response(404, {"message": "Not Found"}))]), owner="ubaldexela-cloud", repo="mnist-einops-cnn")
        self.assertEqual(missing["error"], "github_not_found")
        denied = self._run("github_list_tags", _Client([("/tags", _Response(403, {"message": "Resource not accessible"}))]), owner="ubaldexela-cloud", repo="mnist-einops-cnn")
        self.assertEqual(denied["error"], "github_permission_denied")
        limited = self._run("github_list_issues", _Client([("/issues", _Response(429, {"message": "rate limit"}))]), owner="ubaldexela-cloud", repo="mnist-einops-cnn")
        self.assertEqual(limited["error"], "github_rate_limited")
        bad = self._run("github_list_commits", _Client([("/commits", _Response(200, {"unexpected": True}))]), owner="ubaldexela-cloud", repo="mnist-einops-cnn")
        self.assertEqual(bad["error"], "github_malformed_response")
        auth = self._run("github_get_issue", _Client([("/issues/1", _Response(401, {"message": "Bad credentials"}))]), owner="ubaldexela-cloud", repo="mnist-einops-cnn", number=1)
        self.assertEqual(auth["error"], "github_auth_invalid")

    def test_file_commit_compare_and_pulls(self) -> None:
        raw = base64.b64encode(b"hello read").decode("ascii")
        client = _Client([
            ("/contents/README.md", _Response(200, {"type": "file", "encoding": "base64", "content": raw, "path": "README.md", "size": 10, "sha": "abc"})),
            ("/contents", _Response(200, [{"name": "README.md", "type": "file", "path": "README.md", "size": 10}])),
            ("/commits/abc", _Response(200, {"sha": "abc", "commit": {"message": "Add read"}, "files": [{"filename": "README.md", "status": "added", "changes": 1}]})),
            ("/commits", _Response(200, [{"sha": "abc", "commit": {"message": "Add read", "author": {"date": "2026-01-01T00:00:00Z"}}}] )),
            ("/compare/", _Response(200, {"status": "ahead", "ahead_by": 1, "behind_by": 0, "total_commits": 1, "files": [{"filename": "README.md", "status": "added"}]})),
            ("/pulls/4/comments", _Response(200, [{"user": {"login": "octo"}, "body": "looks good"}])),
            ("/pulls/4/reviews", _Response(200, [{"user": {"login": "octo"}, "state": "APPROVED"}])),
            ("/pulls/4", _Response(200, {"number": 4, "title": "Read tools", "state": "open", "merged": False, "head": {"ref": "feature"}, "base": {"ref": "main"}, "body": "body"})),
            ("/pulls", _Response(200, [{"number": 4, "title": "Read tools", "state": "open"}])),
        ])
        listed = self._run("github_list_contents", client, owner="ubaldexela-cloud", repo="mnist-einops-cnn", path="")
        self.assertEqual(listed["entries"][0]["name"], "README.md")
        text = self._run("github_read_file", client, owner="ubaldexela-cloud", repo="mnist-einops-cnn", path="README.md")
        self.assertEqual(text["text"], "hello read")
        commit = self._run("github_get_commit", client, owner="ubaldexela-cloud", repo="mnist-einops-cnn", sha="abc")
        self.assertEqual(commit["files"][0]["filename"], "README.md")
        compared = self._run("github_compare_refs", client, owner="ubaldexela-cloud", repo="mnist-einops-cnn", base="main", head="feature")
        self.assertEqual(compared["ahead_by"], 1)
        pulls = self._run("github_list_pull_requests", client, owner="ubaldexela-cloud", repo="mnist-einops-cnn")
        self.assertEqual(pulls["pull_requests"][0]["number"], 4)
        comments = self._run("github_list_pull_request_comments", client, owner="ubaldexela-cloud", repo="mnist-einops-cnn", number=4)
        self.assertEqual(comments["reviews"][0]["state"], "APPROVED")
        self.assertTrue(all(item["method"] == "GET" for item in client.calls))

    def test_policy_blocks_collaborators_workflows_and_other_repos(self) -> None:
        client = _Client([])
        blocked = self._run("github_list_collaborators", client, owner="ubaldexela-cloud", repo="mnist-einops-cnn")
        self.assertEqual(blocked["error"], "github_permissions_disabled")
        workflows = self._run("github_list_workflows", client, owner="ubaldexela-cloud", repo="mnist-einops-cnn")
        self.assertEqual(workflows["error"], "github_workflows_disabled")
        outside = self._run("github_list_branches", client, owner="ubaldexela-cloud", repo="icy-github-mcp")
        self.assertEqual(outside["error"], "repo_not_allowlisted")
        self.assertEqual(client.calls, [])
        opened = _policy(allow_workflows=True, allow_permissions=True)
        allowed = _Client([
            ("/collaborators", _Response(200, [{"login": "octo", "role_name": "admin"}])),
            ("/actions/workflows", _Response(200, {"workflows": [{"id": 1, "name": "CI", "path": ".github/workflows/ci.yml", "state": "active"}]})),
            ("/actions/runs/9/logs", _Response(302, None, {})),
            ("/actions/runs", _Response(200, {"workflow_runs": [{"id": 9, "name": "CI", "status": "completed", "conclusion": "success"}]})),
            ("/releases/tags/v1", _Response(200, {"id": 3, "tag_name": "v1", "name": "One", "draft": False, "body": "notes"})),
            ("/releases", _Response(200, [{"id": 3, "tag_name": "v1", "name": "One", "draft": False}])),
        ])
        people = github_reads.run_read("github_list_collaborators", {"owner": "ubaldexela-cloud", "repo": "mnist-einops-cnn"}, headers=self.headers, client=allowed, policy=opened)
        self.assertEqual(people["collaborators"][0]["login"], "octo")
        flows = github_reads.run_read("github_list_workflows", {"owner": "ubaldexela-cloud", "repo": "mnist-einops-cnn"}, headers=self.headers, client=allowed, policy=opened)
        self.assertEqual(flows["workflows"][0]["name"], "CI")
        runs = github_reads.run_read("github_list_workflow_runs", {"owner": "ubaldexela-cloud", "repo": "mnist-einops-cnn"}, headers=self.headers, client=allowed, policy=opened)
        self.assertEqual(runs["runs"][0]["conclusion"], "success")
        log = github_reads.run_read("github_read_workflow_log", {"owner": "ubaldexela-cloud", "repo": "mnist-einops-cnn", "run_id": "9"}, headers=self.headers, client=allowed, policy=opened)
        self.assertTrue(log["log_available"])
        self.assertFalse(log["downloaded"])
        release = github_reads.run_read("github_get_release", {"owner": "ubaldexela-cloud", "repo": "mnist-einops-cnn", "tag": "v1"}, headers=self.headers, client=allowed, policy=opened)
        self.assertEqual(release["tag"], "v1")

    def test_registered_tool_stays_read_only_and_fail_closed(self) -> None:
        self.assertTrue(hasattr(gh, "github_list_branches"))
        self.assertTrue(hasattr(gh, "github_read_file"))
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
            client = _Client([("/branches", _Response(200, [{"name": "main"}]))])
            with patch.dict(os.environ, {"GITHUB_MCP_ROOT": str(root)}):
                gh.set_read_client_for_tests(client, {"Authorization": "Bearer unit-test"})
                try:
                    body = json.loads(gh.github_list_branches("ubaldexela-cloud", "mnist-einops-cnn"))
                finally:
                    gh.set_read_client_for_tests(None, None)
            self.assertTrue(body["ok"], body)
            self.assertEqual(body["branches"], ["main"])
            self.assertEqual(client.calls[0]["method"], "GET")
        disabled = json.loads(gh.github_list_branches("ubaldexela-cloud", "mnist-einops-cnn"))
        self.assertEqual(disabled["error"], "github_mcp_disabled")


if __name__ == "__main__":
    unittest.main()
