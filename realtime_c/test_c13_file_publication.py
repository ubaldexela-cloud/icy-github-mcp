"""C13 file publication through the real MCP wrappers and a fake HTTP client.

No credential read, no socket, and no GitHub child process.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any
from unittest import mock
from urllib.parse import quote

import httpx

from realtime_c import github_approval
from realtime_c.github_approval import (
    GithubPolicy,
    await_publication_approval,
    confirm_publication_authorization,
    load_github_policy,
    prepare_publication_authorization,
    publication_authorization_state,
    reset_publication_authorizations_for_tests,
    visible_github_tool_names,
)
import mcp_servers.github_server as server

ROOT = Path(__file__).resolve().parents[1]
CONFIG_SHA256 = "fd5af162f322429a505b6116071ffc6c345014e64a871b737cba97d164e087e5"
OWNER = "ubaldexela-cloud"
REPO = "my-project"
DESCRIPTION = "Research notes"
MARKER = "preview-body-marker"
API = "https://api.github.com"
MESSAGE = server.CONTENT_COMMIT_MESSAGE


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class FakeHttp:
    def __init__(self, steps: list[tuple[dict[str, Any], Any]], cancel_on_put: threading.Event | None = None) -> None:
        self.steps = list(steps)
        self.calls: list[dict[str, Any]] = []
        self.cancel_on_put = cancel_on_put

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
    ) -> httpx.Response:
        del headers
        if method == "PUT" and self.cancel_on_put is not None:
            self.cancel_on_put.set()
        self.calls.append({"method": method, "url": url, "json": json})
        if not self.steps:
            raise AssertionError(f"unexpected {method} {url}")
        expected, outcome = self.steps.pop(0)
        if expected.get("method") != method or expected.get("url") != url:
            raise AssertionError(f"{method} {url} != {expected}")
        for key, value in expected.get("json", {}).items():
            if json is None or json.get(key) != value:
                raise AssertionError(f"{key}={None if json is None else json.get(key)} != {value}")
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _response(status: int, payload: dict[str, Any] | None = None) -> httpx.Response:
    return httpx.Response(status, json={} if payload is None else payload)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _policy(**overrides: Any) -> GithubPolicy:
    values: dict[str, Any] = {
        "ok": True,
        "error": None,
        "enabled": True,
        "allow_reads": True,
        "allow_writes": True,
        "allow_repo_creation": True,
        "allow_workflows": False,
        "allow_permissions": False,
        "allow_destructive": False,
        "allowed_owner": OWNER,
        "allowed_repos": ("mnist-einops-cnn",),
    }
    values.update(overrides)
    return GithubPolicy(**values)


def _write_config(root: Path, **overrides: Any) -> None:
    data: dict[str, Any] = {
        "enabled": True,
        "allow_reads": True,
        "allow_writes": True,
        "allow_repo_creation": True,
        "allow_workflows": False,
        "allow_permissions": False,
        "allow_destructive": False,
        "allowed_owner": OWNER,
        "allowed_repos": ["mnist-einops-cnn"],
    }
    data.update(overrides)
    config = root / "config"
    config.mkdir(parents=True, exist_ok=True)
    (config / "github_mcp.json").write_text(json.dumps(data), encoding="utf-8")


def _put(path: str, content: str, message: str, sha: str, branch: str = "main", repo: str = REPO) -> tuple[dict[str, Any], Any]:
    url = f"{API}/repos/{OWNER}/{repo}/contents/{quote(path)}"
    return (
        {
            "method": "PUT",
            "url": url,
            "json": {"message": message, "content": _b64(content), "branch": branch},
        },
        _response(201, {"commit": {"sha": sha, "html_url": f"https://github.com/{OWNER}/{repo}/commit/{sha}"}}),
    )


def _get(path: str, content: str, branch: str = "main", repo: str = REPO) -> tuple[dict[str, Any], Any]:
    url = f"{API}/repos/{OWNER}/{repo}/contents/{quote(path)}?ref={quote(branch)}"
    return (
        {"method": "GET", "url": url},
        _response(200, {"type": "file", "encoding": "base64", "path": path, "content": _b64(content)}),
    )


def _pair(path: str, content: str, sha: str, message: str | None = None, branch: str = "main") -> list[tuple[dict[str, Any], Any]]:
    text = MESSAGE if message is None else message
    return [_put(path, content, text, sha, branch), _get(path, content, branch)]


class FilePublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = _Clock()
        self._ids = 0

        def _next_id() -> str:
            self._ids += 1
            return "ghprop_" + f"{self._ids:032x}"

        reset_publication_authorizations_for_tests(clock=self.clock, id_factory=_next_id)
        server.reset_pending_for_tests()
        server.set_repository_creation_client_for_tests(None)
        server.set_content_publication_client_for_tests(None)
        server.set_content_publication_cancel_for_tests(None)
        self.policy = _policy()

    def tearDown(self) -> None:
        server.set_repository_creation_client_for_tests(None)
        server.set_content_publication_client_for_tests(None)
        server.set_content_publication_cancel_for_tests(None)
        server.reset_pending_for_tests()
        reset_publication_authorizations_for_tests()
        config = (ROOT / "config" / "github_mcp.json").read_bytes()
        self.assertEqual(len(config), 1247)
        self.assertEqual(hashlib.sha256(config).hexdigest(), CONFIG_SHA256)
        self.assertEqual(visible_github_tool_names(load_github_policy(ROOT)), frozenset())

    def _accept(
        self,
        files: list[dict[str, str]] | None = None,
        *,
        branch: str = "main",
        repo: str = REPO,
    ) -> tuple[str, str]:
        manifest = files if files is not None else [{"path": "README.md", "content": MARKER}]
        prepared = prepare_publication_authorization(
            self.policy,
            owner=OWNER,
            repo_name=repo,
            visibility="public",
            description=DESCRIPTION,
            branch=branch,
            files=manifest,
            now=self.clock.now,
        )
        self.assertTrue(prepared["ok"], prepared)
        self.assertNotIn(MARKER, json.dumps(prepared["summary"]))
        waiting = await_publication_approval(prepared["authorization_id"], now=self.clock.now)
        self.assertEqual(waiting["state"], "awaiting_approval")
        accepted = confirm_publication_authorization(
            prepared["authorization_id"],
            self.policy,
            owner=OWNER,
            repo_name=repo,
            visibility="public",
            description=DESCRIPTION,
            branch=branch,
            files=manifest,
            now=self.clock.now,
        )
        self.assertTrue(accepted["ok"], accepted)
        self.assertEqual(accepted["authorization_id"], prepared["authorization_id"])
        self.assertNotIn(MARKER, json.dumps(accepted["summary"]))
        self.assertNotIn(MARKER, accepted["spoken_status"])
        content_id = accepted["content_authorization_id"]
        self.assertNotEqual(content_id, prepared["authorization_id"])
        self.assertEqual(publication_authorization_state(content_id), "approval_accepted")
        return prepared["authorization_id"], content_id

    def _open_config(self, **overrides: Any) -> tempfile.TemporaryDirectory[str]:
        tmp = tempfile.TemporaryDirectory()
        _write_config(Path(tmp.name), **overrides)
        return tmp

    def _call(
        self,
        authorization_id: str,
        client: FakeHttp | None,
        root: Path,
        *,
        tool: str = "github_commit_files",
    ) -> dict[str, Any]:
        server.set_content_publication_client_for_tests(client)

        def _headers() -> dict[str, str]:
            return {
                "Authorization": "Bearer fake-test-token",
                "Accept": "application/vnd.github+json",
                "User-Agent": "me3-icy-github-mcp/0.1",
            }

        def _refuse(*_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("network, process, or credential used")

        with mock.patch.object(socket, "create_connection", _refuse), \
                mock.patch.object(subprocess, "Popen", _refuse), \
                mock.patch.object(httpx, "Client", _refuse), \
                mock.patch.object(server, "_auth_token", _refuse), \
                mock.patch.object(server, "_windows_credential_api", _refuse), \
                mock.patch.object(server, "_auth_headers", _headers), \
                mock.patch.dict(os.environ, {"GITHUB_MCP_ROOT": str(root)}):
            raw = getattr(server, tool)(authorization_id)
        result = json.loads(raw)
        self.assertNotIn(MARKER, raw)
        self.assertNotIn("fake-test-token", raw)
        self.assertNotIn("Bearer", raw)
        self.assertNotIn("ghp_", raw)
        self.assertNotIn("confirm_token", raw)
        return result

    def _record(self, authorization_id: str) -> Any:
        return github_approval._PUBLICATIONS.get(authorization_id)

    def test_01_single_file_publication(self) -> None:
        create_id, content_id = self._accept()
        client = FakeHttp(_pair("README.md", MARKER, "sha-readme"))
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertEqual(client.steps, [])
        self.assertEqual([item["method"] for item in client.calls], ["PUT", "GET"])
        self.assertTrue(result["publication_succeeded"], result)
        self.assertTrue(result["publication_complete"])
        self.assertFalse(result["partial"])
        self.assertFalse(result["outcome_uncertain"])
        self.assertEqual(result["verified_paths"], ["README.md"])
        self.assertEqual(result["files"][0]["commit_sha"], "sha-readme")
        self.assertTrue(result["files"][0]["verified"])
        self.assertEqual(publication_authorization_state(content_id), "publication_dispatched")
        self.assertEqual(publication_authorization_state(create_id), "approval_accepted")
        self.assertNotIn("POST", [item["method"] for item in client.calls])

    def test_02_multiple_file_publication(self) -> None:
        files = [
            {"path": "README.md", "content": MARKER},
            {"path": "docs/guide.md", "content": "guide-body"},
        ]
        _create_id, content_id = self._accept(files)
        blocked = FakeHttp([])
        held = self._open_config()
        try:
            refused = self._call(content_id, blocked, Path(held.name), tool="github_create_file")
            self.assertEqual(refused["error"], "manifest_not_single_file")
            self.assertEqual(blocked.calls, [])
            client = FakeHttp(
                _pair("README.md", MARKER, "sha-1", f"{MESSAGE}: README.md")
                + _pair("docs/guide.md", "guide-body", "sha-2", f"{MESSAGE}: docs/guide.md")
            )
            result = self._call(content_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(client.steps, [])
        self.assertEqual(result["intended_manifest_count"], 2)
        self.assertEqual(result["committed_paths"], ["README.md", "docs/guide.md"])
        self.assertEqual(result["verified_paths"], ["README.md", "docs/guide.md"])
        self.assertEqual(result["files"][0]["commit_sha"], "sha-1")
        self.assertEqual(result["files"][1]["commit_sha"], "sha-2")
        self.assertTrue(result["publication_complete"])

    def test_03_put_endpoint_for_every_file(self) -> None:
        self.test_02_multiple_file_publication()

    def test_04_owner_and_repository(self) -> None:
        _create_id, content_id = self._accept()
        client = FakeHttp(_pair("README.md", MARKER, "sha-readme"))
        held = self._open_config()
        try:
            self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertTrue(all(f"/repos/{OWNER}/{REPO}/contents/" in item["url"] for item in client.calls))

    def test_05_path_encoding(self) -> None:
        path = "docs/my notes.md"
        _create_id, content_id = self._accept([
            {"path": "README.md", "content": MARKER},
            {"path": path, "content": "spaced"},
        ])
        client = FakeHttp(
            _pair("README.md", MARKER, "sha-1", f"{MESSAGE}: README.md")
            + _pair(path, "spaced", "sha-2", f"{MESSAGE}: {path}")
        )
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name))
        finally:
            held.cleanup()
        encoded = quote(path)
        self.assertIn(encoded, client.calls[2]["url"])
        self.assertNotIn(" ", client.calls[2]["url"])
        self.assertTrue(result["publication_complete"])

    def test_06_base64_content(self) -> None:
        _create_id, content_id = self._accept()
        client = FakeHttp(_pair("README.md", MARKER, "sha-readme"))
        held = self._open_config()
        try:
            self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertEqual(client.calls[0]["json"]["content"], _b64(MARKER))

    def test_07_branch(self) -> None:
        _create_id, content_id = self._accept(branch="dev")
        client = FakeHttp(_pair("README.md", MARKER, "sha-readme", branch="dev"))
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertEqual(client.calls[0]["json"]["branch"], "dev")
        self.assertIn("ref=dev", client.calls[1]["url"])
        self.assertTrue(result["publication_succeeded"])

    def test_08_commit_message(self) -> None:
        _create_id, content_id = self._accept()
        client = FakeHttp(_pair("README.md", MARKER, "sha-readme"))
        held = self._open_config()
        try:
            self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertEqual(client.calls[0]["json"]["message"], MESSAGE)

    def test_09_separate_commit_shas(self) -> None:
        files = [
            {"path": "README.md", "content": MARKER},
            {"path": "docs/guide.md", "content": "guide-body"},
        ]
        _create_id, content_id = self._accept(files)
        client = FakeHttp(
            _pair("README.md", MARKER, "commit-aaa", f"{MESSAGE}: README.md")
            + _pair("docs/guide.md", "guide-body", "commit-bbb", f"{MESSAGE}: docs/guide.md")
        )
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual([item["commit_sha"] for item in result["files"]], ["commit-aaa", "commit-bbb"])
        self.assertNotEqual(result["files"][0]["commit_sha"], result["files"][1]["commit_sha"])

    def test_10_nested_directory_paths(self) -> None:
        path = "docs/guide/intro.md"
        _create_id, content_id = self._accept([
            {"path": "README.md", "content": MARKER},
            {"path": path, "content": "intro"},
        ])
        client = FakeHttp(
            _pair("README.md", MARKER, "sha-1", f"{MESSAGE}: README.md")
            + _pair(path, "intro", "sha-2", f"{MESSAGE}: {path}")
        )
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertIn("/contents/docs/guide/intro.md", client.calls[2]["url"])
        self.assertEqual(result["verified_paths"], ["README.md", path])

    def test_11_utf8_text(self) -> None:
        text = "café — 你好"
        _create_id, content_id = self._accept([{"path": "README.md", "content": text}])
        client = FakeHttp(_pair("README.md", text, "sha-utf8"))
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertEqual(client.calls[0]["json"]["content"], _b64(text))
        self.assertEqual(result["files"][0]["sha256"], hashlib.sha256(text.encode("utf-8")).hexdigest())
        self.assertTrue(result["files"][0]["verified"])

    def test_12_empty_file(self) -> None:
        _create_id, content_id = self._accept([{"path": "README.md", "content": ""}])
        client = FakeHttp(_pair("README.md", "", "sha-empty"))
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertEqual(client.calls[0]["json"]["content"], "")
        self.assertTrue(result["publication_succeeded"], result)

    def test_13_missing_file_content(self) -> None:
        prepared = prepare_publication_authorization(
            self.policy,
            owner=OWNER,
            repo_name=REPO,
            visibility="public",
            description=DESCRIPTION,
            branch="main",
            files=[{"path": "README.md", "content": None}],
            now=self.clock.now,
        )
        self.assertEqual(prepared["error"], "invalid_manifest_file")
        client = FakeHttp([])
        held = self._open_config()
        try:
            result = self._call("ghprop_missing", client, Path(held.name))
        finally:
            held.cleanup()
        self.assertNotEqual(result.get("publication_succeeded"), True)
        self.assertEqual(client.calls, [])

    def test_14_invalid_path(self) -> None:
        prepared = prepare_publication_authorization(
            self.policy,
            owner=OWNER,
            repo_name=REPO,
            visibility="public",
            description=DESCRIPTION,
            branch="main",
            files=[{"path": "../README.md", "content": MARKER}],
            now=self.clock.now,
        )
        self.assertEqual(prepared["error"], "invalid_manifest_file")
        client = FakeHttp([])
        held = self._open_config()
        try:
            self._call("ghprop_missing", client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(client.calls, [])

    def test_15_duplicate_paths(self) -> None:
        prepared = prepare_publication_authorization(
            self.policy,
            owner=OWNER,
            repo_name=REPO,
            visibility="public",
            description=DESCRIPTION,
            branch="main",
            files=[
                {"path": "README.md", "content": MARKER},
                {"path": "README.md", "content": "other"},
            ],
            now=self.clock.now,
        )
        self.assertEqual(prepared["error"], "duplicate_manifest_path")

    def test_16_existing_file_conflict(self) -> None:
        _create_id, content_id = self._accept()
        client = FakeHttp([
            (_put("README.md", MARKER, MESSAGE, "unused")[0], _response(422, {"message": "sha missing"})),
        ])
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertEqual([item["method"] for item in client.calls], ["PUT"])
        self.assertEqual(result["error"], "file_conflict")
        self.assertEqual(result["verified_paths"], [])
        self.assertFalse(result["publication_succeeded"])
        self.assertFalse(result["outcome_uncertain"])
        self.assertTrue(result["authorization_consumed"])
        self.assertEqual(publication_authorization_state(content_id), "publication_dispatched")

    def test_17_branch_mismatch_uses_only_the_approved_branch(self) -> None:
        _create_id, content_id = self._accept(branch="feature")
        client = FakeHttp(_pair("README.md", MARKER, "sha-feature", branch="feature"))
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertEqual(client.calls[0]["json"]["branch"], "feature")
        self.assertNotIn("ref=main", client.calls[1]["url"])
        self.assertTrue(result["publication_succeeded"])

    def test_18_partial_publication_when_a_later_put_fails(self) -> None:
        files = [
            {"path": "README.md", "content": MARKER},
            {"path": "docs/guide.md", "content": "guide-body"},
        ]
        _create_id, content_id = self._accept(files)
        failed = _put("docs/guide.md", "guide-body", f"{MESSAGE}: docs/guide.md", "nope")
        client = FakeHttp(
            _pair("README.md", MARKER, "sha-1", f"{MESSAGE}: README.md")
            + [(failed[0], _response(500, {"message": "nope"}))]
        )
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual([item["method"] for item in client.calls], ["PUT", "GET", "PUT"])
        self.assertEqual(result["committed_paths"], ["README.md"])
        self.assertEqual(result["verified_paths"], ["README.md"])
        self.assertEqual(result["failed_path"], "docs/guide.md")
        self.assertTrue(result["partial"])
        self.assertTrue(result["repository_may_contain_partial_publication"])
        self.assertFalse(result["publication_complete"])
        self.assertEqual(result["files"][0]["commit_sha"], "sha-1")
        self.assertEqual(client.steps, [])

    def test_19_stop_on_first_failure(self) -> None:
        files = [
            {"path": "README.md", "content": MARKER},
            {"path": "docs/guide.md", "content": "guide-body"},
            {"path": "docs/tail.md", "content": "tail"},
        ]
        _create_id, content_id = self._accept(files)
        failed = _put("docs/guide.md", "guide-body", f"{MESSAGE}: docs/guide.md", "nope")
        client = FakeHttp(
            _pair("README.md", MARKER, "sha-1", f"{MESSAGE}: README.md")
            + [(failed[0], _response(422))]
        )
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertNotIn("docs/tail.md", result["committed_paths"])
        self.assertEqual(result["failed_path"], "docs/guide.md")
        self.assertTrue(all("docs/tail.md" not in item["url"] for item in client.calls))

    def test_20_mandatory_get_after_successful_put(self) -> None:
        _create_id, content_id = self._accept()
        client = FakeHttp(_pair("README.md", MARKER, "sha-readme"))
        held = self._open_config()
        try:
            self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertEqual(client.calls[0]["method"], "PUT")
        self.assertEqual(client.calls[1]["method"], "GET")
        self.assertIn("/contents/README.md?ref=main", client.calls[1]["url"])

    def test_21_content_hash_verification(self) -> None:
        text = "hashed-body"
        _create_id, content_id = self._accept([{"path": "README.md", "content": text}])
        client = FakeHttp(_pair("README.md", text, "sha-hash"))
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertEqual(result["files"][0]["sha256"], hashlib.sha256(text.encode("utf-8")).hexdigest())
        self.assertTrue(result["files"][0]["verified"])

    def test_22_verification_mismatch(self) -> None:
        _create_id, content_id = self._accept()
        client = FakeHttp([
            _put("README.md", MARKER, MESSAGE, "sha-bad"),
            _get("README.md", "different-body"),
        ])
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertEqual([item["method"] for item in client.calls], ["PUT", "GET"])
        self.assertEqual(result["error"], "verification_mismatch")
        self.assertEqual(result["files"][0]["commit_sha"], "sha-bad")
        self.assertFalse(result["files"][0]["verified"])
        self.assertTrue(result["repository_may_contain_partial_publication"])
        self.assertFalse(result["publication_succeeded"])
        self.assertTrue(result["authorization_consumed"])
        self.assertEqual(publication_authorization_state(content_id), "publication_dispatched")
        self.assertFalse(result["outcome_uncertain"])

    def test_23_missing_verification_response(self) -> None:
        _create_id, content_id = self._accept()
        client = FakeHttp([
            _put("README.md", MARKER, MESSAGE, "sha-missing"),
            ({"method": "GET", "url": f"{API}/repos/{OWNER}/{REPO}/contents/README.md?ref=main"}, _response(404)),
        ])
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "verification_missing")
        self.assertEqual(result["files"][0]["commit_sha"], "sha-missing")
        self.assertFalse(result["files"][0]["verified"])
        self.assertTrue(result["outcome_uncertain"])
        self.assertFalse(result["may_still_be_running"])
        self.assertFalse(result["publication_complete"])
        self.assertEqual(publication_authorization_state(content_id), "publication_outcome_uncertain")

    def test_24_verification_timeout(self) -> None:
        _create_id, content_id = self._accept()
        client = FakeHttp([
            _put("README.md", MARKER, MESSAGE, "sha-slow"),
            (
                {"method": "GET", "url": f"{API}/repos/{OWNER}/{REPO}/contents/README.md?ref=main"},
                httpx.TimeoutException("verification timed out"),
            ),
        ])
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertEqual([item["method"] for item in client.calls], ["PUT", "GET"])
        self.assertEqual(result["error"], "verification_timeout")
        self.assertEqual(result["files"][0]["commit_sha"], "sha-slow")
        self.assertTrue(result["outcome_uncertain"])
        self.assertFalse(result["publication_succeeded"])
        self.assertTrue(result["may_still_be_running"])

    def test_25_write_disabled_policy(self) -> None:
        _create_id, content_id = self._accept()
        client = FakeHttp(_pair("README.md", MARKER, "sha-readme"))
        held = self._open_config(allow_writes=False)
        try:
            result = self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "github_writes_disabled")
        self.assertEqual(client.calls, [])
        self.assertEqual(publication_authorization_state(content_id), "approval_accepted")

    def test_26_github_disabled_policy(self) -> None:
        _create_id, content_id = self._accept()
        client = FakeHttp(_pair("README.md", MARKER, "sha-readme"))
        held = self._open_config(enabled=False)
        try:
            result = self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "github_mcp_disabled")
        self.assertEqual(client.calls, [])

    def test_27_missing_content_authorization(self) -> None:
        client = FakeHttp([])
        held = self._open_config()
        try:
            result = self._call("ghprop_" + "0" * 32, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "host_approval_required")
        self.assertFalse(result["write_attempted"])
        self.assertEqual(client.calls, [])

    def test_28_expired_authorization(self) -> None:
        _create_id, content_id = self._accept()
        self.clock.now = 1300.0
        client = FakeHttp([])
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "approval_expired")
        self.assertEqual(client.calls, [])
        self.assertEqual(publication_authorization_state(content_id), "approval_expired")

    def test_29_consumed_authorization(self) -> None:
        _create_id, content_id = self._accept()
        from realtime_c.github_approval import consume_publication_authorization

        consumed = consume_publication_authorization(content_id, now=self.clock.now)
        self.assertEqual(consumed["state"], "approval_consumed")
        client = FakeHttp([])
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "approval_consumed")
        self.assertEqual(client.calls, [])

    def test_30_wrong_repository_authorization(self) -> None:
        _create_id, content_id = self._accept()
        self._record(content_id).repo_name = "other-repo"
        client = FakeHttp([])
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "manifest_changed")
        self.assertEqual(client.calls, [])
        self.assertEqual(publication_authorization_state(content_id), "approval_accepted")

    def test_31_wrong_branch_authorization(self) -> None:
        _create_id, content_id = self._accept(branch="dev")
        self._record(content_id).branch = "main"
        client = FakeHttp([])
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "manifest_changed")
        self.assertEqual(client.calls, [])
        self.assertEqual(publication_authorization_state(content_id), "approval_accepted")

    def test_32_changed_manifest(self) -> None:
        _create_id, content_id = self._accept()
        self._record(content_id).description = "A different description"
        client = FakeHttp([])
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "manifest_changed")
        self.assertEqual(client.calls, [])

    def test_33_changed_file_hash(self) -> None:
        _create_id, content_id = self._accept()
        self._record(content_id).contents["README.md"] = MARKER + "!"
        client = FakeHttp([])
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "changed_file_hash")
        self.assertEqual(client.calls, [])
        self.assertEqual(publication_authorization_state(content_id), "approval_accepted")

    def test_34_unauthorized_file_added_after_approval(self) -> None:
        _create_id, content_id = self._accept()
        self._record(content_id).contents["extra.md"] = "nope"
        client = FakeHttp([])
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "manifest_changed")
        self.assertEqual(client.calls, [])

    def test_35_unauthorized_file_removed_after_approval(self) -> None:
        _create_id, content_id = self._accept([
            {"path": "README.md", "content": MARKER},
            {"path": "docs/guide.md", "content": "guide-body"},
        ])
        del self._record(content_id).contents["docs/guide.md"]
        client = FakeHttp([])
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "manifest_changed")
        self.assertEqual(client.calls, [])

    def test_36_duplicate_publication_attempt(self) -> None:
        _create_id, content_id = self._accept()
        first = FakeHttp(_pair("README.md", MARKER, "sha-once"))
        second = FakeHttp(_pair("README.md", MARKER, "sha-again"))
        held = self._open_config()
        try:
            done = self._call(content_id, first, Path(held.name), tool="github_create_file")
            again = self._call(content_id, second, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertTrue(done["publication_succeeded"])
        self.assertEqual(again["error"], "approval_consumed")
        self.assertEqual(second.calls, [])
        self.assertFalse(again.get("publication_succeeded", False))

    def test_37_cancellation_before_dispatch(self) -> None:
        _create_id, content_id = self._accept()
        cancel = threading.Event()
        cancel.set()
        server.set_content_publication_cancel_for_tests(cancel)
        client = FakeHttp(_pair("README.md", MARKER, "sha-readme"))
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "publication_cancelled")
        self.assertEqual(client.calls, [])
        self.assertFalse(result["authorization_consumed"])
        self.assertEqual(publication_authorization_state(content_id), "approval_accepted")

    def test_38_cancellation_during_an_in_flight_put(self) -> None:
        files = [
            {"path": "README.md", "content": MARKER},
            {"path": "docs/guide.md", "content": "guide-body"},
        ]
        _create_id, content_id = self._accept(files)
        cancel = threading.Event()
        server.set_content_publication_cancel_for_tests(cancel)
        client = FakeHttp(
            _pair("README.md", MARKER, "sha-1", f"{MESSAGE}: README.md"),
            cancel_on_put=cancel,
        )
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual([item["method"] for item in client.calls], ["PUT", "GET"])
        self.assertEqual(result["verified_paths"], ["README.md"])
        self.assertEqual(result["failed_path"], "docs/guide.md")
        self.assertEqual(result["error"], "publication_cancelled")
        self.assertTrue(result["partial"])
        self.assertFalse(result["may_still_be_running"])
        self.assertNotIn("docs/guide.md", result["committed_paths"])

    def test_39_no_blind_retry_after_an_uncertain_put(self) -> None:
        _create_id, content_id = self._accept()
        put = _put("README.md", MARKER, MESSAGE, "unused")
        client = FakeHttp([
            (put[0], httpx.TimeoutException("put timed out")),
            _get("README.md", MARKER),
        ])
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        self.assertEqual([item["method"] for item in client.calls], ["PUT", "GET"])
        self.assertTrue(result["publication_succeeded"], result)
        self.assertTrue(result["files"][0]["verified"])
        self.assertTrue(result["files"][0]["recovered"])
        self.assertEqual(result["files"][0]["commit_sha"], "")

    def test_40_no_credential_or_token_leakage(self) -> None:
        _create_id, content_id = self._accept()
        client = FakeHttp(_pair("README.md", MARKER, "sha-readme"))
        held = self._open_config()
        try:
            result = self._call(content_id, client, Path(held.name), tool="github_create_file")
        finally:
            held.cleanup()
        encoded = json.dumps(result)
        self.assertNotIn("fake-test-token", encoded)
        self.assertNotIn(MARKER, encoded)
        self.assertNotIn("Authorization", encoded)
        for call in client.calls:
            self.assertNotIn("headers", call)
            self.assertNotIn("fake-test-token", json.dumps(call))
        opened = visible_github_tool_names(_policy(allow_writes=True, allow_repo_creation=True))
        self.assertEqual(opened, frozenset({"github_get_repository"}))

    def test_41_grants_are_independent(self) -> None:
        create_id, content_id = self._accept()
        publish_client = FakeHttp([])
        held = self._open_config()
        try:
            blocked = self._call(create_id, publish_client, Path(held.name))
            self.assertEqual(blocked["error"], "creation_grant_cannot_publish")
            self.assertEqual(publish_client.calls, [])
            self.assertEqual(publication_authorization_state(create_id), "approval_accepted")
            server.set_repository_creation_client_for_tests(FakeHttp([
                ({"method": "GET", "url": f"{API}/user"}, _response(200, {"login": OWNER})),
            ]))
            with mock.patch.object(socket, "create_connection", side_effect=AssertionError("socket")), \
                    mock.patch.object(subprocess, "Popen", side_effect=AssertionError("process")), \
                    mock.patch.object(httpx, "Client", side_effect=AssertionError("client")), \
                    mock.patch.object(server, "_auth_token", side_effect=AssertionError("token")), \
                    mock.patch.object(server, "_windows_credential_api", side_effect=AssertionError("cred")), \
                    mock.patch.object(server, "_auth_headers", return_value={"Authorization": "Bearer fake-test-token"}), \
                    mock.patch.dict(os.environ, {"GITHUB_MCP_ROOT": str(Path(held.name))}):
                created = json.loads(server.github_create_repository(content_id))
        finally:
            held.cleanup()
        self.assertEqual(created["error"], "content_grant_cannot_create_repository")
        self.assertFalse(created["write_attempted"])
        self.assertEqual(publication_authorization_state(content_id), "approval_accepted")
        self.assertEqual(
            json.loads((ROOT / "config" / "github_mcp.json").read_text(encoding="utf-8"))["allowed_repos"],
            ["mnist-einops-cnn"],
        )


if __name__ == "__main__":
    unittest.main()
