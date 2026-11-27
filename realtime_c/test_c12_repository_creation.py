"""C12 repository creation through the real MCP wrapper and a fake HTTP client.

No credential read, no socket, and no GitHub child process.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

import httpx

from realtime_c.github_approval import (
    GithubPolicy,
    await_publication_approval,
    confirm_publication_authorization,
    consume_publication_authorization,
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
USER_URL = f"{API}/user"
CREATE_URL = f"{API}/user/repos"


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class FakeHttp:
    def __init__(self, steps: list[tuple[dict[str, Any], Any]]) -> None:
        self.steps = list(steps)
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str, url: str, headers: dict[str, str] | None = None, json: dict[str, Any] | None = None) -> httpx.Response:
        del headers
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

    @property
    def posts(self) -> list[dict[str, Any]]:
        return [item for item in self.calls if item["method"] == "POST"]


def _response(status: int, payload: dict[str, Any] | None = None) -> httpx.Response:
    return httpx.Response(status, json={} if payload is None else payload)


def _user(login: str = OWNER) -> httpx.Response:
    return _response(200, {"login": login})


def _repo_body(
    *,
    name: str = REPO,
    description: str = DESCRIPTION,
    login: str = OWNER,
    private: bool = False,
    size: int = 0,
    visibility: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "full_name": f"{login}/{name}",
        "html_url": f"https://github.com/{login}/{name}",
        "description": description,
        "private": private,
        "visibility": visibility or ("private" if private else "public"),
        "size": size,
        "default_branch": "main",
        "owner": {"login": login},
    }


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


def _manifest() -> list[dict[str, str]]:
    return [{"path": "README.md", "content": MARKER}]


class RepositoryCreationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = _Clock()
        self._ids = 0

        def _next_id() -> str:
            self._ids += 1
            return "ghprop_" + f"{self._ids:032x}"

        reset_publication_authorizations_for_tests(clock=self.clock, id_factory=_next_id)
        server.reset_pending_for_tests()
        server.set_repository_creation_client_for_tests(None)
        self.policy = _policy()

    def tearDown(self) -> None:
        server.set_repository_creation_client_for_tests(None)
        server.reset_pending_for_tests()
        reset_publication_authorizations_for_tests()
        config = (ROOT / "config" / "github_mcp.json").read_bytes()
        self.assertEqual(len(config), 1247)
        self.assertEqual(hashlib.sha256(config).hexdigest(), CONFIG_SHA256)

    def _accept(self, *, repo: str = REPO, description: str = DESCRIPTION, visibility: str = "public") -> str:
        prepared = prepare_publication_authorization(
            self.policy,
            owner=OWNER,
            repo_name=repo,
            visibility=visibility,
            description=description,
            branch="main",
            files=_manifest(),
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
            visibility=visibility,
            description=description,
            branch="main",
            files=_manifest(),
            now=self.clock.now,
        )
        self.assertTrue(accepted["ok"], accepted)
        return prepared["authorization_id"]

    def _open_config(self, **overrides: Any) -> tempfile.TemporaryDirectory[str]:
        tmp = tempfile.TemporaryDirectory()
        _write_config(Path(tmp.name), **overrides)
        return tmp

    def _call(self, authorization_id: str, client: FakeHttp | None, root: Path) -> dict[str, Any]:
        server.set_repository_creation_client_for_tests(client)

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
            raw = server.github_create_repository(authorization_id)
        result = json.loads(raw)
        self.assertNotIn(MARKER, raw)
        self.assertNotIn("fake-test-token", raw)
        self.assertNotIn("confirm_token", raw)
        return result

    def _absent_then_post(self, post: Any) -> list[tuple[dict[str, Any], Any]]:
        return [
            ({"method": "GET", "url": USER_URL}, _user()),
            ({"method": "GET", "url": f"{API}/repos/{OWNER}/{REPO}"}, _response(404)),
            ({
                "method": "POST",
                "url": CREATE_URL,
                "json": {
                    "name": REPO,
                    "description": DESCRIPTION,
                    "private": False,
                    "auto_init": False,
                    "has_issues": False,
                    "has_projects": False,
                    "has_wiki": False,
                },
            }, post),
        ]

    def test_01_through_09_verified_public_create(self) -> None:
        authorization_id = self._accept()
        self.assertEqual(publication_authorization_state(authorization_id), "approval_accepted")
        post_body = _repo_body()
        client = FakeHttp(self._absent_then_post(_response(201, post_body)) + [
            ({"method": "GET", "url": USER_URL}, _user()),
        ])
        held = self._open_config()
        try:
            result = self._call(authorization_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(len(client.posts), 1)
        self.assertEqual(client.posts[0]["url"], CREATE_URL)
        self.assertEqual(client.posts[0]["json"]["name"], REPO)
        self.assertIs(client.posts[0]["json"]["private"], False)
        self.assertEqual(client.posts[0]["json"]["description"], DESCRIPTION)
        self.assertIs(client.posts[0]["json"]["auto_init"], False)
        self.assertIs(client.posts[0]["json"]["has_issues"], False)
        self.assertIs(client.posts[0]["json"]["has_projects"], False)
        self.assertIs(client.posts[0]["json"]["has_wiki"], False)
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["publication_succeeded"])
        self.assertFalse(result["recovered"])
        self.assertEqual(result["full_name"], f"{OWNER}/{REPO}")
        self.assertEqual(result["html_url"], f"https://github.com/{OWNER}/{REPO}")
        self.assertIs(result["private"], False)
        self.assertEqual(publication_authorization_state(authorization_id), "publication_dispatched")
        self.assertEqual(client.steps, [])

    def test_10_matching_repository_already_exists(self) -> None:
        authorization_id = self._accept()
        client = FakeHttp([
            ({"method": "GET", "url": USER_URL}, _user()),
            ({"method": "GET", "url": f"{API}/repos/{OWNER}/{REPO}"}, _response(200, _repo_body())),
        ])
        held = self._open_config()
        try:
            result = self._call(authorization_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["recovered"])
        self.assertEqual(result["full_name"], f"{OWNER}/{REPO}")
        self.assertEqual(result["html_url"], f"https://github.com/{OWNER}/{REPO}")
        self.assertEqual(client.posts, [])
        self.assertFalse(result["write_attempted"])

    def test_11_name_conflict_does_not_substitute_a_repository(self) -> None:
        authorization_id = self._accept()
        occupied = _repo_body(private=True, visibility="private", size=4)
        client = FakeHttp(self._absent_then_post(_response(422, {"message": "name exists"})) + [
            ({"method": "GET", "url": USER_URL}, _user()),
            ({"method": "GET", "url": f"{API}/repos/{OWNER}/{REPO}"}, _response(200, occupied)),
        ])
        held = self._open_config()
        try:
            result = self._call(authorization_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "unrelated_repository_exists")
        self.assertEqual(len(client.posts), 1)
        self.assertNotIn("other-project", json.dumps(result))

    def test_12_wrong_owner_never_posts(self) -> None:
        authorization_id = self._accept()
        client = FakeHttp([])
        held = self._open_config(allowed_owner="someone-else")
        try:
            result = self._call(authorization_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "owner_not_allowlisted")
        self.assertEqual(client.calls, [])
        self.assertEqual(publication_authorization_state(authorization_id), "approval_accepted")

    def test_13_approval_cannot_create_a_different_repository(self) -> None:
        prepared = prepare_publication_authorization(
            self.policy,
            owner=OWNER,
            repo_name=REPO,
            visibility="public",
            description=DESCRIPTION,
            branch="main",
            files=_manifest(),
            now=self.clock.now,
        )
        await_publication_approval(prepared["authorization_id"], now=self.clock.now)
        rejected = confirm_publication_authorization(
            prepared["authorization_id"],
            self.policy,
            owner=OWNER,
            repo_name="other-project",
            visibility="public",
            description=DESCRIPTION,
            branch="main",
            files=_manifest(),
            now=self.clock.now,
        )
        self.assertEqual(rejected["error"], "repository_mismatch")
        client = FakeHttp([])
        held = self._open_config()
        try:
            result = self._call(prepared["authorization_id"], client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "approval_not_accepted")
        self.assertEqual(client.calls, [])

    def test_14_private_visibility_is_rejected(self) -> None:
        prepared = prepare_publication_authorization(
            self.policy,
            owner=OWNER,
            repo_name=REPO,
            visibility="private",
            description=DESCRIPTION,
            branch="main",
            files=_manifest(),
            now=self.clock.now,
        )
        self.assertEqual(prepared["error"], "visibility_not_public")
        client = FakeHttp([])
        held = self._open_config()
        try:
            result = self._call("ghprop_" + "14" * 16, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertNotEqual(result.get("error"), "github_transport_not_authorized")
        self.assertEqual(client.calls, [])

    def test_15_missing_approval_never_posts(self) -> None:
        client = FakeHttp([])
        held = self._open_config()
        try:
            result = self._call("ghprop_" + "15" * 16, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "host_approval_required")
        self.assertEqual(client.calls, [])

    def test_16_expired_approval_never_posts(self) -> None:
        authorization_id = self._accept()
        self.clock.now = 1300.0
        client = FakeHttp([])
        held = self._open_config()
        try:
            result = self._call(authorization_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "approval_expired")
        self.assertEqual(client.calls, [])

    def test_17_consumed_approval_never_posts(self) -> None:
        authorization_id = self._accept()
        consumed = consume_publication_authorization(authorization_id, now=self.clock.now)
        self.assertEqual(consumed["state"], "approval_consumed")
        client = FakeHttp([])
        held = self._open_config()
        try:
            result = self._call(authorization_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "approval_consumed")
        self.assertEqual(client.calls, [])

    def test_18_modified_fields_do_not_reach_the_payload(self) -> None:
        prepared = prepare_publication_authorization(
            self.policy,
            owner=OWNER,
            repo_name=REPO,
            visibility="public",
            description=DESCRIPTION,
            branch="main",
            files=_manifest(),
            now=self.clock.now,
        )
        await_publication_approval(prepared["authorization_id"], now=self.clock.now)
        changed = confirm_publication_authorization(
            prepared["authorization_id"],
            self.policy,
            owner=OWNER,
            repo_name=REPO,
            visibility="public",
            description="Changed notes",
            branch="main",
            files=_manifest(),
            now=self.clock.now,
        )
        self.assertEqual(changed["error"], "description_mismatch")
        client = FakeHttp([])
        held = self._open_config()
        try:
            result = self._call(prepared["authorization_id"], client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "approval_not_accepted")
        self.assertEqual(client.calls, [])
        self.assertEqual(publication_authorization_state(prepared["authorization_id"]), "awaiting_approval")

    def test_19_repository_creation_disabled(self) -> None:
        authorization_id = self._accept()
        client = FakeHttp([])
        held = self._open_config(allow_writes=True, allow_repo_creation=False)
        try:
            result = self._call(authorization_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "github_repo_creation_disabled")
        self.assertEqual(client.calls, [])
        self.assertEqual(publication_authorization_state(authorization_id), "approval_accepted")

    def test_20_writes_disabled(self) -> None:
        authorization_id = self._accept()
        client = FakeHttp([])
        held = self._open_config(allow_writes=False, allow_repo_creation=False)
        try:
            result = self._call(authorization_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "github_writes_disabled")
        self.assertEqual(client.calls, [])

    def test_21_github_disabled(self) -> None:
        authorization_id = self._accept()
        client = FakeHttp([])
        held = self._open_config(enabled=False, allow_writes=False, allow_repo_creation=False)
        try:
            result = self._call(authorization_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "github_mcp_disabled")
        self.assertEqual(client.calls, [])

    def test_22_permission_denied_is_not_retried(self) -> None:
        authorization_id = self._accept()
        client = FakeHttp(self._absent_then_post(_response(403, {"message": "no"})))
        held = self._open_config()
        try:
            result = self._call(authorization_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "github_permission_denied")
        self.assertEqual(len(client.posts), 1)
        self.assertFalse(result["publication_succeeded"])

    def test_23_invalid_authentication_hides_the_credential(self) -> None:
        authorization_id = self._accept()
        client = FakeHttp(self._absent_then_post(_response(401, {"message": "bad"})))
        held = self._open_config()
        try:
            result = self._call(authorization_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "github_auth_invalid")
        self.assertNotIn("Bearer", json.dumps(result))
        self.assertEqual(len(client.posts), 1)

    def test_24_rate_limit(self) -> None:
        authorization_id = self._accept()
        client = FakeHttp(self._absent_then_post(_response(429, {"message": "slow"})))
        held = self._open_config()
        try:
            result = self._call(authorization_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "rate_limited")
        self.assertEqual(len(client.posts), 1)

    def test_25_unexpected_http_status(self) -> None:
        authorization_id = self._accept()
        client = FakeHttp(self._absent_then_post(_response(500, {"message": "down"})))
        held = self._open_config()
        try:
            result = self._call(authorization_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "github_api_error")
        self.assertEqual(result["status"], 500)
        self.assertEqual(len(client.posts), 1)

    def test_26_timeout_before_a_confirmed_response(self) -> None:
        authorization_id = self._accept()
        client = FakeHttp(self._absent_then_post(httpx.TimeoutException("timed out")) + [
            ({"method": "GET", "url": USER_URL}, _user()),
            ({"method": "GET", "url": f"{API}/repos/{OWNER}/{REPO}"}, _response(404)),
        ])
        held = self._open_config()
        try:
            result = self._call(authorization_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "create_outcome_uncertain")
        self.assertTrue(result["outcome_uncertain"])
        self.assertEqual(len(client.posts), 1)

    def test_27_timeout_then_get_finds_the_matching_repository(self) -> None:
        authorization_id = self._accept()
        client = FakeHttp(self._absent_then_post(httpx.TimeoutException("timed out")) + [
            ({"method": "GET", "url": USER_URL}, _user()),
            ({"method": "GET", "url": f"{API}/repos/{OWNER}/{REPO}"}, _response(200, _repo_body())),
        ])
        held = self._open_config()
        try:
            result = self._call(authorization_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["recovered"])
        self.assertEqual(result["full_name"], f"{OWNER}/{REPO}")
        self.assertIs(result["private"], False)
        self.assertEqual(len(client.posts), 1)

    def test_28_timeout_then_get_does_not_find_it(self) -> None:
        authorization_id = self._accept()
        client = FakeHttp(self._absent_then_post(httpx.TimeoutException("timed out")) + [
            ({"method": "GET", "url": USER_URL}, _user()),
            ({"method": "GET", "url": f"{API}/repos/{OWNER}/{REPO}"}, _response(404)),
        ])
        held = self._open_config()
        try:
            result = self._call(authorization_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "create_outcome_uncertain")
        self.assertEqual(result["verify_status"], "absent")
        self.assertEqual(len(client.posts), 1)
        self.assertEqual(publication_authorization_state(authorization_id), "publication_outcome_uncertain")

    def test_29_uncertain_create_does_not_send_a_second_post(self) -> None:
        authorization_id = self._accept()

        def _explode_on_second(method: str, url: str, headers: dict[str, str] | None = None, json: dict[str, Any] | None = None) -> httpx.Response:
            del headers
            posts = [item for item in client.calls if item["method"] == "POST"]
            client.calls.append({"method": method, "url": url, "json": json})
            if method == "POST" and len(posts) >= 1:
                raise AssertionError("blind second POST")
            if method == "GET" and url == USER_URL:
                return _user()
            if method == "GET":
                return _response(404)
            if method == "POST":
                raise httpx.TimeoutException("timed out")
            raise AssertionError(method)

        client = FakeHttp([])
        client.request = _explode_on_second  # type: ignore[method-assign]
        held = self._open_config()
        try:
            result = self._call(authorization_id, client, Path(held.name))
        finally:
            held.cleanup()
        self.assertEqual(result["error"], "create_outcome_uncertain")
        self.assertEqual(sum(1 for item in client.calls if item["method"] == "POST"), 1)

    def test_30_consumed_authorization_cannot_create_again(self) -> None:
        authorization_id = self._accept()
        client = FakeHttp(self._absent_then_post(_response(201, _repo_body())) + [
            ({"method": "GET", "url": USER_URL}, _user()),
        ])
        held = self._open_config()
        try:
            first = self._call(authorization_id, client, Path(held.name))
            second_client = FakeHttp([])
            second = self._call(authorization_id, second_client, Path(held.name))
        finally:
            held.cleanup()
        self.assertTrue(first["ok"], first)
        self.assertEqual(len(client.posts), 1)
        self.assertEqual(second["error"], "approval_consumed")
        self.assertEqual(second_client.calls, [])
        commit = json.loads(server.github_commit_files(authorization_id))
        self.assertNotEqual(commit.get("publication_succeeded"), True)
        self.assertEqual(second_client.posts, [])

    def test_commit_tool_does_not_publish_and_schema_stays_closed(self) -> None:
        authorization_id = self._accept()
        client = FakeHttp(self._absent_then_post(_response(201, _repo_body())) + [
            ({"method": "GET", "url": USER_URL}, _user()),
        ])
        held = self._open_config()
        log = logging.getLogger("me3.github_mcp")
        buffer: list[str] = []

        class _Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                buffer.append(record.getMessage())

        handler = _Capture()
        log.addHandler(handler)
        try:
            with mock.patch.dict(os.environ, {"GITHUB_MCP_ROOT": str(Path(held.name))}):
                blocked = json.loads(server.github_commit_files(authorization_id))
            result = self._call(authorization_id, client, Path(held.name))
            read = json.loads(server.github_get_repository(OWNER, "mnist-einops-cnn"))
        finally:
            log.removeHandler(handler)
            held.cleanup()
        self.assertEqual(blocked["error"], "github_transport_not_authorized")
        self.assertFalse(blocked.get("write_attempted", False))
        self.assertTrue(result["ok"], result)
        self.assertEqual(read["error"], "github_mcp_disabled")
        self.assertNotIn("github_create_repository", visible_github_tool_names(load_github_policy(ROOT)))
        self.assertNotIn("github_commit_files", visible_github_tool_names(load_github_policy(ROOT)))
        self.assertNotIn(MARKER, "\n".join(buffer))
        self.assertNotIn("ghp_", "\n".join(buffer))
        self.assertNotIn("fake-test-token", "\n".join(buffer))
