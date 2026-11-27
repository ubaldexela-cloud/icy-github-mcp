"""Background publisher for one approved public repository.

The voice thread prepares a manifest and records approval. This publisher
then runs repository creation and file publication on the existing worker.
It does not start a worker, open an MCP session, read credentials, or speak.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from realtime_c.background_github_adapter import SessionOwnerMismatch
from realtime_c.background_worker import (
    BackgroundTaskWorker,
    ExecutionContext,
    QueueFull,
    SubmissionRejected,
    WorkerNotRunning,
)
from realtime_c.github_approval import (
    MAX_PUBLICATION_AGGREGATE_BYTES,
    MAX_PUBLICATION_FILE_BYTES,
    publication_text_has_secret,
)
from realtime_c.task_registry import TaskRegistry
from realtime_c.task_result_store import TaskResultStore

PREPARE_TOOL = "github_prepare_publication"
APPROVE_TOOL = "github_approve_publication"
TASK_TYPE = "github_publish_project"
MAX_FILE_BYTES = MAX_PUBLICATION_FILE_BYTES
_TEXT_SUFFIXES = frozenset({".md", ".txt", ".py", ".json", ".toml", ".yml", ".yaml", ".rst"})
_SKIP_DIRS = frozenset({
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".mypy_cache",
    "dist",
    "build",
    ".cursor",
    ".pytest_cache",
})
_SECRET_PATH_PARTS = (".env", "id_rsa", "id_ed25519", "credentials.json")


class PublisherError(Exception):
    """Publisher failure. Messages do not contain file bodies or tokens."""


class ResultStoreFailed(PublisherError):
    """The publication report was not saved."""


@dataclass(frozen=True)
class PublicationAck:
    task_id: str
    operation_id: str
    conversation_id: str
    state: str
    duplicate: bool


def _secret_path(relative: str) -> bool:
    name = Path(relative).name.casefold()
    if name in {".env", "id_rsa", "id_ed25519", "credentials.json"}:
        return True
    if name.startswith(".env.") or name.endswith(".pem"):
        return True
    lowered = relative.replace("\\", "/").casefold()
    return any(part in lowered.split("/") for part in _SECRET_PATH_PARTS)


def _secret_text(text: str) -> bool:
    return publication_text_has_secret(text)


def inspect_project(project_dir: Path) -> dict[str, Any]:
    """Classify one project tree. File bodies stay out of the returned preview."""
    root = project_dir.resolve()
    included: list[dict[str, str]] = []
    excluded: list[dict[str, str]] = []
    if not root.is_dir():
        return {"ok": False, "error": "project_directory_required", "included": [], "excluded": []}
    for current, dirs, files in os.walk(root, followlinks=False):
        kept = []
        for name in sorted(dirs):
            if name in _SKIP_DIRS or name.endswith(".egg-info"):
                relative_dir = Path(current, name).relative_to(root).as_posix()
                excluded.append({"path": relative_dir + "/", "reason": "generated"})
                continue
            kept.append(name)
        dirs[:] = kept
        for name in sorted(files):
            path = Path(current) / name
            if path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            if _secret_path(relative):
                excluded.append({"path": relative, "reason": "secret"})
                continue
            try:
                size = path.stat().st_size
            except OSError:
                excluded.append({"path": relative, "reason": "unreadable"})
                continue
            if path.suffix.casefold() not in _TEXT_SUFFIXES:
                excluded.append({"path": relative, "reason": "unsupported"})
                continue
            if size > MAX_FILE_BYTES:
                excluded.append({"path": relative, "reason": "oversized"})
                continue
            try:
                raw = path.read_bytes()
            except OSError:
                excluded.append({"path": relative, "reason": "unreadable"})
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                excluded.append({"path": relative, "reason": "unsupported"})
                continue
            if _secret_text(text):
                excluded.append({"path": relative, "reason": "secret"})
                continue
            if len(raw) > MAX_FILE_BYTES:
                excluded.append({"path": relative, "reason": "oversized"})
                continue
            included_bytes = sum(len(item["content"]) for item in included)
            if included_bytes + len(raw) > MAX_PUBLICATION_AGGREGATE_BYTES:
                excluded.append({"path": relative, "reason": "oversized"})
                continue
            included.append({"path": relative, "content": raw})
    included.sort(key=lambda item: item["path"])
    return {"ok": True, "included": included, "excluded": excluded}


def _preview_files(summary_files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    preview = []
    for item in summary_files:
        preview.append({
            "path": item.get("path"),
            "size": item.get("size"),
            "sha256": item.get("sha256"),
        })
    return preview


class BackgroundGithubPublisher:
    """Submit one create-then-publish task on the shared worker."""

    def __init__(
        self,
        registry: TaskRegistry,
        worker: BackgroundTaskWorker,
        results: TaskResultStore,
        client: object | None,
        *,
        policy_root: Path | None = None,
    ) -> None:
        if not isinstance(registry, TaskRegistry):
            raise TypeError("registry must be a TaskRegistry")
        if not isinstance(worker, BackgroundTaskWorker):
            raise TypeError("worker must be a BackgroundTaskWorker")
        if not isinstance(results, TaskResultStore):
            raise TypeError("results must be a TaskResultStore")
        self._registry = registry
        self._worker = worker
        self._results = results
        self._client = client
        self._policy_root = policy_root
        bind = getattr(client, "bind_publication_worker", None)
        if callable(bind):
            bind(worker)
        self._pending: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.client_calls = 0

    @property
    def client(self) -> object | None:
        return self._client

    @property
    def worker(self) -> BackgroundTaskWorker:
        return self._worker

    def tools_visible(self) -> bool:
        policy = self._policy()
        return bool(
            policy.ok
            and policy.enabled
            and policy.allow_writes
            and policy.allow_repo_creation
        )

    def prepare(self, conversation_id: str, origin_turn_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
        del origin_turn_id
        policy = self._policy()
        if not policy.ok or not policy.enabled:
            return _denied("github_mcp_disabled", "GitHub publishing is not allowed.")
        project_text = arguments.get("project_dir")
        repo_name = arguments.get("repo_name")
        description = arguments.get("description")
        branch = arguments.get("branch") or "main"
        if not isinstance(project_text, str) or not project_text.strip():
            return _denied("project_directory_required", "Which project directory should I publish?")
        if not isinstance(repo_name, str) or not repo_name.strip():
            return _denied("repository_name_required", "What should the public repository be called?")
        if not isinstance(description, str) or not description.strip():
            return _denied("description_required", "What description should the public repository use?")
        if arguments.get("visibility") not in (None, "public"):
            return _denied("visibility_not_public", "Only a public repository can be published.")
        project = Path(project_text)
        if not project.is_dir():
            return _denied("project_directory_required", "I need an existing project directory. I did not choose one.")
        inspected = inspect_project(project)
        included = list(inspected["included"])
        if not included:
            return _denied("empty_manifest", "There are no files to publish. I did not invent a README.")
        from realtime_c.github_approval import (
            await_publication_approval,
            prepare_publication_authorization,
            publication_clock_now,
        )

        prepared = prepare_publication_authorization(
            policy,
            owner=policy.allowed_owner,
            repo_name=repo_name.strip(),
            visibility="public",
            description=description.strip(),
            branch=str(branch).strip() or "main",
            files=included,
            now=publication_clock_now(),
        )
        if not prepared.get("ok"):
            prepared["excluded"] = inspected["excluded"]
            return prepared
        waiting = await_publication_approval(prepared["authorization_id"], now=publication_clock_now())
        if not waiting.get("ok"):
            return waiting
        summary = prepared["summary"]
        self._pending[conversation_id] = {
            "authorization_id": prepared["authorization_id"],
            "project_dir": str(project.resolve()),
            "repo_name": summary["repo_name"],
            "description": summary["description"],
            "branch": summary["branch"],
            "fingerprint": summary["fingerprint"],
            "paths": [item["path"] for item in summary["files"]],
        }
        excluded = [
            {"path": item["path"], "reason": item["reason"]}
            for item in inspected["excluded"]
        ]
        return {
            "ok": True,
            "state": waiting["state"],
            "owner": summary["owner"],
            "repo_name": summary["repo_name"],
            "visibility": "public",
            "description": summary["description"],
            "branch": summary["branch"],
            "fingerprint": summary["fingerprint"],
            "intended_file_count": len(summary["files"]),
            "files": _preview_files(summary["files"]),
            "excluded": excluded,
            "spoken_status": (
                f"I can publish {len(summary['files'])} files to public repository "
                f"{summary['owner']}/{summary['repo_name']}. "
                "Nothing has been sent. Say yes if this exact preview is what you want public."
            ),
            "write_attempted": False,
            "publication_succeeded": False,
        }

    def approve(self, conversation_id: str, origin_turn_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
        policy = self._policy()
        if not policy.ok or not policy.enabled:
            return _denied("github_mcp_disabled", "GitHub publishing is not allowed.")
        if not policy.allow_writes or not policy.allow_repo_creation:
            return _denied("github_writes_disabled", "GitHub publishing is not allowed.")
        pending = self._pending.get(conversation_id)
        if pending is None:
            return _denied("no_pending_approval", "There is no publication waiting for approval.")
        if arguments.get("approved") is not True:
            return self._reject_pending(conversation_id, pending, policy)
        repo_name = arguments.get("repo_name")
        description = arguments.get("description") or pending["description"]
        branch = arguments.get("branch") or pending["branch"]
        if repo_name != pending["repo_name"] or description != pending["description"] or branch != pending["branch"]:
            return _denied("manifest_changed", "That approval does not match the prepared publication.")
        files, read_error = self._read_paths(Path(pending["project_dir"]), pending["paths"])
        if read_error:
            return _denied(read_error, "The project changed after the preview. Nothing was sent.")
        from realtime_c.github_approval import confirm_publication_authorization, publication_clock_now

        accepted = confirm_publication_authorization(
            pending["authorization_id"],
            policy,
            owner=policy.allowed_owner,
            repo_name=pending["repo_name"],
            visibility="public",
            description=pending["description"],
            branch=pending["branch"],
            files=files,
            now=publication_clock_now(),
        )
        if not accepted.get("ok"):
            return accepted
        content_id = accepted.get("content_authorization_id")
        if not isinstance(content_id, str) or not content_id:
            return _denied("content_grant_missing", "File publication was not authorized.")
        try:
            ack = self._submit(
                conversation_id,
                origin_turn_id,
                create_id=pending["authorization_id"],
                content_id=content_id,
                project_dir=pending["project_dir"],
                repo_name=pending["repo_name"],
                branch=pending["branch"],
                owner=policy.allowed_owner,
                fingerprint=pending["fingerprint"],
            )
        except QueueFull:
            return _denied("github_worker_busy", "A GitHub request is already waiting. I did not replace it.")
        except WorkerNotRunning:
            return _denied("worker_not_running", "Background tasks are not available right now.")
        self._pending.pop(conversation_id, None)
        spoken = "I started creating the public repository and publishing the approved files."
        if ack.duplicate:
            spoken = "That publication is already running in the background."
        return {
            "ok": True,
            "status": "in_progress",
            "task_id": ack.task_id,
            "operation_id": ack.operation_id,
            "state": ack.state,
            "duplicate": ack.duplicate,
            "spoken_status": spoken,
            "write_attempted": False,
            "publication_succeeded": False,
        }

    def assert_worker_owner(self) -> None:
        ident = self._worker.status().thread_ident
        if ident is None or ident != threading.get_ident():
            raise SessionOwnerMismatch("session is owned by the worker thread")

    def _reject_pending(self, conversation_id: str, pending: dict[str, Any], policy: Any) -> dict[str, Any]:
        from realtime_c.github_approval import publication_clock_now, reject_publication_authorization

        rejected = reject_publication_authorization(pending["authorization_id"], now=publication_clock_now())
        self._pending.pop(conversation_id, None)
        del policy
        return rejected

    def _submit(
        self,
        conversation_id: str,
        origin_turn_id: str,
        *,
        create_id: str,
        content_id: str,
        project_dir: str,
        repo_name: str,
        branch: str,
        owner: str,
        fingerprint: str,
    ) -> PublicationAck:
        dedup_key = f"publish:{owner}:{repo_name}:{fingerprint}"
        with self._lock:
            task_id = self._registry.create(
                conversation_id,
                origin_turn_id,
                task_type=TASK_TYPE,
                deduplication_key=dedup_key,
            )
            snapshot = self._registry.get(task_id)
            if snapshot.operations:
                operation = snapshot.operations[0]
                return PublicationAck(task_id, operation.operation_id, conversation_id, snapshot.state, True)
            try:
                admitted = self._worker.submit(
                    task_id,
                    TASK_TYPE,
                    self._execute,
                    arguments={
                        "conversation_id": conversation_id,
                        "create_id": create_id,
                        "content_id": content_id,
                        "project_dir": project_dir,
                        "repo_name": repo_name,
                        "branch": branch,
                        "owner": owner,
                        "fingerprint": fingerprint,
                    },
                )
            except SubmissionRejected:
                snapshot = self._registry.get(task_id)
                if not snapshot.operations:
                    raise
                operation = snapshot.operations[0]
                return PublicationAck(task_id, operation.operation_id, conversation_id, snapshot.state, True)
            return PublicationAck(
                admitted.task_id,
                admitted.operation_id,
                conversation_id,
                admitted.state,
                False,
            )

    def _execute(self, context: ExecutionContext) -> None:
        self.assert_worker_owner()
        conversation_id = context.arguments.get("conversation_id")
        if not isinstance(conversation_id, str):
            raise PublisherError("publication failed")
        if context.cancelled():
            self._registry.note_finished(context.task_id, context.operation_id, outcome="abandoned")
            return
        report = self._run(context)
        if context.cancelled() or report.get("outcome_uncertain"):
            outcome = "abandoned" if context.cancelled() or report.get("may_still_be_running") else "returned"
        else:
            outcome = "returned"
        self._store(conversation_id, context, report)
        self._registry.note_finished(context.task_id, context.operation_id, outcome=outcome)

    def _run(self, context: ExecutionContext) -> dict[str, Any]:
        create_id = str(context.arguments.get("create_id") or "")
        content_id = str(context.arguments.get("content_id") or "")
        project = Path(str(context.arguments.get("project_dir") or ""))
        branch = str(context.arguments.get("branch") or "main")
        owner = str(context.arguments.get("owner") or "")
        repo_name = str(context.arguments.get("repo_name") or "")
        from realtime_c.github_approval import (
            accepted_publication_content_binding,
            publication_authorization_state,
        )

        if publication_authorization_state(create_id) != "approval_accepted":
            return _report_failure("approval_not_accepted", "The repository approval is no longer usable.")
        binding = accepted_publication_content_binding(content_id)
        if not binding.get("ok"):
            return _report_failure(
                str(binding.get("error") or "approval_not_accepted"),
                "The file approval is no longer usable.",
            )
        disk, read_error = self._read_paths(project, [str(item["path"]) for item in binding["files"]])
        if read_error or disk is None:
            return _report_failure("manifest_changed", "A file changed after approval. Nothing was sent.")
        from realtime_c.github_approval import publication_content_bytes

        approved = {
            str(item["path"]): publication_content_bytes(item["content"])
            for item in binding["files"]
        }
        current = {
            str(item["path"]): publication_content_bytes(item["content"])
            for item in disk
        }
        if current != approved:
            return _report_failure("manifest_changed", "A file changed after approval. Nothing was sent.")
        if context.cancelled():
            return _report_failure("publication_cancelled", "Publication was cancelled before anything was sent.")
        created = json.loads(self._dispatch("github_create_repository", create_id))
        if not created.get("publication_succeeded"):
            uncertain = bool(created.get("outcome_uncertain")) or created.get("error") == "create_outcome_uncertain"
            return _report_failure(
                str(created.get("error") or "repository_creation_failed"),
                str(created.get("spoken_status") or "The repository was not created. No files were published."),
                outcome_uncertain=uncertain,
                may_still_be_running=uncertain,
                full_name=created.get("full_name"),
                html_url=created.get("html_url"),
            )
        full_name = str(created.get("full_name") or "")
        if full_name.casefold() != f"{owner}/{repo_name}".casefold() or bool(created.get("private")):
            return _report_failure(
                "repository_metadata_mismatch",
                "The repository response did not match the approved public repository. No files were published.",
                outcome_uncertain=True,
                may_still_be_running=True,
                full_name=full_name,
                html_url=created.get("html_url"),
            )
        if context.cancelled():
            return _report_failure(
                "publication_cancelled",
                "Publication was cancelled after repository creation. No files were published.",
                full_name=full_name,
                html_url=created.get("html_url"),
                outcome_uncertain=True,
                may_still_be_running=True,
            )
        published = json.loads(self._dispatch("github_commit_files", content_id))
        files = []
        for item in published.get("files") or []:
            if not isinstance(item, dict):
                continue
            files.append({
                "path": item.get("path"),
                "commit_sha": item.get("commit_sha") or "",
                "verified": bool(item.get("verified")),
            })
        verified = [item["path"] for item in files if item["verified"]]
        complete = bool(published.get("publication_complete")) and len(verified) == len(approved)
        return {
            "ok": complete,
            "publication_succeeded": complete,
            "publication_complete": complete,
            "full_name": full_name,
            "html_url": created.get("html_url"),
            "private": False,
            "visibility": "public",
            "branch": branch,
            "intended_file_count": len(approved),
            "published_file_count": len(published.get("committed_paths") or []),
            "verified_file_count": len(verified),
            "files": files,
            "partial": bool(published.get("partial")) or not complete,
            "outcome_uncertain": bool(published.get("outcome_uncertain")),
            "may_still_be_running": bool(published.get("may_still_be_running")),
            "failed_path": published.get("failed_path"),
            "error": "" if complete else str(published.get("error") or "publication_incomplete"),
            "spoken_status": (
                "The public repository and approved files were verified."
                if complete
                else str(published.get("spoken_status") or "The publication did not fully verify.")
            ),
            "write_attempted": bool(created.get("write_attempted") or published.get("write_attempted")),
        }

    def _dispatch(self, name: str, proposal_id: str) -> str:
        """One MCP tool call. The server, not this process, performs HTTP.

        When the client owns a session key, the call carries one sealed grant.
        A timeout or a rejected handoff is not retried.
        """
        self.client_calls += 1
        call = getattr(self._client, "call", None)
        if not callable(call):
            raise PublisherError("publication failed")
        arguments: dict[str, Any] = {"proposal_id": proposal_id}
        key = getattr(self._client, "publication_handoff_key", None)
        envelope = None
        if isinstance(key, bytes):
            from realtime_c.github_approval import seal_publication_handoff

            envelope = seal_publication_handoff(proposal_id, key)
            if not envelope:
                return json.dumps({
                    "ok": False,
                    "error": "handoff_unavailable",
                    "spoken_status": "The approval could not be handed to GitHub. Nothing was retried.",
                    "write_attempted": False,
                    "outcome_uncertain": False,
                    "publication_succeeded": False,
                    "grant_admitted": False,
                })
            arguments["grant_envelope"] = envelope
        try:
            text = call(name, arguments)
        except TimeoutError:
            from realtime_c.github_approval import consume_publication_authorization, publication_clock_now

            consume_publication_authorization(proposal_id, now=publication_clock_now())
            return json.dumps({
                "ok": False,
                "error": "handoff_timeout",
                "spoken_status": "The approval handoff timed out. It was not retried.",
                "write_attempted": False,
                "outcome_uncertain": True,
                "publication_succeeded": False,
                "grant_admitted": False,
            })
        if not isinstance(text, str) or not text:
            raise PublisherError("publication failed")
        if envelope is None:
            return text
        try:
            body = json.loads(text)
        except json.JSONDecodeError:
            return json.dumps({
                "ok": False,
                "error": "handoff_malformed",
                "spoken_status": "The approval handoff was rejected. It was not retried.",
                "write_attempted": False,
                "outcome_uncertain": False,
                "publication_succeeded": False,
                "grant_admitted": False,
            })
        if not isinstance(body, dict) or body.get("grant_admitted") is not True:
            if isinstance(body, dict):
                body["grant_admitted"] = False
                body.setdefault("outcome_uncertain", False)
                body.setdefault("write_attempted", False)
                body.setdefault("publication_succeeded", False)
                return json.dumps(body)
            raise PublisherError("publication failed")
        from realtime_c.github_approval import consume_publication_authorization, publication_clock_now

        consume_publication_authorization(proposal_id, now=publication_clock_now())
        return text

    def _store(self, conversation_id: str, context: ExecutionContext, report: dict[str, Any]) -> None:
        payload = json.dumps(report, sort_keys=True)
        if len(payload.encode("utf-8")) > 8000:
            report = {
                "ok": False,
                "publication_succeeded": False,
                "error": "result_too_large",
                "spoken_status": "The publication report was too large to store.",
            }
            payload = json.dumps(report)
        try:
            self._results.put(conversation_id, context.task_id, context.operation_id, payload)
        except Exception as exc:
            raise ResultStoreFailed(type(exc).__name__) from None

    def _read_paths(
        self,
        project: Path,
        paths: list[str],
    ) -> tuple[list[dict[str, str]] | None, str | None]:
        root = project.resolve()
        files: list[dict[str, str]] = []
        for relative in paths:
            candidate = (root / relative).resolve()
            if candidate != root and root not in candidate.parents:
                return None, "manifest_changed"
            if not candidate.is_file():
                return None, "manifest_changed"
            try:
                raw = candidate.read_bytes()
            except OSError:
                return None, "manifest_changed"
            try:
                raw.decode("utf-8")
            except UnicodeDecodeError:
                return None, "unsupported_file_content"
            digest = hashlib.sha256(raw).hexdigest()
            files.append({"path": relative, "content": raw, "sha256": digest})
        return files, None

    def _policy(self) -> Any:
        from realtime_c.github_approval import load_github_policy

        if self._policy_root is not None and not os.environ.get("GITHUB_MCP_ROOT"):
            return load_github_policy(self._policy_root)
        root = Path(os.environ.get("GITHUB_MCP_ROOT") or self._policy_root or Path.cwd())
        return load_github_policy(root)


def _denied(error: str, spoken: str) -> dict[str, Any]:
    return {
        "ok": False,
        "error": error,
        "spoken_status": spoken,
        "write_attempted": False,
        "outcome_uncertain": False,
        "publication_succeeded": False,
    }


def _report_failure(error: str, spoken: str, **extra: Any) -> dict[str, Any]:
    report = _denied(error, spoken)
    report.update({
        "publication_complete": False,
        "partial": False,
        "may_still_be_running": False,
        "intended_file_count": 0,
        "published_file_count": 0,
        "verified_file_count": 0,
        "files": [],
        "visibility": "public",
    })
    report.update(extra)
    return report
