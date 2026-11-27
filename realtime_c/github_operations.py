"""One-shot grants for GitHub and local Git writes.

These grants are separate from repository-creation and publication grants.
A grant can be consumed once. The preview body is hashed, and execution
rejects any change. Fake HTTP tests inject the client. This module does
not enable writes in the production policy.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from realtime_c.git_workspace import workspace_create_branch, workspace_push

TTL_S = 300.0
OPERATIONS = frozenset({
    "create_branch",
    "update_file",
    "create_pull_request",
    "comment_pull_request",
    "create_issue",
    "comment_issue",
    "update_issue",
    "close_issue",
    "create_release",
    "update_release",
    "upload_release_asset",
    "push_branch",
    "create_local_branch",
})
_REQUIRED = {
    "create_branch": ("owner", "repo", "branch", "sha"),
    "update_file": ("owner", "repo", "path", "branch", "content", "message"),
    "create_pull_request": ("owner", "repo", "title", "head", "base", "body"),
    "comment_pull_request": ("owner", "repo", "number", "body"),
    "create_issue": ("owner", "repo", "title", "body"),
    "comment_issue": ("owner", "repo", "number", "body"),
    "update_issue": ("owner", "repo", "number"),
    "close_issue": ("owner", "repo", "number"),
    "create_release": ("owner", "repo", "tag", "name", "body"),
    "update_release": ("owner", "repo", "release_id", "name", "body"),
    "upload_release_asset": ("owner", "repo", "release_id", "name", "content"),
    "push_branch": ("path", "remote", "branch", "expected_head"),
    "create_local_branch": ("path", "branch"),
}
_lock = threading.Lock()
_records: dict[str, dict[str, Any]] = {}


def _denied(error: str, spoken: str, **extra: Any) -> dict[str, Any]:
    payload = {
        "ok": False,
        "error": error,
        "spoken_status": spoken,
        "write_attempted": False,
        "verified": False,
    }
    payload.update(extra)
    return payload


def _canonical(operation: str, fields: dict[str, Any]) -> str:
    payload = {"operation": operation, "fields": {key: fields[key] for key in _REQUIRED[operation]}}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _fingerprint(operation: str, fields: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(operation, fields).encode("utf-8")).hexdigest()


def _preview(operation: str, fields: dict[str, Any]) -> str:
    if operation == "update_file":
        return f"Update {fields['path']} on {fields['branch']} in {fields['owner']}/{fields['repo']}."
    if operation == "close_issue":
        return f"Close issue {fields['number']} in {fields['owner']}/{fields['repo']}."
    if operation == "push_branch":
        return f"Push {fields['branch']} to {fields['remote']} at {fields['expected_head']}."
    if operation == "create_local_branch":
        return f"Create local branch {fields['branch']}."
    if operation == "create_branch":
        return f"Create {fields['branch']} in {fields['owner']}/{fields['repo']}."
    if operation == "create_pull_request":
        return f"Open a pull request {fields['head']} into {fields['base']}."
    if operation == "create_issue":
        return f"Open an issue titled {fields['title']}."
    if operation == "create_release":
        return f"Create release {fields['tag']}."
    if operation == "upload_release_asset":
        return f"Upload {fields['name']} to release {fields['release_id']}."
    return f"Run {operation} on the approved target."


def _ledger(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def _remember(path: Path, authorization_id: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    current = _ledger(path)
    if authorization_id in current:
        return False
    with path.open("a", encoding="utf-8") as handle:
        handle.write(authorization_id + "\n")
    return True


def prepare_operation(policy: Any, operation: str, fields: dict[str, Any], *, now: float | None = None) -> dict[str, Any]:
    if operation not in OPERATIONS:
        return _denied("unknown_operation", "That GitHub operation is not available.")
    if not policy.ok or not policy.enabled:
        return _denied("github_mcp_disabled", "GitHub is not enabled.")
    if not policy.allow_writes and operation not in {"create_local_branch"}:
        return _denied("github_writes_disabled", "GitHub writes are not allowed.")
    missing = [key for key in _REQUIRED[operation] if fields.get(key) in (None, "")]
    if missing:
        return _denied("operation_fields_missing", "The operation preview is incomplete.", missing=missing)
    if "owner" in _REQUIRED[operation]:
        from realtime_c.github_approval import repo_allowlist_error

        error = repo_allowlist_error(policy, f"{fields['owner']}/{fields['repo']}")
        if error:
            return _denied(error, "That repository is not allowed.")
    stamp = time.time() if now is None else now
    authorization_id = "ghop_" + secrets.token_hex(16)
    record = {
        "id": authorization_id,
        "operation": operation,
        "fields": {key: fields[key] for key in _REQUIRED[operation]},
        "fingerprint": _fingerprint(operation, fields),
        "expires": stamp + TTL_S,
        "state": "awaiting_approval",
    }
    with _lock:
        _records[authorization_id] = record
    return {
        "ok": True,
        "authorization_id": authorization_id,
        "operation": operation,
        "fingerprint": record["fingerprint"],
        "preview": _preview(operation, record["fields"]),
        "spoken_status": record["preview"] if False else _preview(operation, record["fields"]) + " Nothing has been sent.",
        "write_attempted": False,
        "verified": False,
    }


def confirm_operation(authorization_id: str, approved: bool, fingerprint: str, *, now: float | None = None) -> dict[str, Any]:
    stamp = time.time() if now is None else now
    with _lock:
        record = _records.get(authorization_id)
        if record is None:
            return _denied("approval_missing", "There is no matching operation approval.")
        if stamp >= float(record["expires"]):
            record["state"] = "expired"
            return _denied("approval_expired", "That operation approval has expired.")
        if record["state"] != "awaiting_approval":
            return _denied("approval_consumed", "That operation approval was already used.", state=record["state"])
        if not approved:
            record["state"] = "rejected"
            return _denied("approval_rejected", "The operation was not approved.")
        if fingerprint != record["fingerprint"]:
            return _denied("manifest_changed", "That approval does not match the prepared operation.")
        record["state"] = "accepted"
    return {
        "ok": True,
        "authorization_id": authorization_id,
        "operation": record["operation"],
        "fingerprint": record["fingerprint"],
        "spoken_status": "The operation was approved once.",
        "write_attempted": False,
        "verified": False,
    }


def _request(client: Any, method: str, url: str, body: dict[str, Any] | None, headers: dict[str, str]) -> Any:
    return client.request(method, url, headers=headers, json=body)


def _verify_get(client: Any, url: str, headers: dict[str, str]) -> Any:
    return client.request("GET", url, headers=headers)


def execute_operation(
    authorization_id: str,
    *,
    policy: Any,
    ledger: Path,
    client: Any = None,
    headers: dict[str, str] | None = None,
    workspace: Path | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    stamp = time.time() if now is None else now
    with _lock:
        record = _records.get(authorization_id)
        if record is None or record["state"] != "accepted":
            return _denied("approval_not_accepted", "That operation is not approved.")
        if stamp >= float(record["expires"]):
            record["state"] = "expired"
            return _denied("approval_expired", "That operation approval has expired.")
        operation = str(record["operation"])
        fields = dict(record["fields"])
        if not policy.allow_writes and operation != "create_local_branch":
            return _denied("github_writes_disabled", "GitHub writes are not allowed.")
        api_operation = operation not in {"create_local_branch", "push_branch"}
        if api_operation and (client is None or headers is None):
            return _denied("github_transport_not_authorized", "GitHub writes are not connected.")
        if not api_operation and workspace is None:
            return _denied("workspace_required", "A workspace is required.")
        if authorization_id in _ledger(ledger):
            record["state"] = "consumed"
            return _denied("approval_replayed", "That operation approval was already used.")
        if not _remember(ledger, authorization_id):
            record["state"] = "consumed"
            return _denied("approval_replayed", "That operation approval was already used.")
        record["state"] = "consumed"
    if operation == "create_local_branch":
        if workspace is None:
            return _denied("workspace_required", "A workspace is required.", write_attempted=False)
        created = workspace_create_branch(workspace, str(fields["path"]), str(fields["branch"]))
        created["verified"] = bool(created.get("ok"))
        created["write_attempted"] = True
        return created
    if operation == "push_branch":
        if workspace is None:
            return _denied("workspace_required", "A workspace is required.", write_attempted=False)
        pushed = workspace_push(
            workspace,
            str(fields["path"]),
            str(fields["remote"]),
            str(fields["branch"]),
            str(fields["expected_head"]),
        )
        pushed["verified"] = bool(pushed.get("ok"))
        pushed["write_attempted"] = True
        return pushed
    return _execute_api(operation, fields, client, headers)


def _execute_api(operation: str, fields: dict[str, Any], client: Any, headers: dict[str, str]) -> dict[str, Any]:
    from urllib.parse import quote

    owner = quote(str(fields.get("owner", "")), safe="")
    repo = quote(str(fields.get("repo", "")), safe="")
    base = f"https://api.github.com/repos/{owner}/{repo}"
    try:
        if operation == "create_branch":
            response = _request(client, "POST", f"{base}/git/refs", {"ref": f"refs/heads/{fields['branch']}", "sha": fields["sha"]}, headers)
            verify = _verify_get(client, f"{base}/git/ref/heads/{quote(str(fields['branch']), safe='')}", headers)
            return _checked(response, verify, "branch")
        if operation == "update_file":
            import base64
            content = str(fields["content"]).encode("utf-8")
            response = _request(client, "PUT", f"{base}/contents/{quote(str(fields['path']), safe='/')}", {
                "message": fields["message"],
                "content": base64.b64encode(content).decode("ascii"),
                "branch": fields["branch"],
            }, headers)
            verify = _verify_get(client, f"{base}/contents/{quote(str(fields['path']), safe='/')}?ref={quote(str(fields['branch']), safe='')}", headers)
            return _checked(response, verify, "file")
        if operation == "create_pull_request":
            response = _request(client, "POST", f"{base}/pulls", {"title": fields["title"], "head": fields["head"], "base": fields["base"], "body": fields["body"]}, headers)
            number = _json(response).get("number")
            verify = _verify_get(client, f"{base}/pulls/{number}", headers) if number else None
            return _checked(response, verify, "pull_request")
        if operation == "comment_pull_request":
            response = _request(client, "POST", f"{base}/pulls/{fields['number']}/reviews", {"body": fields["body"], "event": "COMMENT"}, headers)
            return _checked(response, response, "comment")
        if operation == "create_issue":
            response = _request(client, "POST", f"{base}/issues", {"title": fields["title"], "body": fields["body"]}, headers)
            number = _json(response).get("number")
            verify = _verify_get(client, f"{base}/issues/{number}", headers) if number else None
            return _checked(response, verify, "issue")
        if operation == "comment_issue":
            response = _request(client, "POST", f"{base}/issues/{fields['number']}/comments", {"body": fields["body"]}, headers)
            return _checked(response, response, "comment")
        if operation == "update_issue":
            body = {key: fields[key] for key in fields if key in {"title", "body", "state", "labels"} and fields.get(key) not in (None, "")}
            response = _request(client, "PATCH", f"{base}/issues/{fields['number']}", body, headers)
            verify = _verify_get(client, f"{base}/issues/{fields['number']}", headers)
            return _checked(response, verify, "issue")
        if operation == "close_issue":
            response = _request(client, "PATCH", f"{base}/issues/{fields['number']}", {"state": "closed"}, headers)
            verify = _verify_get(client, f"{base}/issues/{fields['number']}", headers)
            checked = _checked(response, verify, "issue")
            if checked.get("ok") and _json(verify).get("state") != "closed":
                return _denied("verification_failed", "The issue was not verified as closed.", write_attempted=True, outcome_uncertain=True)
            return checked
        if operation == "create_release":
            response = _request(client, "POST", f"{base}/releases", {"tag_name": fields["tag"], "name": fields["name"], "body": fields["body"]}, headers)
            release_id = _json(response).get("id")
            verify = _verify_get(client, f"{base}/releases/{release_id}", headers) if release_id else None
            return _checked(response, verify, "release")
        if operation == "update_release":
            response = _request(client, "PATCH", f"{base}/releases/{fields['release_id']}", {"name": fields["name"], "body": fields["body"]}, headers)
            verify = _verify_get(client, f"{base}/releases/{fields['release_id']}", headers)
            return _checked(response, verify, "release")
        if operation == "upload_release_asset":
            response = _request(client, "POST", f"{base}/releases/{fields['release_id']}/assets?name={quote(str(fields['name']), safe='')}", {"content": fields["content"]}, headers)
            verify = _verify_get(client, f"{base}/releases/{fields['release_id']}/assets", headers)
            return _checked(response, verify, "asset")
    except Exception:
        return _denied("outcome_uncertain", "The write result could not be verified and was not retried.", write_attempted=True, outcome_uncertain=True)
    return _denied("unknown_operation", "That GitHub operation is not available.")


def _json(response: Any) -> dict[str, Any]:
    if response is None:
        return {}
    try:
        body = response.json()
    except Exception:
        return {}
    return body if isinstance(body, dict) else {}


def _checked(response: Any, verify: Any, kind: str) -> dict[str, Any]:
    status = int(getattr(response, "status_code", 0))
    if status not in {200, 201}:
        return _denied("github_api_error", "GitHub rejected the approved operation.", status=status, write_attempted=True)
    verified = verify is not None and int(getattr(verify, "status_code", 0)) in {200, 201}
    if not verified:
        return _denied("verification_failed", "The remote result could not be verified. It was not retried.", write_attempted=True, outcome_uncertain=True)
    body = _json(verify)
    return {
        "ok": True,
        "kind": kind,
        "status": status,
        "verified": True,
        "write_attempted": True,
        "outcome_uncertain": False,
        "remote_id": body.get("id") or body.get("sha") or body.get("number"),
        "spoken_status": "The approved operation was verified.",
    }
