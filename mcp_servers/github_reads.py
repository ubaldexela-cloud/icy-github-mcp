"""Read-only GitHub queries for the existing MCP server.

These functions issue GET requests only. Registration lives with the server
so the existing session remains the only GitHub MCP session.
"""

from __future__ import annotations

import base64
import re
from typing import Any, Callable

from mcp.server.mcpserver import Context
from urllib.parse import quote

GITHUB_API = "https://api.github.com"
MAX_PAGES = 3
MAX_ITEMS = 20
MAX_TEXT = 4_000
MAX_BODY = 262_144

READ_CAPABILITY_TOOLS = (
    "github_list_repositories",
    "github_list_branches",
    "github_list_tags",
    "github_list_collaborators",
    "github_list_contents",
    "github_read_file",
    "github_list_commits",
    "github_get_commit",
    "github_compare_refs",
    "github_list_issues",
    "github_get_issue",
    "github_list_pull_requests",
    "github_get_pull_request",
    "github_list_pull_request_comments",
    "github_list_releases",
    "github_get_release",
    "github_list_workflows",
    "github_list_workflow_runs",
    "github_read_workflow_log",
)
EXECUTE_TOOL_NAME = "github_execute_operation"
READ_TOOL_DESCRIPTIONS = {
    "github_list_repositories": "List repositories the policy allows for the authenticated GitHub account.",
    "github_list_branches": "List branches in an allowlisted repository.",
    "github_list_tags": "List tags in an allowlisted repository.",
    "github_list_collaborators": "List collaborators only when permission reads are enabled.",
    "github_list_contents": "List files and directories in an allowlisted repository.",
    "github_read_file": "Read one text file from an allowlisted repository.",
    "github_list_commits": "List recent commits in an allowlisted repository.",
    "github_get_commit": "Show one commit and the files it changed.",
    "github_compare_refs": "Compare two branches or commits in an allowlisted repository.",
    "github_list_issues": "List issues in an allowlisted repository.",
    "github_get_issue": "Read one issue.",
    "github_list_pull_requests": "List pull requests in an allowlisted repository.",
    "github_get_pull_request": "Read one pull request.",
    "github_list_pull_request_comments": "Read pull request comments and review states.",
    "github_list_releases": "List releases in an allowlisted repository.",
    "github_get_release": "Read one release.",
    "github_list_workflows": "List workflow files only when workflow reads are enabled.",
    "github_list_workflow_runs": "List workflow runs and their statuses.",
    "github_read_workflow_log": "Check that a workflow log exists without downloading the archive.",
}
_REF_RE = re.compile(r"^[A-Za-z0-9._/\-]{1,200}$")
_NEXT_RE = re.compile(r"<([^>]+)>;\s*rel=\"next\"")


def _denied(error: str, spoken: str, **extra: Any) -> dict[str, Any]:
    payload = {"ok": False, "error": error, "spoken_status": spoken, "write_attempted": False}
    payload.update(extra)
    return payload


def _ok(spoken: str, **extra: Any) -> dict[str, Any]:
    payload = {"ok": True, "spoken_status": spoken, "write_attempted": False}
    payload.update(extra)
    return payload


def _status_error(status: int, body: Any) -> dict[str, Any]:
    message = ""
    if isinstance(body, dict):
        raw = body.get("message")
        if isinstance(raw, str):
            message = raw[:180]
    if status == 401:
        return _denied("github_auth_invalid", "GitHub rejected the credentials.", status=status)
    if status == 403:
        lowered = message.casefold()
        if "rate limit" in lowered:
            return _denied("github_rate_limited", "GitHub rate limit was reached.", status=status)
        return _denied("github_permission_denied", "GitHub refused that read.", status=status)
    if status == 404:
        return _denied("github_not_found", "That GitHub resource was not found.", status=status)
    if status == 429:
        return _denied("github_rate_limited", "GitHub rate limit was reached.", status=status)
    return _denied("github_api_error", "GitHub returned an error while reading.", status=status)


def _next_url(headers: Any) -> str | None:
    link = ""
    if hasattr(headers, "get"):
        link = str(headers.get("link") or headers.get("Link") or "")
    match = _NEXT_RE.search(link)
    if match is None:
        return None
    url = match.group(1)
    if not url.startswith(f"{GITHUB_API}/"):
        return None
    return url


def _get_json(client: Any, url: str, headers: dict[str, str]) -> tuple[int, Any, Any]:
    response = client.request("GET", url, headers=headers)
    if int(getattr(response, "status_code", 0)) >= 400:
        try:
            body = response.json()
        except Exception:
            body = None
        return int(response.status_code), body, response
    try:
        body = response.json()
    except Exception:
        return int(response.status_code), None, response
    return int(response.status_code), body, response


def _collect_list(client: Any, url: str, headers: dict[str, str]) -> dict[str, Any] | list[Any]:
    items: list[Any] = []
    pages = 0
    current: str | None = url
    truncated = False
    while current and pages < MAX_PAGES and len(items) < MAX_ITEMS:
        status, body, response = _get_json(client, current, headers)
        if status >= 400 or not isinstance(body, list):
            if status >= 400:
                return _status_error(status, body)
            return _denied("github_malformed_response", "GitHub returned an unexpected list.")
        room = MAX_ITEMS - len(items)
        items.extend(body[:room])
        pages += 1
        nxt = _next_url(getattr(response, "headers", {}))
        if nxt and (len(items) >= MAX_ITEMS or pages >= MAX_PAGES):
            truncated = True
            current = None
        else:
            current = nxt
            if current and len(body) > room:
                truncated = True
    if len(items) >= MAX_ITEMS:
        truncated = True
    return {"items": items, "truncated": truncated, "pages": pages}


def _repo_path(owner: str, repo: str, suffix: str) -> str:
    return f"{GITHUB_API}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}{suffix}"


def _require_repo(arguments: dict[str, Any]) -> tuple[str, str] | dict[str, Any]:
    owner = str(arguments.get("owner") or "").strip()
    repo = str(arguments.get("repo") or "").strip()
    if not owner or not repo:
        return _denied("owner_and_repo_required", "Repository owner and name are required.")
    return owner, repo


def _allow(policy: Any, owner: str, repo: str) -> dict[str, Any] | None:
    from realtime_c.github_approval import repo_allowlist_error

    if not policy.ok or not policy.enabled:
        return _denied("github_mcp_disabled", "GitHub is not enabled.")
    if not policy.allow_reads:
        return _denied("github_reads_disabled", "GitHub reads are not allowed.")
    error = repo_allowlist_error(policy, f"{owner}/{repo}")
    if error:
        return _denied(error, "That repository is not allowed.")
    return None


def _ref(value: object, field: str) -> str | dict[str, Any]:
    text = str(value or "").strip()
    if not text or _REF_RE.fullmatch(text) is None or ".." in text:
        return _denied("invalid_ref", f"The {field} is not valid.")
    return text


def _number(value: object) -> int | dict[str, Any]:
    if isinstance(value, bool) or not isinstance(value, int):
        try:
            if isinstance(value, str) and value.isdigit():
                value = int(value)
            else:
                return _denied("invalid_number", "That number is not valid.")
        except (TypeError, ValueError):
            return _denied("invalid_number", "That number is not valid.")
    number = int(value)
    if number < 1 or number > 1_000_000_000:
        return _denied("invalid_number", "That number is not valid.")
    return number


def _clip(text: str) -> dict[str, Any]:
    if len(text) <= MAX_TEXT:
        return {"text": text, "truncated": False}
    return {"text": text[:MAX_TEXT], "truncated": True}


def _summarize_repo(item: dict[str, Any]) -> dict[str, Any]:
    owner = item.get("owner") if isinstance(item.get("owner"), dict) else {}
    private = bool(item.get("private"))
    return {
        "full_name": item.get("full_name"),
        "owner": owner.get("login"),
        "name": item.get("name"),
        "private": private,
        "visibility": item.get("visibility") or ("private" if private else "public"),
        "default_branch": item.get("default_branch"),
        "description": item.get("description"),
        "html_url": item.get("html_url"),
    }


def run_read(
    operation: str,
    arguments: dict[str, Any],
    *,
    headers: dict[str, str] | None,
    client: Any,
    policy: Any,
) -> dict[str, Any]:
    """Run one read. The caller supplies an HTTP client that records only GETs."""
    if operation not in READ_CAPABILITY_TOOLS:
        return _denied("unknown_read", "That GitHub read is not available.")
    if not policy.ok or not policy.enabled:
        return _denied("github_mcp_disabled", "GitHub is not enabled.")
    if not policy.allow_reads:
        return _denied("github_reads_disabled", "GitHub reads are not allowed.")
    if headers is None:
        return _denied("github_auth_unavailable", "GitHub authentication is not configured.")
    if client is None:
        return _denied("github_transport_not_authorized", "GitHub reads are not connected.")
    try:
        if operation == "github_list_repositories":
            return _list_repositories(arguments, headers, client, policy)
        if operation == "github_list_collaborators" and not policy.allow_permissions:
            return _denied("github_permissions_disabled", "Collaborator reads are not allowed.")
        if operation in {
            "github_list_workflows",
            "github_list_workflow_runs",
            "github_read_workflow_log",
        } and not policy.allow_workflows:
            return _denied("github_workflows_disabled", "Workflow reads are not allowed.")
        bound = _require_repo(arguments)
        if isinstance(bound, dict):
            return bound
        owner, repo = bound
        denied = _allow(policy, owner, repo)
        if denied:
            return denied
        return _REPOS[operation](owner, repo, arguments, headers, client)
    except Exception as exc:
        name = type(exc).__name__
        if name in {"TimeoutException", "ConnectTimeout", "ReadTimeout"}:
            return _denied("network_timeout", "GitHub timed out while reading.")
        return _denied("network_error", "GitHub could not be reached while reading.")


def _list_repositories(arguments: dict[str, Any], headers: dict[str, str], client: Any, policy: Any) -> dict[str, Any]:
    del arguments
    collected = _collect_list(client, f"{GITHUB_API}/user/repos?per_page={MAX_ITEMS}&sort=updated", headers)
    if isinstance(collected, dict) and collected.get("ok") is False:
        return collected
    assert isinstance(collected, dict)
    allowed = {name.casefold() for name in policy.allowed_repos}
    shown = []
    for item in collected["items"]:
        if not isinstance(item, dict):
            continue
        summary = _summarize_repo(item)
        owner = str(summary.get("owner") or "")
        name = str(summary.get("name") or "")
        if owner.casefold() != policy.allowed_owner.casefold() or name.casefold() not in allowed:
            continue
        shown.append(summary)
    return _ok(
        f"Found {len(shown)} allowlisted repositories.",
        repositories=shown,
        truncated=bool(collected["truncated"]),
    )


def _branches(owner: str, repo: str, arguments: dict[str, Any], headers: dict[str, str], client: Any) -> dict[str, Any]:
    del arguments
    collected = _collect_list(client, _repo_path(owner, repo, f"/branches?per_page={MAX_ITEMS}"), headers)
    if isinstance(collected, dict) and collected.get("ok") is False:
        return collected
    assert isinstance(collected, dict)
    names = [item.get("name") for item in collected["items"] if isinstance(item, dict)]
    return _ok(f"Found {len(names)} branches.", branches=names, truncated=bool(collected["truncated"]))


def _tags(owner: str, repo: str, arguments: dict[str, Any], headers: dict[str, str], client: Any) -> dict[str, Any]:
    del arguments
    collected = _collect_list(client, _repo_path(owner, repo, f"/tags?per_page={MAX_ITEMS}"), headers)
    if isinstance(collected, dict) and collected.get("ok") is False:
        return collected
    assert isinstance(collected, dict)
    names = [item.get("name") for item in collected["items"] if isinstance(item, dict)]
    return _ok(f"Found {len(names)} tags.", tags=names, truncated=bool(collected["truncated"]))


def _collaborators(owner: str, repo: str, arguments: dict[str, Any], headers: dict[str, str], client: Any) -> dict[str, Any]:
    del arguments
    collected = _collect_list(client, _repo_path(owner, repo, f"/collaborators?per_page={MAX_ITEMS}"), headers)
    if isinstance(collected, dict) and collected.get("ok") is False:
        return collected
    assert isinstance(collected, dict)
    people = []
    for item in collected["items"]:
        if isinstance(item, dict):
            people.append({"login": item.get("login"), "role": (item.get("role_name") or "")})
    return _ok(f"Found {len(people)} collaborators.", collaborators=people, truncated=bool(collected["truncated"]))


def _contents(owner: str, repo: str, arguments: dict[str, Any], headers: dict[str, str], client: Any) -> dict[str, Any]:
    path = str(arguments.get("path") or "").strip().replace("\\", "/")
    if path.startswith("/") or ".." in path.split("/"):
        return _denied("invalid_path", "That path is not valid.")
    ref = arguments.get("ref") or ""
    query = f"?ref={quote(str(ref), safe='')}" if ref else ""
    if ref and isinstance(_ref(ref, "ref"), dict):
        return _ref(ref, "ref")  # type: ignore[return-value]
    suffix = "/contents" + (f"/{quote(path, safe='/')}" if path else "") + query
    status, body, _response = _get_json(client, _repo_path(owner, repo, suffix), headers)
    if status >= 400:
        return _status_error(status, body)
    if isinstance(body, dict) and body.get("type") == "file":
        return _ok("That path is a file.", kind="file", path=body.get("path"), size=body.get("size"))
    if not isinstance(body, list):
        return _denied("github_malformed_response", "GitHub returned an unexpected directory.")
    entries = []
    for item in body[:MAX_ITEMS]:
        if isinstance(item, dict):
            entries.append({"name": item.get("name"), "type": item.get("type"), "path": item.get("path"), "size": item.get("size")})
    return _ok(f"Found {len(entries)} entries.", kind="dir", entries=entries, truncated=len(body) > MAX_ITEMS)


def _file(owner: str, repo: str, arguments: dict[str, Any], headers: dict[str, str], client: Any) -> dict[str, Any]:
    path = str(arguments.get("path") or "").strip().replace("\\", "/")
    if not path or path.startswith("/") or ".." in path.split("/"):
        return _denied("invalid_path", "That path is not valid.")
    ref = arguments.get("ref") or ""
    if ref and isinstance(_ref(ref, "ref"), dict):
        return _ref(ref, "ref")  # type: ignore[return-value]
    query = f"?ref={quote(str(ref), safe='')}" if ref else ""
    status, body, _response = _get_json(
        client,
        _repo_path(owner, repo, f"/contents/{quote(path, safe='/')}{query}"),
        headers,
    )
    if status >= 400:
        return _status_error(status, body)
    if not isinstance(body, dict) or body.get("encoding") != "base64" or not isinstance(body.get("content"), str):
        return _denied("github_malformed_response", "GitHub did not return file text.")
    try:
        raw = base64.b64decode(re.sub(r"\s+", "", body["content"]), validate=False)
    except Exception:
        return _denied("github_malformed_response", "GitHub did not return file text.")
    text = raw.decode("utf-8", errors="replace")
    clipped = _clip(text)
    return _ok(
        f"Read {path}.",
        path=body.get("path") or path,
        size=len(raw),
        text=clipped["text"],
        truncated=clipped["truncated"],
        sha=body.get("sha"),
    )


def _commits(owner: str, repo: str, arguments: dict[str, Any], headers: dict[str, str], client: Any) -> dict[str, Any]:
    ref = arguments.get("ref") or ""
    query = f"?per_page={MAX_ITEMS}"
    if ref:
        checked = _ref(ref, "ref")
        if isinstance(checked, dict):
            return checked
        query += f"&sha={quote(checked, safe='')}"
    collected = _collect_list(client, _repo_path(owner, repo, f"/commits{query}"), headers)
    if isinstance(collected, dict) and collected.get("ok") is False:
        return collected
    assert isinstance(collected, dict)
    rows = []
    for item in collected["items"]:
        if not isinstance(item, dict):
            continue
        commit = item.get("commit") if isinstance(item.get("commit"), dict) else {}
        rows.append({
            "sha": item.get("sha"),
            "message": str((commit.get("message") or "")).split("\n", 1)[0][:160],
            "date": ((commit.get("author") or {}) if isinstance(commit.get("author"), dict) else {}).get("date"),
        })
    return _ok(f"Found {len(rows)} commits.", commits=rows, truncated=bool(collected["truncated"]))


def _commit(owner: str, repo: str, arguments: dict[str, Any], headers: dict[str, str], client: Any) -> dict[str, Any]:
    sha = _ref(arguments.get("sha") or arguments.get("ref"), "commit")
    if isinstance(sha, dict):
        return sha
    status, body, _response = _get_json(client, _repo_path(owner, repo, f"/commits/{quote(sha, safe='')}"), headers)
    if status >= 400:
        return _status_error(status, body)
    if not isinstance(body, dict):
        return _denied("github_malformed_response", "GitHub returned an unexpected commit.")
    commit = body.get("commit") if isinstance(body.get("commit"), dict) else {}
    files = []
    for item in (body.get("files") or [])[:MAX_ITEMS]:
        if isinstance(item, dict):
            files.append({"filename": item.get("filename"), "status": item.get("status"), "changes": item.get("changes")})
    message = str(commit.get("message") or "").split("\n", 1)[0][:160]
    return _ok(
        f"Commit {str(body.get('sha') or '')[:7]} {message}".strip(),
        sha=body.get("sha"),
        message=message,
        files=files,
        truncated=len(body.get("files") or []) > MAX_ITEMS,
    )


def _compare(owner: str, repo: str, arguments: dict[str, Any], headers: dict[str, str], client: Any) -> dict[str, Any]:
    base = _ref(arguments.get("base"), "base")
    head = _ref(arguments.get("head"), "head")
    if isinstance(base, dict):
        return base
    if isinstance(head, dict):
        return head
    status, body, _response = _get_json(
        client,
        _repo_path(owner, repo, f"/compare/{quote(base, safe='')}...{quote(head, safe='')}"),
        headers,
    )
    if status >= 400:
        return _status_error(status, body)
    if not isinstance(body, dict):
        return _denied("github_malformed_response", "GitHub returned an unexpected comparison.")
    files = []
    for item in (body.get("files") or [])[:MAX_ITEMS]:
        if isinstance(item, dict):
            files.append({"filename": item.get("filename"), "status": item.get("status")})
    return _ok(
        f"{body.get('ahead_by', 0)} commits ahead and {body.get('behind_by', 0)} behind.",
        status=body.get("status"),
        ahead_by=body.get("ahead_by"),
        behind_by=body.get("behind_by"),
        total_commits=body.get("total_commits"),
        files=files,
        truncated=len(body.get("files") or []) > MAX_ITEMS,
    )


def _issues(owner: str, repo: str, arguments: dict[str, Any], headers: dict[str, str], client: Any) -> dict[str, Any]:
    state = str(arguments.get("state") or "open")
    if state not in {"open", "closed", "all"}:
        return _denied("invalid_state", "Issue state must be open, closed, or all.")
    collected = _collect_list(client, _repo_path(owner, repo, f"/issues?state={state}&per_page={MAX_ITEMS}"), headers)
    if isinstance(collected, dict) and collected.get("ok") is False:
        return collected
    assert isinstance(collected, dict)
    rows = []
    for item in collected["items"]:
        if isinstance(item, dict) and "pull_request" not in item:
            rows.append({"number": item.get("number"), "title": str(item.get("title") or "")[:160], "state": item.get("state")})
    return _ok(f"Found {len(rows)} issues.", issues=rows, truncated=bool(collected["truncated"]))


def _issue(owner: str, repo: str, arguments: dict[str, Any], headers: dict[str, str], client: Any) -> dict[str, Any]:
    number = _number(arguments.get("number"))
    if isinstance(number, dict):
        return number
    status, body, _response = _get_json(client, _repo_path(owner, repo, f"/issues/{number}"), headers)
    if status >= 400:
        return _status_error(status, body)
    if not isinstance(body, dict):
        return _denied("github_malformed_response", "GitHub returned an unexpected issue.")
    clipped = _clip(str(body.get("body") or ""))
    return _ok(
        f"Issue {number}: {str(body.get('title') or '')[:120]}",
        number=body.get("number"),
        title=body.get("title"),
        state=body.get("state"),
        labels=[item.get("name") for item in body.get("labels") or [] if isinstance(item, dict)],
        body=clipped["text"],
        truncated=clipped["truncated"],
    )


def _pulls(owner: str, repo: str, arguments: dict[str, Any], headers: dict[str, str], client: Any) -> dict[str, Any]:
    state = str(arguments.get("state") or "open")
    if state not in {"open", "closed", "all"}:
        return _denied("invalid_state", "Pull request state must be open, closed, or all.")
    collected = _collect_list(client, _repo_path(owner, repo, f"/pulls?state={state}&per_page={MAX_ITEMS}"), headers)
    if isinstance(collected, dict) and collected.get("ok") is False:
        return collected
    assert isinstance(collected, dict)
    rows = []
    for item in collected["items"]:
        if isinstance(item, dict):
            rows.append({"number": item.get("number"), "title": str(item.get("title") or "")[:160], "state": item.get("state")})
    return _ok(f"Found {len(rows)} pull requests.", pull_requests=rows, truncated=bool(collected["truncated"]))


def _pull(owner: str, repo: str, arguments: dict[str, Any], headers: dict[str, str], client: Any) -> dict[str, Any]:
    number = _number(arguments.get("number"))
    if isinstance(number, dict):
        return number
    status, body, _response = _get_json(client, _repo_path(owner, repo, f"/pulls/{number}"), headers)
    if status >= 400:
        return _status_error(status, body)
    if not isinstance(body, dict):
        return _denied("github_malformed_response", "GitHub returned an unexpected pull request.")
    head = body.get("head") if isinstance(body.get("head"), dict) else {}
    base = body.get("base") if isinstance(body.get("base"), dict) else {}
    clipped = _clip(str(body.get("body") or ""))
    return _ok(
        f"Pull request {number}: {str(body.get('title') or '')[:120]}",
        number=body.get("number"),
        title=body.get("title"),
        state=body.get("state"),
        merged=bool(body.get("merged")),
        head=head.get("ref"),
        base=base.get("ref"),
        body=clipped["text"],
        truncated=clipped["truncated"],
    )


def _pull_comments(owner: str, repo: str, arguments: dict[str, Any], headers: dict[str, str], client: Any) -> dict[str, Any]:
    number = _number(arguments.get("number"))
    if isinstance(number, dict):
        return number
    comments = _collect_list(client, _repo_path(owner, repo, f"/pulls/{number}/comments?per_page={MAX_ITEMS}"), headers)
    if isinstance(comments, dict) and comments.get("ok") is False:
        return comments
    reviews = _collect_list(client, _repo_path(owner, repo, f"/pulls/{number}/reviews?per_page={MAX_ITEMS}"), headers)
    if isinstance(reviews, dict) and reviews.get("ok") is False:
        return reviews
    assert isinstance(comments, dict) and isinstance(reviews, dict)
    comment_rows = []
    for item in comments["items"]:
        if isinstance(item, dict):
            comment_rows.append({"user": (item.get("user") or {}).get("login") if isinstance(item.get("user"), dict) else None, "body": _clip(str(item.get("body") or ""))["text"][:240]})
    review_rows = []
    for item in reviews["items"]:
        if isinstance(item, dict):
            review_rows.append({"user": (item.get("user") or {}).get("login") if isinstance(item.get("user"), dict) else None, "state": item.get("state")})
    return _ok(
        f"Found {len(comment_rows)} review comments and {len(review_rows)} reviews.",
        comments=comment_rows,
        reviews=review_rows,
        truncated=bool(comments["truncated"] or reviews["truncated"]),
    )


def _releases(owner: str, repo: str, arguments: dict[str, Any], headers: dict[str, str], client: Any) -> dict[str, Any]:
    del arguments
    collected = _collect_list(client, _repo_path(owner, repo, f"/releases?per_page={MAX_ITEMS}"), headers)
    if isinstance(collected, dict) and collected.get("ok") is False:
        return collected
    assert isinstance(collected, dict)
    rows = []
    for item in collected["items"]:
        if isinstance(item, dict):
            rows.append({"id": item.get("id"), "tag": item.get("tag_name"), "name": item.get("name"), "draft": bool(item.get("draft"))})
    return _ok(f"Found {len(rows)} releases.", releases=rows, truncated=bool(collected["truncated"]))


def _release(owner: str, repo: str, arguments: dict[str, Any], headers: dict[str, str], client: Any) -> dict[str, Any]:
    release_id = arguments.get("release_id")
    tag = arguments.get("tag")
    if tag:
        checked = _ref(tag, "tag")
        if isinstance(checked, dict):
            return checked
        url = _repo_path(owner, repo, f"/releases/tags/{quote(checked, safe='')}")
    else:
        number = _number(release_id)
        if isinstance(number, dict):
            return number
        url = _repo_path(owner, repo, f"/releases/{number}")
    status, body, _response = _get_json(client, url, headers)
    if status >= 400:
        return _status_error(status, body)
    if not isinstance(body, dict):
        return _denied("github_malformed_response", "GitHub returned an unexpected release.")
    clipped = _clip(str(body.get("body") or ""))
    return _ok(
        f"Release {body.get('tag_name')}.",
        id=body.get("id"),
        tag=body.get("tag_name"),
        name=body.get("name"),
        draft=bool(body.get("draft")),
        body=clipped["text"],
        truncated=clipped["truncated"],
    )


def _workflows(owner: str, repo: str, arguments: dict[str, Any], headers: dict[str, str], client: Any) -> dict[str, Any]:
    del arguments
    status, body, _response = _get_json(client, _repo_path(owner, repo, "/actions/workflows?per_page=20"), headers)
    if status >= 400:
        return _status_error(status, body)
    if not isinstance(body, dict) or not isinstance(body.get("workflows"), list):
        return _denied("github_malformed_response", "GitHub returned an unexpected workflow list.")
    rows = []
    for item in body["workflows"][:MAX_ITEMS]:
        if isinstance(item, dict):
            rows.append({"id": item.get("id"), "name": item.get("name"), "path": item.get("path"), "state": item.get("state")})
    return _ok(f"Found {len(rows)} workflows.", workflows=rows, truncated=len(body["workflows"]) > MAX_ITEMS)


def _runs(owner: str, repo: str, arguments: dict[str, Any], headers: dict[str, str], client: Any) -> dict[str, Any]:
    del arguments
    status, body, _response = _get_json(client, _repo_path(owner, repo, f"/actions/runs?per_page={MAX_ITEMS}"), headers)
    if status >= 400:
        return _status_error(status, body)
    if not isinstance(body, dict) or not isinstance(body.get("workflow_runs"), list):
        return _denied("github_malformed_response", "GitHub returned an unexpected workflow run list.")
    rows = []
    for item in body["workflow_runs"][:MAX_ITEMS]:
        if isinstance(item, dict):
            rows.append({
                "id": item.get("id"),
                "name": item.get("name"),
                "status": item.get("status"),
                "conclusion": item.get("conclusion"),
                "html_url": item.get("html_url"),
            })
    return _ok(f"Found {len(rows)} workflow runs.", runs=rows, truncated=len(body["workflow_runs"]) > MAX_ITEMS)


def _log(owner: str, repo: str, arguments: dict[str, Any], headers: dict[str, str], client: Any) -> dict[str, Any]:
    number = _number(arguments.get("run_id"))
    if isinstance(number, dict):
        return number
    response = client.request("GET", _repo_path(owner, repo, f"/actions/runs/{number}/logs"), headers=headers)
    status = int(getattr(response, "status_code", 0))
    if status in {302, 200}:
        return _ok(
            "The workflow log is available. The archive was not downloaded.",
            run_id=number,
            log_available=True,
            downloaded=False,
            status=status,
        )
    try:
        body = response.json()
    except Exception:
        body = None
    return _status_error(status, body)


_REPOS: dict[str, Callable[..., dict[str, Any]]] = {
    "github_list_branches": _branches,
    "github_list_tags": _tags,
    "github_list_collaborators": _collaborators,
    "github_list_contents": _contents,
    "github_read_file": _file,
    "github_list_commits": _commits,
    "github_get_commit": _commit,
    "github_compare_refs": _compare,
    "github_list_issues": _issues,
    "github_get_issue": _issue,
    "github_list_pull_requests": _pulls,
    "github_get_pull_request": _pull,
    "github_list_pull_request_comments": _pull_comments,
    "github_list_releases": _releases,
    "github_get_release": _release,
    "github_list_workflows": _workflows,
    "github_list_workflow_runs": _runs,
    "github_read_workflow_log": _log,
}


def register_read_tools(mcp: Any, server: Any, module: Any) -> None:
    """Attach read tools to the existing GitHub MCP server object."""

    def _serve(operation: str, arguments: dict[str, Any]) -> str:
        from realtime_c.github_approval import load_github_policy

        policy = load_github_policy(server.policy_root())
        if not policy.ok or not policy.enabled:
            return server.err("github_mcp_disabled", "GitHub is not enabled.")
        if not policy.allow_reads:
            return server.err("github_reads_disabled", "GitHub reads are not allowed.")
        meta_ok, _wire, _job, meta_error = server.job_metadata(arguments.get("ctx"))
        if not meta_ok:
            return server.err(meta_error or "invalid_job_metadata", "The job metadata is not valid.")
        clean = {key: value for key, value in arguments.items() if key != "ctx"}
        result = run_read(
            operation,
            clean,
            headers=server.headers(),
            client=server.client(),
            policy=policy,
        )
        return server.public_json(result)

    specs = {
        "github_list_repositories": ("List allowlisted repositories for the authenticated account.", []),
        "github_list_branches": ("List branches of an allowlisted repository.", ["owner", "repo"]),
        "github_list_tags": ("List tags of an allowlisted repository.", ["owner", "repo"]),
        "github_list_collaborators": ("List collaborators when permission reads are allowed.", ["owner", "repo"]),
        "github_list_contents": ("List files in an allowlisted repository path.", ["owner", "repo", "path", "ref"]),
        "github_read_file": ("Read a text file from an allowlisted repository.", ["owner", "repo", "path", "ref"]),
        "github_list_commits": ("List recent commits on an allowlisted repository.", ["owner", "repo", "ref"]),
        "github_get_commit": ("Read one commit and its changed files.", ["owner", "repo", "sha"]),
        "github_compare_refs": ("Compare two refs in an allowlisted repository.", ["owner", "repo", "base", "head"]),
        "github_list_issues": ("List issues in an allowlisted repository.", ["owner", "repo", "state"]),
        "github_get_issue": ("Read one issue.", ["owner", "repo", "number"]),
        "github_list_pull_requests": ("List pull requests.", ["owner", "repo", "state"]),
        "github_get_pull_request": ("Read one pull request.", ["owner", "repo", "number"]),
        "github_list_pull_request_comments": ("Read pull request comments and review states.", ["owner", "repo", "number"]),
        "github_list_releases": ("List releases.", ["owner", "repo"]),
        "github_get_release": ("Read one release by id or tag.", ["owner", "repo", "release_id", "tag"]),
        "github_list_workflows": ("List workflow definitions when workflow reads are allowed.", ["owner", "repo"]),
        "github_list_workflow_runs": ("List workflow runs and their statuses.", ["owner", "repo"]),
        "github_read_workflow_log": ("Check whether a workflow log exists without downloading the archive.", ["owner", "repo", "run_id"]),
    }
    optional = {"path", "ref", "state", "number", "sha", "base", "head", "release_id", "tag", "run_id"}
    namespace: dict[str, Any] = {"_serve": _serve, "Context": Context}
    for name, (summary, params) in specs.items():
        parts = []
        for param in params:
            if param in optional:
                parts.append(f"{param}: str = ''")
            else:
                parts.append(f"{param}: str")
        signature = ", ".join(parts)
        if signature:
            signature += ", "
        code = (
            f"def {name}({signature}ctx: Context | None = None) -> str:\n"
            f"    {summary!r}\n"
            f"    return _serve({name!r}, locals())\n"
        )
        exec(code, namespace)  # noqa: S102 - static tool signatures, not user input
        function = namespace[name]
        function.__doc__ = summary
        setattr(module, name, function)
        mcp.tool()(function)
