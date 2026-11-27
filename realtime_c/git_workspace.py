"""Local Git operations inside one explicit workspace root.

Remote URLs with embedded credentials are rejected. This module does not
delete files, reset history, or clean untracked work.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any

_URL_CREDENTIAL_RE = re.compile(r"://[^/\s@]+(?::[^/\s@]*)?@")
_WORKSPACE_LOCK = threading.Lock()
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/\-]{1,120}$")
_TIMEOUT_S = 20.0
_NETWORK_TIMEOUT_S = 60.0


def _denied(error: str, spoken: str, **extra: Any) -> dict[str, Any]:
    payload = {"ok": False, "error": error, "spoken_status": spoken}
    payload.update(extra)
    return payload


def _ok(spoken: str, **extra: Any) -> dict[str, Any]:
    payload = {"ok": True, "spoken_status": spoken}
    payload.update(extra)
    return payload


def redact_remote(url: str) -> str:
    return _URL_CREDENTIAL_RE.sub("://[redacted]@", url)


def load_workspace_root(project_root: Path | None) -> Path | None:
    """Return the configured workspace directory, or None when it is not set."""
    if project_root is None:
        return None
    path = project_root / "config" / "git_workspace.json"
    if not path.is_file():
        return None
    try:
        import json
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    raw = data.get("workspace_root") if isinstance(data, dict) else None
    if not isinstance(raw, str) or not raw.strip():
        return None
    return Path(raw)


def resolve_inside(workspace: Path, requested: str) -> Path | dict[str, Any]:
    """Resolve one path and reject anything outside the workspace."""
    root = workspace.resolve()
    if not root.is_dir():
        return _denied("workspace_root_missing", "The approved workspace directory does not exist.")
    raw = Path(requested)
    if raw.is_absolute():
        candidate = raw
    else:
        candidate = root / raw
    cursor = candidate
    while True:
        if cursor.exists() and cursor.is_symlink():
            return _denied("symlink_rejected", "Symlinked workspace paths are not allowed.")
        if cursor == root or cursor.parent == cursor:
            break
        cursor = cursor.parent
    try:
        resolved = candidate.resolve()
    except OSError:
        return _denied("invalid_path", "That workspace path is not valid.")
    if resolved != root and root not in resolved.parents:
        return _denied("path_outside_workspace", "That path is outside the approved workspace.")
    return resolved


def _git_env(empty_config: Path) -> dict[str, str]:
    env = os.environ.copy()
    for key in ("GITHUB_TOKEN", "GITHUB_MCP_TOKEN", "GH_TOKEN", "GIT_ASKPASS"):
        env.pop(key, None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_GLOBAL"] = str(empty_config)
    env["GIT_CONFIG_SYSTEM"] = str(empty_config)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    return env


def _run_git(repo: Path, args: list[str], *, timeout: float, empty_config: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=_git_env(empty_config),
        check=False,
    )


def _empty_config(workspace: Path) -> Path:
    del workspace
    path = Path(tempfile.gettempdir()) / "me3_icy_empty_gitconfig"
    if not path.exists():
        path.write_text("", encoding="utf-8")
    return path


def _repository(workspace: Path, relative: str) -> Path | dict[str, Any]:
    resolved = resolve_inside(workspace, relative or ".")
    if isinstance(resolved, dict):
        return resolved
    git_dir = resolved / ".git"
    if not git_dir.exists():
        return _denied("not_a_repository", "That folder is not a Git repository.", path=str(resolved))
    return resolved


def _porcelain(repo: Path, empty_config: Path) -> tuple[str, dict[str, Any] | None]:
    try:
        result = _run_git(repo, ["status", "--porcelain=v1", "--branch"], timeout=_TIMEOUT_S, empty_config=empty_config)
    except subprocess.TimeoutExpired:
        return "", _denied("git_timeout", "Git status timed out.")
    except FileNotFoundError:
        return "", _denied("git_unavailable", "Git is not available on this machine.")
    if result.returncode != 0:
        return "", _denied("git_failed", "Git status failed.", detail=redact_remote(result.stderr.strip())[:300])
    return result.stdout, None


def workspace_status(workspace: Path, relative: str = ".") -> dict[str, Any]:
    repo = _repository(workspace, relative)
    if isinstance(repo, dict):
        return repo
    text, error = _porcelain(repo, _empty_config(workspace))
    if error:
        return error
    lines = [line for line in text.splitlines() if line and not line.startswith("##")]
    branch = ""
    for line in text.splitlines():
        if line.startswith("## "):
            branch = line[3:].split("...", 1)[0]
    return _ok(
        "The workspace is clean." if not lines else f"{len(lines)} local changes.",
        path=str(repo),
        branch=branch,
        clean=not lines,
        changed=lines[:50],
        truncated=len(lines) > 50,
    )


def workspace_branch(workspace: Path, relative: str = ".") -> dict[str, Any]:
    status = workspace_status(workspace, relative)
    if not status.get("ok"):
        return status
    return _ok(f"Current branch is {status.get('branch') or 'unknown'}.", branch=status.get("branch"), path=status.get("path"))


def workspace_remotes(workspace: Path, relative: str = ".") -> dict[str, Any]:
    repo = _repository(workspace, relative)
    if isinstance(repo, dict):
        return repo
    try:
        result = _run_git(repo, ["remote", "-v"], timeout=_TIMEOUT_S, empty_config=_empty_config(workspace))
    except subprocess.TimeoutExpired:
        return _denied("git_timeout", "Git remotes timed out.")
    except FileNotFoundError:
        return _denied("git_unavailable", "Git is not available on this machine.")
    if result.returncode != 0:
        return _denied("git_failed", "Git remotes failed.", detail=redact_remote(result.stderr.strip())[:300])
    remotes = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            remotes.append({"name": parts[0], "url": redact_remote(parts[1]), "direction": parts[2] if len(parts) > 2 else ""})
    return _ok(f"Found {len({item['name'] for item in remotes})} remotes.", remotes=remotes)


def workspace_log(workspace: Path, relative: str = ".", limit: int = 10) -> dict[str, Any]:
    repo = _repository(workspace, relative)
    if isinstance(repo, dict):
        return repo
    count = limit if isinstance(limit, int) and 1 <= limit <= 20 else 10
    try:
        result = _run_git(
            repo,
            ["log", f"-n{count}", "--pretty=format:%h%x09%s"],
            timeout=_TIMEOUT_S,
            empty_config=_empty_config(workspace),
        )
    except subprocess.TimeoutExpired:
        return _denied("git_timeout", "Git log timed out.")
    except FileNotFoundError:
        return _denied("git_unavailable", "Git is not available on this machine.")
    if result.returncode != 0:
        return _denied("git_failed", "Git log failed.", detail=redact_remote(result.stderr.strip())[:300])
    commits = []
    for line in result.stdout.splitlines():
        if "\t" in line:
            sha, message = line.split("\t", 1)
            commits.append({"sha": sha, "message": message[:160]})
    return _ok(f"Found {len(commits)} commits.", commits=commits)


def workspace_diff(workspace: Path, relative: str = ".") -> dict[str, Any]:
    repo = _repository(workspace, relative)
    if isinstance(repo, dict):
        return repo
    try:
        result = _run_git(repo, ["diff", "--stat"], timeout=_TIMEOUT_S, empty_config=_empty_config(workspace))
    except subprocess.TimeoutExpired:
        return _denied("git_timeout", "Git diff timed out.")
    except FileNotFoundError:
        return _denied("git_unavailable", "Git is not available on this machine.")
    if result.returncode != 0:
        return _denied("git_failed", "Git diff failed.", detail=redact_remote(result.stderr.strip())[:300])
    text = result.stdout
    truncated = len(text) > 4000
    return _ok("Diff is ready." if text else "There is no unstaged diff.", diff=text[:4000], truncated=truncated)


def workspace_changed(workspace: Path, relative: str = ".") -> dict[str, Any]:
    status = workspace_status(workspace, relative)
    if not status.get("ok"):
        return status
    return _ok(status["spoken_status"], changed=status.get("changed"), clean=status.get("clean"))


def workspace_clean(workspace: Path, relative: str = ".") -> dict[str, Any]:
    status = workspace_status(workspace, relative)
    if not status.get("ok"):
        return status
    return _ok("The workspace is clean." if status.get("clean") else "The workspace has uncommitted changes.", clean=bool(status.get("clean")))


def _reject_remote_url(url: str) -> dict[str, Any] | None:
    if _URL_CREDENTIAL_RE.search(url) or ("://" in url and "@" in url.split("://", 1)[-1]):
        return _denied("credential_in_url", "Remote URLs must not contain credentials.")
    if "://" in url and not url.startswith("https://"):
        return _denied("remote_not_https", "Only https remotes or a local path can be used.")
    return None


def _begin_mutation() -> dict[str, Any] | None:
    if _WORKSPACE_LOCK.acquire(blocking=False):
        return None
    return _denied("workspace_busy", "Another workspace operation is still running.")


def workspace_clone(workspace: Path, source: str, destination: str) -> dict[str, Any]:
    busy = _begin_mutation()
    if busy:
        return busy
    try:
        return _clone_unlocked(workspace, source, destination)
    finally:
        _WORKSPACE_LOCK.release()


def _clone_unlocked(workspace: Path, source: str, destination: str) -> dict[str, Any]:
    if not isinstance(source, str) or not source.strip() or not isinstance(destination, str) or not destination.strip():
        return _denied("clone_target_required", "A source and a new destination are required.")
    rejected = _reject_remote_url(source) if "://" in source else None
    if rejected:
        return rejected
    dest = resolve_inside(workspace, destination)
    if isinstance(dest, dict):
        return dest
    if dest.exists():
        return _denied("destination_exists", "Clone will not overwrite an existing directory.", path=str(dest))
    parent = dest.parent
    if not parent.is_dir():
        return _denied("destination_parent_missing", "The destination folder does not exist.")
    empty = _empty_config(workspace)
    try:
        result = subprocess.run(
            ["git", "clone", "--", source, str(dest)],
            capture_output=True,
            text=True,
            timeout=_NETWORK_TIMEOUT_S,
            env=_git_env(empty),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _denied("git_timeout", "Git clone timed out. The destination was not reused.")
    except FileNotFoundError:
        return _denied("git_unavailable", "Git is not available on this machine.")
    if result.returncode != 0:
        return _denied("git_failed", "Git clone failed.", detail=redact_remote(result.stderr.strip())[:300])
    return _ok(f"Cloned into {dest.name}.", path=str(dest))


def workspace_fetch(workspace: Path, relative: str = ".", remote: str = "origin") -> dict[str, Any]:
    busy = _begin_mutation()
    if busy:
        return busy
    try:
        return _fetch_unlocked(workspace, relative, remote)
    finally:
        _WORKSPACE_LOCK.release()


def _fetch_unlocked(workspace: Path, relative: str, remote: str) -> dict[str, Any]:
    if not _BRANCH_RE.fullmatch(remote or ""):
        return _denied("invalid_remote", "That remote name is not valid.")
    status = workspace_status(workspace, relative)
    if not status.get("ok"):
        return status
    repo = Path(str(status["path"]))
    try:
        result = _run_git(repo, ["fetch", remote], timeout=_NETWORK_TIMEOUT_S, empty_config=_empty_config(workspace))
    except subprocess.TimeoutExpired:
        return _denied("git_timeout", "Git fetch timed out. Local files were not changed.")
    except FileNotFoundError:
        return _denied("git_unavailable", "Git is not available on this machine.")
    if result.returncode != 0:
        return _denied("git_failed", "Git fetch failed. Local files were not changed.", detail=redact_remote(result.stderr.strip())[:300])
    return _ok("Fetched remote updates. Local commits and files were left in place.", clean=status.get("clean"))


def workspace_pull(workspace: Path, relative: str = ".") -> dict[str, Any]:
    busy = _begin_mutation()
    if busy:
        return busy
    try:
        return _pull_unlocked(workspace, relative)
    finally:
        _WORKSPACE_LOCK.release()


def _pull_unlocked(workspace: Path, relative: str) -> dict[str, Any]:
    status = workspace_status(workspace, relative)
    if not status.get("ok"):
        return status
    if not status.get("clean"):
        return _denied(
            "uncommitted_changes",
            "Pull was not started because there are uncommitted changes. Commit or set them aside yourself, then try again.",
            changed=status.get("changed"),
        )
    repo = Path(str(status["path"]))
    try:
        result = _run_git(repo, ["pull", "--ff-only"], timeout=_NETWORK_TIMEOUT_S, empty_config=_empty_config(workspace))
    except subprocess.TimeoutExpired:
        return _denied("git_timeout", "Git pull timed out.")
    except FileNotFoundError:
        return _denied("git_unavailable", "Git is not available on this machine.")
    if result.returncode != 0:
        return _denied(
            "git_failed",
            "Pull did not fast-forward. Local changes were not discarded.",
            detail=redact_remote((result.stderr or result.stdout).strip())[:300],
        )
    return _ok("Pulled fast-forward updates.", detail=redact_remote(result.stdout.strip())[:300])


def workspace_create_branch(workspace: Path, relative: str, branch: str) -> dict[str, Any]:
    busy = _begin_mutation()
    if busy:
        return busy
    try:
        return _branch_unlocked(workspace, relative, branch)
    finally:
        _WORKSPACE_LOCK.release()


def _branch_unlocked(workspace: Path, relative: str, branch: str) -> dict[str, Any]:
    if _BRANCH_RE.fullmatch(branch or "") is None or ".." in branch:
        return _denied("invalid_branch", "That branch name is not valid.")
    repo = _repository(workspace, relative)
    if isinstance(repo, dict):
        return repo
    try:
        result = _run_git(repo, ["switch", "-c", branch], timeout=_TIMEOUT_S, empty_config=_empty_config(workspace))
    except subprocess.TimeoutExpired:
        return _denied("git_timeout", "Creating the branch timed out.")
    except FileNotFoundError:
        return _denied("git_unavailable", "Git is not available on this machine.")
    if result.returncode != 0:
        return _denied("git_failed", "The branch was not created.", detail=redact_remote(result.stderr.strip())[:300])
    return _ok(f"Created and switched to {branch}.", branch=branch)


def workspace_push(workspace: Path, relative: str, remote: str, branch: str, expected_head: str) -> dict[str, Any]:
    busy = _begin_mutation()
    if busy:
        return busy
    try:
        return _push_unlocked(workspace, relative, remote, branch, expected_head)
    finally:
        _WORKSPACE_LOCK.release()


def _push_unlocked(workspace: Path, relative: str, remote: str, branch: str, expected_head: str) -> dict[str, Any]:
    if _BRANCH_RE.fullmatch(remote or "") is None or _BRANCH_RE.fullmatch(branch or "") is None:
        return _denied("invalid_branch", "The remote or branch name is not valid.")
    status = workspace_status(workspace, relative)
    if not status.get("ok"):
        return status
    if not status.get("clean"):
        return _denied("uncommitted_changes", "Push was not started because there are uncommitted changes.", changed=status.get("changed"))
    repo = Path(str(status["path"]))
    try:
        head = _run_git(repo, ["rev-parse", "HEAD"], timeout=_TIMEOUT_S, empty_config=_empty_config(workspace))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return _denied("git_failed", "The current commit could not be read.")
    current = head.stdout.strip()
    if head.returncode != 0 or not current or not current.startswith(expected_head):
        return _denied("head_changed", "The commit changed after approval. Nothing was pushed.", head=current[:12])
    try:
        result = _run_git(repo, ["push", remote, f"{branch}:{branch}"], timeout=_NETWORK_TIMEOUT_S, empty_config=_empty_config(workspace))
    except subprocess.TimeoutExpired:
        return _denied("git_timeout", "Git push timed out. The result was not retried.")
    except FileNotFoundError:
        return _denied("git_unavailable", "Git is not available on this machine.")
    if result.returncode != 0:
        return _denied("git_failed", "Git push failed.", detail=redact_remote(result.stderr.strip())[:300])
    return _ok(f"Pushed {branch}.", head=current)
