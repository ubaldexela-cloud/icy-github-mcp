"""Map a spoken request onto a tool that is actually listed.

This does not replace the language model. Tests and diagnostics use it to
prove a phrase selects a schema that the session is offering.
"""

from __future__ import annotations

_PHRASES: tuple[tuple[str, str], ...] = (
    ("repositories", "github_list_repositories"),
    ("prepare a change", "github_prepare_operation"),
    ("prepare a commit", "github_prepare_operation"),
    ("approve this change", "github_approve_operation"),
    ("readme", "github_read_file"),
    ("latest commits", "github_list_commits"),
    ("pull requests", "github_list_pull_requests"),
    ("clone", "git_clone"),
    ("working tree", "git_status"),
    ("local changes", "git_status"),
    ("what will be committed", "git_diff"),
    ("feature branch", "github_prepare_operation"),
    ("push the approved", "github_prepare_operation"),
    ("pull request", "github_prepare_operation"),
    ("open an issue", "github_prepare_operation"),
)


def propose_tool(utterance: str, schemas: dict[str, object]) -> str | None:
    """Return one listed tool name, or None when the phrase is not available."""
    text = utterance.casefold()
    for phrase, name in _PHRASES:
        if phrase in text and name in schemas:
            return name
    return None
