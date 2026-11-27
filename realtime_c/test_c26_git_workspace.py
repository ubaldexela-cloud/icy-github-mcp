"""Isolated Git workspace tests. No GitHub network calls."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from realtime_c.git_workspace import (
    redact_remote,
    resolve_inside,
    workspace_clone,
    workspace_diff,
    workspace_fetch,
    workspace_log,
    workspace_pull,
    workspace_remotes,
    workspace_status,
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


class WorkspaceBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.origin = self.root / "origin"
        self.origin.mkdir()
        _git(self.origin, "init", "-b", "main")
        _git(self.origin, "config", "user.email", "icy@example.com")
        _git(self.origin, "config", "user.name", "ICY")
        (self.origin / "README.md").write_text("hello\n", encoding="utf-8")
        _git(self.origin, "add", "README.md")
        _git(self.origin, "commit", "-m", "initial")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_clone_status_and_refusal_to_overwrite_or_escape(self) -> None:
        cloned = workspace_clone(self.root, str(self.origin), "copy")
        self.assertTrue(cloned["ok"], cloned)
        self.assertTrue((self.root / "copy" / "README.md").is_file())
        again = workspace_clone(self.root, str(self.origin), "copy")
        self.assertEqual(again["error"], "destination_exists")
        self.assertTrue((self.root / "copy" / "README.md").read_text(encoding="utf-8") == "hello\n")
        outside = resolve_inside(self.root, "../outside")
        self.assertEqual(outside["error"], "path_outside_workspace")
        status = workspace_status(self.root, "copy")
        self.assertTrue(status["clean"], status)
        self.assertEqual(status["branch"], "main")
        history = workspace_log(self.root, "copy")
        self.assertEqual(history["commits"][0]["message"], "initial")
        remotes = workspace_remotes(self.root, "copy")
        self.assertTrue(remotes["ok"], remotes)
        fetched = workspace_fetch(self.root, "copy")
        self.assertTrue(fetched["ok"], fetched)
        self.assertEqual((self.root / "copy" / "README.md").read_text(encoding="utf-8"), "hello\n")
        (self.root / "copy" / "README.md").write_text("changed\n", encoding="utf-8")
        dirty = workspace_status(self.root, "copy")
        self.assertFalse(dirty["clean"])
        blocked = workspace_pull(self.root, "copy")
        self.assertEqual(blocked["error"], "uncommitted_changes")
        self.assertEqual((self.root / "copy" / "README.md").read_text(encoding="utf-8"), "changed\n")
        diff = workspace_diff(self.root, "copy")
        self.assertIn("README.md", diff["diff"])

    def test_credential_urls_are_rejected_and_redacted(self) -> None:
        rejected = workspace_clone(self.root, "https://user:token@github.com/example/repo.git", "secret")
        self.assertEqual(rejected["error"], "credential_in_url")
        self.assertFalse((self.root / "secret").exists())
        self.assertNotIn("token", redact_remote("https://user:token@github.com/example/repo.git"))


if __name__ == "__main__":
    unittest.main()
