"""Credential provider selection. Operating-system stores are mocked."""

from __future__ import annotations

import logging
import os
import unittest
from pathlib import Path
from unittest import mock

from mcp_servers import github_server as gh
from realtime_c import github_credentials as creds


def _classic() -> str:
    return "ghp_" + ("a" * 36)


class _SecretTool:
    def __init__(self) -> None:
        self.value: str | None = None
        self.actions: list[str] = []
        self.fail = False

    def which(self, name: str) -> str | None:
        return "/usr/bin/secret-tool" if name == "secret-tool" else None

    def run(self, action: str, stdin: str | None) -> tuple[int, str, str]:
        self.actions.append(action)
        if self.fail:
            raise RuntimeError("backend exploded")
        if action == "store":
            self.value = stdin
            return 0, "", ""
        if action == "lookup":
            if self.value is None:
                return 1, "", ""
            return 0, self.value + "\n", ""
        if action == "clear":
            self.value = None
            return 0, "", ""
        return 2, "", ""


class CredentialProviderTests(unittest.TestCase):
    def test_windows_is_selected_here_and_does_not_use_the_environment(self) -> None:
        provider = creds.select_provider()
        self.assertIsInstance(provider, creds.WindowsCredentialProvider)
        source = Path(creds.__file__).read_text(encoding="utf-8")
        self.assertNotIn("os.environ", source)
        self.assertNotIn("GITHUB_TOKEN", source)
        self.assertNotIn(".env", source)
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": _classic()}, clear=False):
            with mock.patch.object(gh, "_auth_token", return_value=None):
                self.assertIsNone(provider.retrieve())
                status = provider.status()
        self.assertEqual(status["backend"], "windows-credential-manager")
        self.assertTrue(status["available"])
        self.assertFalse(status["configured"])
        self.assertNotIn("token", status)

    def test_windows_retrieve_uses_the_existing_reader(self) -> None:
        provider = creds.WindowsCredentialProvider()
        token = _classic()
        with mock.patch.object(gh, "_auth_token", return_value=token) as reader:
            self.assertEqual(provider.retrieve(), token)
        reader.assert_called_once()
        auth_source = __import__("inspect").getsource(gh._auth_token)
        self.assertNotIn("os.environ", auth_source)
        self.assertNotIn("GITHUB_TOKEN", auth_source)

    def test_windows_read_failure_is_sanitized(self) -> None:
        provider = creds.WindowsCredentialProvider()

        def explode() -> str:
            raise RuntimeError(_classic())

        with mock.patch.object(gh, "_auth_token", explode):
            with self.assertRaises(creds.CredentialError) as caught:
                provider.retrieve()
        self.assertEqual(str(caught.exception), "RuntimeError")
        self.assertNotIn(_classic(), str(caught.exception))

    def test_windows_rotation_uses_mocked_writes(self) -> None:
        provider = creds.WindowsCredentialProvider()
        vault: dict[str, str] = {}

        def write(secret: str) -> None:
            vault["secret"] = secret

        def delete() -> None:
            vault.pop("secret", None)

        with mock.patch.object(creds, "_windows_write", write), mock.patch.object(creds, "_windows_delete", delete):
            with mock.patch.object(gh, "_auth_token", side_effect=lambda: vault.get("secret")):
                first = provider.store(_classic())
                self.assertTrue(first["ok"], first)
                self.assertNotIn("secret", first)
                rotated = provider.store("github_pat_" + ("b" * 22))
                self.assertTrue(rotated["ok"], rotated)
                self.assertEqual(vault["secret"], "github_pat_" + ("b" * 22))
                removed = provider.delete()
                self.assertTrue(removed["ok"], removed)
                self.assertIsNone(provider.retrieve())

    def test_linux_secret_service_round_trip_and_no_environment_fallback(self) -> None:
        tool = _SecretTool()
        provider = creds.SecretServiceProvider(runner=tool.run, which=tool.which)
        self.assertIsNone(provider.retrieve())
        missing = provider.status()
        self.assertTrue(missing["available"])
        self.assertFalse(missing["configured"])
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": _classic()}, clear=False):
            self.assertIsNone(provider.retrieve())
        stored = provider.store(_classic())
        self.assertTrue(stored["ok"], stored)
        self.assertEqual(provider.retrieve(), _classic())
        self.assertNotIn(_classic(), repr(stored))
        self.assertIn("store", tool.actions)
        self.assertNotIn(_classic(), " ".join(tool.actions))
        rotated = provider.store("github_pat_" + ("c" * 22))
        self.assertTrue(rotated["ok"], rotated)
        self.assertEqual(provider.retrieve(), "github_pat_" + ("c" * 22))
        self.assertTrue(provider.delete()["ok"])
        self.assertIsNone(provider.retrieve())
        self.assertNotIn(_classic(), " ".join(tool.actions))

    def test_secret_service_failure_and_unavailable_backend(self) -> None:
        tool = _SecretTool()
        tool.fail = True
        provider = creds.SecretServiceProvider(runner=tool.run, which=tool.which)
        with self.assertRaises(creds.CredentialError) as caught:
            provider.retrieve()
        self.assertEqual(str(caught.exception), "credential_backend_failed")
        self.assertNotIn("exploded", str(caught.exception))
        absent = creds.SecretServiceProvider(runner=tool.run, which=lambda _name: None)
        self.assertFalse(absent.available())
        self.assertEqual(absent.status()["error"], "secret_service_unavailable")
        self.assertIsNone(absent.retrieve())
        self.assertFalse(absent.store(_classic())["ok"])

    def test_linux_selection_and_platform_token_do_not_log_the_secret(self) -> None:
        tool = _SecretTool()
        records: list[str] = []

        class _Handler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record.getMessage())

        handler = _Handler()
        creds._LOG.addHandler(handler)
        creds._LOG.setLevel(logging.WARNING)
        try:
            with mock.patch.object(creds, "os") as platform_os, mock.patch.object(creds.sys, "platform", "linux"):
                platform_os.name = "posix"
                with mock.patch.object(creds.shutil, "which", return_value=None):
                    selected = creds.select_provider()
                self.assertIsInstance(selected, creds.UnavailableProvider)
                with mock.patch.object(creds.shutil, "which", return_value="/usr/bin/secret-tool"):
                    selected = creds.select_provider()
                self.assertIsInstance(selected, creds.SecretServiceProvider)
                broken = creds.SecretServiceProvider(runner=tool.run, which=tool.which)
                tool.fail = True
                with mock.patch.object(creds, "select_provider", return_value=broken):
                    self.assertIsNone(creds.retrieve_platform_token())
        finally:
            creds._LOG.removeHandler(handler)
        self.assertTrue(records)
        self.assertNotIn(_classic(), "\n".join(records))

    def test_provision_reports_only_status(self) -> None:
        tool = _SecretTool()
        provider = creds.SecretServiceProvider(runner=tool.run, which=tool.which)
        answers = iter([_classic(), _classic()])
        with mock.patch.object(creds, "select_provider", return_value=provider):
            result = creds.provision_from_prompt(lambda _label: next(answers))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["backend"], provider.name)
        self.assertNotIn(_classic(), repr(result))
        mismatch = iter([_classic(), "github_pat_" + ("d" * 22)])
        with mock.patch.object(creds, "select_provider", return_value=provider):
            rejected = creds.provision_from_prompt(lambda _label: next(mismatch))
        self.assertFalse(rejected["ok"])
        self.assertEqual(rejected["error"], "credential_rejected")


if __name__ == "__main__":
    unittest.main()
