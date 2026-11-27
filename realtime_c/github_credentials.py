"""Credential providers for GitHub authentication.

Windows keeps Credential Manager. Linux uses the Freedesktop Secret Service
through ``secret-tool`` and stays inactive until a credential is stored.
There is no environment, dotenv, or plaintext-file fallback.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from typing import Any, Callable

_LOG = logging.getLogger("realtime_c.github_credentials")
_SERVICE = "me3-icy-github-mcp"
_ACCOUNT = "github-token"
_LABEL = "me3-icy-github-mcp"


class CredentialError(Exception):
    """Sanitized provider failure. The message is a fixed code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _status(backend: str, *, available: bool, configured: bool, error: str | None = None) -> dict[str, Any]:
    return {
        "backend": backend,
        "available": available,
        "configured": configured,
        "error": error,
    }


def _accepted_shape(secret: str) -> bool:
    from mcp_servers.github_server import _CLASSIC_PAT_RE, _FINE_PAT_RE

    return bool(_CLASSIC_PAT_RE.fullmatch(secret) or _FINE_PAT_RE.fullmatch(secret))


class UnavailableProvider:
    name = "unavailable"

    def available(self) -> bool:
        return False

    def status(self) -> dict[str, Any]:
        return _status(self.name, available=False, configured=False, error="unavailable_backend")

    def retrieve(self) -> str | None:
        return None

    def store(self, secret: str) -> dict[str, Any]:
        del secret
        return {"ok": False, "backend": self.name, "error": "unavailable_backend"}

    def delete(self) -> dict[str, Any]:
        return {"ok": False, "backend": self.name, "error": "unavailable_backend"}


class WindowsCredentialProvider:
    """Read path is the existing CredReadW implementation."""

    name = "windows-credential-manager"

    def available(self) -> bool:
        return os.name == "nt"

    def status(self) -> dict[str, Any]:
        if not self.available():
            return _status(self.name, available=False, configured=False, error="unavailable_backend")
        try:
            configured = self.retrieve() is not None
        except CredentialError:
            return _status(self.name, available=True, configured=False, error="credential_read_failed")
        return _status(self.name, available=True, configured=configured)

    def retrieve(self) -> str | None:
        if not self.available():
            return None
        from mcp_servers.github_server import _auth_token

        try:
            token = _auth_token()
        except Exception as exc:
            raise CredentialError(type(exc).__name__) from None
        if token is not None and not isinstance(token, str):
            raise CredentialError("credential_read_failed")
        return token

    def store(self, secret: str) -> dict[str, Any]:
        if not self.available():
            return {"ok": False, "backend": self.name, "error": "unavailable_backend"}
        if not isinstance(secret, str) or not _accepted_shape(secret):
            return {"ok": False, "backend": self.name, "error": "credential_rejected"}
        try:
            _windows_write(secret)
        except CredentialError as exc:
            return {"ok": False, "backend": self.name, "error": exc.code}
        stored = self.retrieve()
        if stored != secret:
            return {"ok": False, "backend": self.name, "error": "credential_not_confirmed"}
        return {"ok": True, "backend": self.name, "configured": True}

    def delete(self) -> dict[str, Any]:
        if not self.available():
            return {"ok": False, "backend": self.name, "error": "unavailable_backend"}
        try:
            _windows_delete()
        except CredentialError as exc:
            return {"ok": False, "backend": self.name, "error": exc.code}
        return {"ok": True, "backend": self.name, "configured": self.retrieve() is not None}


class SecretServiceProvider:
    """Freedesktop Secret Service via ``secret-tool``. Inactive until store."""

    name = "freedesktop-secret-service"

    def __init__(
        self,
        runner: Callable[..., tuple[int, str, str]] | None = None,
        which: Callable[[str], str | None] | None = None,
    ) -> None:
        self._runner = runner or _secret_tool
        self._which = which or shutil.which

    def available(self) -> bool:
        return self._which("secret-tool") is not None

    def status(self) -> dict[str, Any]:
        if not self.available():
            return _status(self.name, available=False, configured=False, error="secret_service_unavailable")
        try:
            configured = self.retrieve() is not None
        except CredentialError:
            return _status(self.name, available=True, configured=False, error="credential_read_failed")
        return _status(self.name, available=True, configured=configured)

    def retrieve(self) -> str | None:
        if not self.available():
            return None
        code, text = self._call("lookup")
        if code != 0 or not text:
            return None
        secret = text.strip("\n")
        if not _accepted_shape(secret):
            return None
        return secret

    def store(self, secret: str) -> dict[str, Any]:
        if not self.available():
            return {"ok": False, "backend": self.name, "error": "secret_service_unavailable"}
        if not isinstance(secret, str) or not _accepted_shape(secret):
            return {"ok": False, "backend": self.name, "error": "credential_rejected"}
        code, _text = self._call("store", stdin=secret)
        if code != 0:
            return {"ok": False, "backend": self.name, "error": "credential_store_failed"}
        if self.retrieve() != secret:
            self.delete()
            return {"ok": False, "backend": self.name, "error": "credential_not_confirmed"}
        return {"ok": True, "backend": self.name, "configured": True}

    def delete(self) -> dict[str, Any]:
        if not self.available():
            return {"ok": False, "backend": self.name, "error": "secret_service_unavailable"}
        code, _text = self._call("clear")
        if code != 0:
            return {"ok": False, "backend": self.name, "error": "credential_delete_failed"}
        return {"ok": True, "backend": self.name, "configured": False}

    def _call(self, action: str, stdin: str | None = None) -> tuple[int, str]:
        try:
            code, text, _err = self._runner(action, stdin)
        except CredentialError:
            raise
        except Exception:
            raise CredentialError("credential_backend_failed") from None
        if not isinstance(code, int) or not isinstance(text, str):
            raise CredentialError("credential_backend_failed")
        return code, text


def select_provider() -> UnavailableProvider | WindowsCredentialProvider | SecretServiceProvider:
    if os.name == "nt":
        return WindowsCredentialProvider()
    if sys.platform.startswith("linux"):
        provider = SecretServiceProvider()
        if provider.available():
            return provider
        return UnavailableProvider()
    return UnavailableProvider()


def retrieve_platform_token() -> str | None:
    """Linux/other retrieval. Windows authentication does not call this."""
    if os.name == "nt":
        return None
    provider = select_provider()
    if isinstance(provider, WindowsCredentialProvider):
        return None
    try:
        return provider.retrieve()
    except CredentialError:
        _LOG.warning("github credential retrieval failed")
        return None


def provision_from_prompt(prompt: Callable[[str], str] | None = None) -> dict[str, Any]:
    """Read a hidden credential twice and store it. Nothing secret is printed."""
    ask = prompt or _hidden_prompt
    provider = select_provider()
    if not provider.available():
        return {"ok": False, "backend": provider.name, "error": "unavailable_backend"}
    first = ask("GitHub credential: ")
    second = ask("Repeat GitHub credential: ")
    try:
        if not isinstance(first, str) or first != second:
            return {"ok": False, "backend": provider.name, "error": "credential_rejected"}
        result = provider.store(first)
        return {
            "ok": bool(result.get("ok")),
            "backend": provider.name,
            "error": result.get("error"),
        }
    finally:
        first = ""
        second = ""


def delete_provisioned_credential() -> dict[str, Any]:
    provider = select_provider()
    result = provider.delete()
    return {"ok": bool(result.get("ok")), "backend": provider.name, "error": result.get("error")}


def sanitized_status() -> dict[str, Any]:
    provider = select_provider()
    try:
        return provider.status()
    except CredentialError as exc:
        return _status(provider.name, available=provider.available(), configured=False, error=exc.code)


def _hidden_prompt(label: str) -> str:
    import getpass

    return getpass.getpass(label)


def _secret_tool(action: str, stdin: str | None) -> tuple[int, str, str]:
    if action == "store":
        command = ["secret-tool", "store", "--label", _LABEL, "service", _SERVICE, "username", _ACCOUNT]
    elif action == "lookup":
        command = ["secret-tool", "lookup", "service", _SERVICE, "username", _ACCOUNT]
    elif action == "clear":
        command = ["secret-tool", "clear", "service", _SERVICE, "username", _ACCOUNT]
    else:
        raise CredentialError("credential_backend_failed")
    try:
        completed = subprocess.run(
            command,
            input=None if stdin is None else stdin.encode("utf-8"),
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise CredentialError("credential_backend_failed") from None
    text = completed.stdout.decode("utf-8", errors="ignore")
    return completed.returncode, text, ""


def _windows_write(secret: str) -> None:
    import ctypes

    from mcp_servers.github_server import (
        _CRED_PERSIST_LOCAL_MACHINE,
        _CRED_TARGET,
        _CRED_TYPE_GENERIC,
        _CRED_USERNAME,
        _CREDENTIALW,
        _credential_layout_ok,
    )

    if not _credential_layout_ok():
        raise CredentialError("credential_backend_failed")
    blob = bytearray(secret.encode("utf-16-le"))
    try:
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        write = advapi.CredWriteW
        write.argtypes = (ctypes.POINTER(_CREDENTIALW), ctypes.c_uint32)
        write.restype = ctypes.c_int
        record = _CREDENTIALW()
        record.Type = _CRED_TYPE_GENERIC
        record.TargetName = _CRED_TARGET
        record.UserName = _CRED_USERNAME
        record.Persist = _CRED_PERSIST_LOCAL_MACHINE
        record.CredentialBlobSize = len(blob)
        buffer = ctypes.create_string_buffer(bytes(blob))
        record.CredentialBlob = ctypes.cast(buffer, ctypes.c_void_p)
        if not write(ctypes.byref(record), 0):
            raise CredentialError("credential_store_failed")
    finally:
        for index in range(len(blob)):
            blob[index] = 0


def _windows_delete() -> None:
    import ctypes

    from mcp_servers.github_server import _CRED_TARGET, _CRED_TYPE_GENERIC, _credential_layout_ok

    if not _credential_layout_ok():
        raise CredentialError("credential_backend_failed")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    delete = advapi.CredDeleteW
    delete.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32)
    delete.restype = ctypes.c_int
    if not delete(_CRED_TARGET, _CRED_TYPE_GENERIC, 0):
        raise CredentialError("credential_delete_failed")


def main() -> int:
    result = provision_from_prompt()
    if result.get("ok"):
        print(f"credential stored backend={result['backend']}")
        return 0
    print(f"credential was not stored backend={result.get('backend')} error={result.get('error')}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
