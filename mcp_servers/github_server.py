"""Isolated GitHub MCP server for research-repo publish (optional additive).

Does not share process state with tools/ASR/TTS/browser servers.
Writes require an explicit confirmation token from github_prepare_publish.
Credentials: the GitHub child reads Windows Credential Manager directly.
The parent process does not. Environment variables and .env.github are not used.
"""

from __future__ import annotations

import base64
import contextvars
import ctypes
import hashlib
import socket
import ssl
import json
import logging
import os
import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from mcp.server.mcpserver import Context, MCPServer

logging.basicConfig(stream=sys.stderr, level=logging.INFO)
_LOG = logging.getLogger("me3.github_mcp")

mcp = MCPServer(
    "me3-github",
    instructions=(
        "Optional GitHub publish tools for research documentation. "
        "Always prepare_publish first; create/commit only after explicit user confirmation."
    ),
)

GITHUB_API = "https://api.github.com"
CONFIRM_TTL_S = 300.0
PREPARE_HTTP_DEADLINE_S = 6.75
SERVER_READ_HARD_DEADLINE_S = 7.50
PHASE2_HTTP_DEADLINE_S = 7.50
PRE_TX6_COMMIT_CUTOFF_S = 8.50
MIN_WRITE_BUDGET_S = 1.50
PRIMARY_WRITE_HTTP_DEADLINE_S = 10.00
RECOVERY_VERIFY_HTTP_DEADLINE_S = 12.00
SERVER_WRITE_TOTAL_CAP_S = 13.50
MAX_HTTP_RESPONSE_BYTES = 524_288
MAX_TOOL_RESULT_JSON_BYTES = 262_144

_REPO_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"gho_[A-Za-z0-9]{20,}"),
    re.compile(r"ghu_[A-Za-z0-9]{20,}"),
    re.compile(r"ghs_[A-Za-z0-9]{20,}"),
    re.compile(r"ghr_[A-Za-z0-9]{20,}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
)
_SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:\.env(?:\..+)?|.*credentials.*|.*secret.*|id_rsa|id_ed25519)(?:$|/)"
)
_HOME_PATH_RE = re.compile(
    r"(?i)(?:/home/[A-Za-z0-9._-]+|/Users/[A-Za-z0-9._-]+|"
    r"C:\\\\Users\\\\[A-Za-z0-9._-]+|C:/Users/[A-Za-z0-9._-]+)"
)

_ACTIVE_EXCHANGE_CTX: contextvars.ContextVar["_ExchangeDeadlineCtx | None"] = contextvars.ContextVar(
    "_ACTIVE_EXCHANGE_CTX",
    default=None,
)


class _ExchangeDeadlineCtx:
    def __init__(self, hard_deadline_mono: float, clock) -> None:
        self.hard_deadline_mono = hard_deadline_mono
        self.clock = clock
        self.wire_write_started = False


def _clamp_socket_timeout(phase_timeout: float | None, timeout_exc_cls: type[Exception]) -> float:
    """Use the remaining deadline, not a second full connect budget."""
    ctx = _ACTIVE_EXCHANGE_CTX.get()
    if ctx is None:
        return 5.0 if phase_timeout is None else max(0.001, phase_timeout)
    remaining = ctx.hard_deadline_mono - ctx.clock()
    if remaining <= 0.0:
        raise timeout_exc_cls("HTTP hard operation deadline exceeded")
    if phase_timeout is None:
        return max(0.001, remaining)
    return max(0.001, min(phase_timeout, remaining))


class DeadlineSyncStream:
    """Socket stream that reclamps every read, write, and TLS step on this thread."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        from httpcore import ReadTimeout

        eff = _clamp_socket_timeout(timeout, ReadTimeout)
        self._sock.settimeout(eff)
        return self._sock.recv(max_bytes)

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        from httpcore import WriteTimeout

        if not buffer:
            return
        view = buffer
        while view:
            eff = _clamp_socket_timeout(timeout, WriteTimeout)
            ctx = _ACTIVE_EXCHANGE_CTX.get()
            if ctx is not None:
                ctx.wire_write_started = True
            self._sock.settimeout(eff)
            sent = self._sock.send(view)
            view = view[sent:]

    def close(self) -> None:
        self._sock.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> "DeadlineSyncStream":
        from httpcore import ConnectTimeout

        eff = _clamp_socket_timeout(timeout, ConnectTimeout)
        self._sock.settimeout(eff)
        wrapped = ssl_context.wrap_socket(self._sock, server_hostname=server_hostname)
        return DeadlineSyncStream(wrapped)

    def get_extra_info(self, info: str) -> Any:
        if info == "socket":
            return self._sock
        return None


class DeadlineSyncBackend:
    """Same-thread network backend. It does not start a timer or close a foreign response."""

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> DeadlineSyncStream:
        from httpcore import ConnectTimeout

        eff = _clamp_socket_timeout(timeout, ConnectTimeout)
        source = None if local_address is None else (local_address, 0)
        sock = socket.create_connection((host, port), eff, source_address=source)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return DeadlineSyncStream(sock)

    def connect_unix_socket(self, path: str, timeout: float | None = None, socket_options: Any = None) -> DeadlineSyncStream:
        raise RuntimeError("unix sockets are not used")

    def sleep(self, seconds: float) -> None:
        import time

        time.sleep(seconds)


_CERTAIN_REFUSAL_STATUSES = frozenset({400, 401, 403, 404, 409, 422, 429})
_UNCERTAIN_VERIFY = frozenset({
    "absent",
    "matches_old_baseline",
    "inconclusive",
    "put_diverged_remote_state",
})


def classify_write_outcome(
    *,
    wire_write_started: bool,
    post_send_timeout: bool,
    verify_status: str | None,
    http_status: int | None,
    prior_mutations: int = 0,
    journal_write_attempted: bool | None = None,
) -> dict[str, Any]:
    """Gate A4 from the Rev 7 HTTP deadline design.

    A post-send timeout, HTTP 404 after that timeout, or an unchanged baseline
    is outcome_uncertain. failed_certain is limited to a pre-wire abort or a
    complete 4xx refusal with no prior mutation and no post-send timeout.
    """
    sent = wire_write_started or prior_mutations > 0
    write_attempted = sent if journal_write_attempted is None else journal_write_attempted
    uncertain_verify = verify_status in _UNCERTAIN_VERIFY
    if sent and (post_send_timeout or uncertain_verify or (http_status is not None and http_status >= 500)):
        if verify_status == "absent":
            error = "create_outcome_uncertain"
        else:
            error = "put_outcome_uncertain"
        return {
            "state": "outcome_uncertain",
            "outcome_uncertain": True,
            "write_attempted": True,
            "error": error,
            "verify_status": verify_status,
        }
    if (
        sent
        and prior_mutations == 0
        and not post_send_timeout
        and http_status in _CERTAIN_REFUSAL_STATUSES
    ):
        return {
            "state": "failed_certain",
            "outcome_uncertain": False,
            "write_attempted": True,
            "error": "github_write_refused",
            "verify_status": verify_status,
        }
    if not sent:
        error = "github_connect_timeout" if write_attempted else "github_server_deadline_exceeded"
        return {
            "state": "failed_certain",
            "outcome_uncertain": False,
            "write_attempted": write_attempted,
            "error": error,
            "verify_status": verify_status,
        }
    return {
        "state": "outcome_uncertain",
        "outcome_uncertain": True,
        "write_attempted": True,
        "error": "put_outcome_uncertain",
        "verify_status": verify_status,
    }


def commit_journal_before_cutoff(target: Path, payload: bytes, t0: float, clock) -> str:
    """fsync the temp file, then replace only when the clock is still at or before 8.50s."""
    tmp = target.with_name(target.name + ".tmp")
    fd = os.open(str(tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    if clock() > t0 + PRE_TX6_COMMIT_CUTOFF_S:
        os.unlink(tmp)
        return "failed_certain"
    os.replace(tmp, target)
    return "replaced"


def _deadline_client() -> httpx.Client:
    import httpcore

    transport = httpx.HTTPTransport(
        retries=0,
        trust_env=False,
        limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
    )
    transport._pool = httpcore.ConnectionPool(  # noqa: SLF001
        network_backend=DeadlineSyncBackend(),
        retries=0,
        max_connections=4,
        max_keepalive_connections=2,
    )
    return httpx.Client(transport=transport, trust_env=False, timeout=None)


def _bounded_http_exchange(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    json_body: dict[str, Any] | None = None,
    hard_deadline_mono: float,
    client: httpx.Client | None = None,
    clock=None,
) -> tuple[httpx.Response, bool]:
    import time

    now = time.monotonic if clock is None else clock
    ctx = _ExchangeDeadlineCtx(hard_deadline_mono, now)
    token = _ACTIVE_EXCHANGE_CTX.set(ctx)
    owns = client is None
    http = client or _deadline_client()
    try:
        if now() > hard_deadline_mono:
            raise httpx.TimeoutException("HTTP hard operation deadline exceeded")
        response = http.request(method, url, headers=headers, json=json_body)
        if len(response.content) > MAX_HTTP_RESPONSE_BYTES:
            raise httpx.HTTPError("github_response_too_large")
        return response, ctx.wire_write_started
    finally:
        if owns:
            http.close()
        _ACTIVE_EXCHANGE_CTX.reset(token)


_lock = threading.RLock()
_pending: dict[str, "PendingPublish"] = {}


def redact_text(value: object) -> str:
    """Redact the full value with the shared marker, then slice to 500 characters."""
    from realtime_c.redaction import redact_text as shared_redact_text

    return shared_redact_text(value, max_len=500)


def _public_json(payload: dict[str, Any]) -> str:
    """Redact a tool payload, then cap the JSON encoding at 262144 bytes."""
    from realtime_c.redaction import redact_structure

    text = json.dumps(redact_structure(payload, max_len=None))
    raw = text.encode("utf-8")
    if len(raw) <= MAX_TOOL_RESULT_JSON_BYTES:
        return text
    return raw[:MAX_TOOL_RESULT_JSON_BYTES].decode("utf-8", errors="ignore")


def _install_log_redaction() -> None:
    from realtime_c.redaction import RedactingLogFilter

    if not any(isinstance(item, RedactingLogFilter) for item in _LOG.filters):
        _LOG.addFilter(RedactingLogFilter())


_install_log_redaction()


_CRED_TARGET = "me3-icy-github-mcp-token"
_CRED_USERNAME = "github-token"
_CRED_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2
_CRED_BLOB_MIN_BYTES = 2
_CRED_BLOB_MAX_BYTES = 4096
_CLASSIC_PAT_RE = re.compile(r"ghp_[A-Za-z0-9]{20,}\Z")
_FINE_PAT_RE = re.compile(r"github_pat_[A-Za-z0-9_]{20,}\Z")


class _FILETIME(ctypes.Structure):
    _fields_ = (
        ("dwLowDateTime", ctypes.c_uint32),
        ("dwHighDateTime", ctypes.c_uint32),
    )


class _CREDENTIALW(ctypes.Structure):
    """64-bit CREDENTIALW. Blob fields are not read until metadata matches."""

    _fields_ = (
        ("Flags", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
        ("TargetName", ctypes.c_wchar_p),
        ("Comment", ctypes.c_wchar_p),
        ("LastWritten", _FILETIME),
        ("CredentialBlobSize", ctypes.c_uint32),
        ("CredentialBlob", ctypes.c_void_p),
        ("Persist", ctypes.c_uint32),
        ("AttributeCount", ctypes.c_uint32),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", ctypes.c_wchar_p),
        ("UserName", ctypes.c_wchar_p),
    )


def _credential_layout_ok() -> bool:
    """Reject a process whose CREDENTIALW layout is not the reviewed 64-bit layout."""
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        return False
    if ctypes.sizeof(_CREDENTIALW) != 80:
        return False
    return (
        _CREDENTIALW.Type.offset == 4
        and _CREDENTIALW.TargetName.offset == 8
        and _CREDENTIALW.CredentialBlobSize.offset == 32
        and _CREDENTIALW.CredentialBlob.offset == 40
        and _CREDENTIALW.Persist.offset == 48
        and _CREDENTIALW.UserName.offset == 72
    )


def _u32_at(address: int, offset: int) -> int:
    return int(ctypes.c_uint32.from_address(address + offset).value)


def _pointer_at(address: int, offset: int) -> int:
    return int(ctypes.c_void_p.from_address(address + offset).value or 0)


def _wide_at(address: int) -> str:
    if not address:
        return ""
    return ctypes.wstring_at(address) or ""


def _zero_buffer(buf: bytearray) -> None:
    for index in range(len(buf)):
        buf[index] = 0


def _copy_exact_bytes(address: int, size: int) -> bytearray:
    """Copy exactly ``size`` bytes. The source is not treated as a C string."""
    copied = bytearray(size)
    ctypes.memmove((ctypes.c_char * size).from_buffer(copied), address, size)
    return copied


def _token_from_blob(blob: bytearray) -> str | None:
    """Validate UTF-16LE token bytes. The bytearray is cleared on every exit.

    The returned ``str`` and any later ``Authorization`` header are immutable.
    CPython does not guarantee those copies are erased from managed memory.
    """
    try:
        if len(blob) < _CRED_BLOB_MIN_BYTES or len(blob) > _CRED_BLOB_MAX_BYTES or len(blob) % 2:
            return None
        try:
            text = blob.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
        if "\x00" in text or any(0xD800 <= ord(char) <= 0xDFFF for char in text):
            return None
        if _CLASSIC_PAT_RE.fullmatch(text) or _FINE_PAT_RE.fullmatch(text):
            return text
        return None
    finally:
        _zero_buffer(blob)


def _windows_credential_api():
    """Return ``(read, free)`` for this process, or None when CredReadW is unavailable."""
    if os.name != "nt" or not _credential_layout_ok():
        return None
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    cred_read = advapi.CredReadW
    cred_read.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.POINTER(_CREDENTIALW)),
    )
    cred_read.restype = ctypes.c_int
    cred_free = advapi.CredFree
    cred_free.argtypes = (ctypes.c_void_p,)
    cred_free.restype = None

    def read() -> int | None:
        holder = ctypes.POINTER(_CREDENTIALW)()
        found = cred_read(_CRED_TARGET, _CRED_TYPE_GENERIC, 0, ctypes.byref(holder))
        if not found:
            return None
        return int(ctypes.cast(holder, ctypes.c_void_p).value or 0) or None

    def free(address: int) -> None:
        if address:
            cred_free(ctypes.c_void_p(address))

    return read, free


def _read_secret_with(read, free) -> str | None:
    """Read one generic credential. Metadata is checked before the blob is touched."""
    address = read()
    if not address:
        return None
    blob: bytearray | None = None
    try:
        target = _wide_at(_pointer_at(address, _CREDENTIALW.TargetName.offset))
        username = _wide_at(_pointer_at(address, _CREDENTIALW.UserName.offset))
        cred_type = _u32_at(address, _CREDENTIALW.Type.offset)
        persist = _u32_at(address, _CREDENTIALW.Persist.offset)
        if (
            target != _CRED_TARGET
            or username != _CRED_USERNAME
            or cred_type != _CRED_TYPE_GENERIC
            or persist != _CRED_PERSIST_LOCAL_MACHINE
        ):
            return None
        size = _u32_at(address, _CREDENTIALW.CredentialBlobSize.offset)
        blob_ptr = _pointer_at(address, _CREDENTIALW.CredentialBlob.offset)
        if (
            blob_ptr == 0
            or size < _CRED_BLOB_MIN_BYTES
            or size > _CRED_BLOB_MAX_BYTES
            or size % 2 != 0
        ):
            return None
        blob = _copy_exact_bytes(blob_ptr, size)
    finally:
        free(address)
    try:
        return _token_from_blob(blob)
    finally:
        _zero_buffer(blob)


def _auth_token() -> str | None:
    """Return the child credential, or None. No environment or file fallback."""
    api = _windows_credential_api()
    if api is None:
        return None
    read, free = api
    return _read_secret_with(read, free)


def _credential_configured() -> bool:
    """Startup probe for the child process log. The token is not retained here."""
    return _auth_token() is not None


def _auth_headers() -> dict[str, str] | None:
    token = _auth_token()
    if not token:
        return None
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "me3-icy-github-mcp/0.1",
    }


def _auth_unavailable() -> str:
    return _public_json(
        {
            "ok": False,
            "error": "github_auth_unavailable",
            "spoken_status": "GitHub authentication is not configured.",
        }
    )


def _err(code: str, spoken: str, **extra: Any) -> str:
    payload = {"ok": False, "error": code, "spoken_status": spoken}
    payload.update(extra)
    return _public_json(payload)


def scan_secrets(path: str, content: str) -> str | None:
    """Return a short reason if content/path looks unsafe to publish publicly.

    Heuristic only — does not guarantee detection of all secrets or PII.
    """
    if _SENSITIVE_PATH_RE.search(path.replace("\\", "/")):
        return f"sensitive_path:{path}"
    if _HOME_PATH_RE.search(content):
        return "possible_local_filesystem_path"
    for pattern in _SECRET_PATTERNS:
        if pattern.search(content):
            return "possible_secret_pattern"
    return None


def _validate_repo_relative_path(path: object) -> tuple[str | None, str | None]:
    """Validate a repository-relative path without rewriting unsafe inputs into safe ones.

    Returns (normalized_relative_path, None) on success, or (None, error_code) on rejection.
    Backslash separators are accepted only for already-relative paths and are normalized to '/'.
    Absolute, drive-letter, UNC, traversal, empty, and empty-segment paths are rejected.
    """
    if not isinstance(path, str):
        return None, "invalid_path"
    raw = path.strip()
    if not raw:
        return None, "invalid_path:empty"
    if "\x00" in raw:
        return None, f"invalid_path:{raw}"
    # Reject absolute / UNC / drive forms before any separator rewrite.
    if raw.startswith("/") or raw.startswith("\\"):
        return None, f"invalid_path:{raw}"
    if raw.startswith("//") or raw.startswith("\\\\"):
        return None, f"invalid_path:{raw}"
    if re.match(r"^[A-Za-z]:", raw):
        return None, f"invalid_path:{raw}"

    norm = raw.replace("\\", "/")
    # Defense in depth after separator normalization.
    if norm.startswith("/") or norm.startswith("~"):
        return None, f"invalid_path:{raw}"
    if re.match(r"^[A-Za-z]:", norm):
        return None, f"invalid_path:{raw}"
    if "//" in norm:
        return None, f"invalid_path:{raw}"

    parts = norm.split("/")
    if not parts or any(part == "" for part in parts):
        return None, f"invalid_path:{raw}"
    if any(part in (".", "..") for part in parts):
        return None, f"invalid_path:{raw}"
    return norm, None


def _normalize_files(
    readme_markdown: str,
    extra_files: list[dict[str, Any]] | None,
) -> tuple[dict[str, str], str | None]:
    files: dict[str, str] = {"README.md": readme_markdown}
    for item in extra_files or []:
        if not isinstance(item, dict):
            return {}, "invalid_extra_file_entry"
        content = item.get("content")
        if content is None:
            return {}, "invalid_extra_file_entry"
        path, path_err = _validate_repo_relative_path(item.get("path"))
        if path_err or not path:
            return {}, path_err or "invalid_path"
        if path in files:
            return {}, f"duplicate_path:{path}"
        files[path] = str(content)
    for path, content in files.items():
        reason = scan_secrets(path, content)
        if reason:
            return {}, reason
    return files, None


def _content_fingerprint(
    repo_name: str,
    description: str,
    visibility: str,
    files: dict[str, str],
) -> str:
    blob = json.dumps(
        {
            "name": repo_name,
            "description": description,
            "visibility": visibility,
            "files": {k: files[k] for k in sorted(files)},
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class PendingPublish:
    confirm_token: str
    repo_name: str
    description: str
    visibility: str
    files: dict[str, str]
    sources: list[dict[str, str]]
    content_hash: str
    expires_at: float
    consumed: bool = False
    creating: bool = False
    repo_full_name: str | None = None
    html_url: str | None = None
    default_branch: str = "main"
    files_written: set[str] = field(default_factory=set)


def _purge_expired_locked(now: float | None = None) -> None:
    stamp = time.time() if now is None else now
    dead = [tok for tok, item in _pending.items() if item.expires_at <= stamp or item.consumed]
    for tok in dead:
        _pending.pop(tok, None)


def _get_pending(confirm_token: str) -> tuple[PendingPublish | None, str | None]:
    with _lock:
        item = _pending.get(confirm_token)
        if item is None:
            _purge_expired_locked()
            return None, "confirm_token_invalid"
        if item.consumed:
            _pending.pop(confirm_token, None)
            _purge_expired_locked()
            return None, "confirm_token_reused"
        if item.expires_at <= time.time():
            _pending.pop(confirm_token, None)
            _purge_expired_locked()
            return None, "confirm_token_expired"
        _purge_expired_locked()
        return item, None


def _require_confirmed(user_confirmed: bool) -> str | None:
    if user_confirmed is True:
        return None
    return "user_confirmation_required"


def _validate_repo_name(name: str) -> str | None:
    if not name or not _REPO_NAME_RE.match(name):
        return "invalid_repository_name"
    if name.startswith(".") or name.endswith("."):
        return "invalid_repository_name"
    return None


def reset_pending_for_tests() -> None:
    """Test helper: clear in-memory confirmation state."""
    with _lock:
        _pending.clear()


def prepare_publish_payload(
    repo_name: str,
    description: str,
    readme_markdown: str,
    visibility: str = "public",
    extra_files: list[dict[str, Any]] | None = None,
    sources: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    name = (repo_name or "").strip()
    desc = (description or "").strip()
    vis = (visibility or "public").strip().lower()
    readme = readme_markdown if readme_markdown is not None else ""
    if vis != "public":
        return {
            "ok": False,
            "error": "visibility_not_allowed",
            "spoken_status": "Only public repositories are supported.",
        }
    bad_name = _validate_repo_name(name)
    if bad_name:
        return {
            "ok": False,
            "error": bad_name,
            "spoken_status": "That repository name is not valid.",
        }
    if not desc:
        return {
            "ok": False,
            "error": "description_required",
            "spoken_status": "A repository description is required.",
        }
    if not str(readme).strip():
        return {
            "ok": False,
            "error": "readme_required",
            "spoken_status": "A README is required before publishing.",
        }
    files, scan_err = _normalize_files(str(readme), extra_files)
    if scan_err:
        return {
            "ok": False,
            "error": "secret_or_sensitive_content",
            "reason": scan_err,
            "spoken_status": (
                "I stopped because the proposed files look like they may contain "
                "secrets or sensitive paths. Heuristic scanning is not complete detection."
            ),
        }
    norm_sources: list[dict[str, str]] = []
    for src in sources or []:
        if not isinstance(src, dict):
            continue
        url = str(src.get("url") or "").strip()
        if not url:
            continue
        entry = {
            "title": str(src.get("title") or "").strip(),
            "url": url,
        }
        accessed = str(src.get("accessed") or src.get("date") or "").strip()
        if accessed:
            entry["accessed"] = accessed
        norm_sources.append(entry)

    content_hash = _content_fingerprint(name, desc, vis, files)
    token = secrets.token_urlsafe(24)
    expires_at = time.time() + CONFIRM_TTL_S
    pending = PendingPublish(
        confirm_token=token,
        repo_name=name,
        description=desc,
        visibility=vis,
        files=files,
        sources=norm_sources,
        content_hash=content_hash,
        expires_at=expires_at,
    )
    with _lock:
        _purge_expired_locked()
        _pending[token] = pending

    file_list = [{"path": path, "bytes": len(content.encode("utf-8"))} for path, content in sorted(files.items())]
    return {
        "ok": True,
        "preview": {
            "name": name,
            "description": desc,
            "visibility": vis,
            "files": [{"path": p, "content": files[p]} for p in sorted(files)],
            "references": norm_sources,
            "content_hash": content_hash,
        },
        "confirm_token": token,
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_at)),
        "expires_in_seconds": int(CONFIRM_TTL_S),
        "file_list": file_list,
        "spoken_status": (
            f"Prepared public repository preview named {name}. "
            "Say yes, publish this repository to confirm. "
            "Do not publish until the user explicitly confirms."
        ),
    }


def _http_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    json_body: dict[str, Any] | None = None,
    client: httpx.Client | None = None,
) -> httpx.Response:
    import time

    response, _started = _bounded_http_exchange(
        method,
        url,
        headers=headers,
        json_body=json_body,
        hard_deadline_mono=time.monotonic() + SERVER_READ_HARD_DEADLINE_S,
        client=client,
    )
    return response


def _get_authenticated_login(
    headers: dict[str, str],
    *,
    client: httpx.Client | None = None,
) -> tuple[str | None, str | None]:
    """Return (login, error_code). error_code set when login cannot be trusted."""
    try:
        response = _http_request("GET", f"{GITHUB_API}/user", headers=headers, client=client)
    except httpx.TimeoutException:
        return None, "network_timeout"
    except httpx.HTTPError as exc:
        _LOG.warning("github /user transport error: %s", redact_text(exc))
        return None, "network_error"
    if response.status_code == 401:
        return None, "github_auth_invalid"
    if response.status_code == 403:
        return None, "github_permission_denied"
    if response.status_code != 200:
        return None, "auth_lookup_inconclusive"
    try:
        data = response.json()
    except Exception:
        return None, "auth_lookup_inconclusive"
    login = str((data or {}).get("login") or "").strip()
    if not login:
        return None, "auth_lookup_inconclusive"
    return login, None


def _repo_matches_pending(item: PendingPublish, data: dict[str, Any], login: str) -> bool:
    """True only when owner, name, public visibility, and description match this pending publish.

    Same-name alone is never enough. Non-empty repos are treated as unrelated so a
    pre-existing project is not bound to this confirmation.
    """
    owner = data.get("owner") if isinstance(data.get("owner"), dict) else {}
    owner_login = str(owner.get("login") or "").strip()
    name = str(data.get("name") or "").strip()
    private = bool(data.get("private"))
    visibility = str(data.get("visibility") or ("private" if private else "public")).lower()
    description = str(data.get("description") or "")
    try:
        size = int(data.get("size") if data.get("size") is not None else 0)
    except (TypeError, ValueError):
        size = -1
    if owner_login.casefold() != login.casefold():
        return False
    if name.casefold() != item.repo_name.casefold():
        return False
    if private or visibility != "public":
        return False
    if description != item.description:
        return False
    if size != 0:
        return False
    return True


def _verify_pending_repo(
    item: PendingPublish,
    headers: dict[str, str],
    *,
    client: httpx.Client | None = None,
) -> tuple[str, dict[str, Any] | None]:
    """GET-verify whether the pending public repo already exists for this account.

    Returns (status, detail) where status is one of:
      bound_ready — verified match; detail is repo JSON (caller may bind)
      absent — confirmed not found (404)
      unrelated — something else occupies the name
      inconclusive — auth/network/API ambiguity; do not POST and do not bind
    """
    login, auth_err = _get_authenticated_login(headers, client=client)
    if auth_err or not login:
        return "inconclusive", {"error": auth_err or "auth_lookup_inconclusive"}
    url = f"{GITHUB_API}/repos/{login}/{item.repo_name}"
    try:
        response = _http_request("GET", url, headers=headers, client=client)
    except httpx.TimeoutException:
        return "inconclusive", {"error": "network_timeout"}
    except httpx.HTTPError as exc:
        _LOG.warning("github get repo transport error: %s", redact_text(exc))
        return "inconclusive", {"error": "network_error"}
    if response.status_code == 404:
        return "absent", {"login": login}
    if response.status_code == 401:
        return "inconclusive", {"error": "github_auth_invalid"}
    if response.status_code == 403:
        return "inconclusive", {"error": "github_permission_denied"}
    if response.status_code != 200:
        return "inconclusive", {"error": "repo_lookup_inconclusive", "status": response.status_code}
    try:
        data = response.json()
    except Exception:
        return "inconclusive", {"error": "repo_lookup_inconclusive"}
    if not isinstance(data, dict):
        return "inconclusive", {"error": "repo_lookup_inconclusive"}
    if not _repo_matches_pending(item, data, login):
        return "unrelated", {"login": login, "full_name": data.get("full_name")}
    return "bound_ready", data


def _bind_pending_repo(item: PendingPublish, data: dict[str, Any]) -> dict[str, Any]:
    full_name = str(data.get("full_name") or "")
    html_url = str(data.get("html_url") or "")
    default_branch = str(data.get("default_branch") or "main")
    private = bool(data.get("private"))
    with _lock:
        item.repo_full_name = full_name
        item.html_url = html_url
        item.default_branch = default_branch
        item.creating = False
    return {
        "full_name": full_name,
        "html_url": html_url,
        "private": private,
        "default_branch": default_branch,
    }


def _clear_creating(item: PendingPublish) -> None:
    with _lock:
        item.creating = False


def create_repository_payload(
    confirm_token: str,
    user_confirmed: bool,
    repo_name: str,
    description: str,
    visibility: str = "public",
    *,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    conf_err = _require_confirmed(user_confirmed)
    if conf_err:
        return {
            "ok": False,
            "error": conf_err,
            "spoken_status": "I need an explicit yes, publish this repository before creating it.",
        }
    headers = _auth_headers()
    if headers is None:
        return json.loads(_auth_unavailable())

    item, tok_err = _get_pending(confirm_token)
    if item is None or tok_err:
        return {
            "ok": False,
            "error": tok_err or "confirm_token_invalid",
            "spoken_status": "The publish confirmation is missing, expired, or already used.",
        }

    name = (repo_name or "").strip()
    desc = (description or "").strip()
    vis = (visibility or "public").strip().lower()
    if name != item.repo_name or desc != item.description or vis != item.visibility:
        return {
            "ok": False,
            "error": "preview_mismatch",
            "spoken_status": "The repository details no longer match the approved preview. Prepare again.",
        }
    if vis != "public":
        return {
            "ok": False,
            "error": "visibility_not_allowed",
            "spoken_status": "Only public repositories are supported.",
        }

    with _lock:
        if item.creating or item.repo_full_name:
            return {
                "ok": False,
                "error": "duplicate_publish_in_progress",
                "spoken_status": "A publish for this confirmation is already in progress or finished.",
                "html_url": item.html_url,
                "full_name": item.repo_full_name,
            }
        item.creating = True

    def _success(data: dict[str, Any], *, recovered: bool) -> dict[str, Any]:
        bound = _bind_pending_repo(item, data)
        action = "Recovered" if recovered else "Created"
        return {
            "ok": True,
            "recovered": recovered,
            "full_name": bound["full_name"],
            "html_url": bound["html_url"],
            "private": bound["private"],
            "default_branch": bound["default_branch"],
            "confirm_token": confirm_token,
            "spoken_status": (
                f"{action} public repository {bound['full_name']}. "
                "Next commit the approved files."
            ),
        }

    # GET-before-POST: recover a prior ambiguous create without blindly POSTing again.
    pre_status, pre_detail = _verify_pending_repo(item, headers, client=client)
    if pre_status == "bound_ready" and isinstance(pre_detail, dict):
        return _success(pre_detail, recovered=True)
    if pre_status == "unrelated":
        _clear_creating(item)
        return {
            "ok": False,
            "error": "unrelated_repository_exists",
            "spoken_status": (
                "A different repository already uses that name on this account. "
                "Choose another name and prepare again."
            ),
        }
    if pre_status == "inconclusive":
        _clear_creating(item)
        err = str((pre_detail or {}).get("error") or "create_outcome_uncertain")
        return {
            "ok": False,
            "error": err,
            "spoken_status": (
                "Could not verify whether the repository already exists. "
                "No create retry was sent. Try again shortly."
            ),
        }
    # absent → safe to POST once

    try:
        response = _http_request(
            "POST",
            f"{GITHUB_API}/user/repos",
            headers=headers,
            json_body={
                "name": item.repo_name,
                "description": item.description,
                "private": False,
                "auto_init": False,
                "has_issues": False,
                "has_projects": False,
                "has_wiki": False,
            },
            client=client,
        )
    except httpx.TimeoutException:
        post_status, post_detail = _verify_pending_repo(item, headers, client=client)
        if post_status == "bound_ready" and isinstance(post_detail, dict):
            return _success(post_detail, recovered=True)
        _clear_creating(item)
        return {
            "ok": False,
            "error": "create_outcome_uncertain",
            "verify_status": post_status,
            "spoken_status": (
                "GitHub timed out while creating the repository and verification "
                "could not confirm a matching public empty repo. No blind retry."
            ),
        }
    except httpx.HTTPError as exc:
        _clear_creating(item)
        _LOG.warning("github create repo transport error: %s", redact_text(exc))
        return {
            "ok": False,
            "error": "network_error",
            "spoken_status": "GitHub could not be reached while creating the repository.",
        }

    if response.status_code == 401:
        _clear_creating(item)
        return {
            "ok": False,
            "error": "github_auth_invalid",
            "spoken_status": "GitHub rejected the credentials.",
        }
    if response.status_code == 403:
        _clear_creating(item)
        return {
            "ok": False,
            "error": "github_permission_denied",
            "spoken_status": "GitHub denied permission to create the repository.",
        }
    if response.status_code == 422:
        post_status, post_detail = _verify_pending_repo(item, headers, client=client)
        if post_status == "bound_ready" and isinstance(post_detail, dict):
            return _success(post_detail, recovered=True)
        _clear_creating(item)
        if post_status == "unrelated":
            return {
                "ok": False,
                "error": "unrelated_repository_exists",
                "spoken_status": (
                    "That repository name is already taken by a different repository "
                    "on this account."
                ),
            }
        if post_status == "absent":
            return {
                "ok": False,
                "error": "repository_name_conflict",
                "spoken_status": "GitHub rejected the repository name, and no matching repo was found.",
            }
        return {
            "ok": False,
            "error": "create_outcome_uncertain",
            "verify_status": post_status,
            "spoken_status": (
                "GitHub reported a name conflict and verification was inconclusive. "
                "No blind create retry was sent."
            ),
        }
    if response.status_code == 429:
        _clear_creating(item)
        return {
            "ok": False,
            "error": "rate_limited",
            "spoken_status": "GitHub rate-limited the request. Try again later.",
        }
    if response.status_code not in (200, 201):
        _clear_creating(item)
        _LOG.warning("github create repo http=%s", response.status_code)
        return {
            "ok": False,
            "error": "github_api_error",
            "status": response.status_code,
            "spoken_status": "GitHub returned an error while creating the repository.",
        }

    try:
        data = response.json()
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    login, auth_err = _get_authenticated_login(headers, client=client)
    if auth_err or not login or not _repo_matches_pending(item, data, login):
        # Response ambiguous — GET verify before binding; never assume.
        post_status, post_detail = _verify_pending_repo(item, headers, client=client)
        if post_status == "bound_ready" and isinstance(post_detail, dict):
            return _success(post_detail, recovered=True)
        _clear_creating(item)
        return {
            "ok": False,
            "error": "create_outcome_uncertain",
            "verify_status": post_status,
            "spoken_status": (
                "GitHub create returned an unexpected repository payload. "
                "Nothing was bound without verification."
            ),
        }
    return _success(data, recovered=False)


def _get_contents_for_verify(
    headers: dict[str, str],
    owner: str,
    repo: str,
    path: str,
    branch: str,
    *,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """GET one Contents API path for post-PUT recovery. Never writes.

    Returns status in {match_pending, absent, conflict, inconclusive} — caller
    compares match_pending content against approved text.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{quote(path)}?ref={quote(branch)}"
    try:
        response = _http_request("GET", url, headers=headers, client=client)
    except httpx.TimeoutException:
        return {"status": "inconclusive", "error": "network_timeout", "path": path}
    except httpx.HTTPError as exc:
        _LOG.warning("github get contents transport error path=%s err=%s", path, redact_text(exc))
        return {"status": "inconclusive", "error": "network_error", "path": path}

    if response.status_code == 404:
        return {"status": "absent", "path": path}
    if response.status_code == 401:
        return {"status": "inconclusive", "error": "github_auth_invalid", "path": path}
    if response.status_code == 403:
        return {"status": "inconclusive", "error": "github_permission_denied", "path": path}
    if response.status_code != 200:
        return {
            "status": "inconclusive",
            "error": "contents_lookup_inconclusive",
            "path": path,
            "http_status": response.status_code,
        }
    try:
        data = response.json()
    except Exception:
        return {"status": "inconclusive", "error": "contents_lookup_inconclusive", "path": path}
    if not isinstance(data, dict):
        return {"status": "inconclusive", "error": "contents_lookup_inconclusive", "path": path}
    # Reject directory listings or unexpected payloads.
    if data.get("type") not in (None, "file"):
        return {"status": "inconclusive", "error": "contents_lookup_inconclusive", "path": path}
    if "content" not in data:
        return {"status": "inconclusive", "error": "contents_lookup_inconclusive", "path": path}
    encoding = str(data.get("encoding") or "").lower()
    if encoding and encoding != "base64":
        return {"status": "inconclusive", "error": "contents_lookup_inconclusive", "path": path}
    try:
        raw = str(data.get("content") or "").replace("\n", "")
        decoded = base64.b64decode(raw)
    except Exception:
        return {"status": "inconclusive", "error": "contents_lookup_inconclusive", "path": path}
    return {
        "status": "present",
        "path": path,
        "content": decoded,
        "sha": str(data.get("sha") or ""),
        "html_url": str(data.get("html_url") or ""),
    }


def _payload_bytes(content: Any) -> bytes | None:
    """Bytes to upload. A str is encoded as UTF-8 once. Bytes are not rewritten."""
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8")
    return None


def _recover_uncertain_put(
    headers: dict[str, str],
    owner: str,
    repo: str,
    path: str,
    expected_content: str,
    branch: str,
    *,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """After ambiguous PUT: GET-verify only; never retry PUT."""
    looked = _get_contents_for_verify(
        headers, owner, repo, path, branch, client=client
    )
    status = looked.get("status")
    if status == "present":
        expected = _payload_bytes(expected_content)
        if expected is not None and looked.get("content") == expected:
            return {
                "ok": True,
                "path": path,
                "recovered": True,
                "commit_sha": str(looked.get("sha") or ""),
                "html_url": str(looked.get("html_url") or ""),
            }
        return {
            "ok": False,
            "error": "file_conflict",
            "path": path,
            "verify_status": "content_mismatch",
        }
    if status == "absent":
        return {
            "ok": False,
            "error": "put_outcome_uncertain",
            "path": path,
            "verify_status": "absent",
        }
    return {
        "ok": False,
        "error": str(looked.get("error") or "put_outcome_uncertain"),
        "path": path,
        "verify_status": "inconclusive",
    }


def _put_file(
    headers: dict[str, str],
    owner: str,
    repo: str,
    path: str,
    content: str,
    message: str,
    branch: str,
    *,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    raw_content = _payload_bytes(content)
    if raw_content is None:
        return {"ok": False, "error": "invalid_file_entry", "path": path}
    from realtime_c.github_approval import MAX_PUBLICATION_FILE_BYTES

    if len(raw_content) > MAX_PUBLICATION_FILE_BYTES:
        return {"ok": False, "error": "file_too_large", "path": path}
    encoded = base64.b64encode(raw_content).decode("ascii")
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{quote(path)}"
    try:
        response = _http_request(
            "PUT",
            url,
            headers=headers,
            json_body={
                "message": message,
                "content": encoded,
                "branch": branch,
            },
            client=client,
        )
    except httpx.TimeoutException:
        return _recover_uncertain_put(
            headers, owner, repo, path, raw_content, branch, client=client
        )
    except httpx.HTTPError as exc:
        _LOG.warning("github put file transport error path=%s err=%s", path, redact_text(exc))
        # Ambiguous transport failure: GET-verify; never blind PUT retry.
        return _recover_uncertain_put(
            headers, owner, repo, path, raw_content, branch, client=client
        )

    if response.status_code in (200, 201):
        body = response.json()
        commit = body.get("commit") if isinstance(body, dict) else None
        sha = ""
        html = ""
        if isinstance(commit, dict):
            sha = str(commit.get("sha") or "")
            html = str(commit.get("html_url") or "")
        return {"ok": True, "path": path, "commit_sha": sha, "html_url": html}
    if response.status_code == 409 or response.status_code == 422:
        return {
            "ok": False,
            "error": "file_conflict",
            "path": path,
            "status": response.status_code,
        }
    if response.status_code == 401:
        return {"ok": False, "error": "github_auth_invalid", "path": path}
    if response.status_code == 403:
        return {"ok": False, "error": "github_permission_denied", "path": path}
    if response.status_code == 429:
        return {"ok": False, "error": "rate_limited", "path": path}
    return {
        "ok": False,
        "error": "github_api_error",
        "path": path,
        "status": response.status_code,
    }


def _match_approved_files(
    item: PendingPublish,
    files: list[dict[str, Any]],
) -> tuple[dict[str, str] | None, str | None]:
    if not files:
        return None, "files_required"
    selected: dict[str, str] = {}
    for entry in files:
        if not isinstance(entry, dict):
            return None, "invalid_file_entry"
        path, path_err = _validate_repo_relative_path(entry.get("path"))
        if path_err or not path:
            return None, path_err or "invalid_path"
        content = entry.get("content")
        if content is None:
            return None, "invalid_file_entry"
        raw_content = _payload_bytes(content)
        approved = _payload_bytes(item.files.get(path)) if path in item.files else None
        if path not in item.files:
            return None, f"unapproved_path:{path}"
        if raw_content is None or approved is None or raw_content != approved:
            return None, "content_mismatch"
        selected[path] = raw_content
    return selected, None


def commit_files_payload(
    confirm_token: str,
    user_confirmed: bool,
    owner: str,
    repo: str,
    files: list[dict[str, Any]],
    commit_message: str = "Add research documentation",
    *,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    conf_err = _require_confirmed(user_confirmed)
    if conf_err:
        return {
            "ok": False,
            "error": conf_err,
            "spoken_status": "I need explicit confirmation before committing files.",
        }
    headers = _auth_headers()
    if headers is None:
        return json.loads(_auth_unavailable())

    item, tok_err = _get_pending(confirm_token)
    if item is None or tok_err:
        return {
            "ok": False,
            "error": tok_err or "confirm_token_invalid",
            "spoken_status": "The publish confirmation is missing, expired, or already used.",
        }
    if not item.repo_full_name:
        return {
            "ok": False,
            "error": "repository_not_created",
            "spoken_status": "Create the repository before committing files.",
        }
    expected = f"{owner.strip()}/{repo.strip()}"
    if item.repo_full_name != expected:
        return {
            "ok": False,
            "error": "repository_mismatch",
            "spoken_status": "The repository does not match the approved publish session.",
        }

    selected, match_err = _match_approved_files(item, files)
    if selected is None:
        return {
            "ok": False,
            "error": match_err or "content_mismatch",
            "spoken_status": "The files do not match the approved preview. Prepare again.",
        }

    written: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for path, content in selected.items():
        # already_written is skipped success only for paths recorded on this pending
        # publish after approved content matched (selected via _match_approved_files).
        if path in item.files_written:
            skipped.append({"path": path, "status": "already_written"})
            continue
        message = commit_message if len(selected) == 1 else f"{commit_message}: {path}"
        result = _put_file(
            headers,
            owner.strip(),
            repo.strip(),
            path,
            content,
            message,
            item.default_branch or "main",
            client=client,
        )
        if result.get("ok"):
            with _lock:
                item.files_written.add(path)
            written.append(result)
        else:
            failures.append(result)
            # Stop on first failure to avoid cascading partial publishes without verification.
            break

    all_done = set(item.files.keys()) <= set(item.files_written)
    if all_done:
        with _lock:
            item.consumed = True
            _pending.pop(confirm_token, None)

    ok = (not failures) and (bool(written) or bool(skipped))
    return {
        "ok": ok,
        "files_written": written,
        "files_skipped": skipped,
        "failures": failures,
        "publish_complete": all_done,
        "html_url": item.html_url,
        "full_name": item.repo_full_name,
        "spoken_status": (
            "Committed the approved files."
            if ok and all_done
            else (
                "Committed some files, but the publish is incomplete."
                if (written or skipped) and failures
                else (
                    "No new files were needed; approved paths were already written."
                    if ok and skipped and not written
                    else "Could not commit the approved files."
                )
            )
        ),
    }


def create_file_payload(
    confirm_token: str,
    user_confirmed: bool,
    owner: str,
    repo: str,
    path: str,
    content: str,
    commit_message: str = "Add research documentation",
    *,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    return commit_files_payload(
        confirm_token,
        user_confirmed,
        owner,
        repo,
        [{"path": path, "content": content}],
        commit_message=commit_message,
        client=client,
    )


def get_repository_payload(
    owner: str,
    repo: str,
    *,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    headers = _auth_headers()
    if headers is None:
        return json.loads(_auth_unavailable())
    own = (owner or "").strip()
    name = (repo or "").strip()
    if not own or not name:
        return {
            "ok": False,
            "error": "owner_and_repo_required",
            "spoken_status": "Repository owner and name are required.",
        }
    try:
        response = _http_request(
            "GET",
            f"{GITHUB_API}/repos/{own}/{name}",
            headers=headers,
            client=client,
        )
    except httpx.TimeoutException:
        return {
            "ok": False,
            "error": "network_timeout",
            "spoken_status": "GitHub timed out while reading the repository.",
        }
    except httpx.HTTPError as exc:
        _LOG.warning("github get repo transport error: %s", redact_text(exc))
        return {
            "ok": False,
            "error": "network_error",
            "spoken_status": "GitHub could not be reached while reading the repository.",
        }
    if response.status_code == 404:
        return {
            "ok": False,
            "error": "repository_not_found",
            "spoken_status": "That repository was not found.",
        }
    if response.status_code == 401:
        return {
            "ok": False,
            "error": "github_auth_invalid",
            "spoken_status": "GitHub rejected the credentials.",
        }
    if response.status_code != 200:
        return {
            "ok": False,
            "error": "github_api_error",
            "status": response.status_code,
            "spoken_status": "GitHub returned an error while reading the repository.",
        }
    data = response.json()
    return {
        "ok": True,
        "full_name": data.get("full_name"),
        "owner": ((data.get("owner") or {}) if isinstance(data.get("owner"), dict) else {}).get("login"),
        "name": data.get("name"),
        "html_url": data.get("html_url"),
        "description": data.get("description"),
        "private": bool(data.get("private")),
        "visibility": data.get("visibility") or ("private" if data.get("private") else "public"),
        "default_branch": data.get("default_branch"),
        "created_at": data.get("created_at"),
        "spoken_status": f"Repository {data.get('full_name')} is available.",
    }


@mcp.tool()
def github_prepare_publish(
    repo_name: str,
    description: str,
    readme_markdown: str,
    visibility: str = "public",
    extra_files_json: str = "[]",
    sources_json: str = "[]",
    ctx: Context | None = None,
) -> str:
    """Stage a publish proposal. Does not write to GitHub."""
    from realtime_c.github_approval import load_github_policy, policy_tool_error

    denied = policy_tool_error(load_github_policy(_policy_root()), "github_prepare_publish")
    if denied:
        return _err(denied, "GitHub publishing is not allowed.")
    _ = ctx
    try:
        extra = json.loads(extra_files_json or "[]")
        sources = json.loads(sources_json or "[]")
    except json.JSONDecodeError:
        return _err(
            "invalid_json",
            "The file or source list could not be parsed.",
        )
    if not isinstance(extra, list) or not isinstance(sources, list):
        return _err("invalid_json", "The file or source list must be a JSON array.")
    return _public_json(
        prepare_publish_payload(
            repo_name,
            description,
            readme_markdown,
            visibility=visibility,
            extra_files=extra,
            sources=sources,
        )
    )


def _policy_root() -> Path:
    from pathlib import Path

    return Path(os.environ.get("GITHUB_MCP_ROOT") or os.getcwd())


def _extract_wire_job_metadata(ctx: Context | None):
    """Read ``me3.icy/job_id`` from wire params, then from request meta."""
    from realtime_c.github_approval import JOB_ID_META_KEY, _JOB_RE

    forbidden = {"job_id", "jobId", "icy/job_id", "me3/job_id", "x-job-id"}
    if ctx is None:
        return True, False, None, None
    try:
        req_ctx = ctx.request_context
    except ValueError:
        return True, False, None, None
    raw_params = getattr(req_ctx, "params", None)
    if isinstance(raw_params, dict) and "_meta" in raw_params:
        raw_meta = raw_params["_meta"]
        if raw_meta is not None and not isinstance(raw_meta, dict):
            return False, True, None, "invalid_job_metadata"
    else:
        raw_meta = getattr(req_ctx, "meta", None)
    if not raw_meta:
        return True, True, None, None
    if forbidden & set(raw_meta):
        return False, True, None, "invalid_job_metadata"
    if JOB_ID_META_KEY not in raw_meta:
        return True, True, None, None
    value = raw_meta[JOB_ID_META_KEY]
    if type(value) is not str or _JOB_RE.fullmatch(value) is None:
        return False, True, None, "invalid_job_metadata"
    return True, True, value, None


_repository_creation_client: Any = None


def set_repository_creation_client_for_tests(client: Any) -> None:
    """Install a fake HTTP client for repository creation. None keeps the network closed."""
    global _repository_creation_client
    _repository_creation_client = client


_content_publication_client: Any = None
_content_publication_cancel: threading.Event | None = None
CONTENT_COMMIT_MESSAGE = "Publish approved files"


def set_content_publication_client_for_tests(client: Any) -> None:
    """Install a fake HTTP client for file publication. None keeps the network closed."""
    global _content_publication_client
    _content_publication_client = client


def set_content_publication_cancel_for_tests(event: threading.Event | None) -> None:
    """Test hook checked before each file. None means publication is not cancelled."""
    global _content_publication_cancel
    _content_publication_cancel = event


_production_transport_armed = False
_production_http_factory: Any = None
_owned_http_client: httpx.Client | None = None


def arm_production_http_transport() -> None:
    """Allow the MCP server process to own an HTTP client. Tests stay unarmed."""
    global _production_transport_armed
    _production_transport_armed = True


def set_production_http_factory_for_tests(factory: Any) -> None:
    """Replace production HTTP construction. None restores the real constructor."""
    global _production_http_factory
    _production_http_factory = factory


def close_production_http_transport() -> None:
    """Close the server-owned HTTP client. Repeating this is safe."""
    global _owned_http_client, _production_transport_armed
    client = _owned_http_client
    _owned_http_client = None
    _production_transport_armed = False
    if client is not None:
        closer = getattr(client, "close", None)
        if callable(closer):
            closer()


def reset_production_http_for_tests() -> None:
    """Drop armed transport and any owned client between tests."""
    global _production_http_factory
    close_production_http_transport()
    _production_http_factory = None


def _new_production_http_client() -> httpx.Client:
    """One finite-timeout client. Retries stay off so an uncertain POST is not repeated."""
    return httpx.Client(
        transport=httpx.HTTPTransport(retries=0, trust_env=False),
        trust_env=False,
        timeout=httpx.Timeout(connect=5.0, read=20.0, write=20.0, pool=5.0),
        follow_redirects=False,
    )


def _production_http_client() -> Any:
    global _owned_http_client
    if _owned_http_client is not None:
        return _owned_http_client
    factory = _production_http_factory or _new_production_http_client
    _owned_http_client = factory()
    return _owned_http_client


def _select_publication_http(tool_name: str) -> tuple[Any | None, str | None]:
    """Fake clients win. Production HTTP is used only after the server is armed."""
    if tool_name == "github_create_repository" and _repository_creation_client is not None:
        return _repository_creation_client, None
    if tool_name in {"github_create_file", "github_commit_files"} and _content_publication_client is not None:
        return _content_publication_client, None
    if tool_name not in {"github_create_repository", "github_create_file", "github_commit_files"}:
        return None, None
    if not _production_transport_armed:
        return None, None
    try:
        return _production_http_client(), None
    except Exception:
        return None, "http_client_unavailable"


def _content_cancel_requested() -> bool:
    event = _content_publication_cancel
    return event is not None and event.is_set()


def _put_attempted(client: Any) -> bool:
    calls = getattr(client, "calls", None)
    if not isinstance(calls, list):
        return False
    return any(isinstance(item, dict) and item.get("method") == "PUT" for item in calls)


def _stage_granted_repository_preview(binding: dict[str, Any]) -> str:
    """Scratchpad the existing create payload already requires. This is not a second grant."""
    token = "c12pub_" + secrets.token_hex(16)
    item = PendingPublish(
        confirm_token=token,
        repo_name=str(binding["repo_name"]),
        description=str(binding["description"]),
        visibility="public",
        files={},
        sources=[],
        content_hash=str(binding.get("fingerprint") or ""),
        expires_at=time.time() + CONFIRM_TTL_S,
    )
    with _lock:
        _pending[token] = item
    return token


def _post_attempted(client: Any) -> bool:
    calls = getattr(client, "calls", None)
    if not isinstance(calls, list):
        return False
    return any(isinstance(item, dict) and item.get("method") == "POST" for item in calls)


def _run_admitted_repository_creation(proposal_id: str, client: Any) -> dict[str, Any]:
    """Call the existing create payload once. Commit and file tools never enter here."""
    from realtime_c.github_approval import (
        accepted_publication_create_binding,
        consume_publication_authorization,
        note_publication_dispatched,
        note_publication_outcome_uncertain,
        publication_clock_now,
    )

    binding = accepted_publication_create_binding(proposal_id)
    if not binding.get("ok"):
        binding["write_attempted"] = False
        return binding
    consumed = consume_publication_authorization(proposal_id, now=publication_clock_now())
    if not consumed.get("ok"):
        consumed["write_attempted"] = False
        return consumed
    dispatched = note_publication_dispatched(proposal_id)
    if not dispatched.get("ok"):
        dispatched["write_attempted"] = False
        return dispatched
    token = _stage_granted_repository_preview(binding)
    try:
        result = create_repository_payload(
            token,
            True,
            str(binding["repo_name"]),
            str(binding["description"]),
            "public",
            client=client,
        )
    except Exception:
        noted = note_publication_outcome_uncertain(proposal_id)
        return {
            "ok": False,
            "error": "create_outcome_uncertain",
            "outcome_uncertain": True,
            "publication_state": noted.get("state"),
            "write_attempted": _post_attempted(client),
            "publication_succeeded": False,
            "spoken_status": "Repository creation did not finish and was not retried.",
        }
    if not isinstance(result, dict):
        result = {"ok": False, "error": "create_outcome_uncertain"}
    result.pop("confirm_token", None)
    result["authorization_consumed"] = True
    attempted = _post_attempted(client)
    if result.get("ok"):
        expected = f"{binding['owner']}/{binding['repo_name']}"
        full_name = str(result.get("full_name") or "")
        if full_name.casefold() != expected.casefold() or bool(result.get("private")):
            note_publication_outcome_uncertain(proposal_id)
            return {
                "ok": False,
                "error": "repository_metadata_mismatch",
                "full_name": full_name,
                "private": bool(result.get("private")),
                "outcome_uncertain": True,
                "publication_state": "publication_outcome_uncertain",
                "write_attempted": attempted,
                "publication_succeeded": False,
                "authorization_consumed": True,
                "spoken_status": (
                    "The repository response did not match the approved owner, name, and public visibility."
                ),
            }
        result["write_attempted"] = attempted
        result["outcome_uncertain"] = False
        result["publication_state"] = "publication_dispatched"
        result["publication_succeeded"] = True
        return result
    if result.get("error") == "create_outcome_uncertain":
        note_publication_outcome_uncertain(proposal_id)
        result["outcome_uncertain"] = True
        result["publication_state"] = "publication_outcome_uncertain"
    else:
        result["outcome_uncertain"] = False
        result["publication_state"] = "publication_dispatched"
    result["write_attempted"] = attempted
    result["publication_succeeded"] = False
    return result


def _stage_granted_content_preview(binding: dict[str, Any]) -> str:
    """Scratchpad the existing commit payload already requires. This is not a second grant."""
    token = "c13pub_" + secrets.token_hex(16)
    owner = str(binding["owner"])
    repo = str(binding["repo_name"])
    files: dict[str, Any] = {}
    for entry in binding["files"]:
        raw_content = _payload_bytes(entry.get("content"))
        if raw_content is None:
            raise ValueError("invalid_file_entry")
        files[str(entry["path"])] = raw_content
    item = PendingPublish(
        confirm_token=token,
        repo_name=repo,
        description=str(binding["description"]),
        visibility="public",
        files=files,
        sources=[],
        content_hash=str(binding.get("fingerprint") or ""),
        expires_at=time.time() + CONFIRM_TTL_S,
        repo_full_name=f"{owner}/{repo}",
        default_branch=str(binding["branch"]),
    )
    with _lock:
        _pending[token] = item
    return token


def _verify_published_file(
    headers: dict[str, str],
    owner: str,
    repo: str,
    path: str,
    branch: str,
    expected_sha256: str,
    *,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """GET one path after a successful PUT and compare it with the approved hash."""
    looked = _get_contents_for_verify(headers, owner, repo, path, branch, client=client)
    status = looked.get("status")
    if status == "present":
        if looked.get("path") != path:
            return {"verified": False, "error": "verification_mismatch", "sha256": "", "outcome_uncertain": False}
        body = looked.get("content")
        if not isinstance(body, (bytes, bytearray)):
            return {"verified": False, "error": "verification_mismatch", "sha256": "", "outcome_uncertain": False}
        digest = hashlib.sha256(bytes(body)).hexdigest()
        if digest != expected_sha256:
            return {
                "verified": False,
                "error": "verification_mismatch",
                "sha256": digest,
                "outcome_uncertain": False,
            }
        return {"verified": True, "error": "", "sha256": digest, "outcome_uncertain": False}
    if status == "absent":
        return {
            "verified": False,
            "error": "verification_missing",
            "sha256": "",
            "outcome_uncertain": True,
            "may_still_be_running": False,
        }
    error = str(looked.get("error") or "verification_inconclusive")
    if error == "network_timeout":
        error = "verification_timeout"
    running = error in {"verification_timeout", "network_error", "verification_inconclusive"}
    return {
        "verified": False,
        "error": error,
        "sha256": "",
        "outcome_uncertain": True,
        "may_still_be_running": running,
    }


def _content_result(
    *,
    ok: bool,
    error: str,
    intended: int,
    committed: list[str],
    verified: list[str],
    failed_path: str | None,
    files: list[dict[str, Any]],
    consumed: bool,
    state: str | None,
    attempted: bool,
    uncertain: bool,
    running: bool,
    spoken: str,
) -> dict[str, Any]:
    complete = ok and len(verified) == intended and not uncertain and failed_path is None
    partial = bool(committed) and not complete
    return {
        "ok": complete,
        "error": error,
        "publication_succeeded": complete,
        "publication_complete": complete,
        "partial": partial,
        "outcome_uncertain": uncertain,
        "may_still_be_running": running,
        "repository_may_contain_partial_publication": partial,
        "intended_manifest_count": intended,
        "committed_paths": list(committed),
        "verified_paths": list(verified),
        "failed_path": failed_path,
        "files": files,
        "authorization_consumed": consumed,
        "publication_state": state,
        "write_attempted": attempted,
        "spoken_status": spoken,
    }


def _run_admitted_content_publication(proposal_id: str, tool_name: str, client: Any) -> dict[str, Any]:
    """Publish one approved manifest. Each file is its own Contents API PUT, then a verifying GET."""
    from realtime_c.github_approval import (
        accepted_publication_content_binding,
        consume_publication_authorization,
        note_publication_dispatched,
        note_publication_outcome_uncertain,
        publication_authorization_state,
        publication_clock_now,
    )

    binding = accepted_publication_content_binding(proposal_id)
    if not binding.get("ok"):
        binding.pop("files", None)
        binding["write_attempted"] = False
        binding["publication_complete"] = False
        binding["partial"] = False
        return binding
    approved_files = list(binding["files"])
    if tool_name == "github_create_file" and len(approved_files) != 1:
        return _content_result(
            ok=False,
            error="manifest_not_single_file",
            intended=len(approved_files),
            committed=[],
            verified=[],
            failed_path=None,
            files=[],
            consumed=False,
            state=publication_authorization_state(proposal_id),
            attempted=False,
            uncertain=False,
            running=False,
            spoken="A single-file publication does not match this manifest.",
        )
    if _content_cancel_requested():
        return _content_result(
            ok=False,
            error="publication_cancelled",
            intended=len(approved_files),
            committed=[],
            verified=[],
            failed_path=None,
            files=[],
            consumed=False,
            state="approval_accepted",
            attempted=False,
            uncertain=False,
            running=False,
            spoken="Publication was cancelled before anything was sent.",
        )
    consumed = consume_publication_authorization(proposal_id, now=publication_clock_now())
    if not consumed.get("ok"):
        consumed.pop("files", None)
        consumed["write_attempted"] = False
        return consumed
    dispatched = note_publication_dispatched(proposal_id)
    if not dispatched.get("ok"):
        dispatched.pop("files", None)
        dispatched["write_attempted"] = False
        dispatched["authorization_consumed"] = True
        return dispatched
    owner = str(binding["owner"])
    repo = str(binding["repo_name"])
    branch = str(binding["branch"])
    token = _stage_granted_content_preview(binding)
    headers = _auth_headers()
    committed: list[str] = []
    verified: list[str] = []
    file_rows: list[dict[str, Any]] = []
    failed_path: str | None = None
    error = ""
    uncertain = False
    running = False
    try:
        for entry in approved_files:
            if _content_cancel_requested():
                failed_path = str(entry["path"])
                error = "publication_cancelled"
                break
            path = str(entry["path"])
            message = (
                CONTENT_COMMIT_MESSAGE
                if len(approved_files) == 1
                else f"{CONTENT_COMMIT_MESSAGE}: {path}"
            )
            result = commit_files_payload(
                token,
                True,
                owner,
                repo,
                [{"path": path, "content": entry["content"]}],
                commit_message=message,
                client=client,
            )
            if not result.get("ok"):
                failure = (result.get("failures") or [{}])[0]
                failed_path = str(failure.get("path") or path)
                error = str(failure.get("error") or result.get("error") or "content_publication_failed")
                verify_status = failure.get("verify_status")
                if verify_status == "content_mismatch":
                    error = "verification_mismatch"
                elif error in {"put_outcome_uncertain", "network_timeout", "network_error"} or verify_status in {
                    "absent",
                    "inconclusive",
                }:
                    uncertain = True
                    running = verify_status == "inconclusive" or error == "network_timeout"
                file_rows.append({
                    "path": failed_path,
                    "commit_sha": str(failure.get("commit_sha") or ""),
                    "verified": False,
                    "sha256": "",
                    "error": error,
                })
                break
            written = result.get("files_written") or []
            row = written[0] if written else {}
            commit_sha = "" if row.get("recovered") else str(row.get("commit_sha") or "")
            if row.get("recovered"):
                verified.append(path)
                committed.append(path)
                file_rows.append({
                    "path": path,
                    "commit_sha": commit_sha,
                    "content_sha": str(row.get("commit_sha") or ""),
                    "verified": True,
                    "sha256": str(entry["sha256"]),
                    "recovered": True,
                    "error": "",
                })
                continue
            if headers is None:
                failed_path = path
                error = "verification_missing"
                uncertain = True
                committed.append(path)
                file_rows.append({
                    "path": path,
                    "commit_sha": commit_sha,
                    "verified": False,
                    "sha256": "",
                    "error": error,
                })
                break
            verdict = _verify_published_file(
                headers,
                owner,
                repo,
                path,
                branch,
                str(entry["sha256"]),
                client=client,
            )
            committed.append(path)
            file_rows.append({
                "path": path,
                "commit_sha": commit_sha,
                "verified": bool(verdict.get("verified")),
                "sha256": str(verdict.get("sha256") or ""),
                "error": str(verdict.get("error") or ""),
            })
            if verdict.get("verified"):
                verified.append(path)
                continue
            failed_path = path
            error = str(verdict.get("error") or "verification_mismatch")
            uncertain = bool(verdict.get("outcome_uncertain"))
            running = bool(verdict.get("may_still_be_running"))
            break
    except Exception:
        noted = note_publication_outcome_uncertain(proposal_id)
        return _content_result(
            ok=False,
            error="content_outcome_uncertain",
            intended=len(approved_files),
            committed=committed,
            verified=verified,
            failed_path=failed_path,
            files=file_rows,
            consumed=True,
            state=noted.get("state"),
            attempted=_put_attempted(client),
            uncertain=True,
            running=True,
            spoken="File publication did not finish and was not retried.",
        )
    if uncertain:
        note_publication_outcome_uncertain(proposal_id)
    complete = len(verified) == len(approved_files) and not uncertain and failed_path is None
    if complete:
        spoken = "Verified the approved files."
    elif committed:
        spoken = "The repository may contain a partial publication."
    elif uncertain:
        spoken = "File publication did not finish and was not retried."
    else:
        spoken = "Could not publish the approved files."
    return _content_result(
        ok=complete,
        error="" if complete else error,
        intended=len(approved_files),
        committed=committed,
        verified=verified,
        failed_path=failed_path,
        files=file_rows,
        consumed=True,
        state=publication_authorization_state(proposal_id),
        attempted=_put_attempted(client),
        uncertain=uncertain,
        running=running,
        spoken=spoken,
    )


def _phase1_tool(
    proposal_id: str,
    tool_name: str,
    ctx: Context | None,
    grant_envelope: str | None = None,
) -> str:
    from realtime_c.github_approval import (
        begin_publication_handoff,
        cancel_publication_handoff,
        classify_write_admission,
        commit_publication_handoff,
        load_github_policy,
        load_publication_handoff_key,
        publication_admission_override,
        read_grant_key,
    )

    root = _policy_root()
    policy = load_github_policy(root)
    approval_dir = root / "realtime_c" / "logs" / "github_approvals"
    handoff: dict[str, Any] | None = None
    handoff_key = None
    if isinstance(grant_envelope, str):
        # An omitted envelope keeps the same-process grant path. A present but
        # blank envelope is missing grant data and must fail closed.
        if grant_envelope.strip():
            handoff_key = load_publication_handoff_key()
        handoff = begin_publication_handoff(
            proposal_id,
            grant_envelope,
            handoff_key,
            tool_name=tool_name,
            approval_dir=approval_dir,
        )
        if not handoff.get("ok"):
            return _public_json(handoff)
    meta_ok, _is_wire, caller_job_id, meta_error = _extract_wire_job_metadata(ctx)
    decision = classify_write_admission(
        approval_dir,
        proposal_id,
        tool_name,
        policy=policy,
        meta_ok=meta_ok,
        meta_error=meta_error,
        caller_job_id=caller_job_id,
        raw_key_32b=read_grant_key(approval_dir),
    )
    if not decision.get("ok"):
        upgraded = publication_admission_override(policy, proposal_id, tool_name, decision)
        if upgraded is not None:
            decision = upgraded
    admitted = bool(handoff and handoff.get("ok") and decision.get("ok") and decision.get("mode") == "publication")
    if handoff and handoff.get("ok") and not admitted:
        if handoff.get("inserted"):
            cancel_publication_handoff(proposal_id)
        decision["grant_admitted"] = False
        decision["handoff_from_envelope"] = False
        return _public_json(decision)
    if admitted:
        committed = commit_publication_handoff(
            proposal_id,
            str(handoff.get("capability") or ""),
            handoff_key or b"",
            approval_dir,
        )
        if not committed:
            if handoff.get("inserted"):
                cancel_publication_handoff(proposal_id)
            return _public_json({
                "ok": False,
                "error": "handoff_replayed",
                "spoken_status": "That publication approval was already used.",
                "write_attempted": False,
                "outcome_uncertain": False,
                "publication_succeeded": False,
                "grant_admitted": False,
                "handoff_from_envelope": False,
            })
    if decision.get("ok") and decision.get("mode") == "publication":
        http_client, http_error = _select_publication_http(tool_name)
        if http_error:
            return _public_json({
                "ok": False,
                "error": http_error,
                "mode": "publication",
                "publication_authorized": True,
                "write_attempted": False,
                "outcome_uncertain": False,
                "publication_succeeded": False,
                "grant_admitted": admitted,
                "handoff_from_envelope": admitted,
            })
        if http_client is not None and tool_name == "github_create_repository":
            result = _run_admitted_repository_creation(proposal_id, http_client)
            result["grant_admitted"] = admitted
            result["handoff_from_envelope"] = admitted
            return _public_json(result)
        if http_client is not None and tool_name in {"github_create_file", "github_commit_files"}:
            result = _run_admitted_content_publication(proposal_id, tool_name, http_client)
            result["grant_admitted"] = admitted
            result["handoff_from_envelope"] = admitted
            return _public_json(result)
    if decision.get("ok"):
        # Admitted publication stays blocked until a fake client or the armed server transport exists.
        decision = {
            "ok": False,
            "error": "github_transport_not_authorized",
            "mode": decision.get("mode"),
            "job_id": decision.get("job_id"),
            "publication_authorized": decision.get("mode") == "publication",
            "write_attempted": False,
            "outcome_uncertain": False,
            "publication_succeeded": False,
            "grant_admitted": admitted,
            "handoff_from_envelope": admitted,
        }
    return _public_json(decision)


@mcp.tool()
def github_create_repository(
    proposal_id: str,
    grant_envelope: str | None = None,
    ctx: Context | None = None,
) -> str:
    """Execute a host-approved empty repository proposal."""
    return _phase1_tool(proposal_id, "github_create_repository", ctx, grant_envelope)


@mcp.tool()
def github_create_file(
    proposal_id: str,
    grant_envelope: str | None = None,
    ctx: Context | None = None,
) -> str:
    """Execute a host-approved single-file proposal."""
    return _phase1_tool(proposal_id, "github_create_file", ctx, grant_envelope)


@mcp.tool()
def github_commit_files(
    proposal_id: str,
    grant_envelope: str | None = None,
    ctx: Context | None = None,
) -> str:
    """Execute a host-approved commit proposal."""
    return _phase1_tool(proposal_id, "github_commit_files", ctx, grant_envelope)


@mcp.tool()
def github_get_repository(owner: str, repo: str, ctx: Context | None = None) -> str:
    """Read-only repository verification. Never clears an uncertain-write lock."""
    from realtime_c.github_approval import load_github_policy, policy_tool_error, repo_allowlist_error

    policy = load_github_policy(_policy_root())
    denied = policy_tool_error(policy, "github_get_repository")
    if denied:
        return _err(denied, "GitHub publishing is not allowed.")
    repo_error = repo_allowlist_error(policy, f"{owner}/{repo}")
    if repo_error:
        return _err(repo_error, "That repository is not allowed.")
    meta_ok, _is_wire, _job_id, meta_error = _extract_wire_job_metadata(ctx)
    if not meta_ok:
        return _err(meta_error or "invalid_job_metadata", "The job metadata is not valid.")
    return _public_json(get_repository_payload(owner, repo))


def main() -> None:
    arm_production_http_transport()
    try:
        token_present = _credential_configured()
        _LOG.info(
            "me3-github MCP starting auth=%s api=%s confirm_ttl_s=%s",
            "ok" if token_present else "missing",
            GITHUB_API,
            int(CONFIRM_TTL_S),
        )
        mcp.run(transport="stdio")
    finally:
        close_production_http_transport()


if __name__ == "__main__":
    main()
