"""Host approval grants, schema version 3.

The HMAC covers only the immutable ``approved`` object. ``lifecycle`` is
unsigned. This module does not create a key file on import. A non-TTY
caller cannot mint a grant.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import hmac
import itertools
import json
import os
import re
import secrets
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

HMAC_DOMAIN_PREFIX = b"icy-stage75-grant-v3\x00"
GRANT_TTL_S = 180.0
SCHEMA_VERSION = 3

APPROVED_FIELDS = (
    "schema_version",
    "key_id",
    "proposal_id",
    "operation_class",
    "approval_tier",
    "operation",
    "repo_key",
    "branch",
    "grant_nonce",
    "operation_digest",
    "issued_wall_s",
    "issued_mono_s",
    "grant_expires_wall",
    "grant_expires_mono",
    "boot_id",
    "is_reconcile",
    "reconciles_proposal_id",
    "reconciles_job_id",
)
LIFECYCLE_FIELDS = (
    "state",
    "job_id",
    "consumed_mono_s",
    "updated_wall_s",
    "last_reason",
)
LIFECYCLE_STATES = frozenset({
    "APPROVED",
    "CONSUMED",
    "TAINTED_UNCERTAIN",
    "REVOKED_KEY_ROTATED",
    "EXPIRED_UNEXECUTED",
})
ELEVATED_TIERS = frozenset({
    "APPROVE-WORKFLOW",
    "APPROVE-PERMISSIONS",
    "APPROVE-DESTRUCTIVE",
})
_PROPOSAL_RE = re.compile(r"^ghprop_[0-9a-f]{32}$")
_JOB_RE = re.compile(r"^ghjob_[0-9a-f]{32}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^[0-9a-f]{16}$")


def key_id_for(raw_key_32b: bytes) -> str:
    if len(raw_key_32b) != 32:
        raise ValueError("grant hmac key must be 32 bytes")
    return hashlib.sha256(b"icy-grant-key-id-v1:" + raw_key_32b).hexdigest()[:16]


def compute_grant_hmac(raw_key_32b: bytes, approved: Mapping[str, Any]) -> str:
    """HMAC-SHA256 over the domain prefix and canonical approved JSON."""
    if len(raw_key_32b) != 32:
        raise ValueError("grant hmac key must be 32 bytes")
    canonical = json.dumps(
        dict(approved),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hmac.new(raw_key_32b, HMAC_DOMAIN_PREFIX + canonical, hashlib.sha256).hexdigest()


def verify_grant_hmac(raw_key_32b: bytes, document: Mapping[str, Any]) -> bool:
    """Constant-time check of the signed approved object. Lifecycle is ignored."""
    approved = document.get("approved")
    presented = document.get("hmac_sha256")
    if not isinstance(approved, dict) or not isinstance(presented, str):
        return False
    expected = compute_grant_hmac(raw_key_32b, approved)
    return hmac.compare_digest(expected, presented)


def tier_rejection(operation_class: str, approval_tier: str) -> str | None:
    if operation_class == "W3" and approval_tier == "APPROVE":
        return "elevated_approval_tier_required"
    if operation_class == "W3" and approval_tier not in ELEVATED_TIERS:
        return "elevated_approval_tier_required"
    if operation_class in {"W1", "W2"} and approval_tier != "APPROVE":
        return "approval_tier_mismatch"
    return None


def validate_approved(approved: Mapping[str, Any]) -> str | None:
    """Return an error code, or None when the immutable tuple is well formed."""
    if set(approved) != set(APPROVED_FIELDS):
        return "host_approval_invalid"
    if "reconcile_job_id" in approved:
        return "host_approval_invalid"
    if approved.get("schema_version") != SCHEMA_VERSION:
        return "host_approval_invalid"
    if not _KEY_ID_RE.fullmatch(str(approved.get("key_id", ""))):
        return "host_approval_invalid"
    if not _PROPOSAL_RE.fullmatch(str(approved.get("proposal_id", ""))):
        return "host_approval_invalid"
    if approved.get("operation_class") not in {"W1", "W2", "W3"}:
        return "host_approval_invalid"
    tier_error = tier_rejection(str(approved["operation_class"]), str(approved.get("approval_tier")))
    if tier_error:
        return tier_error
    if not _NONCE_RE.fullmatch(str(approved.get("grant_nonce", ""))):
        return "host_approval_invalid"
    if not _DIGEST_RE.fullmatch(str(approved.get("operation_digest", ""))):
        return "host_approval_invalid"
    if not isinstance(approved.get("is_reconcile"), bool):
        return "host_approval_invalid"
    proposal_ref = approved.get("reconciles_proposal_id")
    job_ref = approved.get("reconciles_job_id")
    if approved["is_reconcile"]:
        if not isinstance(proposal_ref, str) or not _PROPOSAL_RE.fullmatch(proposal_ref):
            return "host_approval_invalid"
        if not isinstance(job_ref, str) or not _JOB_RE.fullmatch(job_ref):
            return "host_approval_invalid"
    elif proposal_ref is not None or job_ref is not None:
        return "host_approval_invalid"
    return None


def fresh_lifecycle(state: str, *, updated_wall_s: float, reason: str) -> dict[str, Any]:
    if state not in LIFECYCLE_STATES:
        raise ValueError(state)
    job_id = None
    consumed = None
    return {
        "state": state,
        "job_id": job_id,
        "consumed_mono_s": consumed,
        "updated_wall_s": round(float(updated_wall_s), 3),
        "last_reason": reason,
    }


def build_grant_document(
    approved: Mapping[str, Any],
    lifecycle: Mapping[str, Any],
    raw_key_32b: bytes,
) -> dict[str, Any]:
    """Assemble a grant. The HMAC is computed before lifecycle is attached."""
    error = validate_approved(approved)
    if error:
        raise ValueError(error)
    if set(lifecycle) != set(LIFECYCLE_FIELDS):
        raise ValueError("host_approval_invalid")
    signed = compute_grant_hmac(raw_key_32b, approved)
    document = {
        "schema_version": SCHEMA_VERSION,
        "approved": dict(approved),
        "lifecycle": dict(lifecycle),
        "hmac_sha256": signed,
    }
    return document


def reject_non_tty(stdin: Any, stdout: Any) -> int | None:
    """Non-interactive stdin or stdout cannot mint a grant."""
    stdin_tty = bool(getattr(stdin, "isatty", lambda: False)())
    stdout_tty = bool(getattr(stdout, "isatty", lambda: False)())
    if not stdin_tty or not stdout_tty:
        return 2
    return None


VOICE_GATE_LOCK_BUDGET_S = 0.00
WORKER_GATE_LOCK_TIMEOUT_S = 0.05
CLI_COMMIT_LOCK_TIMEOUT_S = 2.00
CLI_NONBLOCK_LOCK_TIMEOUT_S = 0.00
JOURNAL_PERSIST_DEADLINE_S = 2.50
SERVER_PHASE1_LOCK_TIMEOUT_S = 0.25
SERVER_PHASE3_LOCK_TIMEOUT_S = 0.25
SERVER_PHASE5_LOCK_TIMEOUT_S = 0.50
STARTUP_SWEEP_LOCK_TIMEOUT_S = 2.00
PREPARED_PRE_EXEC_STALE_S = 30.0

_DURABLE_IO_ERRNOS = frozenset({errno.ENOSPC, errno.EROFS, errno.EIO})
_tmp_seq = itertools.count(1)
_voice_thread_ids: set[int] = set()
_voice_guard = threading.Lock()
_tracked_state_locks: list["TrackedLock"] = []
_INPROC_GATE_LOCK = threading.Lock()


class _GateTls(threading.local):
    held: bool = False


_GATE_LOCK_TLS = _GateTls()


class GateLockTimeoutError(TimeoutError):
    def __init__(self, timeout_s: float) -> None:
        self.timeout_s = timeout_s
        super().__init__(f"gate lock timeout {timeout_s:.2f}s")


class GateLockReentrancyError(RuntimeError):
    pass


class LockOrderViolationError(RuntimeError):
    pass


class VoiceThreadGateForbiddenError(RuntimeError):
    pass


class InvalidGateCapabilityError(RuntimeError):
    pass


class AbortedBeforeReplaceError(RuntimeError):
    pass


class GateDenied(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class TrackedLock:
    """RAM lock that records its owner so FileGateLock can reject lock inversion."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._guard = threading.Lock()
        self._owner: int | None = None

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        ok = self._lock.acquire(blocking, timeout)
        if ok:
            with self._guard:
                self._owner = threading.get_ident()
        return ok

    def release(self) -> None:
        with self._guard:
            self._owner = None
        self._lock.release()

    def __enter__(self) -> "TrackedLock":
        self.acquire()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.release()

    def held_by_current(self) -> bool:
        with self._guard:
            return self._owner == threading.get_ident()


def track_state_lock(lock: TrackedLock) -> None:
    _tracked_state_locks.append(lock)


def register_voice_thread(ident: int | None = None) -> None:
    with _voice_guard:
        _voice_thread_ids.add(threading.get_ident() if ident is None else ident)


def unregister_voice_thread(ident: int | None = None) -> None:
    with _voice_guard:
        _voice_thread_ids.discard(threading.get_ident() if ident is None else ident)


def gate_lock_held_by_current_thread() -> bool:
    return bool(getattr(_GATE_LOCK_TLS, "held", False))


def _fsync_fd(fd: int) -> None:
    os.fsync(fd)


def _assert_may_acquire_gate_lock() -> None:
    with _voice_guard:
        forbidden = threading.get_ident() in _voice_thread_ids
    if forbidden:
        raise VoiceThreadGateForbiddenError("voice thread cannot acquire FileGateLock")
    if gate_lock_held_by_current_thread():
        raise GateLockReentrancyError("FileGateLock is not re-entrant")
    for lock in _tracked_state_locks:
        if lock.held_by_current():
            raise LockOrderViolationError("FileGateLock cannot be acquired while _state_lock is held")


class ActiveGateLock:
    def __init__(self, approval_dir: Path, fd: int) -> None:
        self.pid = os.getpid()
        self.tid = threading.get_ident()
        self.approval_dir = Path(approval_dir)
        self._fd = fd

    def require_valid(self, parent: Path) -> None:
        if self.pid != os.getpid() or self.tid != threading.get_ident():
            raise InvalidGateCapabilityError("gate token owner mismatch")
        if not gate_lock_held_by_current_thread():
            raise InvalidGateCapabilityError("gate token used without the lock")
        if Path(parent).resolve() != self.approval_dir.resolve():
            raise InvalidGateCapabilityError("path is outside the approval directory")


class FileGateLock:
    """In-process mutex plus an OS advisory lock. Never recursive."""

    def __init__(self, approval_dir: Path, timeout_s: float) -> None:
        self.approval_dir = Path(approval_dir)
        self.timeout_s = float(timeout_s)
        self._fd: int | None = None
        self._held = False
        self._token: ActiveGateLock | None = None

    def __enter__(self) -> ActiveGateLock:
        _assert_may_acquire_gate_lock()
        if not _INPROC_GATE_LOCK.acquire(timeout=max(0.0, self.timeout_s)):
            raise GateLockTimeoutError(self.timeout_s)
        fd: int | None = None
        os_locked = False
        try:
            _verify_approval_dir(self.approval_dir)
            lock_path = self.approval_dir / ".gate.lock"
            _verify_not_symlink(lock_path, allow_missing=True)
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(lock_path), flags, 0o600)
            _verify_regular_file(fd)
            if os.name == "nt" and os.fstat(fd).st_size < 1:
                os.write(fd, b"\0")
                _fsync_fd(fd)
            _poll_os_lock(fd, time.monotonic() + max(0.0, self.timeout_s), self.timeout_s)
            os_locked = True
            _GATE_LOCK_TLS.held = True
            self._fd = fd
            self._held = True
            self._token = ActiveGateLock(self.approval_dir, fd)
            return self._token
        except BaseException:
            if os_locked and fd is not None:
                _unlock_os_fd(fd)
            if fd is not None:
                os.close(fd)
            _GATE_LOCK_TLS.held = False
            _INPROC_GATE_LOCK.release()
            raise

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if not self._held:
            return
        fd = self._fd
        self._held = False
        self._token = None
        self._fd = None
        if fd is not None:
            _unlock_os_fd(fd)
            os.close(fd)
        _GATE_LOCK_TLS.held = False
        _INPROC_GATE_LOCK.release()


def _open_nofollow(path: str, flags: int, mode: int = 0o600) -> int:
    """Open a path that lstat already proved is not a reparse point.

    The open is binary. Windows text mode treats 0x1A as end of file and
    rewrites newlines, which corrupts a 32-byte key. O_NOFOLLOW can also fail
    for an ordinary file with ERROR_NOT_A_REPARSE_POINT; the caller has
    already rejected reparse points.
    """
    extra = getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    try:
        return os.open(path, flags | extra, mode)
    except OSError as exc:
        if extra and getattr(exc, "winerror", None) in {4390, 4392}:
            return os.open(path, flags, mode)
        raise


def _is_reparse_point(info: os.stat_result) -> bool:
    """Symlinks, junctions, and other reparse points are not trusted files."""
    if stat.S_ISLNK(info.st_mode):
        return True
    attrs = int(getattr(info, "st_file_attributes", 0) or 0)
    return bool(attrs & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))


def _verify_not_symlink(path: Path, *, allow_missing: bool) -> None:
    try:
        st = path.lstat()
    except FileNotFoundError:
        if allow_missing:
            return
        raise
    if _is_reparse_point(st):
        raise OSError(errno.ELOOP, "symlink rejected", str(path))


def _verify_approval_dir(path: Path) -> None:
    st = path.lstat()
    if _is_reparse_point(st) or not stat.S_ISDIR(st.st_mode):
        raise OSError(errno.ENOTDIR, "approval dir is not a real directory", str(path))
    if os.name != "nt" and (stat.S_IMODE(st.st_mode) & 0o077) != 0:
        raise OSError(errno.EPERM, "approval dir mode is not 0700", str(path))


def _verify_regular_file(fd: int) -> None:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise OSError(errno.EINVAL, "gate lock is not a regular file")
    if os.name != "nt" and (stat.S_IMODE(st.st_mode) & 0o077) != 0:
        raise OSError(errno.EPERM, "gate lock mode is not 0600")


def prepare_private_directory(path: Path) -> None:
    """Create a real directory and limit it to the current user."""
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    _verify_approval_dir(directory)
    restrict_private_path(directory)


def restrict_private_path(path: Path) -> None:
    """Give the current user the only ACL entry. Does not store secrets in the ACL."""
    target = Path(path)
    info = target.lstat()
    if _is_reparse_point(info):
        raise OSError(errno.ELOOP, "reparse point rejected", str(target))
    mode = 0o700 if stat.S_ISDIR(info.st_mode) else 0o600
    os.chmod(target, mode)
    if os.name == "nt":
        _windows_user_only_dacl(os.path.abspath(target), directory=stat.S_ISDIR(info.st_mode))


def _windows_user_only_dacl(path: str, *, directory: bool) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.SetEntriesInAclW.argtypes = [
        wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.SetEntriesInAclW.restype = wintypes.DWORD
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD

    class TRUSTEE(ctypes.Structure):
        _fields_ = [
            ("pMultipleTrustee", ctypes.c_void_p),
            ("MultipleTrusteeOperation", ctypes.c_int),
            ("TrusteeForm", ctypes.c_int),
            ("TrusteeType", ctypes.c_int),
            ("ptstrName", ctypes.c_void_p),
        ]

    class EXPLICIT_ACCESS(ctypes.Structure):
        _fields_ = [
            ("grfAccessPermissions", wintypes.DWORD),
            ("grfAccessMode", ctypes.c_int),
            ("grfInheritance", wintypes.DWORD),
            ("Trustee", TRUSTEE),
        ]

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        buf = ctypes.create_string_buffer(max(needed.value, 1))
        if not advapi32.GetTokenInformation(token, 1, buf, len(buf), ctypes.byref(needed)):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation failed")
        sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p)).contents.value
        entry = EXPLICIT_ACCESS()
        entry.grfAccessPermissions = 0x10000000
        entry.grfAccessMode = 2
        entry.grfInheritance = 0x3 if directory else 0
        entry.Trustee.TrusteeForm = 0
        entry.Trustee.TrusteeType = 1
        entry.Trustee.ptstrName = sid
        acl = ctypes.c_void_p()
        error = advapi32.SetEntriesInAclW(1, ctypes.byref(entry), None, ctypes.byref(acl))
        if error:
            raise OSError(error, "SetEntriesInAclW failed")
        try:
            error = advapi32.SetNamedSecurityInfoW(path, 1, 0x80000004, None, None, acl, None)
            if error:
                raise OSError(error, "SetNamedSecurityInfoW failed")
        finally:
            if acl:
                kernel32.LocalFree(acl)
    finally:
        kernel32.CloseHandle(token)


def _poll_os_lock(fd: int, deadline: float, timeout_s: float) -> None:
    while True:
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError:
            if time.monotonic() >= deadline:
                raise GateLockTimeoutError(timeout_s)
            time.sleep(0.005)


def _unlock_os_fd(fd: int) -> None:
    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        return


def atomic_write_json_0600_locked(
    gate: ActiveGateLock,
    target: Path,
    payload: Mapping[str, Any],
    *,
    abort_check: Callable[[], bool] | None = None,
) -> None:
    """write, fsync, abort check, replace. The previous file stays until replace."""
    target = Path(target)
    gate.require_valid(target.parent)
    data = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    tmp = target.parent / f".{target.name}.{os.getpid()}.{threading.get_ident()}.{next(_tmp_seq)}.tmp"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(tmp), flags, 0o600)
    try:
        os.write(fd, data)
        _fsync_fd(fd)
    except OSError:
        os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.close(fd)
    try:
        gate.require_valid(target.parent)
        if abort_check is not None and abort_check():
            os.unlink(tmp)
            raise AbortedBeforeReplaceError("aborted before os.replace")
        for attempt in range(3):
            try:
                os.replace(tmp, target)
                break
            except PermissionError:
                if attempt == 2 or not tmp.exists():
                    raise
                time.sleep(0.005)
    except Exception:
        if tmp.exists():
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise
    if os.name != "nt":
        dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        dir_fd = os.open(str(target.parent), dir_flags)
        try:
            _fsync_fd(dir_fd)
        finally:
            os.close(dir_fd)


def empty_journal(boot_id: str) -> dict[str, Any]:
    return {
        "version": 2,
        "seq": 0,
        "boot_id": boot_id,
        "_inflight_repos": {},
        "_uncertain_repos": {},
        "jobs": {},
    }


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _queue(pending: list[tuple[str, str, str]], item: tuple[str, str, str]) -> None:
    if item not in pending:
        pending.append(item)


class JournalStore:
    def __init__(self, approval_dir: Path) -> None:
        self.approval_dir = Path(approval_dir)
        self.path = self.approval_dir / "write_journal.json"

    def load_bytes(self) -> bytes | None:
        if not self.path.is_file():
            return None
        return self.path.read_bytes()

    def mutate_locked(
        self,
        gate: ActiveGateLock,
        mutator: Callable[[dict[str, Any]], dict[str, Any]],
        *,
        abort_check: Callable[[], bool] | None = None,
        boot_id: str,
    ) -> dict[str, Any]:
        if self.path.is_file():
            current = _read_json(self.path)
        else:
            current = empty_journal(boot_id)
        updated = mutator(current)
        updated["seq"] = int(updated.get("seq", 0)) + 1
        atomic_write_json_0600_locked(gate, self.path, updated, abort_check=abort_check)
        return updated


def _rollback_under_gate(
    gate: ActiveGateLock,
    approval_dir: Path,
    job_id: str,
    repo_key: str,
    proposal_id: str,
    *,
    now_mono: float,
    now_wall: float,
    boot_id: str,
) -> None:
    """Step R1 restores the grant. Step R2 then marks the journal failed_certain."""
    approval_dir = Path(approval_dir)
    if (approval_dir / f"{proposal_id}.executed").exists():
        raise GateDenied("executed_present")
    grant_path = approval_dir / f"{proposal_id}.grant.json"
    if not grant_path.is_file():
        raise GateDenied("grant_missing")
    document = _read_json(grant_path)
    life = document.get("lifecycle")
    if not isinstance(life, dict):
        raise GateDenied("host_approval_invalid")
    if life.get("state") == "CONSUMED" and life.get("job_id") == job_id:
        approved = document["approved"]
        expires = float(approved["grant_expires_mono"])
        same_boot = approved.get("boot_id") == boot_id and now_mono <= expires
        document["lifecycle"] = {
            "state": "APPROVED" if same_boot else "EXPIRED_UNEXECUTED",
            "job_id": None,
            "consumed_mono_s": None,
            "updated_wall_s": round(float(now_wall), 3),
            "last_reason": "restored_approved" if same_boot else "expired_unexecuted",
        }
        atomic_write_json_0600_locked(gate, grant_path, document)
    journal_path = approval_dir / "write_journal.json"
    if not journal_path.is_file():
        raise GateDenied("journal_missing")
    journal = _read_json(journal_path)
    inflight = journal.setdefault("_inflight_repos", {})
    if not isinstance(inflight, dict):
        raise GateDenied("journal_corrupted")
    if inflight.get(repo_key) == job_id:
        inflight.pop(repo_key)
    job = journal.get("jobs", {}).get(job_id)
    if isinstance(job, dict) and job.get("state") == "prepared" and job.get("write_attempted") is False:
        job["state"] = "failed_certain"
    journal["seq"] = int(journal.get("seq", 0)) + 1
    atomic_write_json_0600_locked(gate, journal_path, journal)


def rollback_pre_dispatch(
    approval_dir: Path,
    job_id: str,
    repo_key: str,
    proposal_id: str,
    pending: list[tuple[str, str, str]],
    *,
    now_mono: float,
    now_wall: float,
    boot_id: str,
    timeout_s: float = WORKER_GATE_LOCK_TIMEOUT_S,
) -> None:
    item = (job_id, repo_key, proposal_id)
    _queue(pending, item)
    with FileGateLock(approval_dir, timeout_s) as gate:
        _rollback_under_gate(
            gate,
            approval_dir,
            job_id,
            repo_key,
            proposal_id,
            now_mono=now_mono,
            now_wall=now_wall,
            boot_id=boot_id,
        )
    pending.remove(item)


def authorize_and_consume(
    approval_dir: Path,
    *,
    proposal_id: str,
    job_id: str,
    raw_key_32b: bytes,
    boot_id: str,
    now_mono: float,
    now_wall: float,
    pending: list[tuple[str, str, str]],
    abort_check: Callable[[], bool] | None = None,
    timeout_s: float = WORKER_GATE_LOCK_TIMEOUT_S,
) -> dict[str, Any]:
    """TX-3 prepared plus inflight, then TX-4 CONSUMED. The HMAC bytes stay put."""
    if not _JOB_RE.fullmatch(job_id) or not _PROPOSAL_RE.fullmatch(proposal_id):
        raise GateDenied("host_approval_invalid")
    approval_dir = Path(approval_dir)
    store = JournalStore(approval_dir)
    with FileGateLock(approval_dir, timeout_s) as gate:
        for item in list(pending):
            _rollback_under_gate(
                gate,
                approval_dir,
                item[0],
                item[1],
                item[2],
                now_mono=now_mono,
                now_wall=now_wall,
                boot_id=boot_id,
            )
            pending.remove(item)
        grant_path = approval_dir / f"{proposal_id}.grant.json"
        if not grant_path.is_file():
            raise GateDenied("grant_missing")
        if (approval_dir / f"{proposal_id}.executed").exists():
            raise GateDenied("executed_present")
        document = _read_json(grant_path)
        if not verify_grant_hmac(raw_key_32b, document):
            raise GateDenied("host_approval_invalid")
        approved = document["approved"]
        if approved.get("proposal_id") != proposal_id or approved.get("boot_id") != boot_id:
            raise GateDenied("host_approval_invalid")
        if now_mono > float(approved["grant_expires_mono"]):
            raise GateDenied("grant_expired")
        life = document.get("lifecycle")
        if not isinstance(life, dict) or life.get("state") != "APPROVED" or life.get("job_id") is not None:
            raise GateDenied("grant_not_approved")
        repo_key = str(approved["repo_key"])
        original_hmac = document["hmac_sha256"]

        def _prepare(journal: dict[str, Any]) -> dict[str, Any]:
            inflight = journal.setdefault("_inflight_repos", {})
            uncertain = journal.setdefault("_uncertain_repos", {})
            if not isinstance(inflight, dict) or not isinstance(uncertain, dict):
                raise GateDenied("journal_corrupted")
            if inflight.get(repo_key) is not None:
                raise GateDenied("repo_write_in_progress")
            if uncertain.get(repo_key) is not None:
                raise GateDenied("repo_uncertain")
            journal.setdefault("jobs", {})[job_id] = {
                "state": "prepared",
                "write_attempted": False,
                "repo_key": repo_key,
                "proposal_id": proposal_id,
                "created_mono_s": now_mono,
            }
            inflight[repo_key] = job_id
            return journal

        try:
            prepared = store.mutate_locked(gate, _prepare, abort_check=abort_check, boot_id=boot_id)
        except OSError:
            raise
        if not isinstance(prepared["_inflight_repos"][repo_key], str):
            raise GateDenied("journal_corrupted")
        if abort_check is not None and abort_check():
            item = (job_id, repo_key, proposal_id)
            _queue(pending, item)
            try:
                _rollback_under_gate(
                    gate, approval_dir, job_id, repo_key, proposal_id,
                    now_mono=now_mono, now_wall=now_wall, boot_id=boot_id,
                )
            except OSError:
                raise
            pending.remove(item)
            raise AbortedBeforeReplaceError("aborted after TX-3")
        document["lifecycle"] = {
            "state": "CONSUMED",
            "job_id": job_id,
            "consumed_mono_s": now_mono,
            "updated_wall_s": round(float(now_wall), 3),
            "last_reason": "consumed",
        }
        if document["hmac_sha256"] != original_hmac:
            raise GateDenied("hmac_recomputed")
        try:
            atomic_write_json_0600_locked(gate, grant_path, document, abort_check=abort_check)
        except (OSError, AbortedBeforeReplaceError):
            item = (job_id, repo_key, proposal_id)
            _queue(pending, item)
            try:
                _rollback_under_gate(
                    gate, approval_dir, job_id, repo_key, proposal_id,
                    now_mono=now_mono, now_wall=now_wall, boot_id=boot_id,
                )
            except OSError:
                raise
            pending.remove(item)
            raise
        written = _read_json(grant_path)
        if written["hmac_sha256"] != original_hmac:
            raise GateDenied("hmac_recomputed")
        return _read_json(store.path)


def sweep_stale_prepared(
    approval_dir: Path,
    pending: list[tuple[str, str, str]],
    *,
    now_mono: float,
    now_wall: float,
    boot_id: str,
    timeout_s: float = WORKER_GATE_LOCK_TIMEOUT_S,
) -> int:
    """Third layer only. Records younger than 30s stay prepared."""
    approval_dir = Path(approval_dir)
    journal_path = approval_dir / "write_journal.json"
    if not journal_path.is_file():
        return 0
    preview = _read_json(journal_path)
    stale: list[tuple[str, str, str]] = []
    for job_id, job in preview.get("jobs", {}).items():
        if not isinstance(job, dict):
            continue
        if job.get("state") != "prepared" or job.get("write_attempted") is not False:
            continue
        created = float(job.get("created_mono_s", now_mono))
        if now_mono - created <= PREPARED_PRE_EXEC_STALE_S:
            continue
        proposal_id = str(job.get("proposal_id"))
        if (approval_dir / f"{proposal_id}.executed").exists():
            continue
        stale.append((str(job_id), str(job.get("repo_key")), proposal_id))
    cleared = 0
    for item in stale:
        before = len(pending)
        rollback_pre_dispatch(
            approval_dir,
            item[0],
            item[1],
            item[2],
            pending,
            now_mono=now_mono,
            now_wall=now_wall,
            boot_id=boot_id,
            timeout_s=timeout_s,
        )
        if len(pending) == before:
            cleared += 1
    return cleared


def promote_dangling_inflight(
    approval_dir: Path,
    *,
    timeout_s: float = WORKER_GATE_LOCK_TIMEOUT_S,
) -> dict[str, str]:
    """An inflight job with no journal row becomes an uncertain string, and stays there."""
    approval_dir = Path(approval_dir)
    with FileGateLock(approval_dir, timeout_s) as gate:
        path = approval_dir / "write_journal.json"
        if not path.is_file():
            return {}
        journal = _read_json(path)
        inflight = journal.get("_inflight_repos")
        jobs = journal.get("jobs")
        uncertain = journal.setdefault("_uncertain_repos", {})
        if not isinstance(inflight, dict) or not isinstance(jobs, dict) or not isinstance(uncertain, dict):
            raise GateDenied("journal_corrupted")
        promoted: dict[str, str] = {}
        for repo_key, job_id in list(inflight.items()):
            if not isinstance(job_id, str) or job_id in jobs:
                continue
            inflight.pop(repo_key)
            uncertain[repo_key] = job_id
            promoted[repo_key] = job_id
        if promoted:
            journal["seq"] = int(journal.get("seq", 0)) + 1
            atomic_write_json_0600_locked(gate, path, journal)
        return promoted


def reconcile_startup_journal(
    approval_dir: Path,
    *,
    now_mono: float,
    now_wall: float,
    boot_id: str | None = None,
    timeout_s: float = STARTUP_SWEEP_LOCK_TIMEOUT_S,
    pipe_write_started: bool = False,
) -> dict[str, Any]:
    """Heal a previous boot. Uncertain rows stay. Prepared rows roll back Grant-First."""
    approval_dir = Path(approval_dir)
    journal_path = approval_dir / "write_journal.json"
    if not journal_path.is_file():
        return {"rolled_back": [], "kept_uncertain": []}
    with FileGateLock(approval_dir, timeout_s) as gate:
        journal = _read_json(journal_path)
        inflight = journal.setdefault("_inflight_repos", {})
        uncertain = journal.setdefault("_uncertain_repos", {})
        jobs = journal.setdefault("jobs", {})
        if not isinstance(inflight, dict) or not isinstance(uncertain, dict) or not isinstance(jobs, dict):
            raise GateDenied("journal_corrupted")
        active_boot = boot_id if boot_id else str(journal.get("boot_id") or "")
        rolled: list[str] = []
        for job_id, job in list(jobs.items()):
            if pipe_write_started:
                break
            if not isinstance(job, dict):
                continue
            if job.get("state") != "prepared" or job.get("write_attempted") is not False:
                continue
            proposal_id = str(job.get("proposal_id") or "")
            if (approval_dir / f"{proposal_id}.executed").exists():
                continue
            _rollback_under_gate(
                gate,
                approval_dir,
                str(job_id),
                str(job.get("repo_key") or ""),
                proposal_id,
                now_mono=now_mono,
                now_wall=now_wall,
                boot_id=active_boot,
            )
            rolled.append(str(job_id))
        journal = _read_json(journal_path)
        inflight = journal.setdefault("_inflight_repos", {})
        uncertain = journal.setdefault("_uncertain_repos", {})
        jobs = journal.setdefault("jobs", {})
        kept: list[str] = []
        for job_id, job in list(jobs.items()):
            if not isinstance(job, dict):
                continue
            repo_key = str(job.get("repo_key") or "")
            proposal_id = str(job.get("proposal_id") or "")
            executed = (approval_dir / f"{proposal_id}.executed").exists()
            sent = pipe_write_started and job.get("state") == "prepared"
            if job.get("state") == "outcome_uncertain" or job.get("write_attempted") is True or executed or sent:
                if repo_key:
                    uncertain[repo_key] = str(job_id)
                    inflight.pop(repo_key, None)
                job["state"] = "outcome_uncertain"
                kept.append(str(job_id))
        for repo_key, job_id in list(inflight.items()):
            if isinstance(job_id, str) and job_id not in jobs:
                inflight.pop(repo_key, None)
                uncertain[repo_key] = job_id
                kept.append(job_id)
        journal["seq"] = int(journal.get("seq", 0)) + 1
        atomic_write_json_0600_locked(gate, journal_path, journal)
        return {"rolled_back": rolled, "kept_uncertain": kept}


def shutdown_disposition(*, pipe_write_started: bool, executed_present: bool) -> str:
    """A sent pipe or an execution marker stays uncertain. Otherwise roll the grant back."""
    if pipe_write_started or executed_present:
        return "outcome_uncertain"
    return "grant_first_rollback"


JOB_ID_META_KEY = "me3.icy/job_id"
_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPO_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_BOOL_FLAGS = (
    "allow_reads",
    "allow_writes",
    "allow_repo_creation",
    "allow_workflows",
    "allow_permissions",
    "allow_destructive",
)
READ_TOOL_NAMES = frozenset({
    "github_get_repository",
    "github_prepare_publish",
    "github_get_job_status",
})
WRITE_TOOL_NAMES = frozenset({
    "github_create_repository",
    "github_create_file",
    "github_commit_files",
})


@dataclass(frozen=True)
class GithubPolicy:
    ok: bool
    error: str | None
    enabled: bool
    allow_reads: bool
    allow_writes: bool
    allow_repo_creation: bool
    allow_workflows: bool
    allow_permissions: bool
    allow_destructive: bool
    allowed_owner: str
    allowed_repos: tuple[str, ...]


def _invalid_policy() -> GithubPolicy:
    return GithubPolicy(False, "policy_invalid", False, False, False, False, False, False, False, "", ())


def _disabled_policy(error: str = "github_mcp_disabled") -> GithubPolicy:
    return GithubPolicy(False, error, False, False, False, False, False, False, False, "", ())


def load_github_policy(root: Path) -> GithubPolicy:
    """Re-read ``config/github_mcp.json``. Missing and malformed files fail closed."""
    path = Path(root) / "config" / "github_mcp.json"
    try:
        st = path.lstat()
    except FileNotFoundError:
        return _disabled_policy()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return _invalid_policy()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return _invalid_policy()
    if not isinstance(data, dict):
        return _invalid_policy()
    if "enabled" in data and not isinstance(data["enabled"], bool):
        return _invalid_policy()
    flags: dict[str, bool] = {}
    for name in _BOOL_FLAGS:
        if name not in data:
            flags[name] = False
            continue
        if not isinstance(data[name], bool):
            return _invalid_policy()
        flags[name] = data[name] is True
    owner = ""
    if "allowed_owner" in data:
        raw_owner = data["allowed_owner"]
        if not isinstance(raw_owner, str) or raw_owner == "*" or _OWNER_RE.fullmatch(raw_owner) is None:
            return _invalid_policy()
        owner = raw_owner
    repos: list[str] = []
    if "allowed_repos" in data:
        raw_repos = data["allowed_repos"]
        if not isinstance(raw_repos, list):
            return _invalid_policy()
        for item in raw_repos:
            if not isinstance(item, str) or item == "*" or _REPO_NAME_RE.fullmatch(item) is None:
                return _invalid_policy()
            repos.append(item)
    return GithubPolicy(
        True,
        None,
        data.get("enabled") is True,
        flags["allow_reads"],
        flags["allow_writes"],
        flags["allow_repo_creation"],
        flags["allow_workflows"],
        flags["allow_permissions"],
        flags["allow_destructive"],
        owner,
        tuple(repos),
    )


def policy_tool_error(policy: GithubPolicy, tool_name: str, operation_class: str | None = None, approval_tier: str | None = None) -> str | None:
    """Return the fail-closed error for this tool, or None when the flag allows it."""
    if not policy.ok:
        return policy.error or "policy_invalid"
    if not policy.enabled:
        return "github_mcp_disabled"
    if tool_name in READ_TOOL_NAMES and not policy.allow_reads and tool_name != "github_get_job_status":
        return "github_reads_disabled"
    if tool_name == "github_get_job_status":
        return None
    if tool_name in WRITE_TOOL_NAMES and not policy.allow_writes:
        return "github_writes_disabled"
    if tool_name == "github_create_repository" and not policy.allow_repo_creation:
        return "github_repo_creation_disabled"
    if operation_class == "W3":
        allowed = (
            (approval_tier == "APPROVE-DESTRUCTIVE" and policy.allow_destructive)
            or (approval_tier == "APPROVE-WORKFLOW" and policy.allow_workflows)
            or (approval_tier == "APPROVE-PERMISSIONS" and policy.allow_permissions)
        )
        if not allowed:
            return "elevated_approval_tier_required"
    return None


def repo_allowlist_error(policy: GithubPolicy, repo_key: str) -> str | None:
    if not policy.allowed_owner:
        return "owner_not_allowlisted"
    if "/" not in repo_key:
        return "repo_not_allowlisted"
    owner, repo = repo_key.split("/", 1)
    if owner.casefold() != policy.allowed_owner.casefold():
        return "owner_not_allowlisted"
    if not policy.allowed_repos:
        return "no_allowed_repos_configured"
    if repo not in policy.allowed_repos:
        return "repo_not_allowlisted"
    return None


def read_grant_key(approval_dir: Path) -> bytes | None:
    """Read a 64-hex key file when a test or operator has created one. Never creates it."""
    path = Path(approval_dir) / ".grant_hmac.key"
    try:
        st = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return None
    try:
        text = path.read_text(encoding="utf-8").strip()
        raw = bytes.fromhex(text)
    except (OSError, UnicodeError, ValueError):
        return None
    if len(raw) != 32:
        return None
    return raw


def job_call_meta(job_id: str | None) -> dict[str, str] | None:
    """Build the Rev 7 wire meta object. None means Mode B may mint."""
    if job_id is None:
        return None
    if not isinstance(job_id, str) or _JOB_RE.fullmatch(job_id) is None:
        raise ValueError("invalid_job_metadata")
    return {JOB_ID_META_KEY: job_id}


def classify_write_admission(
    approval_dir: Path,
    proposal_id: str,
    tool_name: str,
    *,
    policy: GithubPolicy,
    meta_ok: bool,
    meta_error: str | None,
    caller_job_id: str | None,
    raw_key_32b: bytes | None,
) -> dict[str, Any]:
    """Read-only Mode A/B decision. This function does not write the journal or call GitHub."""
    flag_error = policy_tool_error(policy, tool_name)
    if flag_error:
        return {"ok": False, "error": flag_error, "write_attempted": False, "outcome_uncertain": False}
    if not meta_ok:
        return {"ok": False, "error": meta_error or "invalid_job_metadata", "write_attempted": False, "outcome_uncertain": False}
    if not _PROPOSAL_RE.fullmatch(proposal_id):
        return {"ok": False, "error": "host_approval_invalid", "write_attempted": False, "outcome_uncertain": False}
    grant_path = Path(approval_dir) / f"{proposal_id}.grant.json"
    if not grant_path.is_file():
        return {"ok": False, "error": "host_approval_required", "write_attempted": False, "outcome_uncertain": False}
    document = _read_json(grant_path)
    if raw_key_32b is None or not verify_grant_hmac(raw_key_32b, document):
        return {"ok": False, "error": "host_approval_key_missing" if raw_key_32b is None else "host_approval_payload_modified", "write_attempted": False, "outcome_uncertain": False}
    approved = document.get("approved")
    life = document.get("lifecycle")
    if not isinstance(approved, dict) or not isinstance(life, dict):
        return {"ok": False, "error": "host_approval_invalid", "write_attempted": False, "outcome_uncertain": False}
    class_error = policy_tool_error(
        policy,
        tool_name,
        operation_class=str(approved.get("operation_class") or ""),
        approval_tier=str(approved.get("approval_tier") or ""),
    )
    if class_error:
        return {"ok": False, "error": class_error, "write_attempted": False, "outcome_uncertain": False}
    repo_error = repo_allowlist_error(policy, str(approved.get("repo_key") or ""))
    if repo_error:
        return {"ok": False, "error": repo_error, "write_attempted": False, "outcome_uncertain": False}
    journal_path = Path(approval_dir) / "write_journal.json"
    journal = _read_json(journal_path) if journal_path.is_file() else empty_journal(str(approved.get("boot_id") or ""))
    jobs = journal.get("jobs") if isinstance(journal.get("jobs"), dict) else {}
    inflight = journal.get("_inflight_repos") if isinstance(journal.get("_inflight_repos"), dict) else {}
    state = life.get("state")
    repo_key = str(approved.get("repo_key"))
    if state == "CONSUMED":
        if caller_job_id is None:
            return {"ok": False, "error": "missing_job_metadata", "write_attempted": False, "outcome_uncertain": False}
        if caller_job_id != life.get("job_id"):
            return {"ok": False, "error": "grant_job_mismatch", "write_attempted": False, "outcome_uncertain": False}
        job = jobs.get(caller_job_id)
        if not isinstance(job, dict) or job.get("state") != "prepared" or job.get("proposal_id") != proposal_id:
            return {"ok": False, "error": "journal_job_not_prepared", "write_attempted": False, "outcome_uncertain": False}
        if inflight.get(repo_key) != caller_job_id:
            return {"ok": False, "error": "repo_ownership_lost", "write_attempted": False, "outcome_uncertain": False}
        return {
            "ok": True,
            "mode": "A",
            "job_id": caller_job_id,
            "write_attempted": False,
            "outcome_uncertain": False,
        }
    if state == "APPROVED":
        if inflight.get(repo_key) is not None:
            return {"ok": False, "error": "repo_write_in_progress", "write_attempted": False, "outcome_uncertain": False}
        if caller_job_id is not None and caller_job_id in jobs:
            return {"ok": False, "error": "duplicate_job_id", "write_attempted": False, "outcome_uncertain": False}
        return {
            "ok": True,
            "mode": "B",
            "job_id": caller_job_id,
            "mint": caller_job_id is None,
            "write_attempted": False,
            "outcome_uncertain": False,
        }
    return {"ok": False, "error": "grant_not_approved", "write_attempted": False, "outcome_uncertain": False}


PUBLICATION_TTL_S = 300.0
PUBLICATION_STATES = frozenset({
    "preview_prepared",
    "awaiting_approval",
    "approval_accepted",
    "approval_expired",
    "approval_rejected",
    "approval_consumed",
    "publication_failed_before_dispatch",
    "publication_dispatched",
    "publication_outcome_uncertain",
})
_OPEN_PUBLICATION_STATES = frozenset({"preview_prepared", "awaiting_approval", "approval_accepted"})
# A publication file may name a token prefix or contain the scanner's own
# regular expression. Only a complete credential shape is rejected. A
# repeated-character body is accepted only on a line that carries the exact
# marker below. Any other complete shape fails closed, including one that
# sits in a test, a comment, or next to that marker.
MAX_PUBLICATION_FILE_BYTES = 200_000
MAX_PUBLICATION_AGGREGATE_BYTES = 1_000_000
MAX_GRANT_ENVELOPE_BYTES = 2_000_000
MAX_PUBLICATION_FILES = 100
_SYNTHETIC_CREDENTIAL_MARKER = "synthetic-credential-fixture"
_CLASSIC_TOKEN_RE = re.compile(r"ghp_[A-Za-z0-9]{20,}")
_FINE_TOKEN_RE = re.compile(r"github_pat_[A-Za-z0-9_]{20,}")
_OTHER_GITHUB_TOKEN_RE = re.compile(r"gh[ousr]_[A-Za-z0-9]{20,}")
_OPENAI_TOKEN_RE = re.compile(r"sk-[A-Za-z0-9_\-]{20,}")
_AWS_KEY_RE = re.compile(r"A(?:KIA|SIA)[0-9A-Z]{16}")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_AUTH_HEADER_RE = re.compile(r"(?i)authorization\s*:\s*(?:bearer|token|basic)\s+(\S+)")
_TOKEN_PREFIXES = ("github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "sk-")
_SECRET_PATH_RE = re.compile(
    r"(^|/)(\.env($|\.)|id_rsa|id_ed25519|credentials\.json|\.pem$)",
    re.IGNORECASE,
)
_ALLOWLIST_BYPASS_ERRORS = frozenset({
    "host_approval_required",
    "repo_not_allowlisted",
    "no_allowed_repos_configured",
    "owner_not_allowlisted",
})


def visible_github_tool_names(policy: GithubPolicy) -> frozenset[str]:
    """Model-visible GitHub tools.

    Publication and write tools stay hidden until a background publisher exists.
    Showing them here would route a spoken turn into a voice-thread write.
    """
    if not policy.ok or not policy.enabled or not policy.allow_reads:
        return frozenset()
    return frozenset({"github_get_repository"})


def _publication_denied(error: str, spoken: str, **extra: Any) -> dict[str, Any]:
    payload = {
        "ok": False,
        "error": error,
        "spoken_status": spoken,
        "write_attempted": False,
        "outcome_uncertain": False,
        "publication_succeeded": False,
    }
    payload.update(extra)
    return payload


def max_base64_chars(size: int) -> int:
    """Upper bound on the base64 text of ``size`` raw bytes. Reject longer input first."""
    if size < 0:
        return 0
    return 4 * ((size + 2) // 3)


def grant_envelope_too_large(envelope: str) -> bool:
    """True when the serialized envelope exceeds the configured byte limit."""
    return len(envelope.encode("utf-8")) > MAX_GRANT_ENVELOPE_BYTES


def _token_payload(token: str) -> str:
    for prefix in _TOKEN_PREFIXES:
        if token.startswith(prefix):
            return token[len(prefix):]
    return token


def _repeated_character_payload(payload: str) -> bool:
    return len(payload) >= 20 and len(set(payload)) == 1


def _line_marks_synthetic_credential(text: str, start: int) -> bool:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end < 0:
        line_end = len(text)
    return _SYNTHETIC_CREDENTIAL_MARKER in text[line_start:line_end]


def _explicit_synthetic_credential(text: str, token: str, start: int) -> bool:
    """A credential-shaped value is synthetic only when both checks pass.

    The line must name the fixture, and the body must be one repeated
    character. A high-entropy or mixed body stays a credential.
    """
    return (
        _line_marks_synthetic_credential(text, start)
        and _repeated_character_payload(_token_payload(token))
    )


def publication_text_has_secret(text: str) -> bool:
    """True when text contains a complete credential rather than a prefix or pattern."""
    if not isinstance(text, str):
        return False
    if _PRIVATE_KEY_RE.search(text) or _AWS_KEY_RE.search(text):
        return True
    for pattern in (_CLASSIC_TOKEN_RE, _FINE_TOKEN_RE, _OTHER_GITHUB_TOKEN_RE, _OPENAI_TOKEN_RE):
        for match in pattern.finditer(text):
            if not _explicit_synthetic_credential(text, match.group(), match.start()):
                return True
    for match in _AUTH_HEADER_RE.finditer(text):
        credential = match.group(1)
        if len(credential) >= 20 and not _explicit_synthetic_credential(text, credential, match.start(1)):
            return True
    return False


def publication_content_bytes(content: Any) -> bytes | None:
    """Return the exact publication bytes for a string or bytes payload.

    Strings are encoded once as UTF-8. Bytes are returned unchanged.
    Newlines are not translated.
    """
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8")
    return None


def _file_binding(files: list[dict[str, Any]]) -> tuple[tuple[tuple[str, int, str], ...], str, str | None]:
    """Hash exact file bytes. Returns (bindings, readme_sha256, error).

    README.md is recorded when present and is not required.
    """
    if not files:
        return (), "", "empty_manifest"
    if len(files) > MAX_PUBLICATION_FILES:
        return (), "", "too_many_files"
    bindings: list[tuple[str, int, str]] = []
    seen: set[str] = set()
    seen_fold: set[str] = set()
    readme_sha = ""
    total = 0
    for item in files:
        if not isinstance(item, dict):
            return (), "", "invalid_manifest_file"
        path = item.get("path")
        content = item.get("content")
        if not isinstance(path, str) or not isinstance(content, (str, bytes)):
            return (), "", "invalid_manifest_file"
        relative = path.strip().replace("\\", "/")
        if (
            not relative
            or relative.startswith("/")
            or relative.startswith("~")
            or ".." in relative.split("/")
            or any(part in {"", ".", ".."} for part in relative.split("/"))
            or re.match(r"^[A-Za-z]:", relative)
        ):
            return (), "", "invalid_manifest_file"
        raw = publication_content_bytes(content)
        if raw is None:
            return (), "", "invalid_manifest_file"
        if len(raw) > MAX_PUBLICATION_FILE_BYTES:
            return (), "", "file_too_large"
        if total + len(raw) > MAX_PUBLICATION_AGGREGATE_BYTES:
            return (), "", "manifest_too_large"
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return (), "", "unsupported_file_content"
        if _SECRET_PATH_RE.search(relative) or publication_text_has_secret(text):
            return (), "", "secret_or_sensitive_content"
        total += len(raw)
        folded = relative.casefold()
        if relative in seen or folded in seen_fold:
            return (), "", "duplicate_manifest_path"
        seen.add(relative)
        seen_fold.add(folded)
        digest = hashlib.sha256(raw).hexdigest()
        bindings.append((relative, len(raw), digest))
        if relative == "README.md":
            readme_sha = digest
    ordered = tuple(sorted(bindings))
    return ordered, readme_sha, None


def _manifest_fingerprint(
    owner: str,
    repo_name: str,
    visibility: str,
    description: str,
    branch: str,
    files: tuple[tuple[str, int, str], ...],
    readme_sha256: str,
) -> str:
    blob = json.dumps(
        {
            "owner": owner,
            "repo_name": repo_name,
            "visibility": visibility,
            "description": description,
            "branch": branch,
            "readme_sha256": readme_sha256,
            "files": [
                {"path": path, "size": size, "sha256": digest}
                for path, size, digest in files
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class _PublicationRecord:
    authorization_id: str
    owner: str
    repo_name: str
    visibility: str
    description: str
    branch: str
    fingerprint: str
    files: tuple[tuple[str, int, str], ...]
    readme_sha256: str
    created_at: float
    expires_at: float
    state: str
    capability: str = "create"
    linked_publish_id: str | None = None
    contents: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        return {
            "owner": self.owner,
            "repo_name": self.repo_name,
            "visibility": self.visibility,
            "description": self.description,
            "branch": self.branch,
            "fingerprint": self.fingerprint,
            "readme_sha256": self.readme_sha256,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "files": [
                {"path": path, "size": size, "sha256": digest}
                for path, size, digest in self.files
            ],
        }


class _PublicationStore:
    def __init__(self, clock: Callable[[], float] | None = None, id_factory: Callable[[], str] | None = None) -> None:
        self.clock = clock or time.monotonic
        self._id_factory = id_factory or (lambda: "ghprop_" + secrets.token_hex(16))
        self._items: dict[str, _PublicationRecord] = {}
        self._lock = threading.Lock()

    def now(self) -> float:
        return float(self.clock())

    def mint_id(self) -> str:
        return self._id_factory()

    def put(self, record: _PublicationRecord) -> None:
        with self._lock:
            self._items[record.authorization_id] = record

    def get(self, authorization_id: str) -> _PublicationRecord | None:
        with self._lock:
            return self._items.get(authorization_id)


_PUBLICATIONS = _PublicationStore()


def reset_publication_authorizations_for_tests(
    clock: Callable[[], float] | None = None,
    id_factory: Callable[[], str] | None = None,
) -> None:
    """Replace the in-memory publication store. Tests pass a deterministic clock."""
    global _PUBLICATIONS
    _PUBLICATIONS = _PublicationStore(clock=clock, id_factory=id_factory)


def _public_preview(record: _PublicationRecord, spoken: str) -> dict[str, Any]:
    payload = {
        "ok": True,
        "state": record.state,
        "authorization_id": record.authorization_id,
        "summary": record.summary(),
        "spoken_status": spoken,
        "write_attempted": False,
        "outcome_uncertain": False,
        "publication_succeeded": False,
    }
    if record.linked_publish_id:
        payload["content_authorization_id"] = record.linked_publish_id
    return payload


def _expire_if_needed(record: _PublicationRecord, now: float) -> str | None:
    if record.state not in _OPEN_PUBLICATION_STATES:
        return None
    if now < record.expires_at:
        return None
    record.state = "approval_expired"
    return "approval_expired"


def prepare_publication_authorization(
    policy: GithubPolicy,
    *,
    owner: str,
    repo_name: str,
    visibility: str,
    description: str,
    branch: str,
    files: list[dict[str, Any]],
    now: float,
    ttl_s: float = PUBLICATION_TTL_S,
) -> dict[str, Any]:
    """Stage one public-repository preview. This does not write to GitHub or the allowlist."""
    if not policy.ok:
        return _publication_denied(policy.error or "policy_invalid", "GitHub publishing is not allowed.")
    if not policy.enabled:
        return _publication_denied("github_mcp_disabled", "GitHub publishing is not allowed.")
    bound_owner = policy.allowed_owner
    if not bound_owner or owner.casefold() != bound_owner.casefold():
        return _publication_denied("owner_not_allowlisted", "That GitHub owner is not allowed.")
    if visibility != "public":
        return _publication_denied("visibility_not_public", "Only an explicit public repository can be authorized.")
    if _REPO_NAME_RE.fullmatch(repo_name) is None or repo_name.startswith(".") or repo_name.endswith("."):
        return _publication_denied("invalid_repository_name", "That repository name is not valid.")
    if not description.strip():
        return _publication_denied("description_required", "A repository description is required.")
    if not branch.strip() or "/" in branch or branch.startswith("-"):
        return _publication_denied("branch_required", "An initial branch is required.")
    if publication_text_has_secret(description) or publication_text_has_secret(branch):
        return _publication_denied("secret_or_sensitive_content", "The publication preview was rejected.")
    bindings, readme_sha, file_error = _file_binding(files)
    if file_error:
        spoken = "The publication preview was rejected."
        if file_error == "empty_manifest":
            spoken = "A publication needs at least one approved file."
        return _publication_denied(file_error, spoken)
    fingerprint = _manifest_fingerprint(
        bound_owner, repo_name, "public", description, branch, bindings, readme_sha,
    )
    stored_contents: dict[str, Any] = {}
    for item in files:
        relative = str(item["path"]).strip().replace("\\", "/")
        raw = publication_content_bytes(item.get("content"))
        if raw is None:
            return _publication_denied("invalid_manifest_file", "The publication preview was rejected.")
        stored_contents[relative] = raw
    record = _PublicationRecord(
        authorization_id=_PUBLICATIONS.mint_id(),
        owner=bound_owner,
        repo_name=repo_name,
        visibility="public",
        description=description,
        branch=branch,
        fingerprint=fingerprint,
        files=bindings,
        readme_sha256=readme_sha,
        created_at=float(now),
        expires_at=float(now) + float(ttl_s),
        state="preview_prepared",
        capability="create",
        contents=stored_contents,
    )
    _PUBLICATIONS.put(record)
    return _public_preview(
        record,
        f"Prepared a public repository preview for {bound_owner}/{repo_name}. "
        f"{len(bindings)} files. Nothing has been published.",
    )


def await_publication_approval(authorization_id: str, *, now: float) -> dict[str, Any]:
    record = _PUBLICATIONS.get(authorization_id)
    if record is None:
        return _publication_denied("no_pending_approval", "There is no publication waiting for approval.")
    expired = _expire_if_needed(record, now)
    if expired:
        return _publication_denied(expired, "That publication approval has expired.", state=record.state)
    if record.state != "preview_prepared":
        return _publication_denied("approval_not_awaiting", "That publication is not waiting to be shown.", state=record.state)
    record.state = "awaiting_approval"
    return _public_preview(record, f"Waiting for approval of {record.owner}/{record.repo_name}.")


def _presented_binding(
    record: _PublicationRecord,
    *,
    owner: str,
    repo_name: str,
    visibility: str,
    description: str,
    branch: str,
    files: list[dict[str, Any]],
) -> str | None:
    if owner != record.owner:
        return "owner_not_allowlisted"
    if repo_name != record.repo_name:
        return "repository_mismatch"
    if visibility != record.visibility:
        return "visibility_not_public" if visibility != "public" else "visibility_mismatch"
    if description != record.description:
        return "description_mismatch"
    if branch != record.branch:
        return "branch_mismatch"
    bindings, readme_sha, file_error = _file_binding(files)
    if file_error:
        return file_error
    fingerprint = _manifest_fingerprint(
        owner, repo_name, visibility, description, branch, bindings, readme_sha,
    )
    if fingerprint != record.fingerprint or bindings != record.files:
        return "manifest_mismatch"
    return None


def confirm_publication_authorization(
    authorization_id: str | None,
    policy: GithubPolicy,
    *,
    owner: str,
    repo_name: str,
    visibility: str,
    description: str,
    branch: str,
    files: list[dict[str, Any]],
    now: float,
) -> dict[str, Any]:
    """Accept one awaiting preview. A second confirmation does not create another grant."""
    if not authorization_id:
        return _publication_denied("no_pending_approval", "There is no publication waiting for approval.")
    if not policy.ok:
        return _publication_denied(policy.error or "policy_invalid", "GitHub publishing is not allowed.")
    if not policy.enabled:
        return _publication_denied("github_mcp_disabled", "GitHub publishing is not allowed.")
    flag = policy_tool_error(policy, "github_create_repository")
    if flag:
        return _publication_denied(flag, "GitHub publishing is not allowed.")
    record = _PUBLICATIONS.get(authorization_id)
    if record is None:
        return _publication_denied("no_pending_approval", "There is no publication waiting for approval.")
    expired = _expire_if_needed(record, now)
    if expired:
        return _publication_denied(expired, "That publication approval has expired.", state=record.state)
    if record.state == "approval_accepted":
        return _publication_denied("confirmation_replayed", "That publication was already approved.", state=record.state)
    if record.state == "approval_consumed":
        return _publication_denied("approval_consumed", "That publication approval was already used.", state=record.state)
    if record.state != "awaiting_approval":
        return _publication_denied("approval_not_awaiting", "That publication is not waiting for approval.", state=record.state)
    mismatch = _presented_binding(
        record,
        owner=owner,
        repo_name=repo_name,
        visibility=visibility,
        description=description,
        branch=branch,
        files=files,
    )
    if mismatch:
        return _publication_denied(mismatch, "That confirmation does not match the prepared publication.", state=record.state)
    record.state = "approval_accepted"
    _issue_content_capability(record)
    return _public_preview(
        record,
        f"Approved publication of {record.owner}/{record.repo_name}. Nothing has been sent to GitHub.",
    )


def _issue_content_capability(record: _PublicationRecord) -> str:
    """Mint the one-shot file grant for this confirmation. The create grant stays separate."""
    content_id = _PUBLICATIONS.mint_id()
    sibling = _PublicationRecord(
        authorization_id=content_id,
        owner=record.owner,
        repo_name=record.repo_name,
        visibility=record.visibility,
        description=record.description,
        branch=record.branch,
        fingerprint=record.fingerprint,
        files=record.files,
        readme_sha256=record.readme_sha256,
        created_at=record.created_at,
        expires_at=record.expires_at,
        state="approval_accepted",
        capability="publish",
        contents=dict(record.contents),
    )
    _PUBLICATIONS.put(sibling)
    record.capability = "create"
    record.linked_publish_id = content_id
    return content_id


def reject_publication_authorization(authorization_id: str, *, now: float) -> dict[str, Any]:
    record = _PUBLICATIONS.get(authorization_id)
    if record is None:
        return _publication_denied("no_pending_approval", "There is no publication waiting for approval.")
    expired = _expire_if_needed(record, now)
    if expired:
        return _publication_denied(expired, "That publication approval has expired.", state=record.state)
    if record.state not in {"preview_prepared", "awaiting_approval"}:
        return _publication_denied("approval_not_awaiting", "That publication can no longer be rejected.", state=record.state)
    record.state = "approval_rejected"
    return _public_preview(record, "The publication was rejected. Nothing was sent.")


def consume_publication_authorization(authorization_id: str, *, now: float) -> dict[str, Any]:
    """Mark one accepted grant used. Consumption is not a GitHub publication."""
    record = _PUBLICATIONS.get(authorization_id)
    if record is None:
        return _publication_denied("no_pending_approval", "There is no publication waiting for approval.")
    expired = _expire_if_needed(record, now)
    if expired:
        return _publication_denied(expired, "That publication approval has expired.", state=record.state)
    if record.state == "approval_consumed":
        return _publication_denied("approval_consumed", "That publication approval was already used.", state=record.state)
    if record.state != "approval_accepted":
        return _publication_denied("approval_not_accepted", "That publication has not been approved.", state=record.state)
    record.state = "approval_consumed"
    return _public_preview(record, "The publication approval was consumed. GitHub was not contacted.")


def note_publication_failed_before_dispatch(authorization_id: str, *, now: float) -> dict[str, Any]:
    record = _PUBLICATIONS.get(authorization_id)
    if record is None:
        return _publication_denied("no_pending_approval", "There is no publication waiting for approval.")
    if record.state != "approval_accepted":
        return _publication_denied("approval_not_accepted", "That publication has not been approved.", state=record.state)
    if now >= record.expires_at:
        record.state = "approval_expired"
        return _publication_denied("approval_expired", "That publication approval has expired.", state=record.state)
    record.state = "publication_failed_before_dispatch"
    return _public_preview(record, "The publication stopped before anything was sent.")


def note_publication_dispatched(authorization_id: str) -> dict[str, Any]:
    """Record that a later phase sent the operation. This function does not send it."""
    record = _PUBLICATIONS.get(authorization_id)
    if record is None:
        return _publication_denied("no_pending_approval", "There is no publication waiting for approval.")
    if record.state != "approval_consumed":
        return _publication_denied(
            "approval_not_consumed",
            "A publication cannot be marked sent before its approval is consumed.",
            state=record.state,
        )
    record.state = "publication_dispatched"
    return _public_preview(record, "The publication was marked sent. This record is not a success check.")


def note_publication_outcome_uncertain(authorization_id: str) -> dict[str, Any]:
    record = _PUBLICATIONS.get(authorization_id)
    if record is None:
        return _publication_denied("no_pending_approval", "There is no publication waiting for approval.")
    if record.state != "publication_dispatched":
        return _publication_denied(
            "publication_not_dispatched",
            "An uncertain outcome requires a dispatched publication.",
            state=record.state,
        )
    record.state = "publication_outcome_uncertain"
    noted = _public_preview(record, "The publication outcome is uncertain.")
    noted["outcome_uncertain"] = True
    return noted


def evaluate_publication_authorization(
    authorization_id: str | None,
    policy: GithubPolicy,
    *,
    operation: str,
    owner: str,
    repo_name: str,
    visibility: str,
    description: str,
    branch: str,
    files: list[dict[str, Any]],
    now: float,
) -> dict[str, Any]:
    """Check one grant against a presented manifest. This never dispatches or consumes it."""
    if operation == "update_existing_repository":
        return _publication_denied(
            "existing_repository_update_not_authorized",
            "A new-repository approval cannot update an existing repository.",
        )
    if operation in {"delete", "destructive"}:
        return _publication_denied("destructive_unavailable", "Destructive GitHub operations are unavailable.")
    if operation not in {"create_public_repository", "publish_manifest"}:
        return _publication_denied("publication_operation_rejected", "That publication operation is not authorized.")
    if not authorization_id:
        return _publication_denied("no_pending_approval", "There is no publication waiting for approval.")
    if not policy.ok:
        return _publication_denied(policy.error or "policy_invalid", "GitHub publishing is not allowed.")
    if not policy.enabled:
        return _publication_denied("github_mcp_disabled", "GitHub publishing is not allowed.")
    tool_name = "github_create_repository" if operation == "create_public_repository" else "github_commit_files"
    flag = policy_tool_error(policy, tool_name)
    if flag:
        return _publication_denied(flag, "GitHub publishing is not allowed.")
    record = _PUBLICATIONS.get(authorization_id)
    if record is None:
        return _publication_denied("no_pending_approval", "There is no publication waiting for approval.")
    expired = _expire_if_needed(record, now)
    if expired:
        return _publication_denied(expired, "That publication approval has expired.", state=record.state)
    if record.state == "approval_consumed":
        return _publication_denied("approval_consumed", "That publication approval was already used.", state=record.state)
    if record.state != "approval_accepted":
        return _publication_denied("approval_not_accepted", "That publication has not been approved.", state=record.state)
    mismatch = _presented_binding(
        record,
        owner=owner,
        repo_name=repo_name,
        visibility=visibility,
        description=description,
        branch=branch,
        files=files,
    )
    if mismatch:
        return _publication_denied(mismatch, "That confirmation does not match the prepared publication.", state=record.state)
    return _publication_denied(
        "github_transport_not_authorized",
        "That publication is approved and has not been sent.",
        publication_authorized=True,
        state=record.state,
    )


def publication_clock_now() -> float:
    return _PUBLICATIONS.now()


def publication_authorization_state(authorization_id: str) -> str | None:
    record = _PUBLICATIONS.get(authorization_id)
    return None if record is None else record.state


def accepted_publication_create_binding(authorization_id: str) -> dict[str, Any]:
    """Read one accepted create grant. This does not consume it or call GitHub."""
    record = _PUBLICATIONS.get(authorization_id)
    if record is None:
        return _publication_denied("no_pending_approval", "There is no publication waiting for approval.")
    expired = _expire_if_needed(record, _PUBLICATIONS.now())
    if expired:
        return _publication_denied(expired, "That publication approval has expired.", state=record.state)
    if record.state == "approval_consumed" or record.state in {
        "publication_dispatched",
        "publication_outcome_uncertain",
        "publication_failed_before_dispatch",
    }:
        return _publication_denied(
            "approval_consumed",
            "That publication approval was already used.",
            state=record.state,
        )
    if record.state != "approval_accepted":
        return _publication_denied("approval_not_accepted", "That publication has not been approved.", state=record.state)
    if record.capability == "publish":
        return _publication_denied(
            "content_grant_cannot_create_repository",
            "A file-publication approval cannot create a repository.",
            state=record.state,
        )
    if record.visibility != "public":
        return _publication_denied(
            "visibility_not_public",
            "Only an explicit public repository can be authorized.",
            state=record.state,
        )
    return {
        "ok": True,
        "owner": record.owner,
        "repo_name": record.repo_name,
        "description": record.description,
        "visibility": record.visibility,
        "branch": record.branch,
        "fingerprint": record.fingerprint,
        "state": record.state,
        "write_attempted": False,
        "outcome_uncertain": False,
        "publication_succeeded": False,
    }


def accepted_publication_content_binding(authorization_id: str) -> dict[str, Any]:
    """Read one accepted file grant. This does not consume it or call GitHub."""
    record = _PUBLICATIONS.get(authorization_id)
    if record is None:
        return _publication_denied("no_pending_approval", "There is no publication waiting for approval.")
    expired = _expire_if_needed(record, _PUBLICATIONS.now())
    if expired:
        return _publication_denied(expired, "That publication approval has expired.", state=record.state)
    if record.capability != "publish":
        return _publication_denied(
            "creation_grant_cannot_publish",
            "A repository-creation approval cannot publish files.",
            state=record.state,
        )
    if record.state == "approval_consumed" or record.state in {
        "publication_dispatched",
        "publication_outcome_uncertain",
        "publication_failed_before_dispatch",
    }:
        return _publication_denied(
            "approval_consumed",
            "That publication approval was already used.",
            state=record.state,
        )
    if record.state != "approval_accepted":
        return _publication_denied("approval_not_accepted", "That publication has not been approved.", state=record.state)
    fresh = _manifest_fingerprint(
        record.owner,
        record.repo_name,
        record.visibility,
        record.description,
        record.branch,
        record.files,
        record.readme_sha256,
    )
    if fresh != record.fingerprint or record.visibility != "public":
        return _publication_denied(
            "manifest_changed",
            "The approved publication no longer matches its manifest.",
            state=record.state,
        )
    expected_paths = {path for path, _size, _digest in record.files}
    if set(record.contents) != expected_paths:
        return _publication_denied(
            "manifest_changed",
            "The approved publication no longer matches its manifest.",
            state=record.state,
        )
    selected: list[dict[str, Any]] = []
    for path, size, digest in record.files:
        raw = publication_content_bytes(record.contents.get(path))
        if raw is None:
            return _publication_denied(
                "manifest_changed",
                "The approved publication no longer matches its manifest.",
                state=record.state,
            )
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            return _publication_denied(
                "changed_file_hash",
                "The approved publication no longer matches its manifest.",
                state=record.state,
            )
        selected.append({"path": path, "content": raw, "sha256": digest, "size": size})
    return {
        "ok": True,
        "owner": record.owner,
        "repo_name": record.repo_name,
        "description": record.description,
        "visibility": record.visibility,
        "branch": record.branch,
        "fingerprint": record.fingerprint,
        "files": selected,
        "state": record.state,
        "write_attempted": False,
        "outcome_uncertain": False,
        "publication_succeeded": False,
    }


def publication_admission_override(
    policy: GithubPolicy,
    proposal_id: str,
    tool_name: str,
    decision: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Let one accepted publication grant stand in for a missing repo allowlist entry.

    The returned decision is still not a GitHub call. The caller must keep the
    transport blocked.
    """
    if decision.get("ok") or decision.get("error") not in _ALLOWLIST_BYPASS_ERRORS:
        return None
    if tool_name not in WRITE_TOOL_NAMES:
        return None
    record = _PUBLICATIONS.get(proposal_id)
    if record is None:
        return None
    now = _PUBLICATIONS.now()
    expired = _expire_if_needed(record, now)
    if expired:
        return _publication_denied(expired, "That publication approval has expired.", state=record.state)
    if record.state == "approval_consumed" or record.state in {
        "publication_dispatched",
        "publication_outcome_uncertain",
        "publication_failed_before_dispatch",
    }:
        return _publication_denied(
            "approval_consumed",
            "That publication approval was already used.",
            state=record.state,
        )
    if record.state != "approval_accepted":
        return _publication_denied("approval_not_accepted", "That publication has not been approved.", state=record.state)
    if record.owner.casefold() != policy.allowed_owner.casefold():
        return _publication_denied("owner_not_allowlisted", "That GitHub owner is not allowed.", state=record.state)
    if tool_name == "github_create_repository" and not policy.allow_repo_creation:
        return _publication_denied("github_repo_creation_disabled", "GitHub publishing is not allowed.", state=record.state)
    return {
        "ok": True,
        "mode": "publication",
        "job_id": None,
        "write_attempted": False,
        "outcome_uncertain": False,
    }


def direct_write_decision(root: Path, tool_name: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Apply the same write gate a direct client or tool call must pass. Never dispatches."""
    policy = load_github_policy(root)
    denied = policy_tool_error(policy, tool_name)
    if denied:
        return _publication_denied(denied, "GitHub publishing is not allowed.")
    if tool_name not in WRITE_TOOL_NAMES:
        return _publication_denied("publication_tool_not_authorized", "That GitHub operation is not authorized.")
    args = arguments or {}
    proposal_id = args.get("proposal_id") or args.get("authorization_id")
    if not isinstance(proposal_id, str) or not proposal_id:
        return _publication_denied("no_pending_approval", "There is no publication waiting for approval.")
    record = _PUBLICATIONS.get(proposal_id)
    if record is None:
        return _publication_denied("no_pending_approval", "There is no publication waiting for approval.")
    now = _PUBLICATIONS.now()
    expired = _expire_if_needed(record, now)
    if expired:
        return _publication_denied(expired, "That publication approval has expired.", state=record.state)
    if record.state == "approval_consumed":
        return _publication_denied("approval_consumed", "That publication approval was already used.", state=record.state)
    if record.state != "approval_accepted":
        return _publication_denied("approval_not_accepted", "That publication has not been approved.", state=record.state)
    if record.owner.casefold() != policy.allowed_owner.casefold():
        return _publication_denied("owner_not_allowlisted", "That GitHub owner is not allowed.", state=record.state)
    return _publication_denied(
        "github_transport_not_authorized",
        "That publication is approved and has not been sent.",
        publication_authorized=True,
        state=record.state,
    )


# The publication grant is born in the parent process. The MCP server is a
# different process and cannot see that memory. One sealed envelope travels on
# the MCP tool call. The session key is not the GitHub credential and is never
# written into the envelope or a log.
#
# Consumption is recorded in two ledgers that share one replay key:
# the approval directory copy, and a witness directory beside it
# (``github_replay``). A per-grant marker remains as a third witness.
# Deleting, editing, or replacing that one marker does not revive a grant
# while either ledger still verifies. The witness survives an approval-directory
# snapshot restore. Client close deletes only the session-key file. It does
# not delete ledger evidence.
#
# Same-user deletion of both ledgers and the witness key cannot be prevented
# on Windows. That full wipe is outside the protection boundary. A damaged,
# missing, or unreadable ledger fails closed.
#
# Crash before both ledger replaces: nothing was recorded, so one later
# admission can still succeed. Crash after the witness ledger is durable:
# the grant stays consumed. A timeout is not retried. Wall-clock expiry is
# independent of the ledger; turning the clock back cannot revive a recorded
# grant. The child trusts the local clock only for unused grants.
_HANDOFF_DOMAIN = b"icy-publication-handoff-v1\x00"
_HANDOFF_CONSUMED_DOMAIN = b"icy-publication-handoff-consumed-v1\x00"
_REPLAY_DOMAIN = b"icy-publication-replay-v1\x00"
_REPLAY_WITNESS_DIR = "github_replay"
_REPLAY_LEDGER_NAME = "handoff_replay.ledger"
_REPLAY_KEY_NAME = "handoff_replay.key"
_REPLAY_LOCK_NAME = "handoff_replay.lock"
_HANDOFF_LOCK = threading.Lock()
_HANDOFF_KEY: bytes | None = None
_HANDOFF_KEY_LOADED = False


def _handoff_mac(key: bytes, payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        dict(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hmac.new(key, _HANDOFF_DOMAIN + canonical, hashlib.sha256).hexdigest()


def _consumed_mac(key: bytes, proposal_id: str, capability: str) -> str:
    body = _HANDOFF_CONSUMED_DOMAIN + proposal_id.encode("ascii") + b"\x00" + capability.encode("ascii")
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def _handoff_capability(tool_name: str) -> str | None:
    if tool_name == "github_create_repository":
        return "create"
    if tool_name in {"github_create_file", "github_commit_files"}:
        return "publish"
    return None


def load_publication_handoff_key() -> bytes | None:
    """Read the session key once from the private handoff file. Never creates one.

    The environment value is a path inside the approval directory, not a token.
    A symlink or a path outside that directory is ignored.
    """
    global _HANDOFF_KEY, _HANDOFF_KEY_LOADED
    if _HANDOFF_KEY_LOADED:
        return _HANDOFF_KEY
    _HANDOFF_KEY_LOADED = True
    raw_path = os.environ.get("GITHUB_MCP_HANDOFF_PATH")
    approval_raw = os.environ.get("GITHUB_MCP_APPROVAL_DIR")
    if not raw_path or not approval_raw:
        return None
    path = Path(raw_path)
    approval = Path(approval_raw)
    try:
        approval_info = approval.lstat()
        if _is_reparse_point(approval_info) or not stat.S_ISDIR(approval_info.st_mode):
            return None
        key_abs = os.path.normcase(os.path.abspath(path))
        approval_abs = os.path.normcase(os.path.abspath(approval))
        if os.path.dirname(key_abs) != approval_abs:
            return None
        if not path.name.startswith("handoff-") or path.suffix != ".key":
            return None
        info = path.lstat()
        if _is_reparse_point(info) or not stat.S_ISREG(info.st_mode) or info.st_size != 32:
            return None
        fd = _open_nofollow(str(path), os.O_RDWR)
    except OSError:
        return None
    locked = False
    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked = True
        if os.fstat(fd).st_size != 32:
            return None
        key = os.read(fd, 32)
        if len(key) != 32 or key == b"\0" * 32:
            return None
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, b"\0" * 32)
        _fsync_fd(fd)
        _HANDOFF_KEY = key
    except OSError:
        _HANDOFF_KEY = None
        return None
    finally:
        if locked:
            _unlock_os_fd(fd)
        os.close(fd)
    try:
        os.unlink(path)
    except OSError:
        pass
    return _HANDOFF_KEY


def set_publication_handoff_key_for_tests(key: bytes | None) -> None:
    """Install a session key without reading a file. Tests must not pass a token."""
    global _HANDOFF_KEY, _HANDOFF_KEY_LOADED
    _HANDOFF_KEY = key
    _HANDOFF_KEY_LOADED = True


def reset_publication_handoff_for_tests() -> None:
    global _HANDOFF_KEY, _HANDOFF_KEY_LOADED
    _HANDOFF_KEY = None
    _HANDOFF_KEY_LOADED = False


def seal_publication_handoff_approved(approved: Mapping[str, Any], key: bytes) -> str:
    """Sign one already-built payload. The envelope is not written to disk."""
    if len(key) != 32:
        raise ValueError("handoff key must be 32 bytes")
    document = {"v": 1, "approved": dict(approved), "hmac_sha256": _handoff_mac(key, approved)}
    raw = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    envelope = base64.b64encode(raw).decode("ascii")
    if grant_envelope_too_large(envelope):
        raise ValueError("envelope_too_large")
    return envelope


def seal_publication_handoff(
    authorization_id: str,
    key: bytes,
    *,
    now_wall: float | None = None,
) -> str | None:
    """Seal the parent grant. Returns None when that grant cannot be transferred."""
    record = _PUBLICATIONS.get(authorization_id)
    if record is None or record.state != "approval_accepted":
        return None
    if record.capability not in {"create", "publish"}:
        return None
    wall = time.time() if now_wall is None else float(now_wall)
    remaining = float(record.expires_at) - float(_PUBLICATIONS.now())
    if remaining <= 0:
        return None
    files = []
    for path, size, digest in record.files:
        raw = publication_content_bytes(record.contents.get(path))
        if raw is None or len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            return None
        files.append({
            "path": path,
            "size": size,
            "sha256": digest,
            "content_b64": base64.b64encode(raw).decode("ascii"),
        })
    approved = {
        "proposal_id": record.authorization_id,
        "capability": record.capability,
        "owner": record.owner,
        "repo_name": record.repo_name,
        "visibility": record.visibility,
        "description": record.description,
        "branch": record.branch,
        "fingerprint": record.fingerprint,
        "readme_sha256": record.readme_sha256,
        "expires_wall": round(wall + remaining, 3),
        "files": files,
    }
    try:
        return seal_publication_handoff_approved(approved, key)
    except ValueError as exc:
        if str(exc) == "envelope_too_large":
            return None
        raise


def _handoff_denied(error: str, spoken: str) -> dict[str, Any]:
    return _publication_denied(error, spoken, grant_admitted=False, handoff_from_envelope=False)


def _consumed_path(approval_dir: Path, proposal_id: str) -> Path:
    return Path(approval_dir) / f"{proposal_id}.handoff_consumed"


def _read_consumed_marker(path: Path) -> str | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        return ""
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > 128:
        return ""
    try:
        fd = _open_nofollow(str(path), os.O_RDONLY)
        try:
            text = os.read(fd, 128).decode("ascii").strip()
        finally:
            os.close(fd)
    except (OSError, UnicodeError):
        return ""
    if not _DIGEST_RE.fullmatch(text):
        return ""
    return text


def _replay_mac(key: bytes, proposal_id: str, capability: str) -> str:
    body = _REPLAY_DOMAIN + proposal_id.encode("ascii") + b"\x00" + capability.encode("ascii")
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def _witness_dir(approval_dir: Path) -> Path:
    return Path(approval_dir).parent / _REPLAY_WITNESS_DIR


def _directory_kind(path: Path) -> str:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "invalid"
    if _is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
        return "invalid"
    return "dir"


def _read_replay_key(path: Path) -> tuple[str, bytes | None]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "missing", None
    except OSError:
        return "invalid", None
    if _is_reparse_point(info) or not stat.S_ISREG(info.st_mode) or info.st_size != 32:
        return "invalid", None
    try:
        fd = _open_nofollow(str(path), os.O_RDONLY)
        try:
            key = os.read(fd, 32)
        finally:
            os.close(fd)
    except OSError:
        return "invalid", None
    if len(key) != 32:
        return "invalid", None
    return "ok", key


def _read_ledger_lines(path: Path, key: bytes) -> tuple[str, list[str], set[str]]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "missing", [], set()
    except OSError:
        return "invalid", [], set()
    if _is_reparse_point(info) or not stat.S_ISREG(info.st_mode) or info.st_size > 1_000_000:
        return "invalid", [], set()
    try:
        fd = _open_nofollow(str(path), os.O_RDONLY)
        try:
            raw = os.read(fd, 1_000_000)
        finally:
            os.close(fd)
    except OSError:
        return "invalid", [], set()
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        return "invalid", [], set()
    lines = text.splitlines()
    if not lines or lines[0] != "v1":
        return "invalid", [], set()
    kept: list[str] = []
    found: set[str] = set()
    for line in lines[1:]:
        parts = line.split(" ")
        if len(parts) != 3:
            return "invalid", [], set()
        proposal_id, capability, mac = parts
        if _PROPOSAL_RE.fullmatch(proposal_id) is None or capability not in {"create", "publish"}:
            return "invalid", [], set()
        if not _DIGEST_RE.fullmatch(mac):
            return "invalid", [], set()
        if not hmac.compare_digest(_replay_mac(key, proposal_id, capability), mac):
            return "invalid", [], set()
        if proposal_id in found:
            return "invalid", [], set()
        found.add(proposal_id)
        kept.append(line)
    if not kept:
        return "invalid", [], set()
    return "ok", kept, found


def _load_replay_pair(approval_dir: Path) -> tuple[str, bytes | None, list[str], set[str]]:
    """Return clear, paired, witness_only, or invalid. Never returns secret material."""
    approval = Path(approval_dir)
    witness = _witness_dir(approval)
    if _directory_kind(approval) == "invalid":
        return "invalid", None, [], set()
    witness_kind = _directory_kind(witness)
    if witness_kind == "invalid":
        return "invalid", None, [], set()
    key_state, key = ("missing", None)
    if witness_kind == "dir":
        key_state, key = _read_replay_key(witness / _REPLAY_KEY_NAME)
    if key_state == "invalid":
        return "invalid", None, [], set()
    approval_ledger = approval / _REPLAY_LEDGER_NAME
    witness_ledger = witness / _REPLAY_LEDGER_NAME
    if key_state == "missing":
        try:
            if approval_ledger.exists() or witness_ledger.exists():
                return "invalid", None, [], set()
        except OSError:
            return "invalid", None, [], set()
        return "clear", None, [], set()
    assert key is not None
    witness_state, witness_lines, witness_ids = _read_ledger_lines(witness_ledger, key)
    approval_state, _approval_lines, approval_ids = _read_ledger_lines(approval_ledger, key)
    if witness_state == "ok" and approval_state == "ok" and witness_ids == approval_ids:
        return "paired", key, witness_lines, witness_ids
    if witness_state == "ok":
        return "witness_only", key, witness_lines, witness_ids
    return "invalid", None, [], set()


def _publication_replay_status(approval_dir: Path, proposal_id: str) -> str:
    kind, _key, _lines, ids = _load_replay_pair(approval_dir)
    if kind == "invalid":
        return "invalid"
    if proposal_id in ids:
        return "consumed"
    if kind == "witness_only":
        return "invalid"
    marker = _read_consumed_marker(_consumed_path(approval_dir, proposal_id))
    if marker == "":
        return "invalid"
    if marker is not None:
        return "consumed"
    return "clear"


class _ReplayLock:
    """Cross-process mutex for the witness directory. Not consumption evidence."""

    def __init__(self, witness: Path) -> None:
        self.witness = witness
        self._fd: int | None = None

    def __enter__(self) -> int:
        prepare_private_directory(self.witness)
        lock_path = self.witness / _REPLAY_LOCK_NAME
        _verify_not_symlink(lock_path, allow_missing=True)
        fd = _open_nofollow(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        locked = False
        try:
            _verify_regular_file(fd)
            if os.fstat(fd).st_size < 1:
                os.write(fd, b"\0")
                _fsync_fd(fd)
            restrict_private_path(lock_path)
            deadline = time.monotonic() + 5.0
            while True:
                try:
                    if os.name == "nt":
                        import msvcrt

                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("replay ledger lock timed out")
                    time.sleep(0.01)
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd
        self._locked = locked
        return fd

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        fd = self._fd
        self._fd = None
        if fd is None:
            return
        _unlock_os_fd(fd)
        os.close(fd)


def _write_private_bytes(path: Path, payload: bytes) -> None:
    path = Path(path)
    _verify_approval_dir(path.parent)
    try:
        current = path.lstat()
    except FileNotFoundError:
        current = None
    if current is not None and _is_reparse_point(current):
        raise OSError(errno.ELOOP, "reparse point rejected", str(path))
    tmp = path.parent / f".{path.name}.{os.getpid()}.{threading.get_ident()}.{secrets.token_hex(4)}.tmp"
    fd = _open_nofollow(str(tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, payload)
        _fsync_fd(fd)
    except OSError:
        os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.close(fd)
    restrict_private_path(tmp)
    os.replace(tmp, path)
    restrict_private_path(path)


def _create_replay_key(witness: Path) -> bytes:
    path = witness / _REPLAY_KEY_NAME
    _verify_not_symlink(path, allow_missing=True)
    key = secrets.token_bytes(32)
    fd = _open_nofollow(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, key)
        _fsync_fd(fd)
    except OSError:
        os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    os.close(fd)
    restrict_private_path(path)
    return key


def begin_publication_handoff(
    proposal_id: str,
    envelope: str,
    key: bytes | None,
    *,
    tool_name: str,
    approval_dir: Path,
    now_wall: float | None = None,
) -> dict[str, Any]:
    """Verify one envelope and install it in this process. Does not consume it yet.

    The caller commits the handoff after the existing gate accepts the record,
    or cancels it when the gate rejects the record.
    """
    if not isinstance(proposal_id, str) or _PROPOSAL_RE.fullmatch(proposal_id) is None:
        return _handoff_denied("no_pending_approval", "There is no publication waiting for approval.")
    if not isinstance(envelope, str) or not envelope.strip():
        return _handoff_denied("no_pending_approval", "There is no publication waiting for approval.")
    if grant_envelope_too_large(envelope):
        return _handoff_denied("envelope_too_large", "The approval handoff was rejected.")
    if not isinstance(key, bytes) or len(key) != 32:
        return _handoff_denied("handoff_unavailable", "The approval handoff could not be verified.")
    expected_capability = _handoff_capability(tool_name)
    if expected_capability is None:
        return _handoff_denied("publication_tool_not_authorized", "That GitHub operation is not authorized.")
    try:
        decoded = base64.b64decode(envelope, validate=True)
        document = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError):
        return _handoff_denied("handoff_malformed", "The approval handoff was rejected.")
    if not isinstance(document, dict):
        return _handoff_denied("handoff_malformed", "The approval handoff was rejected.")
    approved = document.get("approved")
    presented = document.get("hmac_sha256")
    if not isinstance(approved, dict) or not isinstance(presented, str):
        return _handoff_denied("handoff_malformed", "The approval handoff was rejected.")
    if not hmac.compare_digest(_handoff_mac(key, approved), presented):
        return _handoff_denied("handoff_altered", "The approval handoff was rejected.")
    if approved.get("proposal_id") != proposal_id:
        return _handoff_denied("proposal_mismatch", "That approval does not match this request.")
    capability = approved.get("capability")
    if capability not in {"create", "publish"}:
        return _handoff_denied("handoff_malformed", "The approval handoff was rejected.")
    if capability != expected_capability:
        if capability == "create":
            return _handoff_denied(
                "creation_grant_cannot_publish",
                "A repository-creation approval cannot publish files.",
            )
        return _handoff_denied(
            "content_grant_cannot_create_repository",
            "A file-publication approval cannot create a repository.",
        )
    wall = time.time() if now_wall is None else float(now_wall)
    try:
        expires_wall = float(approved.get("expires_wall"))
    except (TypeError, ValueError):
        return _handoff_denied("handoff_malformed", "The approval handoff was rejected.")
    if wall >= expires_wall:
        return _handoff_denied("handoff_expired", "That publication approval has expired.")
    owner = approved.get("owner")
    repo_name = approved.get("repo_name")
    visibility = approved.get("visibility")
    description = approved.get("description")
    branch = approved.get("branch")
    fingerprint = approved.get("fingerprint")
    readme_sha = approved.get("readme_sha256")
    file_rows = approved.get("files")
    if (
        not isinstance(owner, str)
        or not isinstance(repo_name, str)
        or visibility != "public"
        or not isinstance(description, str)
        or not isinstance(branch, str)
        or not isinstance(fingerprint, str)
        or not isinstance(readme_sha, str)
        or not isinstance(file_rows, list)
        or not file_rows
        or len(file_rows) > MAX_PUBLICATION_FILES
    ):
        return _handoff_denied("handoff_malformed", "The approval handoff was rejected.")
    if publication_text_has_secret(description) or publication_text_has_secret(branch):
        return _handoff_denied("secret_or_sensitive_content", "The approval handoff was rejected.")
    bindings: list[tuple[str, int, str]] = []
    contents: dict[str, bytes] = {}
    seen: set[str] = set()
    seen_fold: set[str] = set()
    found_readme = ""
    total = 0
    for item in file_rows:
        if not isinstance(item, dict):
            return _handoff_denied("handoff_malformed", "The approval handoff was rejected.")
        path = item.get("path")
        declared_size = item.get("size")
        declared_hash = item.get("sha256")
        content_b64 = item.get("content_b64")
        if (
            not isinstance(path, str)
            or not isinstance(declared_size, int)
            or isinstance(declared_size, bool)
            or not isinstance(declared_hash, str)
            or not isinstance(content_b64, str)
            or declared_size < 0
            or declared_size > MAX_PUBLICATION_FILE_BYTES
        ):
            if isinstance(declared_size, int) and not isinstance(declared_size, bool) and (
                declared_size < 0 or declared_size > MAX_PUBLICATION_FILE_BYTES
            ):
                return _handoff_denied("file_too_large", "The approval handoff was rejected.")
            return _handoff_denied("handoff_malformed", "The approval handoff was rejected.")
        if total + declared_size > MAX_PUBLICATION_AGGREGATE_BYTES:
            return _handoff_denied("manifest_too_large", "The approval handoff was rejected.")
        if len(content_b64) > max_base64_chars(declared_size):
            return _handoff_denied("file_too_large", "The approval handoff was rejected.")
        if (
            not path
            or path.startswith("/")
            or path.startswith("~")
            or ".." in path.split("/")
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or re.match(r"^[A-Za-z]:", path)
            or "\\" in path
        ):
            return _handoff_denied("invalid_manifest_file", "The approval handoff was rejected.")
        folded = path.casefold()
        if path in seen or folded in seen_fold:
            return _handoff_denied("duplicate_manifest_path", "The approval handoff was rejected.")
        seen.add(path)
        seen_fold.add(folded)
        if _SECRET_PATH_RE.search(path):
            return _handoff_denied("secret_or_sensitive_content", "The approval handoff was rejected.")
        try:
            raw = base64.b64decode(content_b64, validate=True)
        except ValueError:
            return _handoff_denied("handoff_malformed", "The approval handoff was rejected.")
        if len(raw) != declared_size:
            return _handoff_denied("changed_file_size", "The approval handoff was rejected.")
        if total + len(raw) > MAX_PUBLICATION_AGGREGATE_BYTES:
            return _handoff_denied("manifest_too_large", "The approval handoff was rejected.")
        if hashlib.sha256(raw).hexdigest() != declared_hash:
            return _handoff_denied("changed_file_hash", "The approval handoff was rejected.")
        if len(raw) > MAX_PUBLICATION_FILE_BYTES:
            return _handoff_denied("file_too_large", "The approval handoff was rejected.")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return _handoff_denied("unsupported_file_content", "The approval handoff was rejected.")
        if publication_text_has_secret(text):
            return _handoff_denied("secret_or_sensitive_content", "The approval handoff was rejected.")
        total += len(raw)
        if path == "README.md":
            found_readme = declared_hash
        bindings.append((path, declared_size, declared_hash))
        contents[path] = raw
    if found_readme != readme_sha:
        return _handoff_denied("manifest_mismatch", "The approval handoff was rejected.")
    ordered = tuple(sorted(bindings))
    fresh = _manifest_fingerprint(owner, repo_name, "public", description, branch, ordered, readme_sha)
    if fresh != fingerprint:
        return _handoff_denied("manifest_mismatch", "The approval handoff was rejected.")
    replay = _publication_replay_status(Path(approval_dir), proposal_id)
    if replay == "consumed":
        return _handoff_denied("handoff_replayed", "That publication approval was already used.")
    if replay != "clear":
        return _handoff_denied("handoff_ledger_invalid", "The approval handoff was rejected.")
    now_mono = _PUBLICATIONS.now()
    record = _PublicationRecord(
        authorization_id=proposal_id,
        owner=owner,
        repo_name=repo_name,
        visibility="public",
        description=description,
        branch=branch,
        fingerprint=fingerprint,
        files=ordered,
        readme_sha256=readme_sha,
        created_at=now_mono,
        expires_at=now_mono + max(0.0, expires_wall - wall),
        state="approval_accepted",
        capability=capability,
        contents=contents,
    )
    inserted = False
    with _HANDOFF_LOCK:
        current = _PUBLICATIONS.get(proposal_id)
        if current is None:
            _PUBLICATIONS.put(record)
            inserted = True
        elif (
            current.fingerprint != fingerprint
            or current.capability != capability
            or set(current.contents) != set(contents)
            or any(publication_content_bytes(current.contents.get(path)) != raw for path, raw in contents.items())
        ):
            return _handoff_denied("manifest_mismatch", "The approval handoff was rejected.")
    if capability == "publish":
        binding = accepted_publication_content_binding(proposal_id)
    else:
        binding = accepted_publication_create_binding(proposal_id)
    if not binding.get("ok"):
        if inserted:
            cancel_publication_handoff(proposal_id)
        denied = dict(binding)
        denied["grant_admitted"] = False
        denied["handoff_from_envelope"] = False
        return denied
    return {
        "ok": True,
        "inserted": inserted,
        "capability": capability,
        "grant_admitted": False,
        "handoff_from_envelope": True,
    }


def commit_publication_handoff(
    proposal_id: str,
    capability: str,
    key: bytes,
    approval_dir: Path,
) -> bool:
    """Record one accepted handoff in both replay ledgers, then the marker.

    The marker is not the authority. A later deletion of that file leaves the
    witness ledger in place. This function does not remove ledger evidence.
    """
    if not isinstance(key, bytes) or len(key) != 32:
        return False
    if not isinstance(proposal_id, str) or _PROPOSAL_RE.fullmatch(proposal_id) is None:
        return False
    if capability not in {"create", "publish"}:
        return False
    approval = Path(approval_dir)
    try:
        prepare_private_directory(approval)
        with _ReplayLock(_witness_dir(approval)):
            kind, replay_key, lines, ids = _load_replay_pair(approval)
            status = _publication_replay_status(approval, proposal_id)
            if status == "consumed" or proposal_id in ids:
                return False
            if status != "clear" or kind not in {"clear", "paired"}:
                return False
            if kind == "clear":
                replay_key = _create_replay_key(_witness_dir(approval))
                lines = []
            if replay_key is None:
                return False
            line = f"{proposal_id} {capability} {_replay_mac(replay_key, proposal_id, capability)}"
            body = ("v1\n" + "\n".join([*lines, line]) + "\n").encode("ascii")
            witness = _witness_dir(approval)
            _write_private_bytes(witness / _REPLAY_LEDGER_NAME, body)
            _write_private_bytes(approval / _REPLAY_LEDGER_NAME, body)
            path = _consumed_path(approval, proposal_id)
            mac = _consumed_mac(key, proposal_id, capability)
            fd = _open_nofollow(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.write(fd, (mac + "\n").encode("ascii"))
                _fsync_fd(fd)
            finally:
                os.close(fd)
            restrict_private_path(path)
            return True
    except (OSError, TimeoutError):
        return False


def cancel_publication_handoff(proposal_id: str) -> None:
    """Drop an installation the existing gate did not accept. Does not touch GitHub."""
    with _HANDOFF_LOCK:
        current = _PUBLICATIONS.get(proposal_id)
        if current is not None and current.state == "approval_accepted":
            _PUBLICATIONS._items.pop(proposal_id, None)
