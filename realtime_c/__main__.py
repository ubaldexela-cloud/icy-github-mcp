"""Experimental ICY voice path.

Microphone -> local Silero turn detector -> ASR MCP -> MCP harness ->
streaming TTS MCP -> speaker.

This process does not open the OpenAI Realtime speech session and it does
not use server VAD. realtime_b remains the default assistant.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from me3.config import load_config, scrub_github_tokens_from_process_env
from realtime_c.background_github_adapter import (
    BackgroundGithubAdapter,
    GithubClientRepositoryReader,
    RepositoryReadFailed,
    SessionCloseResult,
)
from realtime_c.github_approval import load_github_policy
from realtime_c.background_worker import BackgroundTaskWorker, ShutdownReport
from realtime_c.engine import VoiceEngine
from realtime_c.harness import Harness
from realtime_c.latency_log import LatencyLog
from realtime_c.combined_tools import CombinedToolSession
from realtime_c.github_mcp import GithubMcpClient
from realtime_c.icy_browser_mcp import IcyBrowserMcpClient
from realtime_c.mcp_client import McpClient
from realtime_c.mcp_tools import ToolsClient
from realtime_c.notify import (
    Dismiss,
    MusicDuck,
    Ringtone,
    command_duck_finished,
    command_ducks,
    music_is_playing,
    settles_stream,
    watch_alerts,
)
from realtime_c.session import CAPTURE_RATE, SAMPLE_RATE
from realtime_c.task_registry import TaskRegistry
from realtime_c.task_result_store import TaskResultStore
from realtime_c.speaker import FarEndMonitor, PlaybackFeeder, PwPlaySink
from realtime_c.state import PlaybackState
from realtime_c.tools_bridge import bind
from realtime_c.vad_turn import TurnVad

LOG_DIR = Path(__file__).resolve().parent / "logs"
CONVERSATION_ID = "icy-conversation"


class DisabledRepositoryReader:
    """Fail closed. This reader does not call GitHub or the network."""

    def read_repository(self, owner: str, repo: str, *, cancelled, wait_for_cancel) -> str:
        del owner, repo, cancelled, wait_for_cancel
        raise RepositoryReadFailed("repository read failed")


class BackgroundRuntime:
    """One in-process background stack. It is absent when startup did not succeed."""

    def __init__(
        self,
        registry: TaskRegistry,
        worker: BackgroundTaskWorker,
        results: TaskResultStore,
        adapter: BackgroundGithubAdapter,
        started: bool,
        error: str | None,
        cleanup_error: str | None = None,
    ) -> None:
        self.registry = registry
        self.worker = worker
        self.results = results
        self.adapter = adapter
        self.started = started
        self.error = error
        self.cleanup_error = cleanup_error
        self.client = None
        self.client_close_settled = False
        self.client_close_ok = False
        self.client_close_error: str | None = None
        self.child_attempted = False
        self.child_terminated = False
        self.child_error: str | None = None
        self.publisher = None


@dataclass(frozen=True)
class BackgroundShutdown:
    """Worker stop and session close, kept as separate facts.

    ``clean`` is true only when the worker has stopped and session close
    either succeeded or there was no session. ``worker_clean`` stays true
    when the worker stopped even if session close failed.
    """

    clean: bool
    thread_alive: bool
    current_task_id: str | None
    cancelled_waiting_ids: tuple[str, ...]
    session_closed: bool
    session_close_error: str | None
    worker_clean: bool
    session_close_attempted: bool = False
    child_process_termination_attempted: bool = False
    child_process_terminated: bool = False
    child_process_error: str | None = None


def start_background_execution(
    reader: object | None = None,
    *,
    worker_factory: Callable[[TaskRegistry], BackgroundTaskWorker] | None = None,
) -> BackgroundRuntime:
    """Start the worker explicitly. A failed start does not raise."""
    registry = TaskRegistry()
    results = TaskResultStore()
    chosen = reader if reader is not None else DisabledRepositoryReader()
    worker: BackgroundTaskWorker | None = None
    adapter: BackgroundGithubAdapter | None = None
    try:
        worker = BackgroundTaskWorker(registry) if worker_factory is None else worker_factory(registry)
        if not isinstance(worker, BackgroundTaskWorker):
            raise TypeError("worker_factory must return a BackgroundTaskWorker")
        adapter = BackgroundGithubAdapter(registry, worker, results, chosen)
        adapter.start()
    except Exception as exc:
        cleanup = None if adapter is None else adapter.startup_cleanup_error
        if worker is None or not isinstance(worker, BackgroundTaskWorker):
            worker = BackgroundTaskWorker(registry)
        if adapter is None:
            adapter = BackgroundGithubAdapter(registry, worker, results, chosen)
        return BackgroundRuntime(
            registry,
            worker,
            results,
            adapter,
            False,
            type(exc).__name__,
            cleanup,
        )
    return BackgroundRuntime(registry, worker, results, adapter, True, None)


def _overall_clean(report: ShutdownReport, session: SessionCloseResult) -> bool:
    worker_clean = report.clean and not report.thread_alive
    session_blocks = session.in_use or session.error is not None or (
        not session.skipped and not session.closed
    )
    return worker_clean and not session_blocks


def shutdown_background(runtime: BackgroundRuntime, timeout: float = 5.0) -> BackgroundShutdown | None:
    """Stop the worker, then close its session only if the worker stopped.

    A runtime that never started has no shutdown to claim. Repeating this
    call joins again and closes an already closed session without a second
    session. The worker report is copied onto the result and is not replaced
    by a session-close error.
    """
    if not runtime.started:
        return None
    report = runtime.adapter.shutdown(timeout)
    session = runtime.adapter.close_owned_session(report)
    if runtime.client is not None and not report.thread_alive:
        _settle_client_close(runtime)
    if runtime.client is not None:
        session_closed = runtime.client_close_ok
        session_error = runtime.client_close_error
        session_attempted = runtime.client_close_settled
        clean = _client_shutdown_clean(
            report.clean and not report.thread_alive,
            session_closed,
            session_error,
            runtime.child_attempted,
            runtime.child_terminated,
            runtime.child_error,
        )
    else:
        session_closed = session.closed
        session_error = session.error
        session_attempted = (not session.skipped) and (not session.in_use) and (
            session.closed or session.error is not None or session.already_closed
        )
        clean = _overall_clean(report, session)
    return BackgroundShutdown(
        clean=clean,
        thread_alive=report.thread_alive,
        current_task_id=report.current_task_id,
        cancelled_waiting_ids=report.cancelled_waiting_ids,
        session_closed=session_closed,
        session_close_error=session_error,
        worker_clean=report.clean and not report.thread_alive,
        session_close_attempted=session_attempted,
        child_process_termination_attempted=runtime.child_attempted,
        child_process_terminated=runtime.child_terminated,
        child_process_error=runtime.child_error,
    )


def close_github_client_after_background(
    client: object,
    outcome: BackgroundShutdown | None,
) -> tuple[bool, str | None]:
    """Close the GitHub client only after the background worker has stopped.

    ``outcome is None`` means the worker never started, so the client may
    close. A still-alive worker leaves the client open. A close exception
    is the exception class name and does not change ``outcome``.
    """
    if outcome is not None and outcome.thread_alive:
        return False, None
    closer = getattr(client, "close", None)
    if not callable(closer):
        return False, "close"
    try:
        closer()
    except Exception as exc:
        return False, type(exc).__name__
    return True, None


def _client_shutdown_clean(
    worker_clean: bool,
    session_closed: bool,
    session_error: str | None,
    child_attempted: bool,
    child_terminated: bool,
    child_error: str | None,
) -> bool:
    """Worker stop, session close, and an observed child exit are separate."""
    if not worker_clean or session_error is not None or not session_closed:
        return False
    if child_attempted and (not child_terminated or child_error is not None):
        return False
    return True


def _settle_client_close(runtime: BackgroundRuntime) -> None:
    """Close one client after its worker is gone. A settled result is not replaced."""
    if runtime.client is None or runtime.client_close_settled:
        return
    closer = getattr(runtime.client, "close", None)
    if not callable(closer):
        runtime.client_close_settled = True
        runtime.client_close_ok = False
        runtime.client_close_error = "close"
        return
    try:
        result = closer()
    except Exception as exc:
        runtime.client_close_settled = True
        runtime.client_close_ok = False
        runtime.client_close_error = type(exc).__name__
        runtime.child_attempted = False
        runtime.child_terminated = False
        runtime.child_error = None
        return
    runtime.client_close_settled = True
    runtime.client_close_ok = True
    runtime.client_close_error = None
    attempted = bool(getattr(result, "child_attempted", False))
    terminated = bool(getattr(result, "child_terminated", False))
    error = getattr(result, "child_error", None)
    if not isinstance(error, str) or not error:
        error = None
    if error or not attempted:
        terminated = False
    runtime.child_attempted = attempted
    runtime.child_terminated = terminated
    runtime.child_error = error


def _session_ready(client: object) -> bool:
    probe = getattr(client, "session_ready", None)
    if callable(probe):
        return bool(probe())
    return getattr(client, "available", None) is True


def _rollback_client(client: object | None) -> str | None:
    """Close a client that no worker can still be using. None means close succeeded."""
    if client is None:
        return None
    closer = getattr(client, "close", None)
    if not callable(closer):
        return "close"
    try:
        closer()
    except Exception as exc:
        return type(exc).__name__
    return None


@dataclass(frozen=True)
class ApplicationStartup:
    """One startup attempt. ``client`` is absent when GitHub was not enabled."""

    runtime: BackgroundRuntime
    client: object | None
    repository_read_ready: bool
    failing_stage: str | None
    error: str | None
    cleanup_error: str | None
    client_constructed: bool


def _idle_runtime(error: str, cleanup: str | None = None, client: object | None = None) -> BackgroundRuntime:
    registry = TaskRegistry()
    worker = BackgroundTaskWorker(registry)
    results = TaskResultStore()
    adapter = BackgroundGithubAdapter(registry, worker, results, DisabledRepositoryReader())
    runtime = BackgroundRuntime(registry, worker, results, adapter, False, error, cleanup)
    runtime.client = client
    if client is not None:
        runtime.client_close_settled = True
        runtime.client_close_ok = cleanup is None
        runtime.client_close_error = cleanup
    return runtime


def _startup_failure(
    stage: str,
    exc: BaseException,
    cleanup_error: str | None,
    client: object | None,
    *,
    constructed: bool,
) -> ApplicationStartup:
    runtime = _idle_runtime(type(exc).__name__, cleanup_error, client if constructed else None)
    return ApplicationStartup(
        runtime,
        client if constructed else None,
        False,
        stage,
        type(exc).__name__,
        cleanup_error,
        constructed,
    )


def open_application_background(
    root: Path,
    *,
    enabled: bool,
    client_factory: Callable[[], object] | None = None,
    worker_factory: Callable[[TaskRegistry], BackgroundTaskWorker] | None = None,
    reader_factory: Callable[[BackgroundTaskWorker], object] | None = None,
    adapter_factory: Callable[..., BackgroundGithubAdapter] | None = None,
) -> ApplicationStartup:
    """Build one background stack. A disabled policy never calls ``client_factory``.

    The enabled branch is for an injected factory. A disabled or invalid
    policy never calls it. Read-only policies start one client and one
    worker. An explicit policy may also allow writes and repository
    creation together. Mixed write flags, workflows, permissions, and
    destructive flags are rejected before the factory runs.
    """
    if not enabled:
        runtime = start_background_execution(
            DisabledRepositoryReader(),
            worker_factory=worker_factory,
        )
        return ApplicationStartup(
            runtime,
            None,
            False,
            None if runtime.started else "worker_startup",
            None if runtime.started else runtime.error,
            runtime.cleanup_error,
            False,
        )
    policy = load_github_policy(root)
    if (
        not policy.ok
        or policy.allow_workflows
        or policy.allow_permissions
        or policy.allow_destructive
    ):
        runtime = _idle_runtime("policy_rejected")
        return ApplicationStartup(runtime, None, False, "policy", "policy_rejected", None, False)
    publishing = bool(policy.allow_writes or policy.allow_repo_creation)
    if publishing and not (policy.allow_writes and policy.allow_repo_creation and policy.allow_reads):
        runtime = _idle_runtime("policy_rejected")
        return ApplicationStartup(runtime, None, False, "policy", "policy_rejected", None, False)
    if client_factory is None:
        runtime = _idle_runtime("client_factory_missing")
        return ApplicationStartup(
            runtime,
            None,
            False,
            "client_construction",
            "client_factory_missing",
            None,
            False,
        )
    try:
        client = client_factory()
    except Exception as exc:
        return _startup_failure("client_construction", exc, None, None, constructed=False)
    try:
        client.start(wait=True)
    except Exception as exc:
        return _startup_failure(
            "client_startup",
            exc,
            _rollback_client(client),
            client,
            constructed=True,
        )
    if not _session_ready(client):
        return _startup_failure(
            "session_initialization",
            RuntimeError("session_not_ready"),
            _rollback_client(client),
            client,
            constructed=True,
        )
    registry = TaskRegistry()
    results = TaskResultStore()
    try:
        worker = BackgroundTaskWorker(registry) if worker_factory is None else worker_factory(registry)
        if not isinstance(worker, BackgroundTaskWorker):
            raise TypeError("worker_factory must return a BackgroundTaskWorker")
    except Exception as exc:
        return _startup_failure(
            "worker_startup",
            exc,
            _rollback_client(client),
            client,
            constructed=True,
        )
    try:
        reader = (
            GithubClientRepositoryReader(client, worker)
            if reader_factory is None
            else reader_factory(worker)
        )
    except Exception as exc:
        return _startup_failure(
            "reader_construction",
            exc,
            _rollback_client(client),
            client,
            constructed=True,
        )
    try:
        if adapter_factory is None:
            adapter = BackgroundGithubAdapter(registry, worker, results, reader)
        else:
            adapter = adapter_factory(registry, worker, results, reader)
        if not isinstance(adapter, BackgroundGithubAdapter):
            raise TypeError("adapter_factory must return a BackgroundGithubAdapter")
    except Exception as exc:
        return _startup_failure(
            "adapter_construction",
            exc,
            _rollback_client(client),
            client,
            constructed=True,
        )
    try:
        adapter.start()
    except Exception as exc:
        alive = True
        try:
            alive = bool(worker.status().running)
        except Exception:
            alive = True
        session_cleanup = adapter.startup_cleanup_error
        client_cleanup = None if alive else _rollback_client(client)
        cleanup = session_cleanup
        if client_cleanup:
            cleanup = f"{session_cleanup}+{client_cleanup}" if session_cleanup else client_cleanup
        if alive:
            runtime = BackgroundRuntime(
                registry,
                worker,
                results,
                adapter,
                True,
                type(exc).__name__,
                cleanup,
            )
            runtime.client = client
            return ApplicationStartup(
                runtime,
                client,
                False,
                "worker_startup",
                type(exc).__name__,
                cleanup,
                True,
            )
        runtime = _idle_runtime(type(exc).__name__, cleanup, client)
        return ApplicationStartup(
            runtime,
            client,
            False,
            "worker_startup",
            type(exc).__name__,
            cleanup,
            True,
        )
    runtime = BackgroundRuntime(registry, worker, results, adapter, True, None)
    runtime.client = client
    from realtime_c.background_github_publisher import BackgroundGithubPublisher

    runtime.publisher = BackgroundGithubPublisher(
        registry,
        worker,
        results,
        client,
        policy_root=root,
    )
    return ApplicationStartup(runtime, client, True, None, None, None, True)


def format_asr_final_report(event: dict) -> str | None:
    """One human-readable line for a final ASR transcript; None for other events.

    Structured JSONL logging is unchanged; this is display-only. Text is truncated
    and newlines flattened so the terminal is not flooded.
    """
    if event.get("event") != "asr_final":
        return None
    text = str(event.get("text") or "").replace("\r", " ").replace("\n", " ").strip()
    if not text:
        text = "(empty)"
    elif len(text) > 240:
        text = text[:240] + "…"
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    return f"[asr_final] {stamp} | {text}"


def main(argv: list[str] | None = None) -> int:
    scrub_github_tokens_from_process_env()
    parser = argparse.ArgumentParser(description="Experimental realtime_c voice path")
    parser.add_argument("--check", action="store_true", help="Load local VAD and the tools MCP server, then exit")
    parser.add_argument("--fdbench-url", default=None, help="Direct-feed benchmark socket instead of the microphone")
    args = parser.parse_args(argv)
    config = load_config()
    if not config.llm_api_key and not args.check:
        print("OpenAI credential is not configured.", file=sys.stderr)
        return 2
    try:
        return asyncio.run(_run(config.llm_api_key, args.fdbench_url, check=args.check, model=config.llm_model))
    except KeyboardInterrupt:
        return 0


async def _run(key: str, fdbench_url: str | None = None, check: bool = False, model: str = "gpt-4o-mini") -> int:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / "events.jsonl"
    state = PlaybackState(SAMPLE_RATE)
    player, capture, link = audio_devices(fdbench_url)
    root = Path(__file__).resolve().parents[1]
    tools = ToolsClient(root)
    bind(tools)
    icy = IcyBrowserMcpClient(root, timeout=90)
    policy = load_github_policy(root)
    github = None
    github_startup: ApplicationStartup | None = None
    if policy.enabled:
        github_startup = open_application_background(
            root,
            enabled=True,
            client_factory=lambda: GithubMcpClient(root, timeout=45),
        )
        github = github_startup.client
    asr = McpClient(root, "realtime_c.mcp_asr_server", timeout=20)
    tts = McpClient(root, "realtime_c.mcp_tts_server", timeout=30)
    duck = MusicDuck(smooth=False)
    notes: list[dict] = []
    note_lock = threading.Lock()

    def write(event: dict) -> None:
        event = dict(event)
        event.setdefault("t", time.monotonic())
        with note_lock:
            notes.append(event)
        try:
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception:
            # Still attempt the human transcript line below when JSONL fails.
            pass
        # Human-readable finals → stdout (under Stage 7 nohup: logs/realtime_c.out).
        # Do not mirror other events; stderr keeps ASR MCP diagnostics only.
        report = format_asr_final_report(event)
        if report is not None:
            try:
                print(report, flush=True)
            except Exception:
                pass

    def command_duck() -> None:
        duck.hold("command")

    def command_unduck() -> None:
        duck.release("command")

    def on_tool(name: str) -> None:
        write({"event": "tool_call", "name": name})
        if settles_stream(name):
            settled = duck.settle_player()
            write({"event": "music_settle", "result": settled})
        if command_ducks(name):
            command_duck()

    marker = _bench_hook(link) if link is not None else (lambda *args, **kwargs: None)

    def stop_voice() -> None:
        player.reject_through(state.generation)
        player.cancel()
        if link is not None:
            link.clear()

    try:
        vad = TurnVad()
    except Exception as exc:
        write({"event": "vad_error", "message": str(exc)[:300]})
        print("Local Silero VAD did not load. realtime_c will not start.", file=sys.stderr)
        return 1
    tools.start()
    if not tools.available:
        write({"event": "mcp_tools_error", "message": str(tools.error)[:300]})
        tools.close()
        print("Tools MCP server did not start.", file=sys.stderr)
        return 1
    write({"event": "mcp_tools_ready", "tools": sorted(tools.schemas)})
    if check:
        tools.close()
        write({"event": "check_ok"})
        return 0
    # Icy is optional: voice keeps working if the Windows tunnel is down.
    icy.start()
    if icy.available:
        write({"event": "icy_browser_mcp_ready", "tools": sorted(icy.schemas)})
    else:
        write({
            "event": "icy_browser_mcp_unavailable",
            "message": str(icy.error)[:300] if icy.error else "not connected",
        })
    if not policy.enabled:
        write({"event": "github_mcp_disabled", "message": "disabled"})
    github_for_tools = None
    if (
        policy.enabled
        and github is not None
        and github_startup is not None
        and github_startup.repository_read_ready
        and getattr(github, "enabled", False)
    ):
        github_for_tools = github
    harness = Harness(
        tools,
        model=model,
        api_key=key,
        on_tool=on_tool,
        include_github_instructions=github_for_tools is not None,
    )
    harness.tools = CombinedToolSession(
        tools,
        icy if icy.available else None,
        github_for_tools,
        on_diag=write,
        project_root=root,
    )
    if policy.enabled and policy.allow_writes:
        harness.tools.attach_operations(True)
    asr.start()
    tts.start()
    if not asr.available or not tts.available:
        write({
            "event": "mcp_media_error",
            "asr": str(asr.error)[:200] if asr.error else "",
            "tts": str(tts.error)[:200] if tts.error else "",
        })
        asr.close()
        tts.close()
        if github_startup is not None and github_startup.runtime.started:
            shutdown_background(github_startup.runtime, timeout=2)
        elif github is not None and (
            github_startup is None or not github_startup.runtime.client_close_settled
        ):
            try:
                alive = github_startup is not None and github_startup.runtime.worker.status().running
            except Exception:
                alive = True
            if not alive:
                github.close()
        icy.close()
        tools.close()
        print("ASR or TTS MCP server did not start.", file=sys.stderr)
        return 1
    write({"event": "mcp_media_ready"})
    background: BackgroundRuntime | None = None
    ringtone = Ringtone()
    voice = os.environ.get("REALTIME_C_TTS_VOICE", "marin").strip() or "marin"
    latency = LatencyLog(
        LOG_DIR / "latency_trials.jsonl",
        LOG_DIR / "latency_session_summaries.jsonl",
        model=model,
        voice=voice,
    )

    engine = VoiceEngine(
        vad,
        asr,
        tts,
        harness,
        state,
        stop_voice,
        music_playing=music_is_playing,
        chime_playing=ringtone.playing,
        on_alert_release=lambda: duck.release("alert"),
        on_command_duck=command_duck,
        on_command_unduck=command_unduck,
        mark=marker,
        note=write,
        emit_audio_out=link is None,
        latency=latency,
    )

    def voice_quiet() -> None:
        engine.note_quiet()
        duck.release("voice")
        duck.release("alert")
        if command_duck_finished("playback_idle"):
            duck.release("command")

    feeder = PlaybackFeeder(
        state,
        player,
        SAMPLE_RATE,
        on_quiet=voice_quiet,
        on_playback=latency.playback,
    )
    # Preroll/start/gap diagnostics use the same note sink as other session events.
    # Gap threshold and preroll timing stay inside PlaybackFeeder unchanged.
    feeder.on_note = write
    # Always keep the pw-play stdin reference. Optionally add the PipeWire
    # Bluetooth loopback monitor, which is closer to post-volume sink output
    # but still before the radio/transducer. Never use that monitor as the mic.
    feeder.on_reference = engine.echo.note_playback
    far_end = FarEndMonitor(engine.echo.note_monitor, sample_rate=CAPTURE_RATE)
    if far_end.start():
        write({
            "event": "far_end_monitor",
            "target": far_end.target,
            "rate": CAPTURE_RATE,
            "ok": True,
        })
    else:
        write({
            "event": "far_end_monitor",
            "ok": False,
            "error": far_end.error or "unavailable",
        })
    feeder.start()
    dismiss = Dismiss()
    alert_stop = asyncio.Event()
    stopping = asyncio.Event()

    async def deliver(message: str) -> str:
        token = dismiss.current()
        kind = "alarm" if message.lower().startswith("alarm") else "timer"
        duck.hold("alert")
        write({"event": "alert_ringtone", "text": message[:80]})
        try:
            await asyncio.to_thread(ringtone.play_and_wait, kind, token, dismiss.current)
        except Exception as exc:  # noqa: BLE001
            duck.release("alert")
            write({"event": "alert_error", "message": str(exc)[:180]})
            return "retry"
        if dismiss.current() != token:
            duck.release("alert")
            write({"event": "alert_dismissed", "text": message[:80]})
            return "dismissed"
        engine.speak_exact(message)
        write({"event": "alert_spoken", "text": message[:80]})
        return "spoken"

    if capture is not None:
        device = os.environ.get("MIC_DEVICE", "plughw:2,0")
        capture.start()
        write({
            "event": "capture_start",
            "device": device,
            "rate": CAPTURE_RATE,
            "format": "S16_LE",
            "channels": 1,
            "ok": capture.proc is not None and capture.proc.poll() is None,
        })
    if link is not None:
        await link.open()
        write({"event": "fdbench_open", "url": link.uri})

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stopping.set)
        except NotImplementedError:
            signal.signal(sig, lambda *_args: stopping.set())

    watcher = asyncio.create_task(watch_alerts(alert_stop, lambda: not stopping.is_set(), deliver, write))
    try:
        if github_startup is not None and github_startup.runtime.started:
            background = github_startup.runtime
        else:
            background = start_background_execution(DisabledRepositoryReader())
        github_blocked = (
            github_startup is not None
            and github_startup.runtime.started
            and not github_startup.repository_read_ready
            and not github_startup.runtime.client_close_settled
        )
        if (
            background.started
            and isinstance(harness.tools, CombinedToolSession)
            and not github_blocked
        ):
            harness.tools.attach_background(background.adapter, background.registry, CONVERSATION_ID)
            publisher = getattr(background, "publisher", None)
            if publisher is not None:
                harness.tools.attach_publisher(publisher)
            write({"event": "background_worker_ready"})
        else:
            write({
                "event": "background_worker_unavailable",
                "message": None if background is None else (background.error or "worker_start_failed"),
            })
        if link is None:
            await _mic_loop(capture, engine, stopping, write)
        else:
            await _bench_loop(link, engine, stopping)
    finally:
        outcome = None
        if background is not None and background.started:
            outcome = shutdown_background(background)
            write({
                "event": "background_shutdown",
                "clean": False if outcome is None else outcome.clean,
                "worker_clean": False if outcome is None else outcome.worker_clean,
                "thread_alive": False if outcome is None else outcome.thread_alive,
                "current_task_id": None if outcome is None else outcome.current_task_id,
                "session_closed": False if outcome is None else outcome.session_closed,
                "session_close_error": None if outcome is None else outcome.session_close_error,
                "session_close_attempted": False if outcome is None else outcome.session_close_attempted,
                "child_process_termination_attempted": False if outcome is None else outcome.child_process_termination_attempted,
                "child_process_terminated": False if outcome is None else outcome.child_process_terminated,
                "child_process_error": None if outcome is None else outcome.child_process_error,
            })
        alert_stop.set()
        watcher.cancel()
        engine.close()
        feeder.close()
        far_end.close()
        if capture is not None:
            capture.stop()
        asr.close()
        tts.close()
        settled = (
            github_startup is not None and github_startup.runtime.client_close_settled
        )
        worker_using_client = False
        if github_startup is not None:
            try:
                worker_using_client = github_startup.runtime.worker.status().running
            except Exception:
                worker_using_client = True
        if github is not None and not settled and not worker_using_client:
            client_closed, client_error = close_github_client_after_background(
                github,
                outcome if background is not None and background.started else None,
            )
        elif settled:
            client_closed = github_startup.runtime.client_close_ok
            client_error = github_startup.runtime.client_close_error
        else:
            client_closed, client_error = False, None
        write({
            "event": "github_client_close",
            "closed": client_closed,
            "error": client_error,
        })
        icy.close()
        tools.close()
        bind(None)
        if link is not None:
            await link.close()
        write({"event": "stopped"})
        latency.close()
    return 0


async def _mic_loop(
    capture: "_Capture",
    engine: VoiceEngine,
    stopping: asyncio.Event,
    write: Callable[[dict], None] | None = None,
) -> None:
    ready = False
    while not stopping.is_set():
        pcm = await asyncio.to_thread(capture.read)
        if pcm is None:
            if write is not None:
                write({"event": "capture_read_empty"})
            # EOF / dead arecord previously spun empty forever (~300/min). Revive.
            revived = await asyncio.to_thread(capture.revive_if_needed)
            if revived is not None and write is not None:
                write({"event": "capture_arecord_revived", **revived})
            await asyncio.sleep(0.2)
            continue
        if not ready and write is not None:
            ready = True
            write({
                "event": "speech_path_ready",
                "capture": True,
                "vad": True,
                "asr": True,
                "tts": True,
                "first_frame_bytes": len(pcm),
            })
        engine.feed(pcm)


async def _bench_loop(link: object, engine: VoiceEngine, stopping: asyncio.Event) -> None:
    while not stopping.is_set():
        pcm = await link.audio.get()
        if pcm is None:
            break
        engine.feed(pcm)


def audio_devices(fdbench_url: str | None):
    """Hardware capture and playback, unless an fdbench URL selects the bridge."""
    if fdbench_url:
        from realtime_c.fdbench_bridge import FdbenchLink

        link = FdbenchLink(fdbench_url)
        return link.sink, None, link
    return PwPlaySink(SAMPLE_RATE), _Capture(), None


def _bench_hook(link: object):
    def hook(stage: str, **fields: object) -> None:
        if stage == "interrupted":
            link.clear()
        link.mark(stage, **fields)

    return hook


class _Capture:
    """USB/ALSA mic via arecord → stdout pipe (16 kHz mono S16_LE).

    Frame size stays 100 ms (CAPTURE_RATE * 2 // 10 bytes). stderr stays DEVNULL
    while running so a stalled stderr pipe cannot deadlock arecord. On EOF, the
    mic loop calls revive_if_needed() so a dead producer does not spin
    capture_read_empty forever.
    """

    _FRAME_BYTES = CAPTURE_RATE * 2 // 10  # 3200 bytes ≈ 100 ms
    _REVIVE_MIN_INTERVAL_S = 1.0

    def __init__(self) -> None:
        self.proc: subprocess.Popen[bytes] | None = None
        self._eof = False
        self._last_revive_at = 0.0
        self._command: list[str] | None = None

    def start(self) -> None:
        device = os.environ.get("MIC_DEVICE", "plughw:2,0")
        self._command = [
            "arecord",
            "-D",
            device,
            "-f",
            "S16_LE",
            "-r",
            str(CAPTURE_RATE),
            "-c",
            "1",
            "-t",
            "raw",
        ]
        self._eof = False
        self.proc = subprocess.Popen(
            self._command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            start_new_session=True,
        )

    def read(self) -> bytes | None:
        proc = self.proc
        if proc is None or proc.stdout is None:
            return None
        chunk = proc.stdout.read(self._FRAME_BYTES)
        if not chunk:
            self._eof = True
            return None
        if len(chunk) % 2:
            chunk = chunk[:-1]
        return chunk or None

    def revive_if_needed(self) -> dict[str, object] | None:
        """Restart arecord after EOF or process exit. Same device/format command.

        Returns a small diagnostic dict when a restart runs; None when the
        producer still looks healthy or a restart was rate-limited.
        """
        proc = self.proc
        alive = proc is not None and proc.poll() is None and not self._eof
        if alive:
            return None
        now = time.monotonic()
        if now - self._last_revive_at < self._REVIVE_MIN_INTERVAL_S:
            return None
        prior = None if proc is None else proc.poll()
        self.stop()
        self.start()
        self._last_revive_at = now
        return {
            "prior_returncode": prior,
            "device": os.environ.get("MIC_DEVICE", "plughw:2,0"),
            "rate": CAPTURE_RATE,
            "format": "S16_LE",
            "channels": 1,
        }

    def stop(self) -> None:
        proc = self.proc
        self.proc = None
        self._eof = False
        if proc is None or proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
