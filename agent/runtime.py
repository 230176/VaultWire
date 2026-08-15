"""Supervised, policy-driven long-running endpoint agent runtime."""

from __future__ import annotations

import ctypes
import hashlib
import ntpath
import signal
import sys
from dataclasses import dataclass
from pathlib import Path
from threading import Event, RLock, Thread, current_thread, main_thread
from time import monotonic
from typing import Callable, Protocol

from agent import __version__
from agent.client import (
    AgentAuthenticationRejected,
    EndpointClient,
    EndpointPolicy,
    JsonTransport,
)
from agent.config import AgentConfig, ConfigStore
from agent.credentials import CredentialProtector
from agent.events import DEFAULT_BATCH_SIZE, SQLiteEventQueue, flush_event_queue
from agent.filesystem import FilesystemCollector
from agent.health import RuntimeHealthSnapshot
from agent.inventory import WindowsInventory, collect_windows_inventory
from agent.policy_cache import PolicyCache
from agent.policy import validate_policy_values
from agent.removable import RemovableVolumeCollector
from agent.service import authenticated_client
from agent.windows_filesystem import WindowsWatchdogFilesystemObserver
from agent.windows_removable import WindowsWmiVolumeEventSource
from agent.windows_removable_filesystem import WindowsRemovableFilesystemWatcherManager


class RuntimeAlreadyRunningError(RuntimeError):
    """Another runtime owns the enrollment-scoped operating-system lock."""


class ManagedCollector(Protocol):
    def start(self) -> object: ...

    def stop(self) -> None: ...


@dataclass(frozen=True)
class RuntimeIntervals:
    queue_flush_seconds: float = 5.0
    heartbeat_seconds: float = 30.0
    policy_refresh_seconds: float = 30.0
    inventory_refresh_seconds: float = 3600.0
    collector_retry_seconds: float = 15.0
    policy_retry_initial_seconds: float = 5.0
    policy_retry_max_seconds: float = 60.0
    shutdown_join_seconds: float = 5.0

    def __post_init__(self) -> None:
        values = tuple(self.__dict__.values())
        if any(isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0 for value in values):
            raise ValueError("Runtime intervals must be positive numbers.")


class RuntimeInstanceLock:
    """Held Windows named mutex, with an advisory-file fallback for tests."""

    _ALREADY_EXISTS = 183

    def __init__(self, directory: Path, endpoint_id: str) -> None:
        enrollment = f"{Path(directory).resolve()}|{endpoint_id}".casefold().encode("utf-8")
        digest = hashlib.sha256(enrollment).hexdigest()
        self.name = f"Local\\NepShield.Agent.Runtime.{digest}"
        self.path = Path(directory) / "agent-runtime.lock"
        self._handle: object | None = None
        self._file = None

    def acquire(self) -> None:
        if self._handle is not None or self._file is not None:
            return
        if sys.platform == "win32":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
            kernel32.CreateMutexW.restype = ctypes.c_void_p
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.restype = ctypes.c_bool
            handle = kernel32.CreateMutexW(None, False, self.name)
            if not handle:
                raise RuntimeError("NepShield could not create the agent runtime lock.")
            if ctypes.get_last_error() == self._ALREADY_EXISTS:
                kernel32.CloseHandle(handle)
                raise RuntimeAlreadyRunningError("NepShield agent is already running.")
            self._handle = (kernel32, handle)
            return

        # The runtime target is Windows. This branch keeps lock behavior testable
        # on other developer platforms while retaining automatic process release.
        import fcntl

        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError):
            handle.close()
            raise RuntimeAlreadyRunningError("NepShield agent is already running.") from None
        self._file = handle

    def release(self) -> None:
        if self._handle is not None:
            kernel32, handle = self._handle
            self._handle = None
            kernel32.CloseHandle(handle)
        if self._file is not None:
            import fcntl

            handle, self._file = self._file, None
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()


class ProtectedFolderWatcher:
    """One queue-only watchdog observer for a validated policy folder."""

    def __init__(
        self,
        path: str,
        queue: SQLiteEventQueue,
        status: Callable[[str], None],
    ) -> None:
        self.path = path
        self.queue = queue
        self.status = status
        self._observer: WindowsWatchdogFilesystemObserver | None = None

    def start(self) -> None:
        collector = FilesystemCollector(self.queue, self.path, status=self.status)
        observer = WindowsWatchdogFilesystemObserver(collector.monitored_root)

        def receive(observation) -> None:
            try:
                collector.process(observation)
            except Exception:
                self.status("A protected-folder observation could not be queued.")

        observer.start(receive)
        self._observer = observer

    def is_alive(self) -> bool:
        return self._observer is not None and self._observer.is_alive()

    def stop(self) -> None:
        observer, self._observer = self._observer, None
        if observer is not None:
            observer.stop()


class RemovableMonitorWorker:
    """Own the WMI/COM loop and its removable-volume watchdog children."""

    def __init__(
        self,
        queue: SQLiteEventQueue,
        status: Callable[[str], None],
        *,
        join_timeout: float = 5.0,
        source_factory: Callable[..., WindowsWmiVolumeEventSource] = WindowsWmiVolumeEventSource,
    ) -> None:
        self.queue = queue
        self.status = status
        self.join_timeout = join_timeout
        self.source_factory = source_factory
        self._stop_event = Event()
        self._thread: Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = Thread(
            target=self._run,
            name="NepShield removable monitor",
            daemon=True,
        )
        self._thread.start()

    def _run(self) -> None:
        processing_lock = RLock()
        filesystem_watchers = WindowsRemovableFilesystemWatcherManager(
            self.queue,
            status=self.status,
            processing_lock=processing_lock,
        )
        collector = RemovableVolumeCollector(
            self.queue,
            status=self.status,
            filesystem_watchers=filesystem_watchers,
            processing_lock=processing_lock,
        )
        try:
            collector.run(self.source_factory(stop_event=self._stop_event))
        except Exception:
            self.status("Removable monitoring stopped unexpectedly; retry is scheduled.")

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def stop(self) -> None:
        self._stop_event.set()
        thread, self._thread = self._thread, None
        if thread is not None and thread is not current_thread():
            thread.join(timeout=self.join_timeout)


def _policy_path_key(path: str) -> str:
    return ntpath.normcase(ntpath.normpath(path.replace("/", "\\")))


class AgentRuntime:
    """Coordinate policy, collectors, inventory, heartbeat, and queue replay."""

    def __init__(
        self,
        config: AgentConfig,
        client: EndpointClient,
        queue: SQLiteEventQueue,
        policy_cache: PolicyCache,
        instance_lock: RuntimeInstanceLock,
        *,
        intervals: RuntimeIntervals | None = None,
        status: Callable[[str], None] = print,
        monotonic_clock: Callable[[], float] = monotonic,
        stop_event: Event | None = None,
        inventory_collector: Callable[[], WindowsInventory] = collect_windows_inventory,
        protected_watcher_factory: Callable[[str, SQLiteEventQueue, Callable[[str], None]], ManagedCollector] = ProtectedFolderWatcher,
        removable_worker_factory: Callable[[SQLiteEventQueue, Callable[[str], None]], ManagedCollector] | None = None,
        client_reloader: Callable[[], EndpointClient] | None = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
    ) -> None:
        self.config = config
        self.client = client
        self.queue = queue
        self.policy_cache = policy_cache
        self.instance_lock = instance_lock
        self.intervals = intervals or RuntimeIntervals()
        self.status = status
        self.monotonic_clock = monotonic_clock
        self.stop_event = stop_event or Event()
        self.inventory_collector = inventory_collector
        self.protected_watcher_factory = protected_watcher_factory
        self.removable_worker_factory = removable_worker_factory or (
            lambda queue, status: RemovableMonitorWorker(
                queue,
                status,
                join_timeout=self.intervals.shutdown_join_seconds,
            )
        )
        self.client_reloader = client_reloader
        self.batch_size = batch_size
        self.policy: EndpointPolicy | None = None
        self.authenticated: bool | None = None
        self._watchers: dict[str, tuple[str, ManagedCollector]] = {}
        self._removable: ManagedCollector | None = None
        self._started = False
        self._offline_reported = False
        self._auth_rejected_reported = False
        self._monitoring_disabled_reported = False
        self._last_reported_collector_state: tuple[int, bool] | None = None
        self._last_reported_queue_state: tuple[int, int, int, str] | None = None
        self._policy_retry_delay = self.intervals.policy_retry_initial_seconds
        self._next_policy = 0.0
        self._next_heartbeat = 0.0
        self._next_inventory = 0.0
        self._next_flush = 0.0
        self._next_reconcile = 0.0

    @classmethod
    def from_store(
        cls,
        store: ConfigStore,
        protector: CredentialProtector,
        transport: JsonTransport | None = None,
        **kwargs,
    ) -> "AgentRuntime":
        def load_client() -> EndpointClient:
            return authenticated_client(store, protector, transport)

        client = load_client()
        queue = SQLiteEventQueue.in_directory(store.directory)
        return cls(
            client.config,
            client,
            queue,
            PolicyCache(store.directory),
            RuntimeInstanceLock(store.directory, client.config.endpoint_id),
            client_reloader=load_client,
            **kwargs,
        )

    def start(self) -> None:
        if self._started:
            return
        self.instance_lock.acquire()
        self._started = True
        self.status("NepShield agent runtime started.")
        cached = self.policy_cache.load(self.config.endpoint_id)
        if cached is None and self.policy_cache.path.exists():
            self.status("Invalid or incompatible local policy cache was ignored.")
        self.policy = cached
        now = self.monotonic_clock()
        policy_available = self._refresh_policy(now)
        if not policy_available and self.authenticated is not False and cached is not None:
            self._reconcile_collectors()
        if self.authenticated is True:
            self._submit_inventory(now)
        if self.authenticated is True:
            self._send_heartbeat(now)
        if self.authenticated is True:
            self._flush_queue(now)
        self._next_reconcile = now + self.intervals.collector_retry_seconds

    def run(self) -> None:
        previous_handlers: dict[int, object] = {}
        try:
            self.start()
            if current_thread() is main_thread():
                for signum in (signal.SIGINT, signal.SIGTERM):
                    try:
                        previous_handlers[signum] = signal.getsignal(signum)
                        signal.signal(signum, lambda _signum, _frame: self.stop_event.set())
                    except (OSError, ValueError):
                        pass
            while not self.stop_event.is_set():
                self.tick()
                delay = max(0.01, min(1.0, self._next_deadline() - self.monotonic_clock()))
                self.stop_event.wait(delay)
        except KeyboardInterrupt:
            self.stop_event.set()
        finally:
            for signum, handler in previous_handlers.items():
                try:
                    signal.signal(signum, handler)
                except (OSError, ValueError):
                    pass
            self.shutdown()

    def tick(self) -> None:
        now = self.monotonic_clock()
        if now >= self._next_policy:
            recovered = self._refresh_policy(now)
            if recovered and self.authenticated is True:
                self._next_heartbeat = min(self._next_heartbeat, now)
                self._next_inventory = min(self._next_inventory, now)
                self._next_flush = min(self._next_flush, now)
        if now >= self._next_reconcile:
            self._reconcile_collectors()
            self._next_reconcile = now + self.intervals.collector_retry_seconds
        if self.authenticated is not False and now >= self._next_heartbeat:
            self._send_heartbeat(now)
        if self.authenticated is not False and now >= self._next_inventory:
            self._submit_inventory(now)
        if self.authenticated is not False and now >= self._next_flush:
            self._flush_queue(now)

    def _refresh_policy(self, now: float) -> bool:
        was_authenticated = self.authenticated
        previous = self.policy
        if self.authenticated is False and self.client_reloader is not None:
            try:
                replacement_client = self.client_reloader()
            except Exception:
                replacement_client = None
            if (
                replacement_client is not None
                and replacement_client.config == self.config
            ):
                # The enrollment-scoped lock, queue, cache, and collectors stay
                # owned by this process; only the in-memory bearer client changes.
                self.client = replacement_client
        try:
            received = self.client.fetch_policy()
            validated = validate_policy_values(
                received.revision,
                received.monitoring_enabled,
                received.removable_storage_monitoring_enabled,
                received.protected_folders,
            )
            policy = EndpointPolicy(
                validated.revision,
                validated.monitoring_enabled,
                validated.removable_storage_monitoring_enabled,
                validated.protected_folders,
            )
        except AgentAuthenticationRejected:
            self._reject_authentication()
            self._next_policy = now + self.intervals.policy_refresh_seconds
            return False
        except Exception:
            self._report_temporary_unavailability()
            self._next_policy = now + self._policy_retry_delay
            self._policy_retry_delay = min(
                self._policy_retry_delay * 2,
                self.intervals.policy_retry_max_seconds,
            )
            return False

        self.authenticated = True
        self._policy_retry_delay = self.intervals.policy_retry_initial_seconds
        self._next_policy = now + self.intervals.policy_refresh_seconds
        if self._offline_reported or was_authenticated is False:
            self.status("NepShield connectivity and authentication restored.")
        self._offline_reported = False
        self._auth_rejected_reported = False
        if previous is not None and policy.revision < previous.revision:
            self.status("Server policy revision is lower than the cached revision; server policy applied.")
        self.policy = policy
        try:
            self.policy_cache.save(self.config.endpoint_id, policy)
        except Exception:
            self.status("The valid server policy could not be cached locally.")
        if previous != policy:
            self.status(f"NepShield policy revision {policy.revision} applied.")
        self._reconcile_collectors()
        return was_authenticated is not True

    def _send_heartbeat(self, now: float) -> None:
        self._next_heartbeat = now + self.intervals.heartbeat_seconds
        try:
            self.client.send_heartbeat(
                __version__, self.runtime_health_snapshot().as_payload()
            )
            self._mark_authenticated_operation_success()
        except AgentAuthenticationRejected:
            self._reject_authentication()
        except Exception:
            self._report_temporary_unavailability()

    def runtime_health_snapshot(self) -> RuntimeHealthSnapshot:
        """Build one report from the runtime's existing policy, collectors, and outbox."""
        policy = self.policy
        monitoring_enabled = policy is not None and policy.monitoring_enabled
        active_watchers = (
            sum(
                1
                for _, watcher in self._watchers.values()
                if self._collector_is_active(watcher)
            )
            if monitoring_enabled
            else 0
        )
        unavailable_folders = (
            max(0, len(policy.protected_folders) - active_watchers)
            if monitoring_enabled and policy is not None
            else 0
        )
        removable_active = bool(
            monitoring_enabled
            and policy is not None
            and policy.removable_storage_monitoring_enabled
            and self._collector_is_active(self._removable)
        )
        return RuntimeHealthSnapshot(
            queue_pending_count=self.queue.pending_count(),
            applied_policy_revision=policy.revision if policy is not None else 0,
            protected_watchers_active_count=active_watchers,
            protected_folders_unavailable_count=unavailable_folders,
            removable_monitoring_active=removable_active,
        )

    @staticmethod
    def _collector_is_active(collector: ManagedCollector | None) -> bool:
        if collector is None:
            return False
        is_alive = getattr(collector, "is_alive", None)
        if not callable(is_alive):
            return True
        try:
            return bool(is_alive())
        except Exception:
            return False

    def _submit_inventory(self, now: float) -> None:
        self._next_inventory = now + self.intervals.inventory_refresh_seconds
        try:
            self.client.submit_inventory(self.inventory_collector())
            self._mark_authenticated_operation_success()
        except AgentAuthenticationRejected:
            self._reject_authentication()
        except Exception:
            self._report_temporary_unavailability()

    def _flush_queue(self, now: float) -> None:
        self._next_flush = now + self.intervals.queue_flush_seconds
        try:
            result = flush_event_queue(self.queue, self.client, batch_size=self.batch_size)
        except Exception:
            self._report_temporary_unavailability()
            return
        self._report_queue_result(result)
        if result.authentication_rejected:
            self._reject_authentication()
        elif result.error:
            self._report_temporary_unavailability()
        elif result.acknowledged_count:
            self._mark_authenticated_operation_success()
            self.status(
                f"NepShield queued events delivered: {result.acknowledged_count}; pending: {result.pending_count}."
            )

    def _report_queue_result(self, result) -> None:
        state_label = (
            "authentication_rejected"
            if result.authentication_rejected
            else "deferred"
            if result.error
            else "ok"
        )
        state = (
            result.submitted_count,
            result.acknowledged_count,
            result.pending_count,
            state_label,
        )
        if state == self._last_reported_queue_state:
            return
        self._last_reported_queue_state = state
        self.status(
            "NepShield queue replay: "
            f"submitted={state[0]}; acknowledged={state[1]}; "
            f"pending={state[2]}; state={state[3]}."
        )

    def _mark_authenticated_operation_success(self) -> None:
        if self.authenticated is not False:
            self.authenticated = True
        if self._offline_reported:
            self.status("NepShield connectivity restored.")
            self._offline_reported = False

    def _report_temporary_unavailability(self) -> None:
        if not self._offline_reported:
            suffix = " using cached policy." if self.policy is not None else "; no monitoring policy is available."
            self.status("NepShield server temporarily unavailable" + suffix)
            self._offline_reported = True

    def _reject_authentication(self) -> None:
        self.authenticated = False
        if not self._auth_rejected_reported:
            self.status("NepShield authentication rejected; collectors suspended.")
            self._auth_rejected_reported = True
        self._stop_all_collectors()

    def _reconcile_collectors(self) -> None:
        policy = self.policy
        if self.authenticated is False or policy is None:
            self._stop_all_collectors()
            self._report_collector_state()
            return
        if not policy.monitoring_enabled:
            self._stop_all_collectors()
            if not self._monitoring_disabled_reported:
                self.status("NepShield monitoring disabled by policy.")
                self._monitoring_disabled_reported = True
            self._report_collector_state()
            return
        self._monitoring_disabled_reported = False

        desired = {_policy_path_key(path): path for path in policy.protected_folders}
        for key in list(self._watchers):
            _, watcher = self._watchers[key]
            alive = getattr(watcher, "is_alive", None)
            if key not in desired or (callable(alive) and not alive()):
                self._stop_protected_watcher(key)
        for key, path in desired.items():
            if key not in self._watchers:
                self._start_protected_watcher(key, path)

        if policy.removable_storage_monitoring_enabled:
            alive = getattr(self._removable, "is_alive", None)
            if self._removable is not None and callable(alive) and not alive():
                self._stop_removable()
            if self._removable is None:
                self._start_removable()
        else:
            self._stop_removable()
        self._report_collector_state()

    def _report_collector_state(self) -> None:
        state = (
            sum(
                1
                for _, watcher in self._watchers.values()
                if self._collector_is_active(watcher)
            ),
            self._collector_is_active(self._removable),
        )
        if state == self._last_reported_collector_state:
            return
        self._last_reported_collector_state = state
        self.status(
            "NepShield collector state: "
            f"protected={state[0]}; removable={1 if state[1] else 0}."
        )

    def _start_protected_watcher(self, key: str, path: str) -> None:
        watcher: ManagedCollector | None = None
        try:
            watcher = self.protected_watcher_factory(path, self.queue, self.status)
            result = watcher.start()
            if result is False:
                raise RuntimeError("collector start rejected")
        except Exception:
            try:
                if watcher is not None:
                    watcher.stop()
            except Exception:
                pass
            self.status("A configured protected folder is unavailable; retry is scheduled.")
            return
        self._watchers[key] = (path, watcher)
        self.status("NepShield protected-folder watcher started.")

    def _stop_protected_watcher(self, key: str) -> None:
        item = self._watchers.pop(key, None)
        if item is None:
            return
        try:
            item[1].stop()
        except Exception:
            pass
        self.status("NepShield protected-folder watcher stopped.")

    def _start_removable(self) -> None:
        worker: ManagedCollector | None = None
        try:
            worker = self.removable_worker_factory(self.queue, self.status)
            result = worker.start()
            if result is False:
                raise RuntimeError("collector start rejected")
        except Exception:
            try:
                if worker is not None:
                    worker.stop()
            except Exception:
                pass
            self.status("NepShield removable monitoring could not start; retry is scheduled.")
            return
        self._removable = worker
        self.status("NepShield removable monitoring started.")

    def _stop_removable(self) -> None:
        worker, self._removable = self._removable, None
        if worker is None:
            return
        try:
            worker.stop()
        except Exception:
            pass
        self.status("NepShield removable monitoring stopped.")

    def _stop_all_collectors(self) -> None:
        for key in list(self._watchers):
            self._stop_protected_watcher(key)
        self._stop_removable()

    def _next_deadline(self) -> float:
        deadlines = [self._next_policy, self._next_reconcile]
        if self.authenticated is not False:
            deadlines.extend((self._next_heartbeat, self._next_inventory, self._next_flush))
        return min(deadlines)

    def shutdown(self) -> None:
        if not self._started:
            return
        self.stop_event.set()
        self._stop_all_collectors()
        self.instance_lock.release()
        self._started = False
        self.status("NepShield agent runtime shutdown complete.")
