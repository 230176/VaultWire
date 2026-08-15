"""Lifecycle management for watchdog observers on eligible removable volumes."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Callable, ContextManager, Protocol

from agent.events import DEFAULT_BATCH_SIZE, EventBatchClient, SQLiteEventQueue
from agent.filesystem import FilesystemObservation
from agent.removable_filesystem import RemovableFilesystemCollector
from agent.windows_filesystem import WindowsWatchdogFilesystemObserver


class StoppableFilesystemObserver(Protocol):
    def start(self, callback: Callable[[FilesystemObservation], None]) -> None: ...

    def stop(self) -> None: ...


@dataclass
class _ActiveWatcher:
    observer: StoppableFilesystemObserver
    active: Event


def windows_volume_root(drive_name: str) -> Path:
    """Convert the bounded WMI form (for example ``E:``) to a volume root."""
    if not isinstance(drive_name, str) or re.fullmatch(r"[A-Za-z]:\\?", drive_name) is None:
        raise ValueError("Windows removable drive name is invalid.")
    return Path(f"{drive_name[:2]}\\")


class WindowsRemovableFilesystemWatcherManager:
    """Start one recursive observer per eligible mounted removable volume."""

    def __init__(
        self,
        queue: SQLiteEventQueue,
        *,
        client: EventBatchClient | None = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
        status: Callable[[str], None] | None = None,
        observer_factory: Callable[[Path], StoppableFilesystemObserver] = (
            WindowsWatchdogFilesystemObserver
        ),
        root_resolver: Callable[[str], Path] = windows_volume_root,
        processing_lock: ContextManager[object] | None = None,
    ) -> None:
        self.queue = queue
        self.client = client
        self.batch_size = batch_size
        self.status = status or (lambda _message: None)
        self.observer_factory = observer_factory
        self.root_resolver = root_resolver
        self.processing_lock = processing_lock
        self._watchers: dict[str, _ActiveWatcher] = {}

    def start(self, drive_name: str, volume_label: str | None = None) -> bool:
        key = drive_name.casefold()
        if key in self._watchers:
            self.status(
                f"Removable-storage file monitoring is already active for {drive_name}."
            )
            return False
        active = Event()
        observer: StoppableFilesystemObserver | None = None
        try:
            root = self.root_resolver(drive_name)
            collector = RemovableFilesystemCollector(
                self.queue,
                root,
                drive_name,
                volume_label=volume_label,
                client=self.client,
                batch_size=self.batch_size,
                status=self.status,
                processing_lock=self.processing_lock,
            )
            observer = self.observer_factory(root)
            handle = _ActiveWatcher(observer, active)
            self._watchers[key] = handle
            active.set()

            def receive(observation: FilesystemObservation) -> None:
                current = self._watchers.get(key)
                if current is handle and active.is_set():
                    try:
                        collector.process(observation)
                    except Exception:
                        self.status(
                            "A removable-storage file observation could not be queued."
                        )

            observer.start(receive)
        except Exception:
            active.clear()
            self._watchers.pop(key, None)
            try:
                if observer is not None:
                    observer.stop()
            except Exception:
                pass
            self.status(
                f"Removable-storage file monitoring could not start for {drive_name}."
            )
            return False
        self.status(f"Removable-storage file monitoring started for {drive_name}.")
        return True

    def stop(self, drive_name: str) -> bool:
        handle = self._watchers.pop(drive_name.casefold(), None)
        if handle is None:
            return False
        handle.active.clear()
        try:
            handle.observer.stop()
        except Exception:
            pass
        self.status(f"Removable-storage file monitoring stopped for {drive_name}.")
        return True

    def close(self) -> None:
        for key in list(self._watchers):
            handle = self._watchers.pop(key)
            handle.active.clear()
            try:
                handle.observer.stop()
            except Exception:
                pass
        self.status("Removable-storage file observers stopped.")
