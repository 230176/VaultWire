"""Thin watchdog adapter for scoped Windows directory notifications."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from agent.filesystem import FilesystemObservation, validate_monitored_root


class WindowsFilesystemObservationError(RuntimeError):
    """The Windows filesystem notification source could not run safely."""


def _load_watchdog_runtime():
    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError as exc:
        raise WindowsFilesystemObservationError(
            "Filesystem monitoring requires the watchdog dependency."
        ) from exc
    return FileSystemEventHandler, Observer


def _event_handler(
    base_handler: type, callback: Callable[[FilesystemObservation], None]
):
    class Handler(base_handler):
        def on_created(self, event):
            callback(
                FilesystemObservation(
                    "created", event.src_path, is_directory=event.is_directory
                )
            )

        def on_modified(self, event):
            callback(
                FilesystemObservation(
                    "modified", event.src_path, is_directory=event.is_directory
                )
            )

        def on_deleted(self, event):
            callback(
                FilesystemObservation(
                    "deleted", event.src_path, is_directory=event.is_directory
                )
            )

        def on_moved(self, event):
            callback(
                FilesystemObservation(
                    "moved",
                    event.src_path,
                    destination_path=event.dest_path,
                    is_directory=event.is_directory,
                )
            )

    return Handler()


class WindowsWatchdogFilesystemObserver:
    """A start/stop watchdog observer reusable by dynamic volume lifecycles."""

    def __init__(self, monitored_root: Path | str) -> None:
        self.monitored_root = validate_monitored_root(monitored_root)
        self._observer = None

    def start(self, callback: Callable[[FilesystemObservation], None]) -> None:
        if self._observer is not None:
            raise WindowsFilesystemObservationError(
                "Filesystem observer has already been started."
            )
        base_handler, observer_type = _load_watchdog_runtime()
        observer = observer_type()
        try:
            observer.schedule(
                _event_handler(base_handler, callback),
                str(self.monitored_root),
                recursive=True,
            )
            observer.start()
        except Exception as exc:
            try:
                observer.stop()
                observer.join(timeout=5)
            except Exception:
                pass
            raise WindowsFilesystemObservationError(
                "Filesystem monitoring could not be started."
            ) from exc
        self._observer = observer

    def is_alive(self) -> bool:
        return self._observer is not None and self._observer.is_alive()

    def join(self, timeout: float) -> None:
        if self._observer is not None:
            self._observer.join(timeout=timeout)

    def stop(self) -> None:
        observer, self._observer = self._observer, None
        if observer is None:
            return
        try:
            observer.stop()
        except Exception:
            pass
        try:
            observer.join(timeout=5)
        except Exception:
            pass


class WindowsWatchdogFilesystemEventSource:
    """Observe exactly one explicitly selected root using watchdog recursively."""

    def __init__(self, monitored_root: Path | str) -> None:
        self.monitored_root = validate_monitored_root(monitored_root)

    def run(self, callback: Callable[[FilesystemObservation], None]) -> None:
        observer = WindowsWatchdogFilesystemObserver(self.monitored_root)
        try:
            observer.start(callback)
            while observer.is_alive():
                observer.join(timeout=0.5)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            raise WindowsFilesystemObservationError(
                "Filesystem monitoring stopped unexpectedly."
            ) from exc
        finally:
            observer.stop()
