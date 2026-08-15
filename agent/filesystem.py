"""Queue-first, privacy-bounded filesystem metadata collection."""

from __future__ import annotations

import os
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from time import monotonic
from typing import Callable, Literal, Protocol

from agent.events import (
    DEFAULT_BATCH_SIZE,
    EventBatchClient,
    EventEnvelope,
    FlushResult,
    SQLiteEventQueue,
    flush_event_queue,
    utc_now,
)

FILE_CREATED_EVENT = "filesystem.file_created"
FILE_MODIFIED_EVENT = "filesystem.file_modified"
FILE_DELETED_EVENT = "filesystem.file_deleted"
FILE_MOVED_EVENT = "filesystem.file_moved"
FILE_MOVED_OUT_EVENT = "filesystem.file_moved_out"
FILE_MOVED_IN_EVENT = "filesystem.file_moved_in"
OUTSIDE_PROTECTED_ROOT = "outside_protected_root"

DEFAULT_DEBOUNCE_SECONDS = 0.75
DEFAULT_DEBOUNCE_CAPACITY = 1024
MAX_RELATIVE_PATH_LENGTH = 1024
MAX_ROOT_LABEL_LENGTH = 64
MAX_EXTENSION_LENGTH = 32


class FilesystemConfigurationError(ValueError):
    """The explicitly selected protected root is not safe to monitor."""


@dataclass(frozen=True)
class FilesystemObservation:
    """Platform-neutral metadata emitted by a filesystem event source."""

    action: Literal["created", "modified", "deleted", "moved"]
    source_path: object
    destination_path: object | None = None
    is_directory: bool = False
    observed_at: datetime | None = None


class FilesystemEventSource(Protocol):
    def run(self, callback: Callable[[FilesystemObservation], None]) -> None: ...


@dataclass(frozen=True)
class ProcessedFilesystemEvent:
    envelope: EventEnvelope
    delivery: FlushResult | None


def validate_monitored_root(path: Path | str) -> Path:
    """Resolve one explicit existing directory without enumerating its contents."""
    try:
        root = Path(path).resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise FilesystemConfigurationError(
            "Monitored path must be an existing accessible directory."
        ) from exc
    if not root.is_dir():
        raise FilesystemConfigurationError("Monitored path must be a directory.")
    return root


def _safe_root_label(value: str) -> str:
    printable = "".join(
        " " if unicodedata.category(character).startswith("C") else character
        for character in value
    )
    normalized = " ".join(printable.split()).strip()
    if not normalized or normalized in {".", ".."} or "/" in normalized or "\\" in normalized:
        return "protected-folder"
    return normalized[:MAX_ROOT_LABEL_LENGTH]


class FilesystemCollector:
    """Convert scoped file observations into the existing durable event outbox."""

    def __init__(
        self,
        queue: SQLiteEventQueue,
        monitored_root: Path | str,
        *,
        root_label: str | None = None,
        client: EventBatchClient | None = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
        debounce_seconds: float = DEFAULT_DEBOUNCE_SECONDS,
        debounce_capacity: int = DEFAULT_DEBOUNCE_CAPACITY,
        clock: Callable[[], datetime] = utc_now,
        monotonic_clock: Callable[[], float] = monotonic,
        status: Callable[[str], None] | None = None,
    ) -> None:
        if debounce_seconds < 0:
            raise FilesystemConfigurationError("Debounce interval cannot be negative.")
        if debounce_capacity < 1:
            raise FilesystemConfigurationError("Debounce capacity must be positive.")
        self.queue = queue
        self.monitored_root = validate_monitored_root(monitored_root)
        self.root_label = _safe_root_label(root_label or self.monitored_root.name)
        self.client = client
        self.batch_size = batch_size
        self.debounce_seconds = float(debounce_seconds)
        self.debounce_capacity = debounce_capacity
        self.clock = clock
        self.monotonic_clock = monotonic_clock
        self.status = status or (lambda _message: None)
        self._recent_modifications: OrderedDict[str, float] = OrderedDict()

    def process(self, observation: object) -> ProcessedFilesystemEvent | None:
        """Validate, enqueue, then optionally deliver one bounded existing batch."""
        if not isinstance(observation, FilesystemObservation) or observation.is_directory:
            return None
        event_type = {
            "created": FILE_CREATED_EVENT,
            "modified": FILE_MODIFIED_EVENT,
            "deleted": FILE_DELETED_EVENT,
            "moved": FILE_MOVED_EVENT,
        }.get(observation.action)
        if event_type is None:
            return None

        if observation.action == "moved":
            source_scope, source_relative = self._classify_path(observation.source_path)
            destination_scope, destination_relative = self._classify_path(
                observation.destination_path
            )
            if "invalid" in {source_scope, destination_scope}:
                return None
            if source_scope == destination_scope == "outside":
                return None
            if source_scope == destination_scope == "inside":
                event_type = FILE_MOVED_EVENT
                payload = {
                    "monitored_root": self.root_label,
                    "old_relative_path": source_relative,
                    "new_relative_path": destination_relative,
                }
                extension = self._extension(destination_relative)
                self._forget_modification(source_relative)
                self._forget_modification(destination_relative)
            elif source_scope == "inside":
                event_type = FILE_MOVED_OUT_EVENT
                payload = {
                    "monitored_root": self.root_label,
                    "relative_path": source_relative,
                    "destination_scope": OUTSIDE_PROTECTED_ROOT,
                }
                extension = self._extension(source_relative)
                self._forget_modification(source_relative)
            else:
                event_type = FILE_MOVED_IN_EVENT
                payload = {
                    "monitored_root": self.root_label,
                    "relative_path": destination_relative,
                    "source_scope": OUTSIDE_PROTECTED_ROOT,
                }
                extension = self._extension(destination_relative)
                self._forget_modification(destination_relative)
        else:
            source_relative = self._relative_path(observation.source_path)
            if source_relative is None:
                return None
            payload = {
                "monitored_root": self.root_label,
                "relative_path": source_relative,
            }
            extension = self._extension(source_relative)
            if observation.action == "modified":
                if self._is_duplicate_modification(source_relative):
                    return None
            else:
                self._forget_modification(source_relative)

        if extension is not None:
            payload["extension"] = extension

        # The durable commit happens before the optional client can be invoked.
        envelope = self.queue.enqueue(
            event_type,
            payload,
            occurred_at=observation.observed_at or self.clock(),
        )
        self.status("Filesystem change detected; event queued.")

        delivery = None
        if self.client is not None:
            delivery = flush_event_queue(self.queue, self.client, batch_size=self.batch_size)
            if delivery.error:
                self.status("Delivery deferred/offline; queued events remain pending.")
        return ProcessedFilesystemEvent(envelope, delivery)

    def run(self, source: FilesystemEventSource) -> None:
        source.run(self.process)

    def _relative_path(self, value: object) -> str | None:
        scope, relative_path = self._classify_path(value)
        return relative_path if scope == "inside" else None

    def _classify_path(self, value: object) -> tuple[str, str | None]:
        """Distinguish a valid external path from invalid path input without exposing it."""
        if not isinstance(value, (str, os.PathLike)):
            return "invalid", None
        try:
            raw = os.fspath(value)
            if not isinstance(raw, str) or not raw or "\x00" in raw:
                return "invalid", None
            candidate = Path(raw)
            if not candidate.is_absolute():
                return "invalid", None
            resolved = candidate.resolve(strict=False)
        except (OSError, RuntimeError, TypeError, ValueError):
            return "invalid", None
        try:
            relative = resolved.relative_to(self.monitored_root)
        except ValueError:
            return "outside", None
        if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            return "invalid", None
        rendered = relative.as_posix()
        if (
            len(rendered) > MAX_RELATIVE_PATH_LENGTH
            or rendered.startswith("/")
            or any(unicodedata.category(character).startswith("C") for character in rendered)
        ):
            return "invalid", None
        return "inside", rendered

    @staticmethod
    def _extension(relative_path: str) -> str | None:
        extension = Path(relative_path).suffix.casefold()
        if not extension or len(extension) > MAX_EXTENSION_LENGTH:
            return None
        if any(unicodedata.category(character).startswith("C") for character in extension):
            return None
        return extension

    def _is_duplicate_modification(self, relative_path: str) -> bool:
        now = float(self.monotonic_clock())
        key = relative_path.casefold()
        previous = self._recent_modifications.get(key)
        if previous is not None and now - previous < self.debounce_seconds:
            return True
        self._recent_modifications[key] = now
        self._recent_modifications.move_to_end(key)
        while len(self._recent_modifications) > self.debounce_capacity:
            self._recent_modifications.popitem(last=False)
        return False

    def _forget_modification(self, relative_path: str) -> None:
        self._recent_modifications.pop(relative_path.casefold(), None)
