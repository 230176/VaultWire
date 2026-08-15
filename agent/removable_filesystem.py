"""Metadata-only filesystem events scoped to mounted removable volumes."""

from __future__ import annotations

import os
import unicodedata
from collections import OrderedDict
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from time import monotonic
from typing import Callable, ContextManager

from agent.events import (
    DEFAULT_BATCH_SIZE,
    EventBatchClient,
    EventEnvelope,
    FlushResult,
    SQLiteEventQueue,
    flush_event_queue,
    utc_now,
)
from agent.filesystem import (
    DEFAULT_DEBOUNCE_CAPACITY,
    DEFAULT_DEBOUNCE_SECONDS,
    MAX_EXTENSION_LENGTH,
    MAX_RELATIVE_PATH_LENGTH,
    FilesystemConfigurationError,
    FilesystemObservation,
    validate_monitored_root,
)

REMOVABLE_FILE_CREATED_EVENT = "removable.file_created"
REMOVABLE_FILE_MODIFIED_EVENT = "removable.file_modified"
REMOVABLE_FILE_DELETED_EVENT = "removable.file_deleted"
REMOVABLE_FILE_MOVED_EVENT = "removable.file_moved"

MAX_DRIVE_NAME_LENGTH = 64
MAX_VOLUME_LABEL_LENGTH = 128
MAX_SIZE_BYTES = (1 << 63) - 1
REMOVABLE_FILE_PAYLOAD_FIELDS = {
    "drive_name",
    "volume_label",
    "relative_path",
    "old_relative_path",
    "new_relative_path",
    "extension",
    "size_bytes",
}


class RemovableFilesystemConfigurationError(FilesystemConfigurationError):
    """A removable filesystem observer cannot be scoped safely."""


@dataclass(frozen=True)
class ProcessedRemovableFilesystemEvent:
    """Queue and optional delivery result for one accepted observation."""

    envelope: EventEnvelope
    delivery: FlushResult | None


def _safe_text(value: object, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    printable = "".join(
        " " if unicodedata.category(character).startswith("C") else character
        for character in value
    )
    normalized = " ".join(printable.split()).strip()
    return normalized[:maximum] or None


class RemovableFilesystemCollector:
    """Map one mounted removable root's notifications into the shared outbox."""

    def __init__(
        self,
        queue: SQLiteEventQueue,
        monitored_root: Path | str,
        drive_name: str,
        *,
        volume_label: str | None = None,
        client: EventBatchClient | None = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
        debounce_seconds: float = DEFAULT_DEBOUNCE_SECONDS,
        debounce_capacity: int = DEFAULT_DEBOUNCE_CAPACITY,
        clock: Callable[[], datetime] = utc_now,
        monotonic_clock: Callable[[], float] = monotonic,
        status: Callable[[str], None] | None = None,
        processing_lock: ContextManager[object] | None = None,
    ) -> None:
        if debounce_seconds < 0 or debounce_capacity < 1:
            raise RemovableFilesystemConfigurationError(
                "Removable file debounce settings are invalid."
            )
        safe_drive = _safe_text(drive_name, MAX_DRIVE_NAME_LENGTH)
        if safe_drive is None:
            raise RemovableFilesystemConfigurationError("Drive name is invalid.")
        self.queue = queue
        self.monitored_root = validate_monitored_root(monitored_root)
        self.drive_name = safe_drive
        self.volume_label = _safe_text(volume_label, MAX_VOLUME_LABEL_LENGTH)
        self.client = client
        self.batch_size = batch_size
        self.debounce_seconds = float(debounce_seconds)
        self.debounce_capacity = debounce_capacity
        self.clock = clock
        self.monotonic_clock = monotonic_clock
        self.status = status or (lambda _message: None)
        self.processing_lock = processing_lock
        self._recent_modifications: OrderedDict[str, float] = OrderedDict()

    def process(
        self, observation: object
    ) -> ProcessedRemovableFilesystemEvent | None:
        if not isinstance(observation, FilesystemObservation) or observation.is_directory:
            return None
        event_type = {
            "created": REMOVABLE_FILE_CREATED_EVENT,
            "modified": REMOVABLE_FILE_MODIFIED_EVENT,
            "deleted": REMOVABLE_FILE_DELETED_EVENT,
            "moved": REMOVABLE_FILE_MOVED_EVENT,
        }.get(observation.action)
        if event_type is None:
            return None

        payload: dict[str, object] = {"drive_name": self.drive_name}
        if self.volume_label is not None:
            payload["volume_label"] = self.volume_label

        size_path: object | None = None
        if observation.action == "moved":
            old_relative = self._relative_path(observation.source_path)
            new_relative = self._relative_path(observation.destination_path)
            if old_relative is None or new_relative is None:
                return None
            payload.update(
                {
                    "old_relative_path": old_relative,
                    "new_relative_path": new_relative,
                }
            )
            extension = self._extension(new_relative)
            size_path = observation.destination_path
            self._forget_modification(old_relative)
            self._forget_modification(new_relative)
        else:
            relative_path = self._relative_path(observation.source_path)
            if relative_path is None:
                return None
            payload["relative_path"] = relative_path
            extension = self._extension(relative_path)
            if observation.action == "modified":
                if self._is_duplicate_modification(relative_path):
                    return None
            else:
                self._forget_modification(relative_path)
            if observation.action in {"created", "modified"}:
                size_path = observation.source_path

        if extension is not None:
            payload["extension"] = extension
        size_bytes = self._observed_size(size_path)
        if size_bytes is not None:
            payload["size_bytes"] = size_bytes
        payload = {
            key: value
            for key, value in payload.items()
            if key in REMOVABLE_FILE_PAYLOAD_FIELDS
        }

        lock = self.processing_lock or nullcontext()
        with lock:
            # The accepted observation is durable before any delivery call.
            envelope = self.queue.enqueue(
                event_type,
                payload,
                occurred_at=observation.observed_at or self.clock(),
            )
            self.status("Removable-storage file activity detected; event queued.")
            delivery = None
            if self.client is not None:
                delivery = flush_event_queue(
                    self.queue, self.client, batch_size=self.batch_size
                )
                if delivery.error:
                    self.status("Delivery deferred/offline; queued events remain pending.")
        return ProcessedRemovableFilesystemEvent(envelope, delivery)

    def _relative_path(self, value: object) -> str | None:
        if not isinstance(value, (str, os.PathLike)):
            return None
        try:
            raw = os.fspath(value)
            if not isinstance(raw, str) or not raw or "\x00" in raw:
                return None
            candidate = Path(raw)
            if not candidate.is_absolute():
                return None
            relative = candidate.resolve(strict=False).relative_to(self.monitored_root)
        except (OSError, RuntimeError, TypeError, ValueError):
            return None
        if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            return None
        rendered = relative.as_posix()
        if (
            len(rendered) > MAX_RELATIVE_PATH_LENGTH
            or rendered.startswith("/")
            or any(unicodedata.category(character).startswith("C") for character in rendered)
        ):
            return None
        return rendered

    @staticmethod
    def _extension(relative_path: str) -> str | None:
        extension = Path(relative_path).suffix.casefold()
        if not extension or len(extension) > MAX_EXTENSION_LENGTH:
            return None
        if any(unicodedata.category(character).startswith("C") for character in extension):
            return None
        return extension

    @staticmethod
    def _observed_size(value: object | None) -> int | None:
        if not isinstance(value, (str, os.PathLike)):
            return None
        try:
            size = os.stat(value, follow_symlinks=False).st_size
        except (OSError, TypeError, ValueError):
            return None
        if isinstance(size, int) and not isinstance(size, bool) and 0 <= size <= MAX_SIZE_BYTES:
            return size
        return None

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
