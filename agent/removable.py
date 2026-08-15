"""Queue-first removable/local volume event collection orchestration."""

from __future__ import annotations

import unicodedata
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, ContextManager, Iterable, Literal, Mapping, Protocol

from agent.events import (
    DEFAULT_BATCH_SIZE,
    EventBatchClient,
    EventEnvelope,
    FlushResult,
    SQLiteEventQueue,
    flush_event_queue,
    utc_now,
)

VOLUME_ARRIVED_EVENT = "removable.volume_arrived"
VOLUME_REMOVED_EVENT = "removable.volume_removed"

_MAX_DRIVE_NAME_LENGTH = 64
_MAX_VOLUME_LABEL_LENGTH = 128
_MAX_FILESYSTEM_LENGTH = 32
_APPROVED_PAYLOAD_FIELDS = {
    "drive_name",
    "drive_type",
    "volume_label",
    "filesystem",
}


@dataclass(frozen=True)
class VolumeObservation:
    """Small platform-neutral observation emitted by a Windows event source."""

    action: Literal["arrival", "removal"]
    drive_name: object
    drive_type: object | None = None
    volume_label: object | None = None
    filesystem: object | None = None
    observed_at: datetime | None = None


@dataclass(frozen=True)
class MountedVolume:
    """Read-only startup metadata for a volume that is already mounted."""

    drive_name: object
    drive_type: object | None = None
    volume_label: object | None = None
    filesystem: object | None = None


class VolumeEventSource(Protocol):
    def observations(self) -> Iterable[VolumeObservation]: ...


class RemovableFilesystemWatchers(Protocol):
    def start(self, drive_name: str, volume_label: str | None = None) -> bool: ...

    def stop(self, drive_name: str) -> bool: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class ProcessedVolumeEvent:
    envelope: EventEnvelope
    delivery: FlushResult | None


def _safe_text(value: object, maximum: int) -> str | None:
    """Remove control/format characters, collapse whitespace, and bound WMI text."""
    if not isinstance(value, str):
        return None
    printable = "".join(
        " " if unicodedata.category(character).startswith("C") else character
        for character in value
    )
    normalized = " ".join(printable.split()).strip()
    return normalized[:maximum] or None


class RemovableVolumeCollector:
    """Convert volume observations to Task 10 events through the durable outbox."""

    def __init__(
        self,
        queue: SQLiteEventQueue,
        *,
        client: EventBatchClient | None = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
        clock: Callable[[], datetime] = utc_now,
        status: Callable[[str], None] | None = None,
        filesystem_watchers: RemovableFilesystemWatchers | None = None,
        processing_lock: ContextManager[object] | None = None,
    ) -> None:
        self.queue = queue
        self.client = client
        self.batch_size = batch_size
        self.clock = clock
        self.status = status or (lambda _message: None)
        self.filesystem_watchers = filesystem_watchers
        self.processing_lock = processing_lock
        self._known_volumes: dict[str, dict[str, str]] = {}

    def monitor_mounted_volume(self, volume: object) -> bool:
        """Seed one eligible startup watcher without creating a raw event."""
        if not isinstance(volume, MountedVolume):
            return False
        drive_name = _safe_text(volume.drive_name, _MAX_DRIVE_NAME_LENGTH)
        if drive_name is None:
            return False
        payload = self._volume_payload(volume, drive_name)
        if payload.get("drive_type") != "removable_disk":
            return False
        self._known_volumes[drive_name.casefold()] = dict(payload)
        lock = self.processing_lock or nullcontext()
        with lock:
            return self._start_filesystem_watcher(
                drive_name,
                payload.get("volume_label"),
            )

    def process(self, observation: object) -> ProcessedVolumeEvent | None:
        """Validate one observation, commit it, then optionally attempt one flush."""
        if not isinstance(observation, VolumeObservation):
            return None
        event_type = {
            "arrival": VOLUME_ARRIVED_EVENT,
            "removal": VOLUME_REMOVED_EVENT,
        }.get(observation.action)
        drive_name = _safe_text(observation.drive_name, _MAX_DRIVE_NAME_LENGTH)
        if event_type is None or drive_name is None:
            return None

        cache_key = drive_name.casefold()
        if observation.action == "arrival":
            payload = self._arrival_payload(observation, drive_name)
        else:
            payload = dict(self._known_volumes.get(cache_key, {"drive_name": drive_name}))

        if (
            observation.action == "removal"
            and payload.get("drive_type") == "removable_disk"
        ):
            self._stop_filesystem_watcher(drive_name)

        # This commit is deliberately before any client call. The delivery path can
        # only see the new event after it is durable in the existing SQLite outbox.
        lock = self.processing_lock or nullcontext()
        with lock:
            envelope = self.queue.enqueue(
                event_type,
                payload,
                occurred_at=observation.observed_at or self.clock(),
            )
            if observation.action == "arrival":
                self._known_volumes[cache_key] = dict(payload)
            else:
                self._known_volumes.pop(cache_key, None)
            self.status(
                "Removable volume arrival detected; event queued."
                if observation.action == "arrival"
                else "Removable volume removal detected; event queued."
            )

            if (
                observation.action == "arrival"
                and payload.get("drive_type") == "removable_disk"
            ):
                # Start only after the volume event is durable, but before a
                # potentially slow delivery attempt can leave activity unobserved.
                self._start_filesystem_watcher(
                    drive_name,
                    payload.get("volume_label"),
                )

            delivery = None
            if self.client is not None:
                delivery = flush_event_queue(
                    self.queue,
                    self.client,
                    batch_size=self.batch_size,
                )
                if delivery.error:
                    self.status("Delivery deferred/offline; queued events remain pending.")
        return ProcessedVolumeEvent(envelope, delivery)

    def run(self, source: VolumeEventSource) -> None:
        observations = None
        try:
            mounted_volumes = getattr(source, "mounted_volumes", None)
            if callable(mounted_volumes):
                for volume in mounted_volumes():
                    self.monitor_mounted_volume(volume)
            observations = iter(source.observations())
            for observation in observations:
                self.process(observation)
        finally:
            # A for-loop does not promise to close a generator when processing is
            # interrupted after yield. Windows sources keep COM proxies in that
            # suspended frame, so deterministically run their cleanup before the
            # interrupt is handled by the CLI.
            try:
                close = getattr(observations, "close", None)
                if close is not None:
                    close()
            finally:
                if self.filesystem_watchers is not None:
                    try:
                        self.filesystem_watchers.close()
                    except Exception:
                        self.status("Removable-storage file observer cleanup was incomplete.")

    def _start_filesystem_watcher(
        self, drive_name: str, volume_label: str | None
    ) -> bool:
        if self.filesystem_watchers is None:
            return False
        try:
            return self.filesystem_watchers.start(drive_name, volume_label)
        except Exception:
            self.status(
                f"Removable-storage file monitoring could not start for {drive_name}."
            )
            return False

    def _stop_filesystem_watcher(self, drive_name: str) -> None:
        if self.filesystem_watchers is None:
            return
        try:
            self.filesystem_watchers.stop(drive_name)
        except Exception:
            self.status(
                f"Removable-storage file monitoring cleanup failed for {drive_name}."
            )

    @staticmethod
    def _arrival_payload(
        observation: VolumeObservation, drive_name: str
    ) -> dict[str, str]:
        return RemovableVolumeCollector._volume_payload(observation, drive_name)

    @staticmethod
    def _volume_payload(
        observation: VolumeObservation | MountedVolume, drive_name: str
    ) -> dict[str, str]:
        candidates: Mapping[str, tuple[object | None, int]] = {
            "drive_type": (observation.drive_type, 32),
            "volume_label": (observation.volume_label, _MAX_VOLUME_LABEL_LENGTH),
            "filesystem": (observation.filesystem, _MAX_FILESYSTEM_LENGTH),
        }
        payload = {"drive_name": drive_name}
        for field, (value, maximum) in candidates.items():
            sanitized = _safe_text(value, maximum)
            if sanitized is not None:
                payload[field] = sanitized
        # Keep the privacy boundary visible even if this method is later extended.
        return {key: value for key, value in payload.items() if key in _APPROVED_PAYLOAD_FIELDS}
