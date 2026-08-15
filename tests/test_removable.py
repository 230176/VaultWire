"""Hardware-free tests for the Windows removable/local-volume collector."""

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import agent.windows_removable as windows_removable
from agent.client import AgentCommunicationError
from agent.events import SQLiteEventQueue, flush_event_queue
from agent.removable import (
    MountedVolume,
    RemovableVolumeCollector,
    VOLUME_ARRIVED_EVENT,
    VOLUME_REMOVED_EVENT,
    VolumeObservation,
)
from agent.windows_removable import WindowsWmiVolumeEventSource


class RecordingClient:
    def __init__(self, queue, *, fail=False):
        self.queue = queue
        self.fail = fail
        self.calls = []

    def submit_events(self, events):
        # The observation must already be committed before transport is entered.
        assert self.queue.pending_count() >= 1
        assert self.queue.oldest()[0].envelope.event_id == events[0].event_id
        self.calls.append(list(events))
        if self.fail:
            raise AgentCommunicationError("Server rejected endpoint authentication (HTTP 401).")
        return {"acknowledged_event_ids": [event.event_id for event in events]}


def test_arrival_maps_to_versioned_raw_event_after_queue_commit(tmp_path):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    client = RecordingClient(queue)
    observed_at = datetime(2026, 8, 14, 13, 20, tzinfo=UTC)
    collector = RemovableVolumeCollector(queue, client=client, clock=lambda: observed_at)

    result = collector.process(
        VolumeObservation("arrival", "E:", "removable_disk", "FIELD KIT", "exFAT")
    )

    assert result is not None
    assert result.envelope.event_type == VOLUME_ARRIVED_EVENT
    assert result.envelope.schema_version == 1
    assert result.envelope.occurred_at == observed_at.isoformat()
    assert client.calls[0][0].event_id == result.envelope.event_id
    assert result.delivery.acknowledged_count == 1
    assert queue.pending_count() == 0


def test_removal_maps_and_reuses_only_prior_approved_metadata(tmp_path):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    collector = RemovableVolumeCollector(queue)
    collector.process(
        VolumeObservation("arrival", "F:", "local_disk", "Portable SSD", "NTFS")
    )

    result = collector.process(VolumeObservation("removal", "f:"))

    assert result is not None
    assert result.envelope.event_type == VOLUME_REMOVED_EVENT
    assert result.envelope.payload == {
        "drive_name": "F:",
        "drive_type": "local_disk",
        "volume_label": "Portable SSD",
        "filesystem": "NTFS",
    }


def test_payload_is_sanitized_bounded_and_contains_only_approved_metadata(
    tmp_path, monkeypatch
):
    def forbid_file_read(*args, **kwargs):
        raise AssertionError("collector must never read files from a volume")

    monkeypatch.setattr(Path, "read_text", forbid_file_read)
    monkeypatch.setattr(Path, "read_bytes", forbid_file_read)
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    collector = RemovableVolumeCollector(queue)

    result = collector.process(
        VolumeObservation(
            "arrival",
            "E:\x00\n",
            "removable_disk\x00",
            "  PRIVATE\nLABEL  " + "x" * 200,
            "exFAT\t",
        )
    )

    payload = result.envelope.payload
    assert set(payload) == {"drive_name", "drive_type", "volume_label", "filesystem"}
    assert payload["drive_name"] == "E:"
    assert payload["drive_type"] == "removable_disk"
    assert payload["filesystem"] == "exFAT"
    assert len(payload["volume_label"]) == 128
    serialized = str(payload).casefold()
    assert all(
        forbidden not in serialized
        for forbidden in ("filename", "directory", "file_content", "copied", "hash", "process")
    )


def test_observation_time_is_normalized_to_utc_and_ignores_device_timestamps(tmp_path):
    timezone_offset = timezone(timedelta(hours=5, minutes=45))
    local_time = datetime(2026, 8, 14, 19, 5, 7, tzinfo=timezone_offset)
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    collector = RemovableVolumeCollector(queue, clock=lambda: local_time)

    result = collector.process(VolumeObservation("arrival", "G:"))

    occurred_at = datetime.fromisoformat(result.envelope.occurred_at)
    assert occurred_at == datetime(2026, 8, 14, 13, 20, 7, tzinfo=UTC)
    assert occurred_at.tzinfo is UTC
    assert timezone_offset is not UTC


def test_malformed_observations_are_ignored_without_queueing(tmp_path):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    collector = RemovableVolumeCollector(queue)

    assert collector.process(object()) is None
    assert collector.process(VolumeObservation("arrival", None)) is None
    unexpected = SimpleNamespace(action="format", drive_name="E:")
    assert collector.process(unexpected) is None
    assert queue.pending_count() == 0


def test_disabled_endpoint_delivery_failure_retains_event_and_replay_uses_same_id(tmp_path):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    disabled_client = RecordingClient(queue, fail=True)
    collector = RemovableVolumeCollector(queue, client=disabled_client)

    first = collector.process(VolumeObservation("arrival", "H:", "removable_disk"))

    pending = queue.oldest()[0]
    assert first.delivery.acknowledged_count == 0
    assert first.delivery.pending_count == 1
    assert pending.envelope.event_id == first.envelope.event_id
    assert pending.attempt_count == 1

    enabled_client = RecordingClient(queue)
    replay = flush_event_queue(queue, enabled_client)

    assert enabled_client.calls[0][0].event_id == first.envelope.event_id
    assert replay.acknowledged_count == 1
    assert queue.pending_count() == 0


class FakeWatcher:
    def __init__(self, events):
        self.events = iter(events)

    def NextEvent(self, timeout_ms):
        event = next(self.events)
        if isinstance(event, BaseException):
            raise event
        return event


class FakeWmiService:
    def __init__(self, events, disks=()):
        self.watcher = FakeWatcher(events)
        self.disks = list(disks)
        self.queries = []

    def ExecNotificationQuery(self, query):
        self.queries.append(query)
        return self.watcher

    def ExecQuery(self, query):
        self.queries.append(query)
        return self.disks


def test_windows_wmi_layer_is_fakeable_and_maps_arrival_and_removal():
    observed_at = datetime(2026, 8, 14, 13, 20, tzinfo=UTC)
    service = FakeWmiService(
        [
            SimpleNamespace(EventType=2, DriveName="E:"),
            SimpleNamespace(EventType=3, DriveName="E:"),
            KeyboardInterrupt(),
        ],
        [
            SimpleNamespace(
                DeviceID="E:", DriveType=2, VolumeName="TRANSFER", FileSystem="exFAT"
            )
        ],
    )
    source = WindowsWmiVolumeEventSource(
        service_factory=lambda: service, clock=lambda: observed_at
    )
    observations = source.observations()

    arrival = next(observations)
    removal = next(observations)

    assert arrival == VolumeObservation(
        "arrival", "E:", "removable_disk", "TRANSFER", "exFAT", observed_at
    )
    assert removal == VolumeObservation("removal", "E:", observed_at=observed_at)
    with pytest.raises(KeyboardInterrupt):
        next(observations)
    assert "Win32_VolumeChangeEvent" in service.queries[0]
    assert "Win32_LogicalDisk" in service.queries[1]


def test_windows_wmi_startup_discovery_maps_mounted_logical_disks_only():
    service = FakeWmiService(
        [],
        [
            SimpleNamespace(
                DeviceID="E:", DriveType=2, VolumeName="TRANSFER", FileSystem="exFAT"
            ),
            SimpleNamespace(
                DeviceID="C:", DriveType=3, VolumeName="WINDOWS", FileSystem="NTFS"
            ),
            SimpleNamespace(
                DeviceID=None, DriveType=2, VolumeName="INVALID", FileSystem="FAT32"
            ),
        ],
    )

    mounted = WindowsWmiVolumeEventSource(
        service_factory=lambda: service
    ).mounted_volumes()

    assert mounted == [
        MountedVolume("E:", "removable_disk", "TRANSFER", "exFAT"),
        MountedVolume("C:", "local_disk", "WINDOWS", "NTFS"),
    ]
    assert len(service.queries) == 1
    assert "Win32_LogicalDisk" in service.queries[0]
    assert "Win32_VolumeChangeEvent" not in service.queries[0]


def test_windows_wmi_layer_skips_unexpected_event_and_survives_metadata_failure():
    observed_at = datetime(2026, 8, 14, 13, 20, tzinfo=UTC)
    class MetadataFailingService(FakeWmiService):
        def ExecQuery(self, query):
            raise RuntimeError("WMI metadata race")

    service = MetadataFailingService(
        [
            SimpleNamespace(EventType="not-a-number", DriveName="E:"),
            SimpleNamespace(EventType=99, DriveName="E:"),
            SimpleNamespace(EventType=2, DriveName="J:"),
        ]
    )
    source = WindowsWmiVolumeEventSource(
        service_factory=lambda: service, clock=lambda: observed_at
    )

    assert next(source.observations()) == VolumeObservation(
        "arrival", "J:", observed_at=observed_at
    )


def test_ctrl_c_after_yield_releases_all_com_proxies_before_uninitialize(
    tmp_path, monkeypatch
):
    lifecycle = []

    class FakeComRuntime:
        def CoInitialize(self):
            lifecycle.append("initialize")

        def CoUninitialize(self):
            lifecycle.append("uninitialize")

    class ReleasingProxy:
        release_name = "proxy"

        def __del__(self):
            lifecycle.append(f"release_{self.release_name}")

    class ComEvent(ReleasingProxy):
        release_name = "event"
        EventType = 3
        DriveName = "E:"

    class ComWatcher(ReleasingProxy):
        release_name = "watcher"

        def NextEvent(self, timeout_ms):
            return ComEvent()

    class ComService(ReleasingProxy):
        release_name = "service"

        def ExecNotificationQuery(self, query):
            return ComWatcher()

    runtime = FakeComRuntime()
    monkeypatch.setattr(windows_removable.sys, "platform", "win32")
    monkeypatch.setattr(
        windows_removable,
        "_load_wmi_runtime",
        lambda: (runtime, lambda moniker: ComService()),
    )
    source = WindowsWmiVolumeEventSource()
    monkeypatch.setattr(source, "mounted_volumes", lambda: [])
    collector = RemovableVolumeCollector(SQLiteEventQueue(tmp_path / "events.sqlite3"))

    def interrupt_after_yield(observation):
        raise KeyboardInterrupt

    monkeypatch.setattr(collector, "process", interrupt_after_yield)

    with pytest.raises(KeyboardInterrupt):
        collector.run(source)

    assert lifecycle == [
        "initialize",
        "release_event",
        "release_watcher",
        "release_service",
        "uninitialize",
    ]


def test_ctrl_c_inside_next_event_clears_com_traceback_before_uninitialize(
    monkeypatch,
):
    lifecycle = []

    class FakeComRuntime:
        def CoInitialize(self):
            lifecycle.append("initialize")

        def CoUninitialize(self):
            lifecycle.append("uninitialize")

    class InterruptingWatcher:
        def NextEvent(self, timeout_ms):
            raise KeyboardInterrupt

        def __del__(self):
            lifecycle.append("release_watcher")

    class ComService:
        def ExecNotificationQuery(self, query):
            return InterruptingWatcher()

        def __del__(self):
            lifecycle.append("release_service")

    runtime = FakeComRuntime()
    monkeypatch.setattr(windows_removable.sys, "platform", "win32")
    monkeypatch.setattr(
        windows_removable,
        "_load_wmi_runtime",
        lambda: (runtime, lambda moniker: ComService()),
    )

    with pytest.raises(KeyboardInterrupt):
        next(WindowsWmiVolumeEventSource().observations())

    assert lifecycle == [
        "initialize",
        "release_watcher",
        "release_service",
        "uninitialize",
    ]


def test_ctrl_c_during_startup_discovery_releases_com_before_uninitialize(
    monkeypatch,
):
    lifecycle = []

    class FakeComRuntime:
        def CoInitialize(self):
            lifecycle.append("initialize")

        def CoUninitialize(self):
            lifecycle.append("uninitialize")

    class InterruptingService:
        def ExecQuery(self, query):
            raise KeyboardInterrupt

        def __del__(self):
            lifecycle.append("release_service")

    runtime = FakeComRuntime()
    monkeypatch.setattr(windows_removable.sys, "platform", "win32")
    monkeypatch.setattr(
        windows_removable,
        "_load_wmi_runtime",
        lambda: (runtime, lambda moniker: InterruptingService()),
    )

    with pytest.raises(KeyboardInterrupt):
        WindowsWmiVolumeEventSource().mounted_volumes()

    assert lifecycle == [
        "initialize",
        "release_service",
        "uninitialize",
    ]
