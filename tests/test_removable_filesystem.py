"""Task 14 removable-storage file metadata and watcher lifecycle tests."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from agent.client import AgentCommunicationError
from agent.events import SQLiteEventQueue, flush_event_queue
from agent.filesystem import FilesystemObservation
from agent.removable import MountedVolume, RemovableVolumeCollector, VolumeObservation
from agent.removable_filesystem import (
    REMOVABLE_FILE_CREATED_EVENT,
    REMOVABLE_FILE_DELETED_EVENT,
    REMOVABLE_FILE_MODIFIED_EVENT,
    REMOVABLE_FILE_MOVED_EVENT,
    RemovableFilesystemCollector,
)
from agent.windows_removable_filesystem import (
    WindowsRemovableFilesystemWatcherManager,
)
from agent.windows_filesystem import WindowsWatchdogFilesystemObserver
import agent.windows_filesystem as windows_filesystem


class RecordingClient:
    def __init__(self, queue, *, failure=False):
        self.queue = queue
        self.failure = failure
        self.calls = []

    def submit_events(self, events):
        pending = {item.envelope.event_id for item in self.queue.oldest()}
        assert all(event.event_id in pending for event in events)
        self.calls.append(list(events))
        if self.failure:
            raise AgentCommunicationError(
                "Server rejected endpoint authentication (HTTP 401)."
            )
        return {"acknowledged_event_ids": [event.event_id for event in events]}


@pytest.fixture
def removable_root(tmp_path):
    root = tmp_path / "Removable"
    (root / "work").mkdir(parents=True)
    return root


@pytest.mark.parametrize(
    ("action", "source_name", "destination_name", "event_type", "path_fields"),
    [
        (
            "created",
            "work/report.docx",
            None,
            REMOVABLE_FILE_CREATED_EVENT,
            {"relative_path": "work/report.docx"},
        ),
        (
            "modified",
            "work/report.docx",
            None,
            REMOVABLE_FILE_MODIFIED_EVENT,
            {"relative_path": "work/report.docx"},
        ),
        (
            "deleted",
            "work/old.txt",
            None,
            REMOVABLE_FILE_DELETED_EVENT,
            {"relative_path": "work/old.txt"},
        ),
        (
            "moved",
            "work/old.docx",
            "work/renamed.docx",
            REMOVABLE_FILE_MOVED_EVENT,
            {
                "old_relative_path": "work/old.docx",
                "new_relative_path": "work/renamed.docx",
            },
        ),
    ],
)
def test_removable_file_actions_map_to_raw_events(
    tmp_path,
    removable_root,
    action,
    source_name,
    destination_name,
    event_type,
    path_fields,
):
    source = removable_root / source_name
    destination = removable_root / destination_name if destination_name else None
    metadata_path = destination if destination is not None else source
    if action in {"created", "modified", "moved"}:
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_path.write_bytes(b"harmless")
    collector = RemovableFilesystemCollector(
        SQLiteEventQueue(tmp_path / "events.sqlite3"),
        removable_root,
        "E:",
        volume_label="FIELD KIT",
    )

    result = collector.process(
        FilesystemObservation(action, source, destination_path=destination)
    )

    assert result.envelope.event_type == event_type
    assert result.envelope.schema_version == 1
    assert result.envelope.payload == {
        "drive_name": "E:",
        "volume_label": "FIELD KIT",
        **path_fields,
        "extension": ".docx" if "docx" in str(metadata_path) else ".txt",
        **({"size_bytes": 8} if action != "deleted" else {}),
    }


def test_payload_is_allowlisted_relative_and_never_reads_contents(
    tmp_path, removable_root, monkeypatch
):
    document = removable_root / "work" / "private.txt"
    document.write_text("content must not be inspected", encoding="utf-8")

    def forbid_read(*args, **kwargs):
        raise AssertionError("removable collector must never read file contents")

    monkeypatch.setattr(Path, "open", forbid_read)
    monkeypatch.setattr(Path, "read_text", forbid_read)
    monkeypatch.setattr(Path, "read_bytes", forbid_read)
    result = RemovableFilesystemCollector(
        SQLiteEventQueue(tmp_path / "events.sqlite3"),
        removable_root,
        "E:",
        volume_label="USB",
    ).process(FilesystemObservation("created", document))

    assert set(result.envelope.payload) == {
        "drive_name",
        "volume_label",
        "relative_path",
        "extension",
        "size_bytes",
    }
    assert result.envelope.payload["relative_path"] == "work/private.txt"
    assert result.envelope.payload["size_bytes"] == len("content must not be inspected")
    serialized = str(result.envelope.payload)
    assert str(removable_root) not in serialized
    assert str(tmp_path) not in serialized
    assert "content must not be inspected" not in serialized
    assert all(
        forbidden not in serialized.casefold()
        for forbidden in (
            "source_path",
            "file_content",
            "clipboard",
            "keystroke",
            "screenshot",
            "process",
            "hash",
        )
    )


def test_paths_outside_or_not_absolute_are_rejected(tmp_path, removable_root):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    collector = RemovableFilesystemCollector(queue, removable_root, "E:")
    outside = tmp_path / "source" / "secret.docx"

    assert collector.process(FilesystemObservation("created", outside)) is None
    assert collector.process(FilesystemObservation("created", "work/relative.txt")) is None
    assert collector.process(
        FilesystemObservation(
            "moved", outside, removable_root / "work" / "destination.docx"
        )
    ) is None
    assert collector.process(
        FilesystemObservation(
            "moved", removable_root / "work" / "inside.docx", outside
        )
    ) is None
    assert queue.pending_count() == 0


def test_modifications_are_debounced_but_other_actions_remain_distinct(
    tmp_path, removable_root
):
    times = iter([10.0, 10.2, 10.8])
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    collector = RemovableFilesystemCollector(
        queue,
        removable_root,
        "E:",
        debounce_seconds=0.75,
        monotonic_clock=lambda: next(times),
    )
    document = removable_root / "work" / "report.txt"

    results = [
        collector.process(FilesystemObservation("modified", document)),
        collector.process(FilesystemObservation("modified", document)),
        collector.process(FilesystemObservation("modified", document)),
    ]
    collector.process(FilesystemObservation("created", document))
    collector.process(FilesystemObservation("deleted", document))
    collector.process(
        FilesystemObservation("moved", document, removable_root / "work" / "renamed.txt")
    )

    assert [result is not None for result in results] == [True, False, True]
    assert [item.envelope.event_type for item in queue.oldest()] == [
        REMOVABLE_FILE_MODIFIED_EVENT,
        REMOVABLE_FILE_MODIFIED_EVENT,
        REMOVABLE_FILE_CREATED_EVENT,
        REMOVABLE_FILE_DELETED_EVENT,
        REMOVABLE_FILE_MOVED_EVENT,
    ]


@pytest.mark.parametrize("failure", [False, True])
def test_delivery_modes_retain_or_replay_the_same_queued_id(
    tmp_path, removable_root, failure
):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    client = RecordingClient(queue, failure=True) if failure else None
    result = RemovableFilesystemCollector(
        queue, removable_root, "E:", client=client
    ).process(FilesystemObservation("created", removable_root / "offline.txt"))

    pending = queue.oldest()[0]
    assert pending.envelope.event_id == result.envelope.event_id
    assert pending.attempt_count == (1 if failure else 0)
    if failure:
        replay_client = RecordingClient(queue)
        replay = flush_event_queue(queue, replay_client)
        assert replay_client.calls[0][0].event_id == result.envelope.event_id
        assert replay.acknowledged_count == 1
        assert queue.pending_count() == 0


class FakeObserver:
    instances = []

    def __init__(self, root, *, fail_stop=False):
        self.root = root
        self.callback = None
        self.stop_count = 0
        self.fail_stop = fail_stop
        self.__class__.instances.append(self)

    def start(self, callback):
        self.callback = callback

    def stop(self):
        self.stop_count += 1
        if self.fail_stop:
            raise OSError("drive disappeared")


def test_volume_arrival_starts_only_eligible_watcher_and_removal_stops_it(
    tmp_path, removable_root
):
    FakeObserver.instances = []
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    manager = WindowsRemovableFilesystemWatcherManager(
        queue,
        observer_factory=FakeObserver,
        root_resolver=lambda _drive: removable_root,
    )
    collector = RemovableVolumeCollector(queue, filesystem_watchers=manager)

    collector.process(VolumeObservation("arrival", "C:", "local_disk"))
    collector.process(VolumeObservation("arrival", "E:", "removable_disk", "USB"))
    observer = FakeObserver.instances[0]
    assert queue.oldest()[0].envelope.event_type == "removable.volume_arrived"
    observer.callback(
        FilesystemObservation("created", removable_root / "work" / "new.txt")
    )
    collector.process(VolumeObservation("removal", "E:"))

    assert len(FakeObserver.instances) == 1
    assert observer.stop_count == 1
    assert [item.envelope.event_type for item in queue.oldest()] == [
        "removable.volume_arrived",
        "removable.volume_arrived",
        REMOVABLE_FILE_CREATED_EVENT,
        "removable.volume_removed",
    ]
    before = queue.pending_count()
    observer.callback(FilesystemObservation("created", removable_root / "late.txt"))
    assert queue.pending_count() == before


def test_rapid_path_disappearance_and_shutdown_cleanup_are_safe(
    tmp_path, removable_root
):
    observers = []

    def factory(root):
        observer = FakeObserver(root, fail_stop=True)
        observers.append(observer)
        return observer

    manager = WindowsRemovableFilesystemWatcherManager(
        SQLiteEventQueue(tmp_path / "events.sqlite3"),
        observer_factory=factory,
        root_resolver=lambda _drive: removable_root,
    )
    assert manager.start("E:", "USB") is True
    assert manager.stop("E:") is True
    assert observers[0].stop_count == 1
    assert manager.start("F:", "USB2") is True
    manager.close()
    assert observers[1].stop_count == 1


def test_start_does_not_scan_or_emit_preexisting_files(tmp_path, removable_root):
    (removable_root / "work" / "already-there.txt").write_text(
        "existing", encoding="utf-8"
    )
    FakeObserver.instances = []
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    manager = WindowsRemovableFilesystemWatcherManager(
        queue,
        observer_factory=FakeObserver,
        root_resolver=lambda _drive: removable_root,
    )

    collector = RemovableVolumeCollector(queue, filesystem_watchers=manager)

    assert collector.monitor_mounted_volume(
        MountedVolume("E:", "removable_disk", "USB", "exFAT")
    ) is True
    assert queue.pending_count() == 0
    assert len(FakeObserver.instances) == 1
    FakeObserver.instances[0].callback(
        FilesystemObservation("created", removable_root / "work" / "after-start.txt")
    )
    assert [item.envelope.event_type for item in queue.oldest()] == [
        REMOVABLE_FILE_CREATED_EVENT
    ]
    manager.close()


def test_startup_discovery_does_not_emit_false_volume_arrival_and_ignores_ineligible(
    tmp_path, removable_root
):
    FakeObserver.instances = []
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    manager = WindowsRemovableFilesystemWatcherManager(
        queue,
        observer_factory=FakeObserver,
        root_resolver=lambda _drive: removable_root,
    )
    collector = RemovableVolumeCollector(queue, filesystem_watchers=manager)

    assert collector.monitor_mounted_volume(
        MountedVolume("C:", "local_disk", "SYSTEM", "NTFS")
    ) is False
    assert collector.monitor_mounted_volume(
        MountedVolume("E:", "removable_disk", "USB", "exFAT")
    ) is True

    assert len(FakeObserver.instances) == 1
    assert queue.pending_count() == 0
    manager.close()


def test_later_arrival_reuses_startup_watcher_and_removal_stops_same_observer(
    tmp_path, removable_root
):
    FakeObserver.instances = []
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    manager = WindowsRemovableFilesystemWatcherManager(
        queue,
        observer_factory=FakeObserver,
        root_resolver=lambda _drive: removable_root,
    )
    collector = RemovableVolumeCollector(queue, filesystem_watchers=manager)

    collector.monitor_mounted_volume(
        MountedVolume("E:", "removable_disk", "USB", "exFAT")
    )
    startup_observer = FakeObserver.instances[0]
    collector.process(
        VolumeObservation("arrival", "e:", "removable_disk", "USB", "exFAT")
    )

    assert len(FakeObserver.instances) == 1
    assert startup_observer.stop_count == 0
    assert [item.envelope.event_type for item in queue.oldest()] == [
        "removable.volume_arrived"
    ]

    collector.process(VolumeObservation("removal", "E:"))

    assert startup_observer.stop_count == 1
    assert [item.envelope.event_type for item in queue.oldest()] == [
        "removable.volume_arrived",
        "removable.volume_removed",
    ]


def test_collector_run_closes_file_watchers_when_wmi_loop_is_interrupted(tmp_path):
    lifecycle = []

    class Watchers:
        def start(self, drive_name, volume_label=None):
            lifecycle.append(("start", drive_name))
            return True

        def stop(self, drive_name):
            lifecycle.append(("stop", drive_name))
            return True

        def close(self):
            lifecycle.append(("close", None))

    class Source:
        def mounted_volumes(self):
            lifecycle.append(("discover", None))
            return [MountedVolume("E:", "removable_disk")]

        def observations(self):
            try:
                raise KeyboardInterrupt
                yield
            finally:
                lifecycle.append(("wmi_close", None))

    collector = RemovableVolumeCollector(
        SQLiteEventQueue(tmp_path / "events.sqlite3"),
        filesystem_watchers=Watchers(),
    )

    with pytest.raises(KeyboardInterrupt):
        collector.run(Source())

    assert lifecycle == [
        ("discover", None),
        ("start", "E:"),
        ("wmi_close", None),
        ("close", None),
    ]


def test_reusable_watchdog_observer_maps_events_recursively_and_joins(
    tmp_path, monkeypatch
):
    lifecycle = []

    class BaseHandler:
        pass

    class RuntimeObserver:
        def schedule(self, handler, path, recursive):
            self.handler = handler
            lifecycle.append(("schedule", path, recursive))

        def start(self):
            lifecycle.append(("start",))

        def is_alive(self):
            return True

        def stop(self):
            lifecycle.append(("stop",))

        def join(self, timeout):
            lifecycle.append(("join", timeout))

    runtime = RuntimeObserver()
    monkeypatch.setattr(
        windows_filesystem,
        "_load_watchdog_runtime",
        lambda: (BaseHandler, lambda: runtime),
    )
    observed = []
    observer = WindowsWatchdogFilesystemObserver(tmp_path)

    observer.start(observed.append)
    runtime.handler.on_created(
        SimpleNamespace(src_path=str(tmp_path / "new.txt"), is_directory=False)
    )
    runtime.handler.on_modified(
        SimpleNamespace(src_path=str(tmp_path / "new.txt"), is_directory=False)
    )
    runtime.handler.on_deleted(
        SimpleNamespace(src_path=str(tmp_path / "new.txt"), is_directory=False)
    )
    runtime.handler.on_moved(
        SimpleNamespace(
            src_path=str(tmp_path / "new.txt"),
            dest_path=str(tmp_path / "renamed.txt"),
            is_directory=False,
        )
    )
    observer.stop()

    assert [item.action for item in observed] == [
        "created",
        "modified",
        "deleted",
        "moved",
    ]
    assert lifecycle == [
        ("schedule", str(tmp_path.resolve()), True),
        ("start",),
        ("stop",),
        ("join", 5),
    ]
