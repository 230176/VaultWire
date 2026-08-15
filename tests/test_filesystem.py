"""Hardware-free tests for scoped filesystem metadata collection."""

from pathlib import Path

import pytest

from agent.client import AgentCommunicationError
from agent.events import SQLiteEventQueue, flush_event_queue
from agent.filesystem import (
    FILE_CREATED_EVENT,
    FILE_DELETED_EVENT,
    FILE_MODIFIED_EVENT,
    FILE_MOVED_IN_EVENT,
    FILE_MOVED_EVENT,
    FILE_MOVED_OUT_EVENT,
    FilesystemCollector,
    FilesystemConfigurationError,
    FilesystemObservation,
    validate_monitored_root,
)


class RecordingClient:
    def __init__(self, queue, *, failure=None):
        self.queue = queue
        self.failure = failure
        self.calls = []

    def submit_events(self, events):
        # Delivery cannot observe the envelope until its SQLite transaction committed.
        pending_ids = [item.envelope.event_id for item in self.queue.oldest()]
        assert events[0].event_id in pending_ids
        self.calls.append(list(events))
        if self.failure:
            raise AgentCommunicationError(self.failure)
        return {"acknowledged_event_ids": [event.event_id for event in events]}


@pytest.fixture
def protected_root(tmp_path):
    root = tmp_path / "Protected Work"
    root.mkdir()
    (root / "drafts").mkdir()
    return root


@pytest.mark.parametrize(
    ("observation", "event_type", "expected"),
    [
        (
            lambda root: FilesystemObservation("created", root / "drafts" / "chapter.docx"),
            FILE_CREATED_EVENT,
            {"relative_path": "drafts/chapter.docx", "extension": ".docx"},
        ),
        (
            lambda root: FilesystemObservation("modified", root / "drafts" / "chapter.docx"),
            FILE_MODIFIED_EVENT,
            {"relative_path": "drafts/chapter.docx", "extension": ".docx"},
        ),
        (
            lambda root: FilesystemObservation("deleted", root / "notes.txt"),
            FILE_DELETED_EVENT,
            {"relative_path": "notes.txt", "extension": ".txt"},
        ),
        (
            lambda root: FilesystemObservation(
                "moved", root / "old.docx", root / "drafts" / "new.docx"
            ),
            FILE_MOVED_EVENT,
            {
                "old_relative_path": "old.docx",
                "new_relative_path": "drafts/new.docx",
                "extension": ".docx",
            },
        ),
    ],
)
def test_file_actions_map_to_versioned_raw_events(
    tmp_path, protected_root, observation, event_type, expected
):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    result = FilesystemCollector(queue, protected_root).process(observation(protected_root))

    assert result is not None
    assert result.envelope.event_type == event_type
    assert result.envelope.schema_version == 1
    assert result.envelope.payload == {
        "monitored_root": "Protected Work",
        **expected,
    }


def test_observation_is_committed_before_delivery_and_contents_are_never_read(
    tmp_path, protected_root, monkeypatch
):
    document = protected_root / "drafts" / "private.txt"
    document.write_text("content the collector must never inspect", encoding="utf-8")

    def forbid_content_read(*args, **kwargs):
        raise AssertionError("filesystem collector must never read file contents")

    monkeypatch.setattr(Path, "open", forbid_content_read)
    monkeypatch.setattr(Path, "read_text", forbid_content_read)
    monkeypatch.setattr(Path, "read_bytes", forbid_content_read)
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    client = RecordingClient(queue)

    result = FilesystemCollector(queue, protected_root, client=client).process(
        FilesystemObservation("created", document)
    )

    assert result.delivery.acknowledged_count == 1
    assert len(client.calls) == 1
    assert queue.pending_count() == 0


def test_payload_uses_only_root_relative_paths_and_not_unrelated_absolute_paths(
    tmp_path, protected_root
):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    result = FilesystemCollector(queue, protected_root).process(
        FilesystemObservation("created", protected_root / "drafts" / "results.csv")
    )

    serialized = str(result.envelope.payload)
    assert str(protected_root) not in serialized
    assert str(tmp_path) not in serialized
    assert "C:\\Windows" not in serialized
    assert set(result.envelope.payload) == {
        "monitored_root",
        "relative_path",
        "extension",
    }


def test_malformed_relative_and_out_of_root_paths_are_ignored(tmp_path, protected_root):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    collector = FilesystemCollector(queue, protected_root)
    outside = tmp_path / "unrelated" / "private.docx"

    assert collector.process(FilesystemObservation("created", outside)) is None
    assert collector.process(FilesystemObservation("created", "..\\private.docx")) is None
    assert collector.process(FilesystemObservation("created", "bad\x00name.docx")) is None
    assert collector.process(FilesystemObservation("created", protected_root)) is None
    assert queue.pending_count() == 0


def test_move_from_inside_to_outside_emits_private_moved_out_event(
    tmp_path, protected_root
):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    outside = tmp_path / "Unrelated Private" / "external-name.docx"

    result = FilesystemCollector(queue, protected_root).process(
        FilesystemObservation(
            "moved", protected_root / "drafts" / "chapter.docx", outside
        )
    )

    assert result.envelope.event_type == FILE_MOVED_OUT_EVENT
    assert result.envelope.payload == {
        "monitored_root": "Protected Work",
        "relative_path": "drafts/chapter.docx",
        "destination_scope": "outside_protected_root",
        "extension": ".docx",
    }
    assert str(outside) not in str(result.envelope.payload)
    assert "external-name.docx" not in str(result.envelope.payload)


def test_move_from_outside_to_inside_emits_private_moved_in_event(
    tmp_path, protected_root
):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    outside = tmp_path / "Unrelated Private" / "external-name.pdf"

    result = FilesystemCollector(queue, protected_root).process(
        FilesystemObservation(
            "moved", outside, protected_root / "drafts" / "accepted.pdf"
        )
    )

    assert result.envelope.event_type == FILE_MOVED_IN_EVENT
    assert result.envelope.payload == {
        "monitored_root": "Protected Work",
        "relative_path": "drafts/accepted.pdf",
        "source_scope": "outside_protected_root",
        "extension": ".pdf",
    }
    assert str(outside) not in str(result.envelope.payload)
    assert "external-name.pdf" not in str(result.envelope.payload)


def test_move_inside_root_remains_normal_moved_event(tmp_path, protected_root):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")

    result = FilesystemCollector(queue, protected_root).process(
        FilesystemObservation(
            "moved",
            protected_root / "draft.docx",
            protected_root / "drafts" / "renamed.docx",
        )
    )

    assert result.envelope.event_type == FILE_MOVED_EVENT
    assert result.envelope.payload["old_relative_path"] == "draft.docx"
    assert result.envelope.payload["new_relative_path"] == "drafts/renamed.docx"
    assert "source_scope" not in result.envelope.payload
    assert "destination_scope" not in result.envelope.payload


def test_move_entirely_outside_root_is_ignored(tmp_path, protected_root):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    collector = FilesystemCollector(queue, protected_root)

    result = collector.process(
        FilesystemObservation(
            "moved",
            tmp_path / "outside-a" / "source.docx",
            tmp_path / "outside-b" / "destination.docx",
        )
    )

    assert result is None
    assert queue.pending_count() == 0


def test_directory_only_events_are_ignored(tmp_path, protected_root):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    result = FilesystemCollector(queue, protected_root).process(
        FilesystemObservation("created", protected_root / "drafts", is_directory=True)
    )
    assert result is None
    assert queue.pending_count() == 0


def test_duplicate_modification_noise_is_debounced_with_bounded_state(
    tmp_path, protected_root
):
    times = iter([10.0, 10.2, 10.8, 11.0])
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    collector = FilesystemCollector(
        queue,
        protected_root,
        debounce_seconds=0.75,
        debounce_capacity=2,
        monotonic_clock=lambda: next(times),
    )
    document = protected_root / "drafts" / "chapter.docx"

    results = [
        collector.process(FilesystemObservation("modified", document)),
        collector.process(FilesystemObservation("modified", document)),
        collector.process(FilesystemObservation("modified", document)),
        collector.process(FilesystemObservation("modified", protected_root / "other.txt")),
    ]

    assert [result is not None for result in results] == [True, False, True, True]
    assert queue.pending_count() == 3
    assert len(collector._recent_modifications) <= 2


def test_distinct_create_delete_and_move_actions_are_never_debounced(
    tmp_path, protected_root
):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    collector = FilesystemCollector(
        queue, protected_root, debounce_seconds=60, monotonic_clock=lambda: 1.0
    )
    source = protected_root / "draft.docx"
    destination = protected_root / "renamed.docx"

    collector.process(FilesystemObservation("created", source))
    collector.process(FilesystemObservation("deleted", source))
    collector.process(FilesystemObservation("moved", source, destination))

    assert [item.envelope.event_type for item in queue.oldest()] == [
        FILE_CREATED_EVENT,
        FILE_DELETED_EVENT,
        FILE_MOVED_EVENT,
    ]


def test_network_failure_retains_same_queued_event_for_later_replay(
    tmp_path, protected_root
):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    offline = RecordingClient(queue, failure="Could not reach the configured NepShield server.")
    collector = FilesystemCollector(queue, protected_root, client=offline)

    first = collector.process(
        FilesystemObservation("created", protected_root / "offline.docx")
    )

    pending = queue.oldest()[0]
    assert first.delivery.acknowledged_count == 0
    assert pending.envelope.event_id == first.envelope.event_id
    assert pending.attempt_count == 1

    replay_client = RecordingClient(queue)
    replay = flush_event_queue(queue, replay_client)
    assert replay_client.calls[0][0].event_id == first.envelope.event_id
    assert replay.acknowledged_count == 1
    assert queue.pending_count() == 0


def test_disabled_delivery_mode_retains_events_without_any_network_call(
    tmp_path, protected_root
):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    result = FilesystemCollector(queue, protected_root, client=None).process(
        FilesystemObservation("deleted", protected_root / "local-only.txt")
    )

    assert result.delivery is None
    assert queue.pending_count() == 1
    assert queue.oldest()[0].attempt_count == 0


def test_disabled_endpoint_rejection_retains_event_locally(tmp_path, protected_root):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    disabled = RecordingClient(
        queue, failure="Server rejected endpoint authentication (HTTP 401)."
    )

    result = FilesystemCollector(queue, protected_root, client=disabled).process(
        FilesystemObservation("modified", protected_root / "draft.docx")
    )

    assert result.delivery.acknowledged_count == 0
    assert result.delivery.pending_count == 1
    assert queue.oldest()[0].envelope.event_id == result.envelope.event_id


def test_monitored_root_validation_requires_an_explicit_existing_directory(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("x", encoding="utf-8")

    with pytest.raises(FilesystemConfigurationError):
        validate_monitored_root(tmp_path / "missing")
    with pytest.raises(FilesystemConfigurationError):
        validate_monitored_root(file_path)
