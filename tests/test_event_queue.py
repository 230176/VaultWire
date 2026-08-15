"""Durable SQLite raw-event queue and one-shot replay tests."""

from datetime import UTC, datetime, timedelta
import sqlite3
from uuid import UUID

import pytest

from agent.events import EventValidationError, SQLiteEventQueue, flush_event_queue


class AcknowledgingClient:
    def __init__(self, acknowledged=None):
        self.acknowledged = acknowledged
        self.calls = []

    def submit_events(self, events):
        self.calls.append(list(events))
        acknowledged = self.acknowledged
        if acknowledged is None:
            acknowledged = [event.event_id for event in events]
        return {"acknowledged_event_ids": acknowledged}


def test_sqlite_queue_initializes_automatically_in_agent_directory(tmp_path):
    queue = SQLiteEventQueue.in_directory(tmp_path / "NepShield" / "Agent")

    assert queue.database_path == tmp_path / "NepShield" / "Agent" / "events.sqlite3"
    assert queue.database_path.is_file()
    with sqlite3.connect(queue.database_path) as connection:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(event_queue)")
        }
    assert columns == {
        "sequence_id",
        "event_id",
        "event_type",
        "schema_version",
        "occurred_at",
        "payload_json",
        "created_at",
        "attempt_count",
        "last_attempt_at",
        "last_error",
    }


def test_queued_event_survives_queue_reopening_with_same_identity(tmp_path):
    path = tmp_path / "events.sqlite3"
    occurred_at = datetime(2026, 8, 14, 6, 30, tzinfo=UTC)
    created = SQLiteEventQueue(path).enqueue(
        "development.test", {"observation": "retained"}, occurred_at=occurred_at
    )

    reopened = SQLiteEventQueue(path)
    stored = reopened.oldest()[0]

    assert stored.envelope == created
    assert stored.attempt_count == 0
    assert stored.envelope.occurred_at == occurred_at.isoformat()


def test_fifo_batch_selection_uses_durable_insertion_order(tmp_path):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    events = [queue.enqueue("development.test", {"position": value}) for value in range(4)]

    selected = queue.oldest(3)

    assert [item.envelope.event_id for item in selected] == [
        event.event_id for event in events[:3]
    ]


def test_secret_fields_are_rejected_and_never_written_to_sqlite(tmp_path):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    credential = "endpoint-credential-that-must-not-be-stored"

    with pytest.raises(EventValidationError, match="credential or secret"):
        queue.enqueue("development.test", {"nested": {"endpoint_credential": credential}})

    assert queue.pending_count() == 0
    assert credential.encode() not in queue.database_path.read_bytes()


def test_events_remain_until_explicit_acknowledgement_and_ack_is_atomic(tmp_path):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    first = queue.enqueue("development.test", {"position": 1})
    second = queue.enqueue("development.test", {"position": 2})

    assert queue.oldest(2)[0].envelope.event_id == first.event_id
    assert queue.pending_count() == 2
    assert queue.acknowledge([first.event_id, second.event_id]) == 2
    assert queue.pending_count() == 0


def test_failed_delivery_retains_event_and_retry_keeps_original_uuid(tmp_path):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    original = queue.enqueue("development.test", {"value": 1})

    class FailingClient:
        def submit_events(self, events):
            raise RuntimeError("Authorization: Bearer should-never-be-copied")

    first_result = flush_event_queue(queue, FailingClient())
    after_failure = queue.oldest()[0]

    assert first_result.acknowledged_count == 0
    assert first_result.pending_count == 1
    assert after_failure.envelope.event_id == original.event_id
    assert after_failure.attempt_count == 1
    assert "Bearer" not in after_failure.last_error

    client = AcknowledgingClient()
    second_result = flush_event_queue(queue, client)

    assert client.calls[0][0].event_id == original.event_id
    assert second_result.acknowledged_count == 1
    assert second_result.pending_count == 0


def test_partial_acknowledgement_deletes_only_safely_persisted_events(tmp_path):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    first = queue.enqueue("development.test", {"position": 1})
    second = queue.enqueue("development.test", {"position": 2})
    client = AcknowledgingClient([first.event_id])

    result = flush_event_queue(queue, client)

    remaining = queue.oldest()[0]
    assert result.submitted_count == 2
    assert result.acknowledged_count == 1
    assert result.pending_count == 1
    assert remaining.envelope.event_id == second.event_id
    assert remaining.attempt_count == 1
    assert remaining.last_error == "Server did not acknowledge this event."


def test_invalid_acknowledgement_cannot_delete_queue_rows(tmp_path):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")
    event = queue.enqueue("development.test", {"value": 1})
    client = AcknowledgingClient(["not-a-uuid"])

    result = flush_event_queue(queue, client)

    assert result.acknowledged_count == 0
    assert queue.oldest()[0].envelope.event_id == event.event_id


@pytest.mark.parametrize(
    ("event_type", "payload", "occurred_at"),
    [
        ("USB.CONNECTED", {}, None),
        ("x" * 65, {}, None),
        ("development.test", [], None),
        ("development.test", {"large": "x" * 16_385}, None),
        ("development.test", {}, datetime(2026, 8, 14, 12, 0)),
    ],
)
def test_enqueue_validation_rejects_malformed_or_oversized_events(
    tmp_path, event_type, payload, occurred_at
):
    queue = SQLiteEventQueue(tmp_path / "events.sqlite3")

    with pytest.raises(EventValidationError):
        queue.enqueue(event_type, payload, occurred_at=occurred_at)

    assert queue.pending_count() == 0


def test_generated_event_ids_are_canonical_uuid4_values(tmp_path):
    event = SQLiteEventQueue(tmp_path / "events.sqlite3").enqueue(
        "development.test", {"safe": True}
    )

    parsed = UUID(event.event_id)
    assert parsed.version == 4
    assert str(parsed) == event.event_id
