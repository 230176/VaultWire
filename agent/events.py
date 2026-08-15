"""Durable local raw-event outbox and one-shot replay orchestration."""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence
from uuid import UUID, uuid4

from agent.config import default_config_directory

EVENT_SCHEMA_VERSION = 1
MAX_EVENT_TYPE_LENGTH = 64
MAX_PAYLOAD_BYTES = 16_384
MAX_BATCH_SIZE = 50
DEFAULT_BATCH_SIZE = 25
EVENT_TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
FORBIDDEN_SECRET_KEYS = {
    "api_key",
    "authorization",
    "browser_credential",
    "credential",
    "encryption_key",
    "password",
    "private_key",
    "secret",
    "token",
}
FORBIDDEN_SECRET_KEY_PARTS = {
    "authorization",
    "credential",
    "password",
    "secret",
    "token",
}


class EventValidationError(ValueError):
    """An event cannot safely enter the durable queue."""


class EventDeliveryError(RuntimeError):
    """A delivery response was not a safe, usable acknowledgement."""


def utc_now() -> datetime:
    return datetime.now(UTC)


def _utc_text(value: datetime, field_name: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise EventValidationError(f"{field_name} must include a UTC offset.")
    return value.astimezone(UTC).isoformat()


def _validate_event_type(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_EVENT_TYPE_LENGTH
        or EVENT_TYPE_PATTERN.fullmatch(value) is None
    ):
        raise EventValidationError(
            "Event type must be 1-64 lowercase letters, numbers, dots, underscores, or hyphens."
        )
    return value


def _check_secret_keys(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if isinstance(key, str):
                normalized = key.casefold().replace("-", "_")
                parts = set(normalized.split("_"))
                if (
                    normalized in FORBIDDEN_SECRET_KEYS
                    or parts.intersection(FORBIDDEN_SECRET_KEY_PARTS)
                    or normalized.endswith(("api_key", "encryption_key", "private_key"))
                ):
                    raise EventValidationError(
                        "Event payload must not contain credential or secret fields."
                    )
            _check_secret_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            _check_secret_keys(nested)


def _payload_json(payload: Mapping[str, Any]) -> str:
    if not isinstance(payload, Mapping):
        raise EventValidationError("Event payload must be a JSON object.")
    _check_secret_keys(payload)
    try:
        encoded = json.dumps(
            dict(payload),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise EventValidationError("Event payload must contain only JSON values.") from exc
    if len(encoded.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise EventValidationError("Event payload exceeds the 16384-byte limit.")
    return encoded


@dataclass(frozen=True)
class EventEnvelope:
    event_id: str
    event_type: str
    schema_version: int
    occurred_at: str
    payload: dict[str, Any]

    def as_payload(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "schema_version": self.schema_version,
            "occurred_at": self.occurred_at,
            "payload": self.payload,
        }


@dataclass(frozen=True)
class QueuedEvent:
    envelope: EventEnvelope
    created_at: str
    attempt_count: int
    last_attempt_at: str | None
    last_error: str | None


@dataclass(frozen=True)
class FlushResult:
    submitted_count: int
    acknowledged_count: int
    pending_count: int
    error: str | None = None
    authentication_rejected: bool = False


class EventBatchClient(Protocol):
    def submit_events(self, events: Sequence[EventEnvelope]) -> dict[str, Any]: ...


class SQLiteEventQueue:
    """A single-process SQLite outbox stored in NepShield's local app-data area."""

    def __init__(self, database_path: Path | None = None) -> None:
        self.database_path = Path(database_path) if database_path else (
            default_config_directory() / "events.sqlite3"
        )
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @classmethod
    def in_directory(cls, directory: Path) -> "SQLiteEventQueue":
        return cls(Path(directory) / "events.sqlite3")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _transaction(self):
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS event_queue (
                    sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    schema_version INTEGER NOT NULL,
                    occurred_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
                    last_attempt_at TEXT,
                    last_error TEXT
                )
                """
            )

    def enqueue(
        self,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        occurred_at: datetime | None = None,
    ) -> EventEnvelope:
        """Validate and commit a newly identified event before returning it."""
        envelope = EventEnvelope(
            event_id=str(uuid4()),
            event_type=_validate_event_type(event_type),
            schema_version=EVENT_SCHEMA_VERSION,
            occurred_at=_utc_text(occurred_at or utc_now(), "occurred_at"),
            payload=json.loads(_payload_json(payload)),
        )
        created_at = _utc_text(utc_now(), "created_at")
        with self._transaction() as connection:
            connection.execute(
                """
                INSERT INTO event_queue (
                    event_id, event_type, schema_version, occurred_at,
                    payload_json, created_at, attempt_count
                ) VALUES (?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    envelope.event_id,
                    envelope.event_type,
                    envelope.schema_version,
                    envelope.occurred_at,
                    _payload_json(envelope.payload),
                    created_at,
                ),
            )
        return envelope

    def oldest(self, limit: int = DEFAULT_BATCH_SIZE) -> list[QueuedEvent]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_BATCH_SIZE:
            raise EventValidationError(f"Batch size must be between 1 and {MAX_BATCH_SIZE}.")
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT event_id, event_type, schema_version, occurred_at,
                       payload_json, created_at, attempt_count,
                       last_attempt_at, last_error
                FROM event_queue
                ORDER BY sequence_id ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        finally:
            connection.close()
        return [self._to_event(row) for row in rows]

    def pending_count(self) -> int:
        connection = self._connect()
        try:
            row = connection.execute("SELECT COUNT(*) AS count FROM event_queue").fetchone()
        finally:
            connection.close()
        return int(row["count"])

    def record_attempt(self, event_ids: Sequence[str], attempted_at: datetime | None = None) -> None:
        identifiers = self._canonical_ids(event_ids)
        if not identifiers:
            return
        placeholders = ",".join("?" for _ in identifiers)
        values = [_utc_text(attempted_at or utc_now(), "last_attempt_at"), *identifiers]
        with self._transaction() as connection:
            connection.execute(
                f"""
                UPDATE event_queue
                SET attempt_count = attempt_count + 1,
                    last_attempt_at = ?,
                    last_error = NULL
                WHERE event_id IN ({placeholders})
                """,
                values,
            )

    def record_error(self, event_ids: Sequence[str], error: str) -> None:
        identifiers = self._canonical_ids(event_ids)
        if not identifiers:
            return
        safe_error = " ".join(str(error).split())[:240] or "Event delivery failed."
        placeholders = ",".join("?" for _ in identifiers)
        with self._transaction() as connection:
            connection.execute(
                f"UPDATE event_queue SET last_error = ? WHERE event_id IN ({placeholders})",
                [safe_error, *identifiers],
            )

    def acknowledge(self, event_ids: Sequence[str]) -> int:
        """Delete only explicitly acknowledged IDs in one committed transaction."""
        identifiers = self._canonical_ids(event_ids)
        if not identifiers:
            return 0
        placeholders = ",".join("?" for _ in identifiers)
        with self._transaction() as connection:
            cursor = connection.execute(
                f"DELETE FROM event_queue WHERE event_id IN ({placeholders})",
                identifiers,
            )
        return cursor.rowcount

    @staticmethod
    def _canonical_ids(event_ids: Sequence[str]) -> list[str]:
        canonical: list[str] = []
        for event_id in event_ids:
            try:
                normalized = str(UUID(event_id))
            except (AttributeError, TypeError, ValueError) as exc:
                raise EventValidationError("Acknowledgement contains an invalid event ID.") from exc
            if normalized not in canonical:
                canonical.append(normalized)
        return canonical

    @staticmethod
    def _to_event(row: sqlite3.Row) -> QueuedEvent:
        return QueuedEvent(
            envelope=EventEnvelope(
                event_id=row["event_id"],
                event_type=row["event_type"],
                schema_version=row["schema_version"],
                occurred_at=row["occurred_at"],
                payload=json.loads(row["payload_json"]),
            ),
            created_at=row["created_at"],
            attempt_count=row["attempt_count"],
            last_attempt_at=row["last_attempt_at"],
            last_error=row["last_error"],
        )


def flush_event_queue(
    queue: SQLiteEventQueue,
    client: EventBatchClient,
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> FlushResult:
    """Attempt one bounded batch; a later invocation performs any retry."""
    batch = queue.oldest(batch_size)
    if not batch:
        return FlushResult(0, 0, 0)

    submitted_ids = [item.envelope.event_id for item in batch]
    queue.record_attempt(submitted_ids)
    try:
        response = client.submit_events([item.envelope for item in batch])
        acknowledgements = response.get("acknowledged_event_ids")
        if not isinstance(acknowledgements, list) or not all(
            isinstance(item, str) for item in acknowledgements
        ):
            raise EventDeliveryError("Server returned invalid event acknowledgement data.")
        acknowledged_ids = queue._canonical_ids(acknowledgements)
        if not set(acknowledged_ids).issubset(submitted_ids):
            raise EventDeliveryError("Server acknowledged an event that was not submitted.")
    except EventDeliveryError as exc:
        queue.record_error(submitted_ids, str(exc))
        return FlushResult(len(batch), 0, queue.pending_count(), str(exc))
    except Exception as exc:
        # EndpointClient already sanitizes transport failures. Do not risk copying a
        # custom client's exception (which may contain its Authorization header).
        error = "Event delivery failed; queued events were retained."
        queue.record_error(submitted_ids, error)
        return FlushResult(
            len(batch),
            0,
            queue.pending_count(),
            error,
            bool(getattr(exc, "authentication_rejected", False)),
        )

    queue.acknowledge(acknowledged_ids)
    unacknowledged_ids = [item for item in submitted_ids if item not in acknowledged_ids]
    if unacknowledged_ids:
        queue.record_error(unacknowledged_ids, "Server did not acknowledge this event.")
    return FlushResult(
        len(batch), len(acknowledged_ids), queue.pending_count(),
        "Some submitted events were not acknowledged." if unacknowledged_ids else None,
    )
