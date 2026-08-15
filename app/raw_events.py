"""Validated raw endpoint-event transport and idempotent MongoDB persistence."""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import UTC, datetime
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError

MAX_EVENT_TYPE_LENGTH = 64
MAX_PAYLOAD_BYTES = 16_384
MAX_EVENT_BYTES = 20_000
MAX_BATCH_BYTES = 262_144
MAX_BATCH_SIZE = 50
SUPPORTED_SCHEMA_VERSION = 1
EVENT_TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
MAX_ADMIN_EVENT_RESULTS = 100

EVENT_TYPE_LABELS = {
    "removable.volume_arrived": "Removable volume connected",
    "removable.volume_removed": "Removable volume removed",
    "removable.file_created": "File created on removable storage",
    "removable.file_modified": "File modified on removable storage",
    "removable.file_deleted": "File deleted from removable storage",
    "removable.file_moved": "File moved/renamed on removable storage",
    "filesystem.file_created": "File created",
    "filesystem.file_modified": "File modified",
    "filesystem.file_deleted": "File deleted",
    "filesystem.file_moved": "File moved or renamed",
    "filesystem.file_moved_out": "File moved out of protected folder",
    "filesystem.file_moved_in": "File moved into protected folder",
}
REMOVABLE_PAYLOAD_FIELDS = (
    ("drive_name", "Drive"),
    ("drive_type", "Drive type"),
    ("volume_label", "Volume label"),
    ("filesystem", "Filesystem"),
)
REMOVABLE_FILE_PAYLOAD_FIELDS = {
    "removable.file_created": (
        ("drive_name", "Drive"),
        ("volume_label", "Volume label"),
        ("relative_path", "Relative path"),
        ("extension", "Extension"),
        ("size_bytes", "Observed size"),
    ),
    "removable.file_modified": (
        ("drive_name", "Drive"),
        ("volume_label", "Volume label"),
        ("relative_path", "Relative path"),
        ("extension", "Extension"),
        ("size_bytes", "Observed size"),
    ),
    "removable.file_deleted": (
        ("drive_name", "Drive"),
        ("volume_label", "Volume label"),
        ("relative_path", "Relative path"),
        ("extension", "Extension"),
    ),
    "removable.file_moved": (
        ("drive_name", "Drive"),
        ("volume_label", "Volume label"),
        ("old_relative_path", "Old relative path"),
        ("new_relative_path", "New relative path"),
        ("extension", "Extension"),
        ("size_bytes", "Observed size"),
    ),
}
FILESYSTEM_PAYLOAD_FIELDS = {
    "filesystem.file_created": (
        ("relative_path", "Relative path"),
        ("extension", "Extension"),
        ("monitored_root", "Protected folder"),
    ),
    "filesystem.file_modified": (
        ("relative_path", "Relative path"),
        ("extension", "Extension"),
        ("monitored_root", "Protected folder"),
    ),
    "filesystem.file_deleted": (
        ("relative_path", "Relative path"),
        ("extension", "Extension"),
        ("monitored_root", "Protected folder"),
    ),
    "filesystem.file_moved": (
        ("old_relative_path", "Old relative path"),
        ("new_relative_path", "New relative path"),
        ("extension", "Extension"),
        ("monitored_root", "Protected folder"),
    ),
    "filesystem.file_moved_out": (
        ("relative_path", "Relative source path"),
        ("extension", "Extension"),
        ("monitored_root", "Protected folder"),
        ("destination_scope", "Destination"),
    ),
    "filesystem.file_moved_in": (
        ("relative_path", "Relative destination path"),
        ("extension", "Extension"),
        ("monitored_root", "Protected folder"),
        ("source_scope", "Source"),
    ),
}


@dataclass(frozen=True)
class StoredRawEvent:
    """Stored transport data safe to use as input to the administrator view."""

    endpoint_id: str
    event_id: str
    event_type: str
    schema_version: int
    occurred_at: datetime
    received_at: datetime
    payload: dict[str, Any]


@dataclass(frozen=True)
class AdministratorRawEvent:
    """A raw event enriched from trusted endpoint and user relationships."""

    event: StoredRawEvent
    endpoint: Any | None
    assigned_employee: Any | None
    label: str
    details: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class RawEventPage:
    events: list[AdministratorRawEvent]
    has_more: bool


class RawEventEnvelope(BaseModel):
    """Strict versioned envelope; endpoint identity is deliberately absent."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_id: UUID
    event_type: str = Field(min_length=1, max_length=MAX_EVENT_TYPE_LENGTH)
    schema_version: int = Field(strict=True)
    occurred_at: datetime
    payload: dict[str, Any]

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, value: str) -> str:
        if EVENT_TYPE_PATTERN.fullmatch(value) is None:
            raise ValueError(
                "event type may contain lowercase letters, numbers, dots, underscores, and hyphens"
            )
        return value

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, value: int) -> int:
        if isinstance(value, bool) or value != SUPPORTED_SCHEMA_VERSION:
            raise ValueError("unsupported event schema version")
        return value

    @field_validator("occurred_at", mode="before")
    @classmethod
    def validate_occurred_at(cls, value: Any) -> Any:
        if not isinstance(value, str):
            raise ValueError("occurred_at must be an ISO-8601 timestamp string")
        return value

    @field_validator("occurred_at")
    @classmethod
    def normalize_occurred_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a UTC offset")
        return value.astimezone(UTC)

    @field_validator("payload")
    @classmethod
    def validate_payload_size(cls, value: dict[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        )
        if len(encoded.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise ValueError(f"payload exceeds the {MAX_PAYLOAD_BYTES}-byte limit")
        return value

    @model_validator(mode="after")
    def validate_event_size(self) -> "RawEventEnvelope":
        encoded = json.dumps(self.model_dump(mode="json"), separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_EVENT_BYTES:
            raise ValueError(f"event exceeds the {MAX_EVENT_BYTES}-byte limit")
        return self


class RawEventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[RawEventEnvelope] = Field(min_length=1, max_length=MAX_BATCH_SIZE)

    @model_validator(mode="after")
    def validate_batch_size(self) -> "RawEventBatch":
        encoded = json.dumps(self.model_dump(mode="json"), separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_BATCH_BYTES:
            raise ValueError(f"batch exceeds the {MAX_BATCH_BYTES}-byte limit")
        return self


class MongoRawEventRepository:
    """Raw endpoint events, isolated from both audit events and future alerts."""

    def __init__(self, database: Any) -> None:
        self.collection = database["raw_endpoint_events"]

    async def ensure_indexes(self) -> None:
        await self.collection.create_index(
            [("endpoint_id", ASCENDING), ("event_id", ASCENDING)],
            unique=True,
            name="unique_endpoint_event",
        )
        await self.collection.create_index(
            [("endpoint_id", ASCENDING), ("received_at", DESCENDING)],
            name="endpoint_received_events",
        )
        await self.collection.create_index(
            [("received_at", DESCENDING)], name="recent_received_events"
        )
        await self.collection.create_index(
            [("event_type", ASCENDING), ("received_at", DESCENDING)],
            name="event_type_received_events",
        )
        await self.collection.create_index(
            [
                ("endpoint_id", ASCENDING),
                ("event_type", ASCENDING),
                ("occurred_at", DESCENDING),
            ],
            name="endpoint_type_occurred_events",
        )

    async def store_idempotent(
        self,
        endpoint_id: str,
        envelope: RawEventEnvelope,
        received_at: datetime,
    ) -> None:
        identity = {"endpoint_id": endpoint_id, "event_id": str(envelope.event_id)}
        document = {
            **identity,
            "event_type": envelope.event_type,
            "schema_version": envelope.schema_version,
            "occurred_at": envelope.occurred_at,
            "received_at": received_at,
            "payload": envelope.payload,
        }
        try:
            await self.collection.update_one(
                identity, {"$setOnInsert": document}, upsert=True
            )
        except DuplicateKeyError:
            # A concurrent replay can race another upsert. The unique document is
            # already durable, so this event is still safe to acknowledge.
            if await self.collection.find_one(identity, {"_id": 1}) is None:
                raise

    async def list_recent(
        self,
        *,
        endpoint_ids: list[str] | None = None,
        event_type: str | None = None,
        limit: int,
    ) -> list[StoredRawEvent]:
        query: dict[str, Any] = {}
        if endpoint_ids is not None:
            if not endpoint_ids:
                return []
            query["endpoint_id"] = (
                endpoint_ids[0] if len(endpoint_ids) == 1 else {"$in": endpoint_ids}
            )
        if event_type is not None:
            query["event_type"] = event_type
        cursor = self.collection.find(query).sort("received_at", DESCENDING).limit(limit)
        events: list[StoredRawEvent] = []
        async for document in cursor:
            event = self._to_stored_event(document)
            if event is not None:
                events.append(event)
        return events

    async def find_by_identity(
        self, endpoint_id: str, event_id: str
    ) -> StoredRawEvent | None:
        return self._to_stored_event(
            await self.collection.find_one(
                {"endpoint_id": endpoint_id, "event_id": event_id}
            )
        )

    async def find_protected_correlation_candidates(
        self,
        endpoint_id: str,
        *,
        occurred_from: datetime,
        occurred_to: datetime,
        limit: int,
    ) -> list[StoredRawEvent]:
        query = {
            "endpoint_id": endpoint_id,
            "event_type": {
                "$in": ["filesystem.file_moved_out", "filesystem.file_deleted"]
            },
            "occurred_at": {"$gte": occurred_from, "$lte": occurred_to},
        }
        cursor = self.collection.find(query).sort(
            [("occurred_at", DESCENDING), ("event_id", ASCENDING)]
        ).limit(limit)
        events: list[StoredRawEvent] = []
        async for document in cursor:
            event = self._to_stored_event(document)
            if event is not None:
                events.append(event)
        return events

    @staticmethod
    def _to_stored_event(document: dict[str, Any] | None) -> StoredRawEvent | None:
        if document is None:
            return None
        try:
            endpoint_id = str(UUID(document["endpoint_id"]))
            event_id = str(UUID(document["event_id"]))
            event_type = document["event_type"]
            schema_version = document["schema_version"]
            occurred_at = document["occurred_at"]
            received_at = document["received_at"]
            payload = document["payload"]
        except (KeyError, TypeError, ValueError):
            return None
        if (
            not isinstance(event_type, str)
            or EVENT_TYPE_PATTERN.fullmatch(event_type) is None
            or isinstance(schema_version, bool)
            or not isinstance(schema_version, int)
            or not isinstance(occurred_at, datetime)
            or not isinstance(received_at, datetime)
            or not isinstance(payload, dict)
        ):
            return None
        return StoredRawEvent(
            endpoint_id=endpoint_id,
            event_id=event_id,
            event_type=event_type,
            schema_version=schema_version,
            occurred_at=occurred_at.astimezone(UTC)
            if occurred_at.tzinfo is not None
            else occurred_at.replace(tzinfo=UTC),
            received_at=received_at.astimezone(UTC)
            if received_at.tzinfo is not None
            else received_at.replace(tzinfo=UTC),
            payload=payload,
        )


class RawEventService:
    def __init__(self, repository: Any, rule_evaluator: Any = None) -> None:
        self.repository = repository
        self.rule_evaluator = rule_evaluator

    async def ingest(
        self, endpoint_id: str, events: list[RawEventEnvelope]
    ) -> list[str]:
        acknowledged: list[str] = []
        for event in events:
            received_at = datetime.now(UTC)
            await self.repository.store_idempotent(endpoint_id, event, received_at)
            if self.rule_evaluator is not None:
                stored = await self.repository.find_by_identity(
                    endpoint_id, str(event.event_id)
                )
                if stored is None:
                    raise RuntimeError("Stored raw event could not be read for rule evaluation.")
                # Evaluation is deliberately after durable storage and before the
                # acknowledgement. Replays safely repeat this idempotent step.
                await self.rule_evaluator.evaluate(stored)
            acknowledged.append(str(event.event_id))
        return acknowledged


class AdministratorRawEventService:
    """Read-only, bounded raw-event query layer for administrators.

    Context is deliberately joined from the durable endpoint and user records;
    no identity supplied inside an endpoint event payload is used for display.
    """

    def __init__(self, events: Any, endpoints: Any, users: Any) -> None:
        self.events = events
        self.endpoints = endpoints
        self.users = users

    async def list_events(
        self,
        *,
        endpoint_id: str = "",
        employee_id: str = "",
        event_type: str = "",
    ) -> RawEventPage:
        directory = await self.endpoints.list_all()
        selected_endpoint = endpoint_id.strip()
        selected_employee = employee_id.strip()
        selected_type = event_type.strip()

        valid_endpoint_ids = {item.endpoint_id for item in directory}
        endpoint_ids: list[str] | None = None
        if selected_endpoint:
            if selected_endpoint not in valid_endpoint_ids:
                return RawEventPage([], False)
            endpoint_ids = [selected_endpoint]

        if selected_employee:
            employee_endpoint_ids = [
                item.endpoint_id
                for item in directory
                if str(item.assigned_user_id) == selected_employee
            ]
            if not employee_endpoint_ids:
                return RawEventPage([], False)
            if endpoint_ids is None:
                endpoint_ids = employee_endpoint_ids
            elif endpoint_ids[0] not in employee_endpoint_ids:
                return RawEventPage([], False)

        if selected_type and EVENT_TYPE_PATTERN.fullmatch(selected_type) is None:
            return RawEventPage([], False)

        stored = await self.events.list_recent(
            endpoint_ids=endpoint_ids,
            event_type=selected_type or None,
            limit=MAX_ADMIN_EVENT_RESULTS + 1,
        )
        enriched = await self._enrich(stored[:MAX_ADMIN_EVENT_RESULTS], directory)
        return RawEventPage(enriched, len(stored) > MAX_ADMIN_EVENT_RESULTS)

    async def find_event(
        self, endpoint_id: str, event_id: str
    ) -> AdministratorRawEvent | None:
        try:
            normalized_endpoint_id = str(UUID(endpoint_id))
            normalized_event_id = str(UUID(event_id))
        except (TypeError, ValueError):
            return None
        event = await self.events.find_by_identity(
            normalized_endpoint_id, normalized_event_id
        )
        if event is None:
            return None
        return (await self._enrich([event], await self.endpoints.list_all()))[0]

    async def filter_options(self) -> tuple[list[Any], list[Any]]:
        """Return retained records too, so disabled context remains reviewable."""
        return await self.endpoints.list_all(), [
            user for user in await self.users.list_users() if user.role.value == "employee"
        ]

    async def _enrich(
        self, events: list[StoredRawEvent], directory: list[Any]
    ) -> list[AdministratorRawEvent]:
        endpoint_by_id = {endpoint.endpoint_id: endpoint for endpoint in directory}
        user_ids = {endpoint.assigned_user_id for endpoint in directory}
        users = {
            user_id: await self.users.find_by_id(user_id)
            for user_id in user_ids
        }
        return [
            AdministratorRawEvent(
                event=event,
                endpoint=endpoint_by_id.get(event.endpoint_id),
                assigned_employee=users.get(
                    endpoint_by_id[event.endpoint_id].assigned_user_id
                )
                if event.endpoint_id in endpoint_by_id
                else None,
                label=EVENT_TYPE_LABELS.get(event.event_type, event.event_type),
                details=_safe_details(event.event_type, event.payload),
            )
            for event in events
        ]


def _safe_details(event_type: str, payload: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """Render only known metadata, never arbitrary raw event payload content."""
    if event_type not in EVENT_TYPE_LABELS:
        return ()
    details: list[tuple[str, str]] = []
    if event_type in REMOVABLE_FILE_PAYLOAD_FIELDS:
        fields = REMOVABLE_FILE_PAYLOAD_FIELDS[event_type]
        maximums = {
            "drive_name": 64,
            "volume_label": 128,
            "relative_path": 1024,
            "old_relative_path": 1024,
            "new_relative_path": 1024,
            "extension": 32,
        }
        validator = _safe_filesystem_display_text
    elif event_type.startswith("filesystem."):
        fields = FILESYSTEM_PAYLOAD_FIELDS.get(event_type, ())
        maximums = {
            "relative_path": 1024,
            "old_relative_path": 1024,
            "new_relative_path": 1024,
            "extension": 32,
            "monitored_root": 64,
            "source_scope": 32,
            "destination_scope": 32,
        }
        validator = _safe_filesystem_display_text
    else:
        fields = REMOVABLE_PAYLOAD_FIELDS
        maximums = {
            "drive_name": 64,
            "drive_type": 32,
            "volume_label": 128,
            "filesystem": 32,
        }
        validator = _safe_display_text
    for field, label in fields:
        if field == "size_bytes":
            raw_size = payload.get(field)
            value = (
                f"{raw_size} bytes"
                if isinstance(raw_size, int)
                and not isinstance(raw_size, bool)
                and 0 <= raw_size <= (1 << 63) - 1
                else None
            )
        elif field in {"source_scope", "destination_scope"}:
            value = (
                "Outside protected folder"
                if payload.get(field) == "outside_protected_root"
                else None
            )
        elif field in {"drive_name", "volume_label"}:
            value = _safe_display_text(payload.get(field), maximums[field])
        else:
            value = validator(payload.get(field), maximums[field])
        if value is not None:
            details.append((label, value))
    return tuple(details)


def _safe_display_text(value: Any, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > maximum:
        return None
    # Paths and credential-shaped content are not useful removable-volume metadata.
    lowered = normalized.casefold()
    if "\\" in normalized or "/" in normalized or any(
        marker in lowered
        for marker in ("password", "credential", "secret", "token", "digest", "vault", "encrypt")
    ):
        return None
    return normalized


def _safe_filesystem_display_text(value: Any, maximum: int) -> str | None:
    """Allow bounded relative paths but reject absolute/traversal representations."""
    if not isinstance(value, str) or not value or len(value) > maximum:
        return None
    if any(unicodedata.category(character).startswith("C") for character in value):
        return None
    normalized = value.replace("\\", "/")
    parts = normalized.split("/")
    if (
        normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
        or any(part in {"", ".", ".."} for part in parts)
    ):
        return None
    return normalized
