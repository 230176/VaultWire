"""Read-only administrator audit reporting and safe CSV serialization."""

import csv
import io
from dataclasses import dataclass
from datetime import UTC, datetime, time
from typing import Any

from bson import ObjectId

from app.auth import AuditService
from app.models import User

PAGE_SIZE = 100
MAX_SELECTIONS = 100

# These keys are deliberately the only optional context values that can leave the
# audit store through this feature.  Audit context is otherwise treated as internal.
SAFE_CONTEXT_FIELDS = {
    "state": "State",
    "previous_state": "Previous state",
    "new_revision": "New revision",
    "previous_revision": "Previous revision",
    "exported_record_count": "Exported record count",
}


@dataclass(frozen=True)
class AuditRecord:
    id: str
    event_type: str
    occurred_at: datetime
    actor: str
    subject: str
    outcome: str
    reason: str
    resource_id: str
    context: tuple[tuple[str, str], ...]


def _as_utc(value: Any) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


def _text(value: Any, *, maximum: int = 512) -> str:
    if value is None:
        return ""
    return str(value).replace("\x00", "")[:maximum]


def _safe_context(document: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    context = document.get("context")
    if not isinstance(context, dict):
        return ()
    return tuple(
        (label, _text(context[key]))
        for key, label in SAFE_CONTEXT_FIELDS.items()
        if key in context and isinstance(context[key], (str, int, float, bool))
    )


def _record(document: dict[str, Any]) -> AuditRecord | None:
    occurred_at = _as_utc(document.get("occurred_at"))
    event_type = document.get("event_type")
    if occurred_at is None or not isinstance(event_type, str):
        return None
    # actor is retained with the event, so deleted/disabled users do not erase history.
    actor = _text(document.get("actor_username") or document.get("username"), maximum=64)
    return AuditRecord(
        id=_text(document.get("_id"), maximum=80),
        event_type=_text(event_type, maximum=128),
        occurred_at=occurred_at,
        actor=actor,
        subject=_text(document.get("username"), maximum=64),
        outcome=_text(document.get("outcome"), maximum=64),
        reason=_text(document.get("reason"), maximum=256),
        resource_id=_text(document.get("resource_id"), maximum=128),
        context=_safe_context(document),
    )


def parse_utc_range(value: str, *, end: bool = False) -> datetime | None:
    value = value.strip()
    if not value:
        return None
    try:
        if len(value) == 10:
            parsed = datetime.combine(datetime.fromisoformat(value).date(), time.max if end else time.min)
        else:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Use an ISO UTC date or date/time value.") from exc
    return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class AuditReportService:
    """Bounded administrator reporting over immutable audit events."""

    def __init__(self, repository: Any, audit: AuditService) -> None:
        self.repository = repository
        self.audit = audit

    @staticmethod
    def _query(event_type: str, actor: str, occurred_from: datetime | None, occurred_to: datetime | None) -> dict[str, Any]:
        query: dict[str, Any] = {}
        if event_type:
            query["event_type"] = event_type
        if actor:
            query["$or"] = [{"actor_username": actor}, {"username": actor}]
        if occurred_from or occurred_to:
            dates: dict[str, datetime] = {}
            if occurred_from:
                dates["$gte"] = occurred_from
            if occurred_to:
                dates["$lte"] = occurred_to
            query["occurred_at"] = dates
        return query

    async def list_records(self, *, event_type: str, actor: str, occurred_from: datetime | None, occurred_to: datetime | None) -> tuple[list[AuditRecord], bool]:
        documents = await self.repository.list_recent(
            self._query(event_type, actor, occurred_from, occurred_to), limit=PAGE_SIZE + 1
        )
        records = [record for document in documents[:PAGE_SIZE] if (record := _record(document))]
        return records, len(documents) > PAGE_SIZE

    async def find_record(self, record_id: str) -> AuditRecord | None:
        records = await self._find_selected([record_id])
        return records[0] if records else None

    async def _find_selected(self, record_ids: list[str]) -> list[AuditRecord]:
        unique = list(dict.fromkeys(value for value in record_ids if value))[:MAX_SELECTIONS]
        object_ids: list[Any] = []
        for value in unique:
            if ObjectId.is_valid(value):
                object_ids.append(ObjectId(value))
            else:
                # Supports repository test doubles which retain string identifiers.
                object_ids.append(value)
        documents = await self.repository.find_by_ids(object_ids)
        by_id = {record.id: record for document in documents if (record := _record(document))}
        return [by_id[value] for value in unique if value in by_id]

    async def export_selected(self, record_ids: list[str], *, administrator: User) -> list[AuditRecord]:
        records = await self._find_selected(record_ids)
        if not records:
            raise ValueError("Select at least one audit record to export.")
        await self.audit.record(
            "audit.records_exported",
            username=administrator.username,
            user_id=administrator.id,
            outcome="success",
            actor_username=administrator.username,
            actor_user_id=administrator.id,
            context={"exported_record_count": len(records)},
        )
        return records


def _csv_text(value: str) -> str:
    return f"'{value}" if value.startswith(("=", "+", "-", "@")) else value


def records_to_csv(records: list[AuditRecord]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(["Audit ID", "Occurred At (UTC)", "Event Type", "Actor", "Subject", "Outcome", "Reason", "Resource ID", "Approved Context"])
    for record in records:
        context = "; ".join(f"{label}: {value}" for label, value in record.context)
        writer.writerow([
            _csv_text(record.id), record.occurred_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            _csv_text(record.event_type), _csv_text(record.actor), _csv_text(record.subject),
            _csv_text(record.outcome), _csv_text(record.reason), _csv_text(record.resource_id), _csv_text(context),
        ])
    return output.getvalue()
