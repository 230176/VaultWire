"""Deterministic built-in rules and administrator alert review services."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import PurePosixPath
from typing import Any
from uuid import UUID, uuid5

from pymongo import ASCENDING, DESCENDING, ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.models import Alert, AlertSeverity, AlertStatus, Role, User
from app.raw_events import AdministratorRawEvent, StoredRawEvent, _safe_filesystem_display_text

REMOVABLE_WRITE_RULE_ID = "builtin.removable_file_created"
REMOVABLE_WRITE_RULE_VERSION = 1
PROTECTED_MOVE_OUT_RULE_ID = "builtin.protected_file_moved_out"
PROTECTED_MOVE_OUT_RULE_VERSION = 1
POSSIBLE_TRANSFER_RULE_ID = "builtin.possible_protected_file_transfer"
POSSIBLE_TRANSFER_RULE_VERSION = 1
CORRELATION_WINDOW = timedelta(seconds=120)
MAX_ALERT_RESULTS = 50
MAX_REVIEW_REASON_LENGTH = 500
ALERT_ID_NAMESPACE = UUID("243d4dda-e12d-4a5b-9351-11a0f8ba18f7")

RULE_DEFINITIONS = {
    REMOVABLE_WRITE_RULE_ID: {
        "version": REMOVABLE_WRITE_RULE_VERSION,
        "title": "File created on removable storage",
        "severity": AlertSeverity.MEDIUM,
    },
    PROTECTED_MOVE_OUT_RULE_ID: {
        "version": PROTECTED_MOVE_OUT_RULE_VERSION,
        "title": "Protected file moved outside protected folder",
        "severity": AlertSeverity.HIGH,
    },
    POSSIBLE_TRANSFER_RULE_ID: {
        "version": POSSIBLE_TRANSFER_RULE_VERSION,
        "title": "Possible protected-file transfer to removable storage",
        "severity": AlertSeverity.HIGH,
    },
}


class InvalidAlertTransition(ValueError):
    pass


class InvalidAlertReviewReason(ValueError):
    pass


class AlertNotFound(LookupError):
    pass


@dataclass(frozen=True)
class AlertPage:
    alerts: list[Alert]
    has_more: bool
    page: int


@dataclass(frozen=True)
class AdministratorAlert:
    alert: Alert
    endpoint: Any | None
    assigned_employee: Any | None
    evidence: tuple[AdministratorRawEvent, ...]


class MongoAlertRepository:
    """Durable alerts with unique deterministic rule/evidence identities."""

    def __init__(self, database: Any) -> None:
        self.collection = database["alerts"]

    async def ensure_indexes(self) -> None:
        await self.collection.create_index("alert_id", unique=True, name="unique_alert_id")
        await self.collection.create_index(
            "deduplication_key", unique=True, name="unique_alert_deduplication_key"
        )
        await self.collection.create_index(
            [("status_rank", ASCENDING), ("created_at", DESCENDING)],
            name="active_alert_review_order",
        )
        await self.collection.create_index(
            [("endpoint_id", ASCENDING), ("created_at", DESCENDING)],
            name="endpoint_alerts",
        )
        await self.collection.create_index(
            [("assigned_employee_id", ASCENDING), ("created_at", DESCENDING)],
            name="employee_alerts",
        )
        await self.collection.create_index(
            [("rule_id", ASCENDING), ("created_at", DESCENDING)],
            name="rule_alerts",
        )

    async def create_idempotent(self, document: dict[str, Any]) -> Alert:
        try:
            await self.collection.insert_one(document)
        except DuplicateKeyError:
            # Concurrent evaluation or replay is expected. The unique deduplication
            # index makes the already-created alert authoritative.
            pass
        stored = await self.collection.find_one(
            {"deduplication_key": document["deduplication_key"]}
        )
        alert = self._to_alert(stored)
        if alert is None:
            raise RuntimeError("Alert could not be read after idempotent creation.")
        return alert

    async def find_by_alert_id(self, alert_id: str) -> Alert | None:
        return self._to_alert(await self.collection.find_one({"alert_id": alert_id}))

    async def list_filtered(
        self,
        *,
        status: AlertStatus | None,
        severity: AlertSeverity | None,
        endpoint_id: str | None,
        employee_id: Any,
        rule_id: str | None,
        skip: int,
        limit: int,
    ) -> list[Alert]:
        query: dict[str, Any] = {}
        if status is not None:
            query["status"] = status.value
        if severity is not None:
            query["severity"] = severity.value
        if endpoint_id is not None:
            query["endpoint_id"] = endpoint_id
        if employee_id is not None:
            query["assigned_employee_id"] = employee_id
        if rule_id is not None:
            query["rule_id"] = rule_id
        cursor = (
            self.collection.find(query)
            .sort([("status_rank", ASCENDING), ("created_at", DESCENDING)])
            .skip(skip)
            .limit(limit)
        )
        alerts: list[Alert] = []
        async for item in cursor:
            alert = self._to_alert(item)
            if alert is not None:
                alerts.append(alert)
        return alerts

    async def transition_status(
        self,
        alert_id: str,
        previous_status: AlertStatus,
        new_status: AlertStatus,
        reason: str,
        changed_at: datetime,
        actor: User,
    ) -> Alert | None:
        history = {
            "previous_status": previous_status.value,
            "new_status": new_status.value,
            "reason": reason,
            "changed_at": changed_at,
            "administrator_id": actor.id,
            "administrator_username": actor.username,
        }
        set_fields: dict[str, Any] = {
            "status": new_status.value,
            "status_rank": _status_rank(new_status),
            "updated_at": changed_at,
        }
        update: dict[str, Any] = {
            "$set": set_fields,
            "$push": {"status_history": history},
        }
        if new_status is AlertStatus.RESOLVED:
            set_fields.update(
                {
                    "resolved_at": changed_at,
                    "resolved_by": actor.id,
                    "resolution_reason": reason,
                }
            )
        elif previous_status is AlertStatus.RESOLVED:
            update["$unset"] = {
                "resolved_at": "",
                "resolved_by": "",
                "resolution_reason": "",
            }
        stored = await self.collection.find_one_and_update(
            {"alert_id": alert_id, "status": previous_status.value},
            update,
            return_document=ReturnDocument.AFTER,
        )
        return self._to_alert(stored)

    @staticmethod
    def _to_alert(item: dict[str, Any] | None) -> Alert | None:
        if item is None:
            return None
        try:
            return Alert(
                alert_id=str(UUID(item["alert_id"])),
                rule_id=item["rule_id"],
                rule_version=int(item["rule_version"]),
                title=item["title"],
                summary=item["summary"],
                severity=AlertSeverity(item["severity"]),
                status=AlertStatus(item["status"]),
                endpoint_id=str(UUID(item["endpoint_id"])),
                endpoint_device_name=item["endpoint_context"]["device_name"],
                assigned_employee_id=item["assigned_employee_id"],
                assigned_employee_username=item["assigned_employee_context"]["username"],
                assigned_employee_display_name=item["assigned_employee_context"]["display_name"],
                created_at=_utc(item["created_at"]),
                updated_at=_utc(item["updated_at"]),
                source_events=tuple(dict(source) for source in item["source_events"]),
                deduplication_key=item["deduplication_key"],
                status_history=tuple(
                    {**entry, "changed_at": _utc(entry.get("changed_at"))}
                    for entry in item.get("status_history", ())
                ),
                resolved_at=_utc(item.get("resolved_at")),
                resolved_by=item.get("resolved_by"),
                resolution_reason=item.get("resolution_reason"),
            )
        except (KeyError, TypeError, ValueError):
            return None


class BuiltInRuleEvaluator:
    """Evaluate the small, versioned built-in rule set synchronously on ingestion."""

    def __init__(self, raw_events: Any, alerts: Any, endpoints: Any, users: Any) -> None:
        self.raw_events = raw_events
        self.alerts = alerts
        self.endpoints = endpoints
        self.users = users

    async def evaluate(self, event: StoredRawEvent) -> None:
        if event.event_type == "removable.file_created":
            await self._create_direct(
                event,
                REMOVABLE_WRITE_RULE_ID,
                "File created on removable storage on the assigned endpoint.",
            )
            await self._correlate_possible_transfer(event)
        elif event.event_type == "filesystem.file_moved_out":
            await self._create_direct(
                event,
                PROTECTED_MOVE_OUT_RULE_ID,
                "Protected file moved outside the protected folder on the assigned endpoint.",
            )

    async def _create_direct(
        self, event: StoredRawEvent, rule_id: str, summary: str
    ) -> Alert:
        return await self._create_alert(rule_id, event, (event,), summary)

    async def _correlate_possible_transfer(self, removable_event: StoredRawEvent) -> None:
        removable_name = _safe_filename_evidence(removable_event.payload)
        if removable_name is None:
            return
        candidates = await self.raw_events.find_protected_correlation_candidates(
            removable_event.endpoint_id,
            occurred_from=removable_event.occurred_at - CORRELATION_WINDOW,
            occurred_to=removable_event.occurred_at,
            limit=100,
        )
        matches = [
            candidate
            for candidate in candidates
            if _safe_filename_evidence(candidate.payload) == removable_name
        ]
        if not matches:
            return
        # Nearest prior observation wins. UUID ordering makes equal timestamps stable.
        protected_event = sorted(
            matches,
            key=lambda item: (
                -(item.occurred_at - datetime(1970, 1, 1, tzinfo=UTC)).total_seconds(),
                item.event_id,
            ),
        )[0]
        await self._create_alert(
            POSSIBLE_TRANSFER_RULE_ID,
            removable_event,
            (protected_event, removable_event),
            "Possible protected-file transfer to removable storage based on correlated endpoint events.",
        )

    async def _create_alert(
        self,
        rule_id: str,
        triggering_event: StoredRawEvent,
        sources: tuple[StoredRawEvent, ...],
        summary: str,
    ) -> Alert:
        endpoint = await self.endpoints.find_by_endpoint_id(triggering_event.endpoint_id)
        if endpoint is None:
            raise RuntimeError("Trusted endpoint context is unavailable for rule evaluation.")
        employee = await self.users.find_by_id(endpoint.assigned_user_id)
        if employee is None or employee.role is not Role.EMPLOYEE:
            raise RuntimeError("Trusted assigned employee context is unavailable for rule evaluation.")
        definition = RULE_DEFINITIONS[rule_id]
        ordered_sources = tuple(
            sorted(sources, key=lambda item: (item.occurred_at, item.event_id))
        )
        deduplication_key = _deduplication_key(
            rule_id,
            endpoint.endpoint_id,
            tuple(source.event_id for source in ordered_sources),
        )
        now = datetime.now(UTC)
        document = {
            "alert_id": str(uuid5(ALERT_ID_NAMESPACE, deduplication_key)),
            "rule_id": rule_id,
            "rule_version": definition["version"],
            "title": definition["title"],
            "summary": summary,
            "severity": definition["severity"].value,
            "status": AlertStatus.OPEN.value,
            "status_rank": _status_rank(AlertStatus.OPEN),
            "endpoint_id": endpoint.endpoint_id,
            "endpoint_context": {"device_name": endpoint.device_name},
            "assigned_employee_id": employee.id,
            "assigned_employee_context": {
                "user_id": employee.id,
                "username": employee.username,
                "display_name": employee.display_name,
            },
            "created_at": now,
            "updated_at": now,
            "source_events": [
                {"endpoint_id": source.endpoint_id, "event_id": source.event_id}
                for source in ordered_sources
            ],
            "deduplication_key": deduplication_key,
            "status_history": [],
        }
        return await self.alerts.create_idempotent(document)


class AdministratorAlertService:
    """Bounded alert queries and audited administrator status transitions."""

    _allowed_transitions = {
        AlertStatus.OPEN: {AlertStatus.INVESTIGATING, AlertStatus.RESOLVED},
        AlertStatus.INVESTIGATING: {AlertStatus.RESOLVED},
        AlertStatus.RESOLVED: {AlertStatus.OPEN},
    }

    def __init__(
        self,
        alerts: Any,
        endpoints: Any,
        users: Any,
        raw_event_view: Any,
        audit: Any,
    ) -> None:
        self.alerts = alerts
        self.endpoints = endpoints
        self.users = users
        self.raw_event_view = raw_event_view
        self.audit = audit

    async def list_alerts(
        self,
        *,
        status: str = "",
        severity: str = "",
        endpoint_id: str = "",
        employee_id: str = "",
        rule_id: str = "",
        page: int = 1,
    ) -> AlertPage:
        directory = await self.endpoints.list_all()
        employees = [user for user in await self.users.list_users() if user.role is Role.EMPLOYEE]
        selected_status = _parse_enum(AlertStatus, status)
        selected_severity = _parse_enum(AlertSeverity, severity)
        selected_endpoint = endpoint_id.strip() or None
        selected_rule = rule_id.strip() or None
        selected_employee: Any = None
        invalid = (bool(status.strip()) and selected_status is None) or (
            bool(severity.strip()) and selected_severity is None
        )
        if selected_endpoint and selected_endpoint not in {item.endpoint_id for item in directory}:
            invalid = True
        if selected_rule and selected_rule not in RULE_DEFINITIONS:
            invalid = True
        if employee_id.strip():
            employee_by_string = {str(item.id): item.id for item in employees}
            selected_employee = employee_by_string.get(employee_id.strip())
            if selected_employee is None:
                invalid = True
        normalized_page = max(1, page)
        if invalid:
            return AlertPage([], False, normalized_page)
        items = await self.alerts.list_filtered(
            status=selected_status,
            severity=selected_severity,
            endpoint_id=selected_endpoint,
            employee_id=selected_employee,
            rule_id=selected_rule,
            skip=(normalized_page - 1) * MAX_ALERT_RESULTS,
            limit=MAX_ALERT_RESULTS + 1,
        )
        return AlertPage(items[:MAX_ALERT_RESULTS], len(items) > MAX_ALERT_RESULTS, normalized_page)

    async def find_alert(self, alert_id: str) -> AdministratorAlert | None:
        try:
            normalized = str(UUID(alert_id))
        except (TypeError, ValueError):
            return None
        alert = await self.alerts.find_by_alert_id(normalized)
        if alert is None:
            return None
        endpoint = await self.endpoints.find_by_endpoint_id(alert.endpoint_id)
        employee = await self.users.find_by_id(alert.assigned_employee_id)
        evidence: list[AdministratorRawEvent] = []
        for source in alert.source_events:
            event = await self.raw_event_view.find_event(
                source["endpoint_id"], source["event_id"]
            )
            if event is not None:
                evidence.append(event)
        return AdministratorAlert(alert, endpoint, employee, tuple(evidence))

    async def transition(
        self,
        alert_id: str,
        new_status_value: str,
        reason: str,
        *,
        actor: User,
        source_ip: str | None,
        user_agent: str | None,
    ) -> Alert:
        normalized_reason = " ".join(reason.split())
        if not normalized_reason or len(normalized_reason) > MAX_REVIEW_REASON_LENGTH:
            raise InvalidAlertReviewReason(
                f"Review reason must be between 1 and {MAX_REVIEW_REASON_LENGTH} characters."
            )
        try:
            normalized_id = str(UUID(alert_id))
            new_status = AlertStatus(new_status_value.strip())
        except (TypeError, ValueError) as exc:
            raise InvalidAlertTransition("Select a valid alert status.") from exc
        current = await self.alerts.find_by_alert_id(normalized_id)
        if current is None:
            raise AlertNotFound
        if new_status not in self._allowed_transitions[current.status]:
            raise InvalidAlertTransition(
                f"Alert cannot move from {current.status.value} to {new_status.value}."
            )
        changed_at = datetime.now(UTC)
        updated = await self.alerts.transition_status(
            normalized_id,
            current.status,
            new_status,
            normalized_reason,
            changed_at,
            actor,
        )
        if updated is None:
            raise InvalidAlertTransition("Alert status changed concurrently; review and retry.")
        await self.audit.record(
            "alert.status_changed",
            username=current.assigned_employee_username,
            user_id=current.assigned_employee_id,
            source_ip=source_ip,
            user_agent=user_agent,
            outcome="success",
            reason=normalized_reason,
            actor_username=actor.username,
            actor_user_id=actor.id,
            resource_id=current.alert_id,
            context={
                "alert_id": current.alert_id,
                "rule_id": current.rule_id,
                "rule_version": current.rule_version,
                "endpoint_id": current.endpoint_id,
                "assigned_employee_id": str(current.assigned_employee_id),
                "previous_status": current.status.value,
                "new_status": new_status.value,
                "changed_at": changed_at.isoformat(),
            },
        )
        return updated

    async def filter_options(self) -> tuple[list[Any], list[Any]]:
        return await self.endpoints.list_all(), [
            user for user in await self.users.list_users() if user.role is Role.EMPLOYEE
        ]


def _safe_filename_evidence(payload: dict[str, Any]) -> tuple[str, str] | None:
    path = _safe_filesystem_display_text(payload.get("relative_path"), 1024)
    extension = _safe_filesystem_display_text(payload.get("extension"), 32)
    if path is None or extension is None:
        return None
    name = PurePosixPath(path).name
    derived_extension = PurePosixPath(name).suffix
    if not derived_extension or extension.casefold() != derived_extension.casefold():
        return None
    return name.casefold(), derived_extension.casefold()


def _deduplication_key(rule_id: str, endpoint_id: str, event_ids: tuple[str, ...]) -> str:
    material = "\x1f".join((rule_id, endpoint_id, *event_ids)).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _status_rank(status: AlertStatus) -> int:
    return {
        AlertStatus.OPEN: 0,
        AlertStatus.INVESTIGATING: 1,
        AlertStatus.RESOLVED: 2,
    }[status]


def _utc(value: Any) -> Any:
    if not isinstance(value, datetime):
        return value
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _parse_enum(enum_type: Any, value: str) -> Any | None:
    if not value.strip():
        return None
    try:
        return enum_type(value.strip())
    except ValueError:
        return None
