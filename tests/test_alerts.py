"""Focused deterministic-rule, durability, and administrator-review tests."""

import asyncio
import re
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

import app.main
from app.alerts import (
    AdministratorAlertService,
    BuiltInRuleEvaluator,
    CORRELATION_WINDOW,
    MongoAlertRepository,
    POSSIBLE_TRANSFER_RULE_ID,
    PROTECTED_MOVE_OUT_RULE_ID,
    REMOVABLE_WRITE_RULE_ID,
)
from app.auth import AuditService
from app.config import settings
from app.dependencies import get_administrator_alert_service, get_auth_service
from app.models import AlertSeverity, AlertStatus, EndpointPlatform, ManagedEndpoint, Role, User
from app.raw_events import AdministratorRawEventService, RawEventEnvelope, RawEventService, StoredRawEvent


class InMemoryUsers:
    def __init__(self):
        now = datetime.now(UTC)
        self.admin = User(ObjectId(), "admin.user", "unused", Role.ADMINISTRATOR, True, "Administrator", now)
        self.employee = User(ObjectId(), "ishant", "unused", Role.EMPLOYEE, True, "Ishant", now)
        self.items = {self.admin.id: self.admin, self.employee.id: self.employee}

    async def find_by_id(self, user_id):
        return self.items.get(user_id)

    async def list_users(self):
        return list(self.items.values())


class InMemoryEndpoints:
    def __init__(self, employee_id):
        self.primary = self._new("NEP-LAPTOP-01", employee_id)
        self.secondary = self._new("NEP-LAPTOP-02", employee_id)
        self.items = {
            self.primary.endpoint_id: self.primary,
            self.secondary.endpoint_id: self.secondary,
        }

    @staticmethod
    def _new(name, employee_id):
        return ManagedEndpoint(
            endpoint_id=str(uuid4()),
            device_name=name,
            assigned_user_id=employee_id,
            platform=EndpointPlatform.WINDOWS,
            active=True,
            credential_digest="digest-only",
            created_at=datetime.now(UTC),
            created_by=ObjectId(),
        )

    async def find_by_endpoint_id(self, endpoint_id):
        return self.items.get(endpoint_id)

    async def list_all(self):
        return list(self.items.values())


class InMemoryRawEvents:
    def __init__(self):
        self.documents = {}
        self.operations = []

    async def store_idempotent(self, endpoint_id, envelope, received_at):
        self.operations.append(("stored", str(envelope.event_id)))
        identity = (endpoint_id, str(envelope.event_id))
        self.documents.setdefault(
            identity,
            StoredRawEvent(
                endpoint_id,
                str(envelope.event_id),
                envelope.event_type,
                envelope.schema_version,
                envelope.occurred_at,
                received_at,
                deepcopy(envelope.payload),
            ),
        )

    async def find_by_identity(self, endpoint_id, event_id):
        return self.documents.get((endpoint_id, event_id))

    async def find_protected_correlation_candidates(
        self, endpoint_id, *, occurred_from, occurred_to, limit
    ):
        return sorted(
            [
                item
                for item in self.documents.values()
                if item.endpoint_id == endpoint_id
                and item.event_type in {"filesystem.file_moved_out", "filesystem.file_deleted"}
                and occurred_from <= item.occurred_at <= occurred_to
            ],
            key=lambda item: (-item.occurred_at.timestamp(), item.event_id),
        )[:limit]

    async def list_recent(self, *, endpoint_ids=None, event_type=None, limit):
        items = list(self.documents.values())
        if endpoint_ids is not None:
            items = [item for item in items if item.endpoint_id in endpoint_ids]
        if event_type is not None:
            items = [item for item in items if item.event_type == event_type]
        return sorted(items, key=lambda item: item.received_at, reverse=True)[:limit]


class InMemoryAlerts:
    def __init__(self):
        self.documents = {}

    async def create_idempotent(self, document):
        self.documents.setdefault(document["deduplication_key"], deepcopy(document))
        return MongoAlertRepository._to_alert(self.documents[document["deduplication_key"]])

    async def find_by_alert_id(self, alert_id):
        return next(
            (
                MongoAlertRepository._to_alert(item)
                for item in self.documents.values()
                if item["alert_id"] == alert_id
            ),
            None,
        )

    async def list_filtered(
        self, *, status, severity, endpoint_id, employee_id, rule_id, skip, limit
    ):
        items = [MongoAlertRepository._to_alert(item) for item in self.documents.values()]
        if status is not None:
            items = [item for item in items if item.status is status]
        if severity is not None:
            items = [item for item in items if item.severity is severity]
        if endpoint_id is not None:
            items = [item for item in items if item.endpoint_id == endpoint_id]
        if employee_id is not None:
            items = [item for item in items if item.assigned_employee_id == employee_id]
        if rule_id is not None:
            items = [item for item in items if item.rule_id == rule_id]
        ranks = {AlertStatus.OPEN: 0, AlertStatus.INVESTIGATING: 1, AlertStatus.RESOLVED: 2}
        items.sort(key=lambda item: (ranks[item.status], -item.created_at.timestamp()))
        return items[skip : skip + limit]

    async def transition_status(
        self, alert_id, previous_status, new_status, reason, changed_at, actor
    ):
        document = next(
            (item for item in self.documents.values() if item["alert_id"] == alert_id), None
        )
        if document is None or document["status"] != previous_status.value:
            return None
        document["status"] = new_status.value
        document["status_rank"] = {
            AlertStatus.OPEN: 0,
            AlertStatus.INVESTIGATING: 1,
            AlertStatus.RESOLVED: 2,
        }[new_status]
        document["updated_at"] = changed_at
        document["status_history"].append(
            {
                "previous_status": previous_status.value,
                "new_status": new_status.value,
                "reason": reason,
                "changed_at": changed_at,
                "administrator_id": actor.id,
                "administrator_username": actor.username,
            }
        )
        if new_status is AlertStatus.RESOLVED:
            document.update(
                resolved_at=changed_at,
                resolved_by=actor.id,
                resolution_reason=reason,
            )
        elif previous_status is AlertStatus.RESOLVED:
            for field in ("resolved_at", "resolved_by", "resolution_reason"):
                document.pop(field, None)
        return MongoAlertRepository._to_alert(document)


class InMemoryAudit:
    def __init__(self):
        self.events = []

    async def append(self, event):
        self.events.append(deepcopy(event))


class FakeAuth:
    def __init__(self, users):
        self.users = users

    async def resolve_session(self, token):
        return {"admin-session": self.users.admin, "employee-session": self.users.employee}.get(token)


class NoopDatabase:
    database = None

    async def connect(self):
        pass

    async def ping(self):
        return True

    async def close(self):
        pass


@pytest.fixture
def alert_context():
    users = InMemoryUsers()
    endpoints = InMemoryEndpoints(users.employee.id)
    raw = InMemoryRawEvents()
    alerts = InMemoryAlerts()
    audit_repository = InMemoryAudit()
    evaluator = BuiltInRuleEvaluator(raw, alerts, endpoints, users)
    ingestion = RawEventService(raw, evaluator)
    raw_view = AdministratorRawEventService(raw, endpoints, users)
    review = AdministratorAlertService(
        alerts, endpoints, users, raw_view, AuditService(audit_repository)
    )
    return users, endpoints, raw, alerts, audit_repository, ingestion, review


def envelope(event_type, occurred_at, payload, event_id=None):
    return RawEventEnvelope.model_validate(
        {
            "event_id": event_id or str(uuid4()),
            "event_type": event_type,
            "schema_version": 1,
            "occurred_at": occurred_at.isoformat(),
            "payload": payload,
        }
    )


def ingest(service, endpoint_id, *events):
    return asyncio.run(service.ingest(endpoint_id, list(events)))


def alert_values(repository):
    return [MongoAlertRepository._to_alert(item) for item in repository.documents.values()]


def removable_payload(path="exports/chapter.docx"):
    return {
        "drive_name": "E:",
        "volume_label": "THESIS_USB",
        "relative_path": path,
        "extension": ".docx",
        "size_bytes": 4096,
    }


def protected_payload(path="drafts/chapter.docx"):
    return {
        "monitored_root": "Thesis",
        "relative_path": path,
        "extension": ".docx",
    }


def test_removable_create_produces_one_medium_alert_and_replay_is_idempotent(alert_context):
    _, endpoints, _, alerts, audit, ingestion, _ = alert_context
    event = envelope("removable.file_created", datetime(2026, 8, 15, 4, 0, tzinfo=UTC), removable_payload())

    first = ingest(ingestion, endpoints.primary.endpoint_id, event)
    second = ingest(ingestion, endpoints.primary.endpoint_id, event)

    stored = alert_values(alerts)
    assert first == second == [str(event.event_id)]
    assert len(stored) == 1
    assert stored[0].rule_id == REMOVABLE_WRITE_RULE_ID
    assert stored[0].severity is AlertSeverity.MEDIUM
    assert stored[0].title == "File created on removable storage"
    assert next(iter(alerts.documents.values()))["assigned_employee_id"] == stored[0].assigned_employee_id
    assert audit.events == []


def test_removable_modification_and_volume_arrival_do_not_create_alerts(alert_context):
    _, endpoints, _, alerts, _, ingestion, _ = alert_context
    now = datetime(2026, 8, 15, 4, 0, tzinfo=UTC)

    ingest(
        ingestion,
        endpoints.primary.endpoint_id,
        envelope("removable.file_modified", now, removable_payload()),
        envelope(
            "removable.volume_arrived",
            now + timedelta(seconds=1),
            {"drive_name": "E:", "drive_type": "removable_disk"},
        ),
    )

    assert alerts.documents == {}


def test_moved_out_produces_one_high_alert_without_destination_claim(alert_context):
    _, endpoints, _, alerts, _, ingestion, _ = alert_context
    event = envelope(
        "filesystem.file_moved_out",
        datetime(2026, 8, 15, 4, 0, tzinfo=UTC),
        {**protected_payload(), "destination_scope": "outside_protected_root"},
    )

    ingest(ingestion, endpoints.primary.endpoint_id, event)

    alert = alert_values(alerts)[0]
    assert alert.rule_id == PROTECTED_MOVE_OUT_RULE_ID
    assert alert.severity is AlertSeverity.HIGH
    assert "outside protected folder" in alert.title
    assert "destination" not in alert.summary.casefold()


def test_matching_same_endpoint_inside_window_creates_high_possible_transfer(alert_context):
    _, endpoints, _, alerts, _, ingestion, _ = alert_context
    protected_at = datetime(2026, 8, 15, 4, 0, tzinfo=UTC)
    protected = envelope("filesystem.file_deleted", protected_at, protected_payload())
    removable = envelope(
        "removable.file_created",
        protected_at + CORRELATION_WINDOW,
        removable_payload("copied/chapter.docx"),
    )

    ingest(ingestion, endpoints.primary.endpoint_id, protected, removable)
    correlated = next(item for item in alert_values(alerts) if item.rule_id == POSSIBLE_TRANSFER_RULE_ID)

    assert correlated.severity is AlertSeverity.HIGH
    assert [source["event_id"] for source in correlated.source_events] == [
        str(protected.event_id),
        str(removable.event_id),
    ]
    wording = f"{correlated.title} {correlated.summary}".casefold()
    assert "possible" in wording and "correlated" in wording
    assert "confirmed copy" not in wording
    assert "exfiltration" not in wording


@pytest.mark.parametrize("case", ["other_endpoint", "outside_window", "filename_mismatch"])
def test_correlation_rejects_unsafe_relationships(alert_context, case):
    _, endpoints, _, alerts, _, ingestion, _ = alert_context
    protected_at = datetime(2026, 8, 15, 4, 0, tzinfo=UTC)
    removable_at = protected_at + timedelta(seconds=60)
    protected_endpoint = endpoints.primary.endpoint_id
    removable_endpoint = endpoints.primary.endpoint_id
    protected_path = "drafts/chapter.docx"
    if case == "other_endpoint":
        protected_endpoint = endpoints.secondary.endpoint_id
    elif case == "outside_window":
        removable_at = protected_at + CORRELATION_WINDOW + timedelta(microseconds=1)
    elif case == "filename_mismatch":
        protected_path = "drafts/another.docx"

    ingest(
        ingestion,
        protected_endpoint,
        envelope("filesystem.file_deleted", protected_at, protected_payload(protected_path)),
    )
    ingest(
        ingestion,
        removable_endpoint,
        envelope("removable.file_created", removable_at, removable_payload()),
    )

    assert all(item.rule_id != POSSIBLE_TRANSFER_RULE_ID for item in alert_values(alerts))


def test_correlation_selects_nearest_match_deterministically_and_cannot_duplicate(alert_context):
    _, endpoints, _, alerts, _, ingestion, _ = alert_context
    base = datetime(2026, 8, 15, 4, 0, tzinfo=UTC)
    older = envelope("filesystem.file_deleted", base, protected_payload())
    nearer = envelope("filesystem.file_deleted", base + timedelta(seconds=50), protected_payload("other/chapter.docx"))
    removable = envelope("removable.file_created", base + timedelta(seconds=60), removable_payload())

    ingest(ingestion, endpoints.primary.endpoint_id, older, nearer, removable)
    ingest(ingestion, endpoints.primary.endpoint_id, removable)

    correlated = [item for item in alert_values(alerts) if item.rule_id == POSSIBLE_TRANSFER_RULE_ID]
    assert len(correlated) == 1
    assert {source["event_id"] for source in correlated[0].source_events} == {
        str(nearer.event_id),
        str(removable.event_id),
    }


def test_raw_event_is_stored_before_evaluation_failure_and_retry_is_safe(alert_context):
    users, endpoints, raw, alerts, _, _, _ = alert_context
    real = BuiltInRuleEvaluator(raw, alerts, endpoints, users)

    class FailAfterEvaluationOnce:
        def __init__(self):
            self.first = True

        async def evaluate(self, event):
            assert (event.endpoint_id, event.event_id) in raw.documents
            raw.operations.append(("evaluated", event.event_id))
            await real.evaluate(event)
            if self.first:
                self.first = False
                raise RuntimeError("temporary rule failure")

    service = RawEventService(raw, FailAfterEvaluationOnce())
    event = envelope("removable.file_created", datetime(2026, 8, 15, 4, 0, tzinfo=UTC), removable_payload())

    with pytest.raises(RuntimeError, match="temporary rule failure"):
        ingest(service, endpoints.primary.endpoint_id, event)
    assert raw.operations[:2] == [("stored", str(event.event_id)), ("evaluated", str(event.event_id))]
    assert (endpoints.primary.endpoint_id, str(event.event_id)) in raw.documents
    assert len(alerts.documents) == 1

    assert ingest(service, endpoints.primary.endpoint_id, event) == [str(event.event_id)]
    assert len(raw.documents) == 1
    assert len(alerts.documents) == 1


@pytest.fixture
def alert_web_context(alert_context, monkeypatch):
    users, endpoints, raw, alerts, audit, ingestion, review = alert_context
    event = envelope("removable.file_created", datetime(2026, 8, 15, 4, 0, tzinfo=UTC), removable_payload())
    ingest(ingestion, endpoints.primary.endpoint_id, event)
    monkeypatch.setattr(app.main, "MongoDatabase", NoopDatabase)
    app.main.app.dependency_overrides[get_auth_service] = lambda: FakeAuth(users)
    app.main.app.dependency_overrides[get_administrator_alert_service] = lambda: review
    try:
        yield users, endpoints, raw, alerts, audit, event, review
    finally:
        app.main.app.dependency_overrides.clear()


def authenticated_client(client, session="admin-session"):
    client.cookies.set(settings.session_cookie_name, session)


def csrf_from(response):
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match
    return match.group(1)


def test_alert_pages_are_administrator_only(alert_web_context):
    with TestClient(app.main.app) as client:
        unauthenticated = client.get("/administrator/alerts", follow_redirects=False)
        authenticated_client(client, "employee-session")
        employee = client.get("/administrator/alerts")

    assert unauthenticated.status_code == 303
    assert unauthenticated.headers["location"] == "/login"
    assert employee.status_code == 403


def test_administrator_list_filters_and_safe_detail_evidence(alert_web_context):
    users, endpoints, _, alerts, _, event, _ = alert_web_context
    alert = alert_values(alerts)[0]
    with TestClient(app.main.app) as client:
        authenticated_client(client)
        page = client.get("/administrator/alerts")
        matching = client.get(
            f"/administrator/alerts?status=open&severity=medium&endpoint={endpoints.primary.endpoint_id}"
            f"&employee={users.employee.id}&rule={REMOVABLE_WRITE_RULE_ID}"
        )
        excluded = client.get("/administrator/alerts?severity=high")
        detail = client.get(f"/administrator/alerts/{alert.alert_id}")

    assert page.status_code == matching.status_code == excluded.status_code == detail.status_code == 200
    assert alert.title in page.text and alert.title in matching.text
    assert "No matching alerts" in excluded.text
    assert "Endpoint assigned to: Ishant" in detail.text
    assert f"/administrator/events/{endpoints.primary.endpoint_id}/{event.event_id}" in detail.text
    assert "View raw event" in detail.text
    assert "does not establish which person performed" in detail.text


def test_status_reason_required_and_full_lifecycle_is_audited(alert_web_context):
    _, _, _, alerts, audit, _, _ = alert_web_context
    alert = alert_values(alerts)[0]
    with TestClient(app.main.app) as client:
        authenticated_client(client)
        detail = client.get(f"/administrator/alerts/{alert.alert_id}")
        missing = client.post(
            f"/administrator/alerts/{alert.alert_id}/status",
            data={"new_status": "investigating", "reason": "", "csrf_token": csrf_from(detail)},
        )
        investigating = client.post(
            f"/administrator/alerts/{alert.alert_id}/status",
            data={"new_status": "investigating", "reason": "Reviewing evidence", "csrf_token": csrf_from(missing)},
            follow_redirects=False,
        )
        detail = client.get(f"/administrator/alerts/{alert.alert_id}")
        resolved = client.post(
            f"/administrator/alerts/{alert.alert_id}/status",
            data={"new_status": "resolved", "reason": "Expected approved activity", "csrf_token": csrf_from(detail)},
            follow_redirects=False,
        )
        detail = client.get(f"/administrator/alerts/{alert.alert_id}")
        reopened = client.post(
            f"/administrator/alerts/{alert.alert_id}/status",
            data={"new_status": "open", "reason": "New evidence requires review", "csrf_token": csrf_from(detail)},
            follow_redirects=False,
        )
        final_detail = client.get(f"/administrator/alerts/{alert.alert_id}")

    current = alert_values(alerts)[0]
    assert missing.status_code == 422
    assert investigating.status_code == resolved.status_code == reopened.status_code == 303
    assert current.status is AlertStatus.OPEN
    assert current.resolved_at is None and current.resolution_reason is None
    assert len(current.status_history) == 3
    assert "Expected approved activity" in final_detail.text
    assert [item["event_type"] for item in audit.events] == ["alert.status_changed"] * 3
    assert audit.events[-1]["context"]["previous_status"] == "resolved"
    assert audit.events[-1]["context"]["new_status"] == "open"
    assert audit.events[-1]["actor_username"] == "admin.user"


def test_direct_open_to_resolved_is_supported(alert_context):
    users, endpoints, _, alerts, audit, ingestion, review = alert_context
    event = envelope("removable.file_created", datetime(2026, 8, 15, 4, 0, tzinfo=UTC), removable_payload())
    ingest(ingestion, endpoints.primary.endpoint_id, event)
    alert = alert_values(alerts)[0]

    resolved = asyncio.run(
        review.transition(
            alert.alert_id,
            "resolved",
            "Reviewed directly",
            actor=users.admin,
            source_ip="127.0.0.1",
            user_agent="pytest",
        )
    )

    assert resolved.status is AlertStatus.RESOLVED
    assert resolved.resolved_by == users.admin.id
    assert resolved.resolution_reason == "Reviewed directly"
    assert len(audit.events) == 1


def test_disabling_current_user_and_endpoint_does_not_erase_historical_alert(alert_web_context):
    users, endpoints, _, alerts, _, _, _ = alert_web_context
    alert = alert_values(alerts)[0]
    users.items[users.employee.id] = replace(users.employee, enabled=False)
    endpoints.items[endpoints.primary.endpoint_id] = replace(endpoints.primary, active=False)

    with TestClient(app.main.app) as client:
        authenticated_client(client)
        detail = client.get(f"/administrator/alerts/{alert.alert_id}")

    assert detail.status_code == 200
    assert len(alerts.documents) == 1
    assert "Account currently disabled" in detail.text
    assert "Currently disabled" in detail.text
    assert "Endpoint assigned to: Ishant" in detail.text


class IndexCollection:
    def __init__(self):
        self.create_calls = []

    async def create_index(self, keys, **options):
        self.create_calls.append((keys, options))


def test_alert_repository_creates_unique_deduplication_and_query_indexes():
    collection = IndexCollection()
    repository = MongoAlertRepository({"alerts": collection})

    asyncio.run(repository.ensure_indexes())

    options = {item[1]["name"]: item for item in collection.create_calls}
    assert options["unique_alert_id"][1]["unique"] is True
    assert options["unique_alert_deduplication_key"] == (
        "deduplication_key",
        {"unique": True, "name": "unique_alert_deduplication_key"},
    )
    assert {
        "active_alert_review_order",
        "endpoint_alerts",
        "employee_alerts",
        "rule_alerts",
    } <= set(options)
