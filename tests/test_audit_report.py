"""Administrator audit-report filtering and safe CSV unit tests."""

import asyncio
import csv
from datetime import UTC, datetime, timedelta
from io import StringIO

import pytest

from app.audit_report import AuditReportService, records_to_csv
from app.auth import AuditService
from app.models import Role, User


class AuditRepository:
    def __init__(self, events):
        self.events = events
        self.appended = []

    async def append(self, event):
        self.appended.append(dict(event))

    async def list_recent(self, query, *, limit):
        items = sorted(self.events, key=lambda item: item["occurred_at"], reverse=True)
        if query.get("event_type"):
            items = [item for item in items if item["event_type"] == query["event_type"]]
        if "$or" in query:
            actor = query["$or"][0]["actor_username"]
            items = [item for item in items if item.get("actor_username") == actor or item.get("username") == actor]
        if "occurred_at" in query:
            dates = query["occurred_at"]
            items = [item for item in items if dates.get("$gte", item["occurred_at"]) <= item["occurred_at"] <= dates.get("$lte", item["occurred_at"])]
        return items[:limit]

    async def find_by_ids(self, ids):
        return [item for item in self.events if item["_id"] in ids]


def event(identifier, when, **values):
    return {"_id": identifier, "event_type": "vault.downloaded", "occurred_at": when,
            "username": "employee", "outcome": "success", **values}


def test_audit_filter_is_newest_first_and_export_is_allowlisted_and_audited():
    now = datetime.now(UTC)
    repository = AuditRepository([
        event("old", now - timedelta(hours=2), actor_username="admin"),
        event("new", now - timedelta(hours=1), actor_username="admin", resource_id="doc-1",
              context={"exported_record_count": 3, "password_hash": "must-not-leak"}, password_hash="also-hidden"),
        event("other", now, event_type="authentication.login_failed", username="other"),
    ])
    audit = AuditService(repository)
    service = AuditReportService(repository, audit)

    records, has_more = asyncio.run(service.list_records(
        event_type="vault.downloaded", actor="admin", occurred_from=now - timedelta(days=1), occurred_to=now
    ))
    assert [record.id for record in records] == ["new", "old"]
    assert not has_more

    administrator = User("admin-id", "admin", "hash", Role.ADMINISTRATOR, True)
    exported = asyncio.run(service.export_selected(["new", "missing"], administrator=administrator))
    rows = list(csv.reader(StringIO(records_to_csv(exported))))
    assert rows[1][0] == "new"
    assert "must-not-leak" not in " ".join(rows[1])
    assert repository.appended[-1]["event_type"] == "audit.records_exported"
    assert repository.appended[-1]["context"] == {"exported_record_count": 1}


def test_csv_quotes_newlines_and_formula_cells_are_safe():
    now = datetime.now(UTC)
    repository = AuditRepository([event("one", now, reason='=SUM(1,1) "quoted"\nnext')])
    service = AuditReportService(repository, AuditService(repository))
    record = asyncio.run(service.find_record("one"))
    rows = list(csv.reader(StringIO(records_to_csv([record]))))
    assert rows[1][6] == "'=SUM(1,1) \"quoted\"\nnext"


def test_export_requires_a_stored_selection():
    repository = AuditRepository([])
    service = AuditReportService(repository, AuditService(repository))
    administrator = User("admin-id", "admin", "hash", Role.ADMINISTRATOR, True)
    with pytest.raises(ValueError, match="Select at least one"):
        asyncio.run(service.export_selected([], administrator=administrator))
    assert not repository.appended
