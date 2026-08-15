"""Employee transparency scoping and presentation tests."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from app.employee_transparency import ACTIVITY_LIMIT, EmployeeTransparencyService
from app.models import AccessRequestStatus, Role, UnlockRequestStatus, User


class AuditRepository:
    def __init__(self, records):
        self.records = records
        self.query = None
        self.limit = None

    async def list_recent(self, query, *, limit):
        self.query, self.limit = query, limit
        return self.records


class EmptyAccess:
    async def list_my_requests(self, user):
        return []

    async def list_my_unlock_requests(self, user):
        return []


class EmptyVault:
    async def list_documents(self, user):
        return []


def test_activity_is_subject_scoped_bounded_and_does_not_render_raw_context():
    employee = User(7, "employee.a", "unused", Role.EMPLOYEE, True)
    now = datetime.now(UTC)
    repository = AuditRepository([
        {"event_type": "vault.access_request_approved", "occurred_at": now, "context": {"endpoint_secret": "never show"}},
        {"event_type": "endpoint.policy_updated", "occurred_at": now - timedelta(seconds=1)},
    ])
    service = EmployeeTransparencyService(repository, EmptyAccess(), EmptyVault())

    activity = asyncio.run(service.list_activity(employee))

    assert repository.query["user_id"] == employee.id
    assert repository.query["event_type"]["$in"]
    assert repository.limit == ACTIVITY_LIMIT
    assert [item.label for item in activity] == ["Your access request was approved."]
    assert "never show" not in activity[0].label


def test_recent_updates_show_only_decided_employee_request_outcomes():
    now = datetime.now(UTC)
    employee = User(7, "employee.a", "unused", Role.EMPLOYEE, True)
    access = SimpleNamespace(
        list_my_requests=lambda user: _async([SimpleNamespace(
            request=SimpleNamespace(status=AccessRequestStatus.APPROVED, decided_at=now),
            document=SimpleNamespace(original_filename="shared-plan.pdf"),
        )]),
        list_my_unlock_requests=lambda user: _async([SimpleNamespace(
            request=SimpleNamespace(status=UnlockRequestStatus.REJECTED, decided_at=now - timedelta(seconds=1)),
            document=SimpleNamespace(original_filename="own-plan.pdf"),
        )]),
    )
    vault = SimpleNamespace(list_documents=lambda user: _async([]))
    updates = asyncio.run(EmployeeTransparencyService(AuditRepository([]), access, vault).recent_updates(employee))

    assert [(item.label, item.detail) for item in updates] == [
        ("Access request approved", "shared-plan.pdf"),
        ("Unlock request rejected", "own-plan.pdf"),
    ]


async def _async(value):
    return value
