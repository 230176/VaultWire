"""Safe, employee-facing summaries of retained governance records."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.models import AccessRequestStatus, DocumentState, UnlockRequestStatus, User

ACTIVITY_LIMIT = 50
RECENT_UPDATE_LIMIT = 5

# Only these subject-scoped events may appear in the employee view. Raw endpoint
# events and all other audit context remain administrator-only.
EMPLOYEE_ACTIVITY_TYPES = {
    "vault.document_uploaded": "You uploaded a document to your vault.",
    "vault.document_downloaded": "You downloaded a document from your vault.",
    "vault.shared_document_downloaded": "You downloaded a document shared with you.",
    "vault.access_request_submitted": "You submitted an access request.",
    "vault.access_request_approved": "Your access request was approved.",
    "vault.access_request_rejected": "Your access request was rejected.",
    "vault.unlock_request_submitted": "You submitted an unlock request.",
    "vault.unlock_request_approved": "Your unlock request was approved.",
    "vault.unlock_request_rejected": "Your unlock request was rejected.",
    "vault.document_locked": "One of your documents was locked.",
    "vault.document_unlocked": "One of your documents was unlocked.",
    "vault.permission_revoked": "Your shared-document access was revoked.",
}


@dataclass(frozen=True)
class EmployeeActivity:
    occurred_at: datetime
    label: str


@dataclass(frozen=True)
class EmployeeUpdate:
    occurred_at: datetime
    label: str
    detail: str


def _utc(value: Any) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


class EmployeeTransparencyService:
    """Presents narrowly scoped, human-readable employee transparency data."""

    def __init__(self, audit_repository: Any, access_service: Any, vault_service: Any) -> None:
        self.audit_repository = audit_repository
        self.access_service = access_service
        self.vault_service = vault_service

    async def list_activity(self, user: User) -> list[EmployeeActivity]:
        documents = await self.audit_repository.list_recent(
            {"user_id": user.id, "event_type": {"$in": sorted(EMPLOYEE_ACTIVITY_TYPES)}},
            limit=ACTIVITY_LIMIT,
        )
        return [
            EmployeeActivity(occurred_at, label)
            for document in documents
            if (occurred_at := _utc(document.get("occurred_at"))) is not None
            and (label := EMPLOYEE_ACTIVITY_TYPES.get(document.get("event_type"))) is not None
        ]

    async def recent_updates(self, user: User) -> list[EmployeeUpdate]:
        """Use request/document state, rather than a notification store."""
        updates: list[EmployeeUpdate] = []
        for item in await self.access_service.list_my_requests(user):
            request = item.request
            if request.status in {AccessRequestStatus.APPROVED, AccessRequestStatus.REJECTED} and (occurred_at := _utc(request.decided_at)):
                updates.append(EmployeeUpdate(occurred_at, f"Access request {request.status.value}", item.document.original_filename if item.document else "Document unavailable"))
        for item in await self.access_service.list_my_unlock_requests(user):
            request = item.request
            if request.status in {UnlockRequestStatus.APPROVED, UnlockRequestStatus.REJECTED} and (occurred_at := _utc(request.decided_at)):
                updates.append(EmployeeUpdate(occurred_at, f"Unlock request {request.status.value}", item.document.original_filename if item.document else "Document unavailable"))
        for document in await self.vault_service.list_documents(user):
            if document.state is DocumentState.LOCKED and (occurred_at := _utc(document.locked_at)):
                updates.append(EmployeeUpdate(occurred_at, "Document currently locked", document.original_filename))
        return sorted(updates, key=lambda item: item.occurred_at, reverse=True)[:RECENT_UPDATE_LIMIT]
