"""Controlled non-owner document access and centralized read authorization."""

from dataclasses import dataclass
from datetime import UTC, datetime
import secrets
from typing import Any

from bson import ObjectId

from app.auth import AuditService
from app.models import (
    AccessRequest,
    AccessRequestStatus,
    DocumentAccessDecision,
    DocumentAccessKind,
    DocumentPermission,
    DocumentState,
    Role,
    User,
    VaultDocument,
)
from app.repositories import DuplicatePendingAccessRequestError

MAXIMUM_REASON_LENGTH = 1_000


class InvalidAccessReason(ValueError):
    pass


class DuplicateAccessRequest(ValueError):
    pass


class AccessRequestNotFound(LookupError):
    pass


class AccessRequestNotPending(ValueError):
    pass


class DocumentNotRequestable(LookupError):
    pass


class PermissionNotRevocable(LookupError):
    pass


class InvalidPermissionExpiry(ValueError):
    pass


class DocumentStateTransitionError(ValueError):
    pass


class DocumentGovernanceNotFound(LookupError):
    pass


@dataclass(frozen=True)
class RequestableDocumentView:
    document: VaultDocument
    owner: User | None
    latest_request: AccessRequest | None
    access_kind: DocumentAccessKind


@dataclass(frozen=True)
class AccessRequestView:
    request: AccessRequest
    document: VaultDocument | None
    requester: User | None
    owner: User | None
    decider: User | None
    permission: DocumentPermission | None


@dataclass(frozen=True)
class SharedDocumentView:
    permission: DocumentPermission
    document: VaultDocument
    owner: User | None
    access_kind: DocumentAccessKind


@dataclass(frozen=True)
class GovernanceDocumentView:
    document: VaultDocument
    owner: User | None
    locking_administrator: User | None


@dataclass(frozen=True)
class PermissionView:
    permission: DocumentPermission
    document: VaultDocument | None
    grantee: User | None
    owner: User | None
    access_kind: DocumentAccessKind


def utc_datetime(value: datetime | None) -> datetime | None:
    """Normalize stored and submitted datetimes to timezone-aware UTC."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def validate_reason(reason: str, *, label: str) -> str:
    normalized = reason.strip()
    if not normalized:
        raise InvalidAccessReason(f"{label} is required.")
    if len(normalized) > MAXIMUM_REASON_LENGTH:
        raise InvalidAccessReason(
            f"{label} must be {MAXIMUM_REASON_LENGTH} characters or fewer."
        )
    return normalized


class DocumentAuthorizationService:
    """The only policy boundary for document reads.

    Usability and governance state are checked before ownership or sharing so a
    document lock overrides both without changing permission records or download
    routes.
    """

    def __init__(self, documents: Any, permissions: Any) -> None:
        self.documents = documents
        self.permissions = permissions

    async def authorize_read(
        self, actor: User, document_id: Any, *, now: datetime | None = None
    ) -> DocumentAccessDecision:
        document = await self.documents.find_by_id(document_id)
        if document is None:
            return DocumentAccessDecision(DocumentAccessKind.NOT_FOUND)
        if not document.usable:
            return DocumentAccessDecision(DocumentAccessKind.UNUSABLE, document)
        if document.state is DocumentState.LOCKED:
            return DocumentAccessDecision(DocumentAccessKind.LOCKED, document)
        if actor.role is not Role.EMPLOYEE:
            return DocumentAccessDecision(DocumentAccessKind.DENIED, document)
        if document.owner_id == actor.id:
            return DocumentAccessDecision(DocumentAccessKind.OWNER, document)

        permission = await self.permissions.find_relationship(actor.id, document.id)
        if permission is None:
            return DocumentAccessDecision(DocumentAccessKind.DENIED, document)
        kind = self.permission_access_kind(permission, now=now)
        return DocumentAccessDecision(kind, document, permission)

    @staticmethod
    def permission_access_kind(
        permission: DocumentPermission, *, now: datetime | None = None
    ) -> DocumentAccessKind:
        if not permission.active or permission.revoked_at is not None:
            return DocumentAccessKind.REVOKED
        expires_at = utc_datetime(permission.expires_at)
        checked_at = utc_datetime(now) if now is not None else datetime.now(UTC)
        if expires_at is not None and expires_at <= checked_at:
            return DocumentAccessKind.EXPIRED
        return DocumentAccessKind.SHARED


class AccessControlService:
    """Application workflow for requests, decisions, permissions, and listings."""

    def __init__(
        self,
        documents: Any,
        requests: Any,
        permissions: Any,
        users: Any,
        audit: AuditService,
        authorization: DocumentAuthorizationService | None = None,
    ) -> None:
        self.documents = documents
        self.requests = requests
        self.permissions = permissions
        self.users = users
        self.audit = audit
        self.authorization = authorization or DocumentAuthorizationService(
            documents, permissions
        )

    async def submit_request(
        self,
        requester: User,
        document_id: str,
        reason: str,
        *,
        source_ip: str | None,
        user_agent: str | None,
    ) -> AccessRequest:
        normalized_reason = validate_reason(reason, label="Request reason")
        parsed_document_id = self._object_id(document_id)
        document = await self.documents.find_by_id(parsed_document_id)
        if (
            requester.role is not Role.EMPLOYEE
            or document is None
            or not document.usable
            or document.state is not DocumentState.ACTIVE
            or document.owner_id == requester.id
        ):
            raise DocumentNotRequestable

        decision = await self.authorization.authorize_read(requester, document.id)
        if decision.kind is DocumentAccessKind.SHARED:
            raise DuplicateAccessRequest("You already have access to this document.")
        if await self.requests.find_pending(requester.id, document.id) is not None:
            raise DuplicateAccessRequest(
                "You already have a pending request for this document."
            )

        request = AccessRequest(
            id=ObjectId(),
            requester_id=requester.id,
            document_id=document.id,
            reason=normalized_reason,
            status=AccessRequestStatus.PENDING,
            requested_at=datetime.now(UTC),
        )
        try:
            await self.requests.create(request)
        except DuplicatePendingAccessRequestError as exc:
            raise DuplicateAccessRequest(
                "You already have a pending request for this document."
            ) from exc
        await self.audit.record(
            "vault.access_request_submitted",
            username=requester.username,
            user_id=requester.id,
            source_ip=source_ip,
            user_agent=user_agent,
            outcome="success",
            resource_id=document.id,
            context={
                "request_id": request.id,
                "requester_id": requester.id,
                "document_owner_id": document.owner_id,
            },
        )
        return request

    async def decide_request(
        self,
        administrator: User,
        request_id: str,
        decision: str,
        reason: str,
        expires_at: datetime | None,
        *,
        source_ip: str | None,
        user_agent: str | None,
    ) -> AccessRequest:
        if administrator.role is not Role.ADMINISTRATOR:
            raise AccessRequestNotFound
        normalized_reason = validate_reason(reason, label="Decision reason")
        parsed_request_id = self._object_id(request_id)
        request = await self.requests.find_by_id(parsed_request_id)
        if request is None:
            raise AccessRequestNotFound
        if request.status is not AccessRequestStatus.PENDING:
            raise AccessRequestNotPending("This access request has already been decided.")
        document = await self.documents.find_by_id(request.document_id)
        if document is None or not document.usable:
            raise DocumentNotRequestable

        normalized_decision = decision.strip().casefold()
        now = datetime.now(UTC)
        permission = None
        normalized_expiry = utc_datetime(expires_at)
        if normalized_decision == AccessRequestStatus.APPROVED.value:
            if document.state is not DocumentState.ACTIVE:
                raise DocumentNotRequestable
            requester = await self.users.find_by_id(request.requester_id)
            if (
                requester is None
                or requester.role is not Role.EMPLOYEE
                or document.owner_id == requester.id
            ):
                raise DocumentNotRequestable
            if normalized_expiry is not None and normalized_expiry <= now:
                raise InvalidPermissionExpiry("Permission expiry must be in the future.")
            status = AccessRequestStatus.APPROVED
        elif normalized_decision == AccessRequestStatus.REJECTED.value:
            requester = await self.users.find_by_id(request.requester_id)
            status = AccessRequestStatus.REJECTED
            normalized_expiry = None
        else:
            raise ValueError("Decision must be approve or reject.")

        claim_token = secrets.token_urlsafe(24)
        if not await self.requests.claim_pending(request.id, claim_token, now):
            raise AccessRequestNotPending("This access request has already been decided.")
        try:
            if status is AccessRequestStatus.APPROVED:
                permission = await self.permissions.activate(
                    request.requester_id,
                    request.document_id,
                    now,
                    administrator.id,
                    request.id,
                    normalized_expiry,
                )
            decided = await self.requests.decide_pending(
                request.id,
                claim_token,
                status,
                now,
                administrator.id,
                normalized_reason,
                permission.id if permission is not None else None,
                permission.expires_at if permission is not None else None,
            )
            if decided is None:
                raise AccessRequestNotPending(
                    "This access request has already been decided."
                )
        except Exception:
            if permission is not None:
                await self.permissions.revoke(
                    permission.id,
                    datetime.now(UTC),
                    administrator.id,
                    "approval_not_finalized",
                )
            await self.requests.release_claim(request.id, claim_token)
            raise
        await self.audit.record(
            f"vault.access_request_{status.value}",
            username=requester.username if requester else str(request.requester_id),
            user_id=request.requester_id,
            source_ip=source_ip,
            user_agent=user_agent,
            outcome="success",
            reason=normalized_reason,
            actor_username=administrator.username,
            actor_user_id=administrator.id,
            resource_id=request.document_id,
            context={
                "request_id": request.id,
                "requester_id": request.requester_id,
                "permission_id": permission.id if permission else None,
                "expires_at": permission.expires_at if permission else None,
            },
        )
        return decided

    async def revoke_permission(
        self,
        administrator: User,
        permission_id: str,
        reason: str,
        *,
        source_ip: str | None,
        user_agent: str | None,
    ) -> DocumentPermission:
        if administrator.role is not Role.ADMINISTRATOR:
            raise PermissionNotRevocable
        normalized_reason = validate_reason(reason, label="Revocation reason")
        parsed_permission_id = self._object_id(permission_id)
        current = await self.permissions.find_by_id(parsed_permission_id)
        if current is None or not current.active or current.revoked_at is not None:
            raise PermissionNotRevocable
        permission = await self.permissions.revoke(
            current.id, datetime.now(UTC), administrator.id, normalized_reason
        )
        if permission is None:
            raise PermissionNotRevocable
        grantee = await self.users.find_by_id(permission.grantee_id)
        await self.audit.record(
            "vault.permission_revoked",
            username=grantee.username if grantee else str(permission.grantee_id),
            user_id=permission.grantee_id,
            source_ip=source_ip,
            user_agent=user_agent,
            outcome="success",
            reason=normalized_reason,
            actor_username=administrator.username,
            actor_user_id=administrator.id,
            resource_id=permission.document_id,
            context={
                "permission_id": permission.id,
                "grantee_id": permission.grantee_id,
                "source_request_id": permission.source_request_id,
            },
        )
        return permission

    async def list_requestable(self, requester: User) -> list[RequestableDocumentView]:
        documents = await self.documents.list_usable_not_owned(requester.id)
        requests = await self.requests.list_for_requester(requester.id)
        latest = {}
        for request in requests:
            latest.setdefault(request.document_id, request)
        views = []
        for document in documents:
            owner = await self.users.find_by_id(document.owner_id)
            decision = await self.authorization.authorize_read(requester, document.id)
            views.append(
                RequestableDocumentView(
                    document, owner, latest.get(document.id), decision.kind
                )
            )
        return views

    async def list_my_requests(self, requester: User) -> list[AccessRequestView]:
        return [
            await self._request_view(request)
            for request in await self.requests.list_for_requester(requester.id)
        ]

    async def list_all_requests(self) -> list[AccessRequestView]:
        return [
            await self._request_view(request)
            for request in await self.requests.list_all()
        ]

    async def list_shared_with_me(self, grantee: User) -> list[SharedDocumentView]:
        views = []
        for permission in await self.permissions.list_for_grantee(grantee.id):
            if self.authorization.permission_access_kind(permission) is not DocumentAccessKind.SHARED:
                continue
            document = await self.documents.find_by_id(permission.document_id)
            if document is None or not document.usable:
                continue
            decision = await self.authorization.authorize_read(grantee, document.id)
            if decision.kind not in {DocumentAccessKind.SHARED, DocumentAccessKind.LOCKED}:
                continue
            owner = await self.users.find_by_id(document.owner_id)
            views.append(SharedDocumentView(permission, document, owner, decision.kind))
        return views

    async def list_governance_documents(
        self, administrator: User
    ) -> list[GovernanceDocumentView]:
        if administrator.role is not Role.ADMINISTRATOR:
            raise DocumentGovernanceNotFound
        views = []
        for document in await self.documents.list_all():
            owner = await self.users.find_by_id(document.owner_id)
            locking_administrator = (
                await self.users.find_by_id(document.locked_by)
                if document.locked_by is not None
                else None
            )
            views.append(GovernanceDocumentView(document, owner, locking_administrator))
        return views

    async def change_document_state(
        self,
        administrator: User,
        document_id: str,
        target_state: DocumentState,
        reason: str,
        *,
        source_ip: str | None,
        user_agent: str | None,
    ) -> VaultDocument:
        if administrator.role is not Role.ADMINISTRATOR:
            raise DocumentGovernanceNotFound
        label = "Lock reason" if target_state is DocumentState.LOCKED else "Unlock reason"
        normalized_reason = validate_reason(reason, label=label)
        try:
            parsed_document_id = ObjectId(document_id)
        except Exception as exc:
            raise DocumentGovernanceNotFound from exc
        expected_state = (
            DocumentState.ACTIVE
            if target_state is DocumentState.LOCKED
            else DocumentState.LOCKED
        )
        changed_at = datetime.now(UTC)
        document = await self.documents.transition_state(
            parsed_document_id,
            expected_state,
            target_state,
            changed_at,
            administrator.id,
            normalized_reason,
        )
        if document is None:
            existing = await self.documents.find_by_id(parsed_document_id)
            if existing is None or not existing.usable:
                raise DocumentGovernanceNotFound
            raise DocumentStateTransitionError(
                f"Document is already {existing.state.value}."
            )
        owner = await self.users.find_by_id(document.owner_id)
        await self.audit.record(
            "vault.document_locked"
            if target_state is DocumentState.LOCKED
            else "vault.document_unlocked",
            username=owner.username if owner else str(document.owner_id),
            user_id=document.owner_id,
            source_ip=source_ip,
            user_agent=user_agent,
            outcome="success",
            reason=normalized_reason,
            actor_username=administrator.username,
            actor_user_id=administrator.id,
            resource_id=document.id,
            context={
                "document_owner_id": document.owner_id,
                "previous_state": expected_state.value,
                "state": target_state.value,
                "transitioned_at": changed_at,
            },
        )
        return document

    async def list_permissions(self) -> list[PermissionView]:
        views = []
        for permission in await self.permissions.list_all():
            document = await self.documents.find_by_id(permission.document_id)
            grantee = await self.users.find_by_id(permission.grantee_id)
            owner = await self.users.find_by_id(document.owner_id) if document else None
            if grantee is not None:
                access_kind = (
                    await self.authorization.authorize_read(grantee, permission.document_id)
                ).kind
            else:
                access_kind = DocumentAccessKind.DENIED
            views.append(PermissionView(permission, document, grantee, owner, access_kind))
        return views

    async def _request_view(self, request: AccessRequest) -> AccessRequestView:
        document = await self.documents.find_by_id(request.document_id)
        requester = await self.users.find_by_id(request.requester_id)
        owner = await self.users.find_by_id(document.owner_id) if document else None
        decider = (
            await self.users.find_by_id(request.decided_by)
            if request.decided_by is not None
            else None
        )
        permission = (
            await self.permissions.find_by_id(request.permission_id)
            if request.permission_id is not None
            else None
        )
        return AccessRequestView(
            request, document, requester, owner, decider, permission
        )

    @staticmethod
    def _object_id(value: str) -> ObjectId:
        try:
            return ObjectId(value)
        except Exception as exc:
            raise DocumentNotRequestable from exc
