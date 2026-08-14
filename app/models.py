"""Small domain models shared by authentication modules."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any


class Role(StrEnum):
    """Roles currently implemented by NepShield."""

    EMPLOYEE = "employee"
    ADMINISTRATOR = "administrator"


class AccessRequestStatus(StrEnum):
    """Lifecycle states retained for every document access request."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class DocumentAccessKind(StrEnum):
    """Central read-authorization outcomes, including future lock overrides."""

    OWNER = "owner"
    SHARED = "shared"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"
    LOCKED = "locked"
    UNUSABLE = "unusable"
    NOT_FOUND = "not_found"


class DocumentState(StrEnum):
    """Administrator-governed state of encrypted document content."""

    ACTIVE = "active"
    LOCKED = "locked"


@dataclass(frozen=True)
class User:
    """Authenticated user data safe to pass to routes and templates."""

    id: Any
    username: str
    password_hash: str
    role: Role
    enabled: bool
    display_name: str = ""
    created_at: datetime | None = None


@dataclass(frozen=True)
class VaultDocument:
    """Metadata for encrypted content owned by one employee."""

    id: Any
    owner_id: Any
    original_filename: str
    media_type: str
    plaintext_size: int
    storage_name: str
    nonce: bytes
    created_at: datetime
    usable: bool = True
    state: DocumentState = DocumentState.ACTIVE
    locked_at: datetime | None = None
    locked_by: Any = None
    lock_reason: str | None = None


@dataclass(frozen=True)
class AccessRequest:
    """A retained employee request; approval is not itself file permission."""

    id: Any
    requester_id: Any
    document_id: Any
    reason: str
    status: AccessRequestStatus
    requested_at: datetime
    decided_at: datetime | None = None
    decided_by: Any = None
    decision_reason: str | None = None
    permission_id: Any = None
    permission_expires_at: datetime | None = None


@dataclass(frozen=True)
class DocumentPermission:
    """The reusable, revocable grantee/document authorization relationship."""

    id: Any
    grantee_id: Any
    document_id: Any
    active: bool
    granted_at: datetime
    granted_by: Any
    source_request_id: Any
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    revoked_by: Any = None
    revocation_reason: str | None = None


@dataclass(frozen=True)
class DocumentAccessDecision:
    """Result returned by the single document-read authorization boundary."""

    kind: DocumentAccessKind
    document: VaultDocument | None = None
    permission: DocumentPermission | None = None
