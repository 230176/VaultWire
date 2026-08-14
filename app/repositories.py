"""MongoDB persistence for users, sessions, and audit events."""

from datetime import UTC, datetime, timedelta
from typing import Any

from bson import ObjectId
from pymongo import ASCENDING, DESCENDING, ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.models import (
    AccessRequest,
    AccessRequestStatus,
    DocumentPermission,
    DocumentState,
    Role,
    User,
    VaultDocument,
)

USERNAME_INDEX_KEY = (("username", ASCENDING),)


def _utc(value: Any) -> Any:
    """MongoDB commonly returns UTC datetimes without tzinfo; normalize on read."""
    if not isinstance(value, datetime):
        return value
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class UserAlreadyExistsError(Exception):
    """Raised when a canonical username is already registered."""


class UsernameIndexConfigurationError(RuntimeError):
    """Raised when the existing username index cannot enforce user uniqueness."""


class DuplicatePendingAccessRequestError(Exception):
    """Raised when the partial unique index finds an existing pending request."""


class MongoUserRepository:
    def __init__(self, database: Any) -> None:
        self.collection = database["users"]

    async def ensure_indexes(self) -> None:
        """Ensure a full unique index protects canonical usernames.

        Earlier NepShield stages created the same index with MongoDB's default
        name, ``username_1``. Reusing that compatible index keeps setup
        idempotent and avoids code 85 (equivalent index with a different name).
        """
        indexes = await self.collection.index_information()
        username_indexes = [
            (name, definition)
            for name, definition in indexes.items()
            if tuple(definition.get("key", ())) == USERNAME_INDEX_KEY
        ]
        for _, definition in username_indexes:
            if (
                definition.get("unique")
                and not definition.get("sparse")
                and "partialFilterExpression" not in definition
            ):
                return

        if username_indexes:
            names = ", ".join(name for name, _ in username_indexes)
            raise UsernameIndexConfigurationError(
                "Existing username index does not provide full unique username "
                f"protection: {names}. No indexes or user data were changed."
            )

        await self.collection.create_index(
            [("username", ASCENDING)], unique=True, name="unique_username"
        )

    async def create(
        self,
        username: str,
        password_hash: str,
        role: Role,
        created_at: datetime,
        display_name: str,
    ) -> User:
        document = {
            "display_name": display_name,
            "username": username,
            "password_hash": password_hash,
            "role": role.value,
            "enabled": True,
            "created_at": created_at,
        }
        try:
            result = await self.collection.insert_one(document)
        except DuplicateKeyError as error:
            raise UserAlreadyExistsError(username) from error
        return User(
            result.inserted_id, username, password_hash, role, True, display_name, created_at
        )

    async def list_users(self) -> list[User]:
        cursor = self.collection.find({}).sort("created_at", DESCENDING)
        users: list[User] = []
        async for document in cursor:
            user = self._to_user(document)
            if user is not None:
                users.append(user)
        return users

    async def set_enabled(self, user_id: Any, enabled: bool) -> bool:
        result = await self.collection.update_one(
            {"_id": user_id}, {"$set": {"enabled": enabled}}
        )
        return result.modified_count == 1

    async def find_by_username(self, username: str) -> User | None:
        return self._to_user(await self.collection.find_one({"username": username}))

    async def find_by_id(self, user_id: Any) -> User | None:
        return self._to_user(await self.collection.find_one({"_id": user_id}))

    async def update_password_hash(self, user_id: Any, password_hash: str) -> None:
        await self.collection.update_one(
            {"_id": user_id}, {"$set": {"password_hash": password_hash}}
        )

    @staticmethod
    def _to_user(document: dict[str, Any] | None) -> User | None:
        if document is None:
            return None
        try:
            role = Role(document["role"])
        except (KeyError, ValueError):
            return None
        return User(
            id=document["_id"],
            username=document["username"],
            password_hash=document["password_hash"],
            role=role,
            enabled=document.get("enabled", True),
            display_name=document.get("display_name", document["username"]),
            created_at=MongoUserRepository._to_datetime(document.get("created_at")),
        )

    @staticmethod
    def _to_datetime(value: Any) -> datetime | None:
        """Read both MongoDB datetimes and ISO timestamps from older user data."""
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return None
        return None


class MongoSessionRepository:
    def __init__(self, database: Any) -> None:
        self.collection = database["sessions"]

    async def ensure_indexes(self) -> None:
        await self.collection.create_index("token_digest", unique=True, name="unique_session")
        await self.collection.create_index(
            "expires_at", expireAfterSeconds=0, name="expire_sessions"
        )

    async def create(
        self,
        token_digest: str,
        user_id: Any,
        created_at: datetime,
        expires_at: datetime,
    ) -> None:
        await self.collection.insert_one(
            {
                "token_digest": token_digest,
                "user_id": user_id,
                "created_at": created_at,
                "expires_at": expires_at,
            }
        )

    async def find_valid(self, token_digest: str, now: datetime) -> dict[str, Any] | None:
        return await self.collection.find_one(
            {"token_digest": token_digest, "expires_at": {"$gt": now}}
        )

    async def delete(self, token_digest: str) -> None:
        await self.collection.delete_one({"token_digest": token_digest})


class MongoAuditRepository:
    """Append-only audit persistence; intentionally exposes no mutation methods."""

    def __init__(self, database: Any) -> None:
        self.collection = database["audit_events"]

    async def ensure_indexes(self) -> None:
        await self.collection.create_index(
            [("occurred_at", DESCENDING)], name="recent_audit_events"
        )
        await self.collection.create_index(
            [("user_id", ASCENDING), ("occurred_at", DESCENDING)],
            name="user_audit_events",
        )

    async def append(self, event: dict[str, Any]) -> None:
        await self.collection.insert_one(event)


class MongoVaultRepository:
    """Persist vault metadata; encrypted content remains on the filesystem."""

    def __init__(self, database: Any) -> None:
        self.collection = database["vault_documents"]

    async def ensure_indexes(self) -> None:
        await self.collection.create_index(
            [("owner_id", ASCENDING), ("created_at", DESCENDING)],
            name="owner_vault_documents",
        )
        await self.collection.create_index(
            "storage_name", unique=True, name="unique_vault_storage_name"
        )

    async def create(self, document: VaultDocument) -> VaultDocument:
        await self.collection.insert_one(
            {
                "_id": document.id,
                "owner_id": document.owner_id,
                "original_filename": document.original_filename,
                "media_type": document.media_type,
                "plaintext_size": document.plaintext_size,
                "storage_name": document.storage_name,
                "nonce": document.nonce,
                "created_at": document.created_at,
                "usable": document.usable,
                "state": document.state.value,
            }
        )
        return document

    async def list_for_owner(self, owner_id: Any) -> list[VaultDocument]:
        cursor = self.collection.find({"owner_id": owner_id}).sort(
            "created_at", DESCENDING
        )
        documents: list[VaultDocument] = []
        async for item in cursor:
            document = self._to_document(item)
            if document is not None:
                documents.append(document)
        return documents

    async def find_owned(self, document_id: Any, owner_id: Any) -> VaultDocument | None:
        return self._to_document(
            await self.collection.find_one({"_id": document_id, "owner_id": owner_id})
        )

    async def find_by_id(self, document_id: Any) -> VaultDocument | None:
        return self._to_document(await self.collection.find_one({"_id": document_id}))

    async def list_all(self) -> list[VaultDocument]:
        cursor = self.collection.find({}).sort("created_at", DESCENDING)
        documents: list[VaultDocument] = []
        async for item in cursor:
            document = self._to_document(item)
            if document is not None:
                documents.append(document)
        return documents

    async def transition_state(
        self,
        document_id: Any,
        expected_state: DocumentState,
        target_state: DocumentState,
        changed_at: datetime,
        changed_by: Any,
        reason: str,
    ) -> VaultDocument | None:
        if expected_state is DocumentState.ACTIVE:
            state_filter: dict[str, Any] = {
                "$or": [
                    {"state": DocumentState.ACTIVE.value},
                    {"state": {"$exists": False}},
                    {"state": None},
                ]
            }
        else:
            state_filter = {"state": expected_state.value}

        update: dict[str, Any] = {"$set": {"state": target_state.value}}
        if target_state is DocumentState.LOCKED:
            update["$set"].update(
                {
                    "locked_at": changed_at,
                    "locked_by": changed_by,
                    "lock_reason": reason,
                }
            )
        else:
            update["$unset"] = {
                "locked_at": "",
                "locked_by": "",
                "lock_reason": "",
            }
        item = await self.collection.find_one_and_update(
            {"_id": document_id, "usable": {"$ne": False}, **state_filter},
            update,
            return_document=ReturnDocument.AFTER,
        )
        return self._to_document(item)

    async def list_usable_not_owned(self, owner_id: Any) -> list[VaultDocument]:
        cursor = self.collection.find(
            {"owner_id": {"$ne": owner_id}, "usable": {"$ne": False}}
        ).sort("created_at", DESCENDING)
        documents: list[VaultDocument] = []
        async for item in cursor:
            document = self._to_document(item)
            if document is not None:
                documents.append(document)
        return documents

    @staticmethod
    def _to_document(item: dict[str, Any] | None) -> VaultDocument | None:
        if item is None:
            return None
        try:
            return VaultDocument(
                id=item["_id"],
                owner_id=item["owner_id"],
                original_filename=item["original_filename"],
                media_type=item["media_type"],
                plaintext_size=item["plaintext_size"],
                storage_name=item["storage_name"],
                nonce=bytes(item["nonce"]),
                created_at=_utc(item["created_at"]),
                usable=item.get("usable", True),
                state=DocumentState(item.get("state") or DocumentState.ACTIVE.value),
                locked_at=_utc(item.get("locked_at")),
                locked_by=item.get("locked_by"),
                lock_reason=item.get("lock_reason"),
            )
        except (KeyError, TypeError, ValueError):
            return None


class MongoAccessRequestRepository:
    """Retain request/decision history separately from usable permissions."""

    def __init__(self, database: Any) -> None:
        self.collection = database["access_requests"]

    async def ensure_indexes(self) -> None:
        await self.collection.create_index(
            [("requester_id", ASCENDING), ("document_id", ASCENDING)],
            unique=True,
            partialFilterExpression={"status": AccessRequestStatus.PENDING.value},
            name="unique_pending_document_request",
        )
        await self.collection.create_index(
            [("requested_at", DESCENDING)], name="recent_access_requests"
        )
        await self.collection.create_index(
            [("requester_id", ASCENDING), ("requested_at", DESCENDING)],
            name="requester_access_requests",
        )

    async def create(self, request: AccessRequest) -> AccessRequest:
        try:
            await self.collection.insert_one(
                {
                    "_id": request.id,
                    "requester_id": request.requester_id,
                    "document_id": request.document_id,
                    "reason": request.reason,
                    "status": request.status.value,
                    "requested_at": request.requested_at,
                    "decided_at": request.decided_at,
                    "decided_by": request.decided_by,
                    "decision_reason": request.decision_reason,
                    "permission_id": request.permission_id,
                    "permission_expires_at": request.permission_expires_at,
                }
            )
        except DuplicateKeyError as error:
            raise DuplicatePendingAccessRequestError from error
        return request

    async def find_by_id(self, request_id: Any) -> AccessRequest | None:
        return self._to_request(await self.collection.find_one({"_id": request_id}))

    async def find_pending(
        self, requester_id: Any, document_id: Any
    ) -> AccessRequest | None:
        return self._to_request(
            await self.collection.find_one(
                {
                    "requester_id": requester_id,
                    "document_id": document_id,
                    "status": AccessRequestStatus.PENDING.value,
                }
            )
        )

    async def list_for_requester(self, requester_id: Any) -> list[AccessRequest]:
        return await self._list(
            self.collection.find({"requester_id": requester_id}).sort(
                "requested_at", DESCENDING
            )
        )

    async def list_all(self) -> list[AccessRequest]:
        return await self._list(self.collection.find({}).sort("requested_at", DESCENDING))

    async def decide_pending(
        self,
        request_id: Any,
        claim_token: str,
        status: AccessRequestStatus,
        decided_at: datetime,
        decided_by: Any,
        decision_reason: str,
        permission_id: Any = None,
        permission_expires_at: datetime | None = None,
    ) -> AccessRequest | None:
        item = await self.collection.find_one_and_update(
            {
                "_id": request_id,
                "status": AccessRequestStatus.PENDING.value,
                "decision_claim": claim_token,
            },
            {
                "$set": {
                    "status": status.value,
                    "decided_at": decided_at,
                    "decided_by": decided_by,
                    "decision_reason": decision_reason,
                    "permission_id": permission_id,
                    "permission_expires_at": permission_expires_at,
                },
                "$unset": {"decision_claim": "", "decision_claimed_at": ""},
            },
            return_document=ReturnDocument.AFTER,
        )
        return self._to_request(item)

    async def claim_pending(
        self, request_id: Any, claim_token: str, claimed_at: datetime
    ) -> bool:
        item = await self.collection.find_one_and_update(
            {
                "_id": request_id,
                "status": AccessRequestStatus.PENDING.value,
                "$or": [
                    {"decision_claim": {"$exists": False}},
                    {"decision_claimed_at": {"$lt": claimed_at - timedelta(minutes=5)}},
                ],
            },
            {
                "$set": {
                    "decision_claim": claim_token,
                    "decision_claimed_at": claimed_at,
                }
            },
            return_document=ReturnDocument.AFTER,
        )
        return item is not None

    async def release_claim(self, request_id: Any, claim_token: str) -> None:
        await self.collection.update_one(
            {
                "_id": request_id,
                "status": AccessRequestStatus.PENDING.value,
                "decision_claim": claim_token,
            },
            {"$unset": {"decision_claim": "", "decision_claimed_at": ""}},
        )

    async def _list(self, cursor: Any) -> list[AccessRequest]:
        requests: list[AccessRequest] = []
        async for item in cursor:
            request = self._to_request(item)
            if request is not None:
                requests.append(request)
        return requests

    @staticmethod
    def _to_request(item: dict[str, Any] | None) -> AccessRequest | None:
        if item is None:
            return None
        try:
            return AccessRequest(
                id=item["_id"],
                requester_id=item["requester_id"],
                document_id=item["document_id"],
                reason=item["reason"],
                status=AccessRequestStatus(item["status"]),
                requested_at=_utc(item["requested_at"]),
                decided_at=_utc(item.get("decided_at")),
                decided_by=item.get("decided_by"),
                decision_reason=item.get("decision_reason"),
                permission_id=item.get("permission_id"),
                permission_expires_at=_utc(item.get("permission_expires_at")),
            )
        except (KeyError, TypeError, ValueError):
            return None


class MongoDocumentPermissionRepository:
    """Store one durable permission relationship for each grantee/document pair."""

    def __init__(self, database: Any) -> None:
        self.collection = database["document_permissions"]

    async def ensure_indexes(self) -> None:
        await self.collection.create_index(
            [("grantee_id", ASCENDING), ("document_id", ASCENDING)],
            unique=True,
            name="unique_document_grantee_permission",
        )
        await self.collection.create_index(
            [("grantee_id", ASCENDING), ("active", ASCENDING), ("expires_at", ASCENDING)],
            name="valid_grantee_permissions",
        )

    async def activate(
        self,
        grantee_id: Any,
        document_id: Any,
        granted_at: datetime,
        granted_by: Any,
        source_request_id: Any,
        expires_at: datetime | None,
    ) -> DocumentPermission:
        permission_id = ObjectId()
        item = await self.collection.find_one_and_update(
            {"grantee_id": grantee_id, "document_id": document_id},
            {
                "$setOnInsert": {"_id": permission_id},
                "$set": {
                    "active": True,
                    "granted_at": granted_at,
                    "granted_by": granted_by,
                    "source_request_id": source_request_id,
                    "expires_at": expires_at,
                    "revoked_at": None,
                    "revoked_by": None,
                    "revocation_reason": None,
                },
                "$push": {
                    "history": {
                        "action": "granted",
                        "at": granted_at,
                        "actor_id": granted_by,
                        "request_id": source_request_id,
                        "expires_at": expires_at,
                    }
                },
            },
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        permission = self._to_permission(item)
        if permission is None:
            raise RuntimeError("Permission activation did not return a valid record.")
        return permission

    async def find_relationship(
        self, grantee_id: Any, document_id: Any
    ) -> DocumentPermission | None:
        return self._to_permission(
            await self.collection.find_one(
                {"grantee_id": grantee_id, "document_id": document_id}
            )
        )

    async def find_by_id(self, permission_id: Any) -> DocumentPermission | None:
        return self._to_permission(await self.collection.find_one({"_id": permission_id}))

    async def list_for_grantee(self, grantee_id: Any) -> list[DocumentPermission]:
        cursor = self.collection.find({"grantee_id": grantee_id}).sort(
            "granted_at", DESCENDING
        )
        permissions: list[DocumentPermission] = []
        async for item in cursor:
            permission = self._to_permission(item)
            if permission is not None:
                permissions.append(permission)
        return permissions

    async def list_all(self) -> list[DocumentPermission]:
        cursor = self.collection.find({}).sort("granted_at", DESCENDING)
        permissions: list[DocumentPermission] = []
        async for item in cursor:
            permission = self._to_permission(item)
            if permission is not None:
                permissions.append(permission)
        return permissions

    async def revoke(
        self,
        permission_id: Any,
        revoked_at: datetime,
        revoked_by: Any,
        reason: str,
    ) -> DocumentPermission | None:
        item = await self.collection.find_one_and_update(
            {"_id": permission_id, "active": True},
            {
                "$set": {
                    "active": False,
                    "revoked_at": revoked_at,
                    "revoked_by": revoked_by,
                    "revocation_reason": reason,
                },
                "$push": {
                    "history": {
                        "action": "revoked",
                        "at": revoked_at,
                        "actor_id": revoked_by,
                        "reason": reason,
                    }
                },
            },
            return_document=ReturnDocument.AFTER,
        )
        return self._to_permission(item)

    @staticmethod
    def _to_permission(item: dict[str, Any] | None) -> DocumentPermission | None:
        if item is None:
            return None
        try:
            return DocumentPermission(
                id=item["_id"],
                grantee_id=item["grantee_id"],
                document_id=item["document_id"],
                active=item["active"],
                granted_at=_utc(item["granted_at"]),
                granted_by=item["granted_by"],
                source_request_id=item["source_request_id"],
                expires_at=_utc(item.get("expires_at")),
                revoked_at=_utc(item.get("revoked_at")),
                revoked_by=item.get("revoked_by"),
                revocation_reason=item.get("revocation_reason"),
            )
        except (KeyError, TypeError, ValueError):
            return None
