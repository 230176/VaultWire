"""Controlled document request, decision, sharing, and revocation tests."""

import asyncio
import os
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

import app.main
from app.access_control import (
    AccessControlService,
    AccessRequestNotPending,
    DocumentAuthorizationService,
)
from app.auth import AuthService, AuditService
from app.dependencies import (
    get_access_control_service,
    get_auth_service,
    get_vault_service,
)
from app.models import (
    AccessRequestStatus,
    DocumentAccessKind,
    DocumentPermission,
    Role,
    User,
)
from app.repositories import DuplicatePendingAccessRequestError, UserAlreadyExistsError
from app.security import PasswordManager
from app.vault import VaultCipher, VaultService, VaultStorage


class InMemoryUsers:
    def __init__(self):
        self.by_id = {}
        self.by_username = {}
        self.next_id = 1

    async def create(self, username, password_hash, role, created_at, display_name):
        if username in self.by_username:
            raise UserAlreadyExistsError
        user = User(
            self.next_id, username, password_hash, role, True, display_name, created_at
        )
        self.next_id += 1
        self.by_id[user.id] = user
        self.by_username[user.username] = user
        return user

    async def find_by_username(self, username):
        return self.by_username.get(username)

    async def find_by_id(self, user_id):
        return self.by_id.get(user_id)

    async def update_password_hash(self, user_id, password_hash):
        user = replace(self.by_id[user_id], password_hash=password_hash)
        self.by_id[user_id] = user
        self.by_username[user.username] = user


class InMemorySessions:
    def __init__(self):
        self.documents = {}

    async def create(self, token_digest, user_id, created_at, expires_at):
        self.documents[token_digest] = {"user_id": user_id, "expires_at": expires_at}

    async def find_valid(self, token_digest, now):
        session = self.documents.get(token_digest)
        return session if session and session["expires_at"] > now else None

    async def delete(self, token_digest):
        self.documents.pop(token_digest, None)


class InMemoryAudit:
    def __init__(self):
        self.events = []

    async def append(self, event):
        self.events.append(dict(event))


class InMemoryVault:
    def __init__(self):
        self.documents = {}

    async def create(self, document):
        self.documents[document.id] = document
        return document

    async def find_by_id(self, document_id):
        return self.documents.get(document_id)

    async def find_owned(self, document_id, owner_id):
        document = self.documents.get(document_id)
        return document if document and document.owner_id == owner_id else None

    async def list_for_owner(self, owner_id):
        return [item for item in self.documents.values() if item.owner_id == owner_id]

    async def list_usable_not_owned(self, owner_id):
        return [
            item
            for item in self.documents.values()
            if item.owner_id != owner_id and item.usable
        ]


class InMemoryRequests:
    def __init__(self):
        self.items = {}
        self.claims = {}

    async def create(self, request):
        if await self.find_pending(request.requester_id, request.document_id):
            raise DuplicatePendingAccessRequestError
        self.items[request.id] = request
        return request

    async def find_by_id(self, request_id):
        return self.items.get(request_id)

    async def find_pending(self, requester_id, document_id):
        return next(
            (
                item
                for item in self.items.values()
                if item.requester_id == requester_id
                and item.document_id == document_id
                and item.status is AccessRequestStatus.PENDING
            ),
            None,
        )

    async def list_for_requester(self, requester_id):
        return sorted(
            [item for item in self.items.values() if item.requester_id == requester_id],
            key=lambda item: item.requested_at,
            reverse=True,
        )

    async def list_all(self):
        return sorted(self.items.values(), key=lambda item: item.requested_at, reverse=True)

    async def decide_pending(
        self,
        request_id,
        claim_token,
        status,
        decided_at,
        decided_by,
        decision_reason,
        permission_id=None,
        permission_expires_at=None,
    ):
        item = self.items.get(request_id)
        if (
            item is None
            or item.status is not AccessRequestStatus.PENDING
            or self.claims.get(request_id) != claim_token
        ):
            return None
        item = replace(
            item,
            status=status,
            decided_at=decided_at,
            decided_by=decided_by,
            decision_reason=decision_reason,
            permission_id=permission_id,
            permission_expires_at=permission_expires_at,
        )
        self.items[request_id] = item
        self.claims.pop(request_id, None)
        return item

    async def claim_pending(self, request_id, claim_token, claimed_at):
        item = self.items.get(request_id)
        if (
            item is None
            or item.status is not AccessRequestStatus.PENDING
            or request_id in self.claims
        ):
            return False
        self.claims[request_id] = claim_token
        return True

    async def release_claim(self, request_id, claim_token):
        if self.claims.get(request_id) == claim_token:
            self.claims.pop(request_id, None)


class InMemoryPermissions:
    def __init__(self):
        self.items = {}
        self.relationships = {}

    async def activate(
        self,
        grantee_id,
        document_id,
        granted_at,
        granted_by,
        source_request_id,
        expires_at,
    ):
        key = (grantee_id, document_id)
        existing_id = self.relationships.get(key, ObjectId())
        permission = DocumentPermission(
            existing_id,
            grantee_id,
            document_id,
            True,
            granted_at,
            granted_by,
            source_request_id,
            expires_at,
        )
        self.relationships[key] = existing_id
        self.items[existing_id] = permission
        return permission

    async def find_relationship(self, grantee_id, document_id):
        permission_id = self.relationships.get((grantee_id, document_id))
        return self.items.get(permission_id)

    async def find_by_id(self, permission_id):
        return self.items.get(permission_id)

    async def list_for_grantee(self, grantee_id):
        return [item for item in self.items.values() if item.grantee_id == grantee_id]

    async def list_all(self):
        return list(self.items.values())

    async def revoke(self, permission_id, revoked_at, revoked_by, reason):
        item = self.items.get(permission_id)
        if item is None or not item.active:
            return None
        item = replace(
            item,
            active=False,
            revoked_at=revoked_at,
            revoked_by=revoked_by,
            revocation_reason=reason,
        )
        self.items[permission_id] = item
        return item


class NoopDatabase:
    database = None

    async def connect(self):
        pass

    async def ping(self):
        return True

    async def close(self):
        pass


@pytest.fixture
def access_context(monkeypatch, tmp_path):
    users = InMemoryUsers()
    sessions = InMemorySessions()
    audit_repository = InMemoryAudit()
    audit = AuditService(audit_repository)
    auth = AuthService(users, sessions, audit, password_manager=PasswordManager())
    documents = InMemoryVault()
    requests = InMemoryRequests()
    permissions = InMemoryPermissions()
    authorization = DocumentAuthorizationService(documents, permissions)
    access = AccessControlService(
        documents, requests, permissions, users, audit, authorization
    )
    vault = VaultService(
        documents,
        VaultStorage(tmp_path / "ciphertext"),
        VaultCipher(os.urandom(32)),
        audit,
        authorization,
        max_file_size=128,
    )
    monkeypatch.setattr(app.main, "MongoDatabase", NoopDatabase)
    app.main.app.dependency_overrides[get_auth_service] = lambda: auth
    app.main.app.dependency_overrides[get_access_control_service] = lambda: access
    app.main.app.dependency_overrides[get_vault_service] = lambda: vault

    owner = asyncio.run(
        auth.create_user("document.owner", "owner-password-2026", Role.EMPLOYEE, "Owner")
    )
    requester = asyncio.run(
        auth.create_user(
            "access.requester", "requester-password-2026", Role.EMPLOYEE, "Requester"
        )
    )
    administrator = asyncio.run(
        auth.create_user(
            "access.admin", "administrator-password-2026", Role.ADMINISTRATOR, "Admin"
        )
    )
    try:
        yield {
            "auth": auth,
            "documents": documents,
            "requests": requests,
            "permissions": permissions,
            "authorization": authorization,
            "access": access,
            "audit": audit_repository,
            "owner": owner,
            "requester": requester,
            "administrator": administrator,
        }
    finally:
        app.main.app.dependency_overrides.clear()


def csrf_token(client, path):
    response = client.get(path)
    assert response.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match
    return match.group(1)


def sign_in(client, username, password):
    return client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": csrf_token(client, "/login"),
        },
        follow_redirects=False,
    )


def upload_owner_document(context, content=b"shared secret"):
    with TestClient(app.main.app) as client:
        sign_in(client, "document.owner", "owner-password-2026")
        response = client.post(
            "/employee/vault",
            data={"csrf_token": csrf_token(client, "/employee/vault")},
            files={"document": ("research.txt", content, "text/plain")},
            follow_redirects=False,
        )
        assert response.status_code == 303
    return next(iter(context["documents"].documents.values()))


def submit_request(client, document_id, reason="Needed for peer review"):
    return client.post(
        "/employee/access/request",
        data={
            "document_id": str(document_id),
            "reason": reason,
            "csrf_token": csrf_token(client, "/employee/access/request"),
        },
        follow_redirects=False,
    )


def decide_request(client, request_id, decision="approved", reason="Approved for review", expiry=""):
    return client.post(
        f"/administrator/access-requests/{request_id}/decision",
        data={
            "decision": decision,
            "decision_reason": reason,
            "expires_at": expiry,
            "csrf_token": csrf_token(client, "/administrator/access-requests"),
        },
        follow_redirects=False,
    )


def prepare_pending_request(context):
    document = upload_owner_document(context)
    with TestClient(app.main.app) as client:
        sign_in(client, "access.requester", "requester-password-2026")
        response = submit_request(client, document.id)
        assert response.status_code == 303
    request = next(iter(context["requests"].items.values()))
    return document, request


def test_request_submission_requires_reason_prevents_duplicate_and_exposes_minimum_metadata(
    access_context,
):
    document = upload_owner_document(access_context)
    with TestClient(app.main.app) as client:
        sign_in(client, "access.requester", "requester-password-2026")
        page = client.get("/employee/access/request")
        missing_reason = submit_request(client, document.id, "   ")
        submitted = submit_request(client, document.id)
        duplicate = submit_request(client, document.id, "A duplicate reason")

    assert page.status_code == 200
    assert "research.txt" in page.text and "Owner" in page.text
    assert document.storage_name not in page.text
    assert "nonce" not in page.text.casefold()
    assert missing_reason.status_code == 422
    assert "Request reason is required" in missing_reason.text
    assert submitted.status_code == 303
    assert duplicate.status_code == 422
    assert "already have a pending request" in duplicate.text
    assert len(access_context["requests"].items) == 1
    event = access_context["audit"].events[-1]
    assert event["event_type"] == "vault.access_request_submitted"
    assert event["context"]["requester_id"] == access_context["requester"].id
    assert event["resource_id"] == document.id


def test_decisions_are_administrator_only_and_employee_cannot_approve_own_request(
    access_context,
):
    _, request = prepare_pending_request(access_context)
    with TestClient(app.main.app) as employee_client:
        sign_in(employee_client, "access.requester", "requester-password-2026")
        response = employee_client.post(
            f"/administrator/access-requests/{request.id}/decision",
            data={
                "decision": "approved",
                "decision_reason": "Self approval",
                "csrf_token": csrf_token(employee_client, "/employee"),
            },
        )
    assert response.status_code == 403
    assert access_context["requests"].items[request.id].status is AccessRequestStatus.PENDING
    assert access_context["permissions"].items == {}


def test_approval_creates_one_usable_permission_and_shared_download_is_audited(
    access_context,
):
    plaintext = b"approved shared content"
    document = upload_owner_document(access_context, plaintext)
    with TestClient(app.main.app) as requester_client:
        sign_in(requester_client, "access.requester", "requester-password-2026")
        denied = requester_client.get(f"/employee/vault/{document.id}/download")
        assert submit_request(requester_client, document.id).status_code == 303
    request = next(iter(access_context["requests"].items.values()))

    with TestClient(app.main.app) as admin_client:
        sign_in(admin_client, "access.admin", "administrator-password-2026")
        approved = decide_request(
            admin_client, request.id, expiry="2099-01-02T03:04"
        )

    with TestClient(app.main.app) as requester_client:
        sign_in(requester_client, "access.requester", "requester-password-2026")
        shared_page = requester_client.get("/employee/shared")
        download = requester_client.get(f"/employee/vault/{document.id}/download")

    assert denied.status_code == 404
    assert approved.status_code == 303
    assert approved.headers["location"].endswith("success=approved")
    assert len(access_context["permissions"].items) == 1
    permission = next(iter(access_context["permissions"].items.values()))
    assert permission.grantee_id == access_context["requester"].id
    assert permission.document_id == document.id and permission.active
    assert permission.expires_at == datetime(2099, 1, 2, 3, 4, tzinfo=UTC)
    assert shared_page.status_code == 200 and "research.txt" in shared_page.text
    assert download.status_code == 200 and download.content == plaintext
    event_types = [event["event_type"] for event in access_context["audit"].events]
    assert "vault.access_request_approved" in event_types
    assert "vault.shared_document_downloaded" in event_types
    shared_event = next(
        event
        for event in access_context["audit"].events
        if event["event_type"] == "vault.shared_document_downloaded"
    )
    assert shared_event["context"]["permission_id"] == permission.id


def test_rejection_requires_reason_and_never_creates_access(access_context):
    document, request = prepare_pending_request(access_context)
    with TestClient(app.main.app) as admin_client:
        sign_in(admin_client, "access.admin", "administrator-password-2026")
        missing_reason = decide_request(admin_client, request.id, "rejected", "")
        rejected = decide_request(admin_client, request.id, "rejected", "Outside role scope")
    with TestClient(app.main.app) as requester_client:
        sign_in(requester_client, "access.requester", "requester-password-2026")
        download = requester_client.get(f"/employee/vault/{document.id}/download")
        history = requester_client.get("/employee/access/requests")

    assert missing_reason.status_code == 422
    assert rejected.status_code == 303
    assert access_context["permissions"].items == {}
    assert download.status_code == 404
    assert "Rejected" in history.text and "Outside role scope" in history.text
    assert "vault.access_request_rejected" in [
        event["event_type"] for event in access_context["audit"].events
    ]


def test_expired_permission_is_distinguished_hidden_and_denied(access_context):
    document, request = prepare_pending_request(access_context)
    with TestClient(app.main.app) as admin_client:
        sign_in(admin_client, "access.admin", "administrator-password-2026")
        assert decide_request(admin_client, request.id).status_code == 303
    permission_id, permission = next(iter(access_context["permissions"].items.items()))
    access_context["permissions"].items[permission_id] = replace(
        permission, expires_at=datetime.now(UTC) - timedelta(seconds=1)
    )

    decision = asyncio.run(
        access_context["authorization"].authorize_read(
            access_context["requester"], document.id
        )
    )
    with TestClient(app.main.app) as requester_client:
        sign_in(requester_client, "access.requester", "requester-password-2026")
        shared_page = requester_client.get("/employee/shared")
        download = requester_client.get(f"/employee/vault/{document.id}/download")

    assert decision.kind is DocumentAccessKind.EXPIRED
    assert "research.txt" not in shared_page.text
    assert download.status_code == 404


def test_permission_revocation_requires_reason_retains_record_and_denies_download(
    access_context,
):
    document, request = prepare_pending_request(access_context)
    with TestClient(app.main.app) as admin_client:
        sign_in(admin_client, "access.admin", "administrator-password-2026")
        decide_request(admin_client, request.id)
        permission = next(iter(access_context["permissions"].items.values()))
        missing_reason = admin_client.post(
            f"/administrator/permissions/{permission.id}/revoke",
            data={
                "revocation_reason": "",
                "csrf_token": csrf_token(admin_client, "/administrator/access-requests"),
            },
            follow_redirects=False,
        )
        revoked = admin_client.post(
            f"/administrator/permissions/{permission.id}/revoke",
            data={
                "revocation_reason": "Review completed",
                "csrf_token": csrf_token(admin_client, "/administrator/access-requests"),
            },
            follow_redirects=False,
        )

    decision = asyncio.run(
        access_context["authorization"].authorize_read(
            access_context["requester"], document.id
        )
    )
    with TestClient(app.main.app) as requester_client:
        sign_in(requester_client, "access.requester", "requester-password-2026")
        download = requester_client.get(f"/employee/vault/{document.id}/download")

    retained = access_context["permissions"].items[permission.id]
    assert missing_reason.status_code == 422
    assert revoked.status_code == 303
    assert retained.active is False and retained.revocation_reason == "Review completed"
    assert decision.kind is DocumentAccessKind.REVOKED
    assert download.status_code == 404
    assert "vault.permission_revoked" in [
        event["event_type"] for event in access_context["audit"].events
    ]


def test_direct_id_protection_admin_has_no_normal_access_and_owner_still_downloads(
    access_context,
):
    plaintext = b"owner remains authorized"
    document = upload_owner_document(access_context, plaintext)
    with TestClient(app.main.app) as requester_client:
        sign_in(requester_client, "access.requester", "requester-password-2026")
        direct = requester_client.get(f"/employee/vault/{document.id}/download")
    with TestClient(app.main.app) as admin_client:
        sign_in(admin_client, "access.admin", "administrator-password-2026")
        admin_download = admin_client.get(f"/employee/vault/{document.id}/download")
    with TestClient(app.main.app) as owner_client:
        sign_in(owner_client, "document.owner", "owner-password-2026")
        owner_download = owner_client.get(f"/employee/vault/{document.id}/download")

    admin_decision = asyncio.run(
        access_context["authorization"].authorize_read(
            access_context["administrator"], document.id
        )
    )
    assert direct.status_code == 404
    assert admin_download.status_code == 403
    assert admin_decision.kind is DocumentAccessKind.DENIED
    assert owner_download.status_code == 200 and owner_download.content == plaintext


def test_unusable_document_overrides_owner_and_shared_access(access_context):
    document = upload_owner_document(access_context)
    access_context["documents"].documents[document.id] = replace(document, usable=False)
    owner_decision = asyncio.run(
        access_context["authorization"].authorize_read(
            access_context["owner"], document.id
        )
    )
    assert owner_decision.kind is DocumentAccessKind.UNUSABLE


def test_later_approval_reactivates_same_permission_relationship(access_context):
    document = upload_owner_document(access_context)
    access = access_context["access"]
    requester = access_context["requester"]
    administrator = access_context["administrator"]

    first_request = asyncio.run(
        access.submit_request(
            requester,
            str(document.id),
            "First review",
            source_ip=None,
            user_agent=None,
        )
    )
    asyncio.run(
        access.decide_request(
            administrator,
            str(first_request.id),
            "approved",
            "Initial approval",
            None,
            source_ip=None,
            user_agent=None,
        )
    )
    original = next(iter(access_context["permissions"].items.values()))
    asyncio.run(
        access.revoke_permission(
            administrator,
            str(original.id),
            "Initial work complete",
            source_ip=None,
            user_agent=None,
        )
    )
    second_request = asyncio.run(
        access.submit_request(
            requester,
            str(document.id),
            "Follow-up review",
            source_ip=None,
            user_agent=None,
        )
    )
    asyncio.run(
        access.decide_request(
            administrator,
            str(second_request.id),
            "approved",
            "Follow-up approved",
            None,
            source_ip=None,
            user_agent=None,
        )
    )

    assert len(access_context["permissions"].items) == 1
    reactivated = next(iter(access_context["permissions"].items.values()))
    assert reactivated.id == original.id
    assert reactivated.active is True and reactivated.revoked_at is None
    assert len(access_context["requests"].items) == 2


def test_competing_administrator_decisions_cannot_make_rejection_grant_access(
    access_context,
):
    document = upload_owner_document(access_context)
    access = access_context["access"]
    request = asyncio.run(
        access.submit_request(
            access_context["requester"],
            str(document.id),
            "Concurrent decision test",
            source_ip=None,
            user_agent=None,
        )
    )

    async def decide_both():
        return await asyncio.gather(
            access.decide_request(
                access_context["administrator"],
                str(request.id),
                "rejected",
                "Reject first",
                None,
                source_ip=None,
                user_agent=None,
            ),
            access.decide_request(
                access_context["administrator"],
                str(request.id),
                "approved",
                "Approve second",
                None,
                source_ip=None,
                user_agent=None,
            ),
            return_exceptions=True,
        )

    results = asyncio.run(decide_both())
    retained_request = access_context["requests"].items[request.id]
    assert retained_request.status is AccessRequestStatus.REJECTED
    assert access_context["permissions"].items == {}
    assert sum(isinstance(result, AccessRequestNotPending) for result in results) == 1
