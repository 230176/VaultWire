"""Employee vault cryptography, workflow, authorization, and audit tests."""

import asyncio
import base64
import os
import re
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

import app.main
from app.access_control import DocumentAuthorizationService
from app.auth import AuthService, AuditService
from app.dependencies import get_auth_service, get_vault_service
from app.models import Role, User
from app.security import PasswordManager
from app.vault import VaultCipher, VaultIntegrityError, VaultService, VaultStorage


class InMemoryUsers:
    def __init__(self):
        self.by_id = {}
        self.by_username = {}
        self.next_id = 1

    async def create(self, username, password_hash, role, created_at, display_name):
        user = User(self.next_id, username, password_hash, role, True, display_name, created_at)
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
        self.documents[token_digest] = {
            "user_id": user_id,
            "expires_at": expires_at,
        }

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

    async def list_for_owner(self, owner_id):
        return [
            document
            for document in self.documents.values()
            if document.owner_id == owner_id
        ]

    async def find_owned(self, document_id, owner_id):
        document = self.documents.get(document_id)
        if document is None or document.owner_id != owner_id:
            return None
        return document

    async def find_by_id(self, document_id):
        return self.documents.get(document_id)


class InMemoryPermissions:
    async def find_relationship(self, grantee_id, document_id):
        return None


class NoopDatabase:
    database = None

    async def connect(self):
        pass

    async def ping(self):
        return True

    async def close(self):
        pass


@pytest.fixture
def vault_context(monkeypatch, tmp_path):
    users = InMemoryUsers()
    sessions = InMemorySessions()
    audit_repository = InMemoryAudit()
    audit = AuditService(audit_repository)
    auth = AuthService(users, sessions, audit, password_manager=PasswordManager())
    repository = InMemoryVault()
    authorization = DocumentAuthorizationService(repository, InMemoryPermissions())
    storage = VaultStorage(tmp_path / "ciphertext")
    vault = VaultService(
        repository,
        storage,
        VaultCipher(os.urandom(32)),
        audit,
        authorization,
        max_file_size=64,
    )
    monkeypatch.setattr(app.main, "MongoDatabase", NoopDatabase)
    app.main.app.dependency_overrides[get_auth_service] = lambda: auth
    app.main.app.dependency_overrides[get_vault_service] = lambda: vault
    try:
        yield auth, repository, storage, audit_repository
    finally:
        app.main.app.dependency_overrides.clear()


def create_user(service, username, password, role):
    return asyncio.run(service.create_user(username, password, role))


def csrf_token(client, path):
    response = client.get(path)
    assert response.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match
    return match.group(1)


def sign_in(client, username, password):
    token = csrf_token(client, "/login")
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token},
        follow_redirects=False,
    )


def upload(client, filename, content, media_type="text/plain"):
    token = csrf_token(client, "/employee/vault")
    return client.post(
        "/employee/vault",
        data={"csrf_token": token},
        files={"document": (filename, content, media_type)},
        follow_redirects=False,
    )


def test_aes_gcm_round_trip_uses_ciphertext_and_rejects_tampering():
    cipher = VaultCipher(os.urandom(32))
    plaintext = b"confidential employee document"
    aad = b"owner-and-document-binding"

    nonce, ciphertext = cipher.encrypt(plaintext, aad)

    assert len(nonce) == 12
    assert ciphertext != plaintext
    assert cipher.decrypt(nonce, ciphertext, aad) == plaintext

    second_nonce, _ = cipher.encrypt(plaintext, aad)
    assert second_nonce != nonce

    tampered = bytearray(ciphertext)
    tampered[-1] ^= 1
    with pytest.raises(VaultIntegrityError):
        cipher.decrypt(nonce, bytes(tampered), aad)


def test_base64_key_must_decode_to_an_aes_256_key():
    encoded = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    assert isinstance(VaultCipher.from_base64(encoded), VaultCipher)


def test_employee_upload_is_encrypted_listed_owned_and_audited(vault_context):
    auth, repository, storage, audit = vault_context
    create_user(auth, "vault.owner", "employee-password-2026", Role.EMPLOYEE)
    plaintext = b"private notes"

    with TestClient(app.main.app) as client:
        sign_in(client, "vault.owner", "employee-password-2026")
        response = upload(client, "notes.txt", plaintext)
        page = client.get("/employee/vault?success=uploaded")

    assert response.status_code == 303
    assert response.headers["location"] == "/employee/vault?success=uploaded"
    assert "notes.txt" in page.text
    assert "Document encrypted and stored successfully" in page.text
    document = next(iter(repository.documents.values()))
    assert document.owner_id == 1
    assert document.original_filename == "notes.txt"
    assert document.storage_name != "notes.txt"
    assert storage.read(document.storage_name) != plaintext
    event = audit.events[-1]
    assert event["event_type"] == "vault.document_uploaded"
    assert event["resource_id"] == document.id


def test_owner_can_download_plaintext_and_success_is_audited(vault_context):
    auth, repository, _, audit = vault_context
    create_user(auth, "vault.owner", "employee-password-2026", Role.EMPLOYEE)
    plaintext = b"download me"

    with TestClient(app.main.app) as client:
        sign_in(client, "vault.owner", "employee-password-2026")
        upload(client, "download.txt", plaintext)
        document = next(iter(repository.documents.values()))
        response = client.get(f"/employee/vault/{document.id}/download")

    assert response.status_code == 200
    assert response.content == plaintext
    assert "attachment" in response.headers["content-disposition"]
    assert response.headers["cache-control"] == "no-store"
    assert [event["event_type"] for event in audit.events[-2:]] == [
        "vault.document_uploaded",
        "vault.document_downloaded",
    ]


def test_non_owner_cannot_download_by_changing_document_id(vault_context):
    auth, repository, _, audit = vault_context
    create_user(auth, "vault.owner", "employee-password-2026", Role.EMPLOYEE)
    create_user(auth, "other.user", "different-password-2026", Role.EMPLOYEE)

    with TestClient(app.main.app) as owner_client:
        sign_in(owner_client, "vault.owner", "employee-password-2026")
        upload(owner_client, "owned.txt", b"owner secret")
    document = next(iter(repository.documents.values()))

    with TestClient(app.main.app) as other_client:
        sign_in(other_client, "other.user", "different-password-2026")
        response = other_client.get(f"/employee/vault/{document.id}/download")

    assert response.status_code == 404
    assert "requested document was not found" in response.text
    assert not [
        event
        for event in audit.events
        if event["event_type"] == "vault.document_downloaded"
    ]


@pytest.mark.parametrize(
    ("filename", "content", "media_type", "message"),
    [
        ("malware.exe", b"not allowed", "application/octet-stream", "Allowed file types"),
        ("large.txt", b"x" * 65, "text/plain", "exceeds the 64 bytes"),
        ("fake.pdf", b"not actually a pdf", "application/pdf", "not a valid PDF"),
    ],
)
def test_invalid_and_oversized_uploads_are_rejected(
    vault_context, filename, content, media_type, message
):
    auth, repository, _, audit = vault_context
    create_user(auth, "vault.owner", "employee-password-2026", Role.EMPLOYEE)

    with TestClient(app.main.app) as client:
        sign_in(client, "vault.owner", "employee-password-2026")
        response = upload(client, filename, content, media_type)

    assert response.status_code == 422
    assert message in response.text
    assert repository.documents == {}
    assert not [event for event in audit.events if event["event_type"].startswith("vault.")]


def test_vault_is_employee_only_and_requires_authentication(vault_context):
    auth, _, _, _ = vault_context
    create_user(auth, "admin.user", "administrator-password", Role.ADMINISTRATOR)

    with TestClient(app.main.app) as anonymous_client:
        anonymous = anonymous_client.get("/employee/vault", follow_redirects=False)
    with TestClient(app.main.app) as admin_client:
        sign_in(admin_client, "admin.user", "administrator-password")
        administrator = admin_client.get("/employee/vault")

    assert anonymous.status_code == 303
    assert anonymous.headers["location"] == "/login"
    assert administrator.status_code == 403


def test_vault_upload_requires_csrf(vault_context):
    auth, repository, _, _ = vault_context
    create_user(auth, "vault.owner", "employee-password-2026", Role.EMPLOYEE)

    with TestClient(app.main.app) as client:
        sign_in(client, "vault.owner", "employee-password-2026")
        response = client.post(
            "/employee/vault",
            files={"document": ("notes.txt", b"secret", "text/plain")},
        )

    assert response.status_code == 403
    assert repository.documents == {}
