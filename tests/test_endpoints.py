"""Managed endpoint lifecycle and independent machine-authentication tests."""

import asyncio
import json
import re
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from bson import ObjectId
from fastapi.testclient import TestClient
from pymongo.errors import DuplicateKeyError

import app.main
from app.auth import AuditService, AuthService
from app.endpoint_health import RuntimeStatus, SynchronizationStatus
from app.dependencies import (
    get_administrator_raw_event_service,
    get_auth_service,
    get_endpoint_service,
)
from app.dependencies import get_raw_event_service
from app.endpoints import EndpointService
from app.models import EndpointRuntimeHealth, ManagedEndpoint, Role, User
from app.repositories import EndpointAlreadyExistsError, MongoEndpointRepository
from app.raw_events import (
    AdministratorRawEventService,
    MAX_ADMIN_EVENT_RESULTS,
    MongoRawEventRepository,
    RawEventEnvelope,
    RawEventService,
)
from app.security import PasswordManager, endpoint_credential_digest

ADMIN_PASSWORD = "administrator-password"
EMPLOYEE_PASSWORD = "employee-password-2026"
PASSWORDS = PasswordManager()
ADMIN_HASH = PASSWORDS.hash(ADMIN_PASSWORD)
EMPLOYEE_HASH = PASSWORDS.hash(EMPLOYEE_PASSWORD)


class InMemoryUsers:
    def __init__(self):
        now = datetime.now(UTC)
        self.admin = User(
            ObjectId(), "admin.user", ADMIN_HASH, Role.ADMINISTRATOR, True, "Administrator", now
        )
        self.employee = User(
            ObjectId(), "team.member", EMPLOYEE_HASH, Role.EMPLOYEE, True, "Team Member", now
        )
        self.by_id = {self.admin.id: self.admin, self.employee.id: self.employee}
        self.by_username = {
            self.admin.username: self.admin,
            self.employee.username: self.employee,
        }

    async def find_by_id(self, user_id):
        return self.by_id.get(user_id)

    async def find_by_username(self, username):
        return self.by_username.get(username)

    async def list_users(self):
        return list(self.by_id.values())

    async def update_password_hash(self, user_id, password_hash):
        user = replace(self.by_id[user_id], password_hash=password_hash)
        self.by_id[user_id] = user
        self.by_username[user.username] = user

    async def set_enabled(self, user_id, enabled):
        user = replace(self.by_id[user_id], enabled=enabled)
        self.by_id[user_id] = user
        self.by_username[user.username] = user


class InMemorySessions:
    def __init__(self):
        self.items = {}

    async def create(self, token_digest, user_id, created_at, expires_at):
        self.items[token_digest] = {"user_id": user_id, "expires_at": expires_at}

    async def find_valid(self, token_digest, now):
        item = self.items.get(token_digest)
        return item if item and item["expires_at"] > now else None

    async def delete(self, token_digest):
        self.items.pop(token_digest, None)


class InMemoryAudit:
    def __init__(self):
        self.events = []

    async def append(self, event):
        self.events.append(dict(event))


class InMemoryEndpoints:
    def __init__(self):
        self.items: dict[str, ManagedEndpoint] = {}

    async def create(self, endpoint):
        if endpoint.endpoint_id in self.items:
            raise EndpointAlreadyExistsError(endpoint.endpoint_id)
        self.items[endpoint.endpoint_id] = endpoint
        return endpoint

    async def find_by_endpoint_id(self, endpoint_id):
        return self.items.get(endpoint_id)

    async def list_all(self):
        return sorted(self.items.values(), key=lambda item: item.created_at, reverse=True)

    async def transition_active_state(
        self, endpoint_id, expected_active, active, changed_at, changed_by, reason
    ):
        endpoint = self.items.get(endpoint_id)
        if endpoint is None or endpoint.active is not expected_active:
            return None
        endpoint = replace(
            endpoint,
            active=active,
            last_status_changed_at=changed_at,
            last_status_changed_by=changed_by,
            last_status_reason=reason,
        )
        self.items[endpoint_id] = endpoint
        return endpoint

    async def rotate_credential(
        self, endpoint_id, credential_digest, rotated_at, rotated_by, reason
    ):
        endpoint = self.items.get(endpoint_id)
        if endpoint is None:
            return None
        endpoint = replace(
            endpoint,
            credential_digest=credential_digest,
            credential_version=endpoint.credential_version + 1,
            credential_rotated_at=rotated_at,
            credential_rotated_by=rotated_by,
        )
        self.items[endpoint_id] = endpoint
        return endpoint

    async def update_inventory(self, endpoint_id, inventory, updated_at):
        endpoint = self.items.get(endpoint_id)
        if endpoint is None or not endpoint.active:
            return None
        endpoint = replace(endpoint, **inventory, inventory_updated_at=updated_at)
        self.items[endpoint_id] = endpoint
        return endpoint

    async def record_heartbeat(self, endpoint_id, agent_version, last_seen_at):
        endpoint = self.items.get(endpoint_id)
        if endpoint is None or not endpoint.active:
            return None
        endpoint = replace(
            endpoint, agent_version=agent_version, last_seen_at=last_seen_at
        )
        self.items[endpoint_id] = endpoint
        return endpoint

    async def record_runtime_heartbeat(
        self, endpoint_id, agent_version, received_at, runtime_health
    ):
        endpoint = self.items.get(endpoint_id)
        if endpoint is None or not endpoint.active:
            return None
        endpoint = replace(
            endpoint,
            agent_version=agent_version,
            last_seen_at=received_at,
            last_runtime_heartbeat_at=received_at,
            runtime_health=EndpointRuntimeHealth(**runtime_health),
        )
        self.items[endpoint_id] = endpoint
        return endpoint


class NoopDatabase:
    database = None

    async def connect(self):
        pass

    async def ping(self):
        return True

    async def close(self):
        pass


@pytest.fixture
def endpoint_context(monkeypatch):
    users = InMemoryUsers()
    sessions = InMemorySessions()
    audit_repository = InMemoryAudit()
    endpoints = InMemoryEndpoints()
    audit = AuditService(audit_repository)
    auth = AuthService(users, sessions, audit, password_manager=PASSWORDS)
    service = EndpointService(endpoints, users, audit)

    monkeypatch.setattr(app.main, "MongoDatabase", NoopDatabase)
    app.main.app.dependency_overrides[get_auth_service] = lambda: auth
    app.main.app.dependency_overrides[get_endpoint_service] = lambda: service
    try:
        yield service, users, endpoints, audit_repository
    finally:
        app.main.app.dependency_overrides.clear()


def csrf_token(client, path):
    response = client.get(path)
    assert response.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match
    return match.group(1)


def sign_in(client, username="admin.user", password=ADMIN_PASSWORD):
    return client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": csrf_token(client, "/login"),
        },
        follow_redirects=False,
    )


def machine_headers(endpoint_id, credential):
    return {
        "X-NepShield-Endpoint-ID": endpoint_id,
        "Authorization": f"Bearer {credential}",
    }


def register_direct(context, name="TEAM-LAPTOP-01"):
    service, users, _, _ = context
    return asyncio.run(service.register(name, users.employee.id, actor=users.admin))


def inventory_payload(**overrides):
    payload = {
        "reported_hostname": "REPORTED-HOST",
        "windows_version": "Windows 11 Pro",
        "os_build": "26100",
        "architecture": "AMD64",
        "agent_version": "0.1.0",
    }
    payload.update(overrides)
    return payload


def test_endpoint_ids_are_unique_uuid4_and_credentials_are_securely_digested(endpoint_context):
    first = register_direct(endpoint_context, "LAPTOP-01")
    second = register_direct(endpoint_context, "LAPTOP-02")

    assert first.endpoint.endpoint_id != second.endpoint.endpoint_id
    assert UUID(first.endpoint.endpoint_id).version == 4
    assert UUID(second.endpoint.endpoint_id).version == 4
    assert first.credential != second.credential
    assert len(first.credential) >= 43
    assert first.endpoint.credential_digest == endpoint_credential_digest(first.credential)
    assert first.endpoint.credential_digest != first.credential
    assert first.credential not in repr(first.endpoint)


def test_existing_endpoint_uuid_collision_is_retried_with_a_new_uuid(
    endpoint_context, monkeypatch
):
    first = register_direct(endpoint_context, "COLLISION-OWNER")
    replacement_id = uuid4()
    generated = iter((UUID(first.endpoint.endpoint_id), replacement_id))
    monkeypatch.setattr("app.endpoints.uuid4", lambda: next(generated))

    second = register_direct(endpoint_context, "RETRIED-ENDPOINT")

    assert second.endpoint.endpoint_id == str(replacement_id)
    assert second.endpoint.endpoint_id != first.endpoint.endpoint_id


def test_new_endpoint_health_is_never_reported_without_breaking_registration(
    endpoint_context,
):
    service, _, _, _ = endpoint_context
    issued = register_direct(endpoint_context, "NEW-HEALTH-ENDPOINT")

    entry = asyncio.run(service.get_directory_entry(issued.endpoint.endpoint_id))

    assert entry.endpoint.last_runtime_heartbeat_at is None
    assert entry.endpoint.runtime_health is None
    assert entry.health.runtime_status is RuntimeStatus.NEVER_REPORTED
    assert entry.health.synchronization_status is SynchronizationStatus.UNKNOWN


def test_registration_is_admin_only_and_plaintext_is_shown_once(endpoint_context):
    _, users, endpoints, _ = endpoint_context
    with TestClient(app.main.app) as client:
        sign_in(client, users.employee.username, EMPLOYEE_PASSWORD)
        forbidden = client.get("/administrator/endpoints")
        assert forbidden.status_code == 403
        forbidden_post = client.post(
            "/administrator/endpoints",
            data={
                "device_name": "UNAUTHORIZED-LAPTOP",
                "assigned_employee_id": str(users.employee.id),
                "csrf_token": csrf_token(client, "/employee"),
            },
        )
        assert forbidden_post.status_code == 403
        assert endpoints.items == {}

    with TestClient(app.main.app) as client:
        sign_in(client)
        response = client.post(
            "/administrator/endpoints",
            data={
                "device_name": "SITA-LAPTOP",
                "assigned_employee_id": str(users.employee.id),
                "csrf_token": csrf_token(client, "/administrator/endpoints"),
            },
        )
        match = re.search(r"data-endpoint-credential>([^<]+)</code>", response.text)
        assert match
        credential = match.group(1)
        later_page = client.get("/administrator/endpoints")

    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    assert credential not in later_page.text
    stored = next(iter(endpoints.items.values()))
    assert stored.credential_digest == endpoint_credential_digest(credential)
    assert credential not in repr(stored)


def test_valid_machine_credential_returns_only_minimal_identity(endpoint_context):
    issued = register_direct(endpoint_context)
    with TestClient(app.main.app) as client:
        response = client.get(
            "/service/v1/identity",
            headers=machine_headers(issued.endpoint.endpoint_id, issued.credential),
        )

    assert response.status_code == 200
    assert response.json() == {
        "endpoint_id": issued.endpoint.endpoint_id,
        "device_name": "TEAM-LAPTOP-01",
        "assigned_employee": {
            "id": str(endpoint_context[1].employee.id),
            "username": "team.member",
            "display_name": "Team Member",
        },
        "platform": "windows",
        "status": "active",
    }
    assert "credential" not in response.text
    assert "digest" not in response.text


@pytest.mark.parametrize("case", ["wrong", "unknown", "missing", "session_only"])
def test_machine_authentication_failures_are_generic(endpoint_context, case):
    issued = register_direct(endpoint_context)
    with TestClient(app.main.app) as client:
        if case == "session_only":
            sign_in(client, "team.member", EMPLOYEE_PASSWORD)
            response = client.get("/service/v1/identity")
        elif case == "missing":
            response = client.get("/service/v1/identity")
        elif case == "unknown":
            response = client.get(
                "/service/v1/identity",
                headers=machine_headers(str(uuid4()), issued.credential),
            )
        else:
            response = client.get(
                "/service/v1/identity",
                headers=machine_headers(issued.endpoint.endpoint_id, "wrong-credential"),
            )

    assert response.status_code == 401
    assert response.json() == {"detail": "Endpoint authentication failed."}
    assert response.headers["www-authenticate"] == "Bearer"


def test_disable_and_reenable_take_effect_immediately(endpoint_context):
    service, users, _, _ = endpoint_context
    issued = register_direct(endpoint_context)
    asyncio.run(
        service.set_active(
            issued.endpoint.endpoint_id, False, "Laptop under investigation", actor=users.admin
        )
    )
    with TestClient(app.main.app) as client:
        disabled = client.get(
            "/service/v1/identity",
            headers=machine_headers(issued.endpoint.endpoint_id, issued.credential),
        )
        asyncio.run(
            service.set_active(
                issued.endpoint.endpoint_id, True, "Investigation complete", actor=users.admin
            )
        )
        enabled = client.get(
            "/service/v1/identity",
            headers=machine_headers(issued.endpoint.endpoint_id, issued.credential),
        )

    assert disabled.status_code == 401
    assert enabled.status_code == 200


def test_credential_rotation_invalidates_old_and_discloses_only_replacement(endpoint_context):
    service, users, _, _ = endpoint_context
    original = register_direct(endpoint_context)
    rotated = asyncio.run(
        service.rotate_credential(
            original.endpoint.endpoint_id, "Scheduled credential rotation", actor=users.admin
        )
    )
    with TestClient(app.main.app) as client:
        old_response = client.get(
            "/service/v1/identity",
            headers=machine_headers(original.endpoint.endpoint_id, original.credential),
        )
        new_response = client.get(
            "/service/v1/identity",
            headers=machine_headers(rotated.endpoint.endpoint_id, rotated.credential),
        )

    assert rotated.credential != original.credential
    assert rotated.endpoint.credential_version == 2
    assert rotated.endpoint.credential_rotated_at is not None
    assert old_response.status_code == 401
    assert new_response.status_code == 200


def test_administrator_can_manage_full_lifecycle_through_csrf_forms(endpoint_context):
    issued = register_direct(endpoint_context)
    endpoint_id = issued.endpoint.endpoint_id
    with TestClient(app.main.app) as client:
        sign_in(client)
        disabled = client.post(
            f"/administrator/endpoints/{endpoint_id}/disable",
            data={
                "reason": "Device reported missing",
                "csrf_token": csrf_token(client, "/administrator/endpoints"),
            },
            follow_redirects=False,
        )
        rejected = client.get(
            "/service/v1/identity", headers=machine_headers(endpoint_id, issued.credential)
        )
        enabled = client.post(
            f"/administrator/endpoints/{endpoint_id}/enable",
            data={
                "reason": "Device recovered",
                "csrf_token": csrf_token(client, "/administrator/endpoints"),
            },
            follow_redirects=False,
        )
        rotation = client.post(
            f"/administrator/endpoints/{endpoint_id}/rotate",
            data={
                "reason": "Rotate after recovery",
                "csrf_token": csrf_token(client, "/administrator/endpoints"),
            },
        )
        match = re.search(r"data-endpoint-credential>([^<]+)</code>", rotation.text)
        assert match
        replacement = match.group(1)
        old_rejected = client.get(
            "/service/v1/identity", headers=machine_headers(endpoint_id, issued.credential)
        )
        replacement_accepted = client.get(
            "/service/v1/identity", headers=machine_headers(endpoint_id, replacement)
        )
        later_page = client.get("/administrator/endpoints")

    assert disabled.status_code == 303
    assert disabled.headers["location"].endswith("success=disabled")
    assert rejected.status_code == 401
    assert enabled.status_code == 303
    assert enabled.headers["location"].endswith("success=enabled")
    assert rotation.status_code == 200
    assert old_rejected.status_code == 401
    assert replacement_accepted.status_code == 200
    assert replacement not in later_page.text


def test_machine_identity_does_not_grant_browser_privileges(endpoint_context):
    issued = register_direct(endpoint_context)
    headers = machine_headers(issued.endpoint.endpoint_id, issued.credential)
    with TestClient(app.main.app) as client:
        admin = client.get("/administrator/endpoints", headers=headers, follow_redirects=False)
        employee = client.get("/employee", headers=headers, follow_redirects=False)

    assert admin.status_code == 303
    assert employee.status_code == 303
    assert admin.headers["location"] == "/login"
    assert employee.headers["location"] == "/login"


def test_employee_account_state_is_independent_from_endpoint_state(endpoint_context):
    _, users, _, _ = endpoint_context
    issued = register_direct(endpoint_context)
    asyncio.run(users.set_enabled(users.employee.id, False))
    with TestClient(app.main.app) as client:
        response = client.get(
            "/service/v1/identity",
            headers=machine_headers(issued.endpoint.endpoint_id, issued.credential),
        )

    assert response.status_code == 200


def test_lifecycle_reasons_are_mandatory(endpoint_context):
    service, users, _, _ = endpoint_context
    issued = register_direct(endpoint_context)
    with pytest.raises(ValueError, match="reason is required"):
        asyncio.run(service.set_active(issued.endpoint.endpoint_id, False, "", actor=users.admin))
    with pytest.raises(ValueError, match="reason is required"):
        asyncio.run(service.rotate_credential(issued.endpoint.endpoint_id, "", actor=users.admin))


def test_lifecycle_audits_contain_context_but_never_credentials(endpoint_context):
    service, users, _, audit = endpoint_context
    issued = register_direct(endpoint_context)
    asyncio.run(service.set_active(issued.endpoint.endpoint_id, False, "Lost laptop", actor=users.admin))
    asyncio.run(service.set_active(issued.endpoint.endpoint_id, True, "Laptop recovered", actor=users.admin))
    rotated = asyncio.run(
        service.rotate_credential(issued.endpoint.endpoint_id, "Post-recovery rotation", actor=users.admin)
    )

    assert [event["event_type"] for event in audit.events] == [
        "endpoint.registered",
        "endpoint.disabled",
        "endpoint.enabled",
        "endpoint.credential_rotated",
    ]
    serialized = json.dumps(audit.events, default=str)
    assert issued.credential not in serialized
    assert rotated.credential not in serialized
    assert issued.endpoint.credential_digest not in serialized
    assert rotated.endpoint.credential_digest not in serialized
    assert all(event["actor_username"] == "admin.user" for event in audit.events)
    assert all(event["resource_id"] == issued.endpoint.endpoint_id for event in audit.events)


class IndexCollection:
    def __init__(self, indexes=None):
        self.create_calls = []
        self.indexes = indexes or {"_id_": {"key": [("_id", 1)]}}
        self.dropped = []

    async def index_information(self):
        return dict(self.indexes)

    async def drop_index(self, name):
        self.dropped.append(name)
        self.indexes.pop(name, None)

    async def create_index(self, keys, **options):
        self.create_calls.append((keys, options))


class InsertCollection:
    def __init__(self):
        self.document = None

    async def insert_one(self, document):
        self.document = dict(document)


class UpdateCollection:
    def __init__(self, returned_document):
        self.returned_document = returned_document
        self.calls = []

    async def find_one_and_update(self, query, update, **options):
        self.calls.append((query, update, options))
        document = dict(self.returned_document)
        document.update(update["$set"])
        return document


def test_mongo_repository_persists_digest_but_has_no_plaintext_credential_field(endpoint_context):
    issued = register_direct(endpoint_context)
    collection = InsertCollection()
    repository = MongoEndpointRepository({"endpoints": collection})
    asyncio.run(repository.create(issued.endpoint))

    assert collection.document is not None
    assert collection.document["credential_digest"] == endpoint_credential_digest(
        issued.credential
    )
    assert "credential" not in collection.document
    assert issued.credential not in json.dumps(collection.document, default=str)


def test_endpoint_repository_creates_uuid_uniqueness_and_lifecycle_indexes():
    collection = IndexCollection()
    repository = MongoEndpointRepository({"endpoints": collection})
    asyncio.run(repository.ensure_indexes())

    unique = next(
        (keys, options)
        for keys, options in collection.create_calls
        if options.get("name") == "unique_endpoint_uuid"
    )
    assert unique == ("endpoint_id", {"unique": True, "name": "unique_endpoint_uuid"})
    assert {options["name"] for _, options in collection.create_calls} == {
        "unique_endpoint_uuid",
        "employee_endpoints",
        "endpoint_lifecycle",
    }


def test_endpoint_repository_removes_only_obsolete_unique_endpoint_name_index():
    collection = IndexCollection(
        {
            "_id_": {"key": [("_id", 1)]},
            "endpoint_name_1": {
                "key": [("endpoint_name", 1)],
                "unique": True,
            },
            "endpoint_name_lookup": {"key": [("endpoint_name", 1)]},
        }
    )
    repository = MongoEndpointRepository({"endpoints": collection})

    asyncio.run(repository.ensure_indexes())

    assert collection.dropped == ["endpoint_name_1"]
    assert "endpoint_name_lookup" in collection.indexes


class DuplicateInsertCollection:
    def __init__(self, key_pattern, index_name):
        self.key_pattern = key_pattern
        self.index_name = index_name

    async def insert_one(self, document):
        raise DuplicateKeyError(
            "duplicate key",
            11000,
            {
                "keyPattern": self.key_pattern,
                "indexName": self.index_name,
            },
        )


def test_repository_does_not_misclassify_non_uuid_duplicate_as_uuid_collision(
    endpoint_context,
):
    issued = register_direct(endpoint_context)
    repository = MongoEndpointRepository(
        {
            "endpoints": DuplicateInsertCollection(
                {"endpoint_name": 1}, "endpoint_name_1"
            )
        }
    )

    with pytest.raises(DuplicateKeyError):
        asyncio.run(repository.create(issued.endpoint))


def test_repository_translates_only_endpoint_id_duplicate_for_retry(endpoint_context):
    issued = register_direct(endpoint_context)
    repository = MongoEndpointRepository(
        {
            "endpoints": DuplicateInsertCollection(
                {"endpoint_id": 1}, "unique_endpoint_uuid"
            )
        }
    )

    with pytest.raises(EndpointAlreadyExistsError):
        asyncio.run(repository.create(issued.endpoint))


def test_mongo_inventory_and_heartbeat_updates_are_explicitly_allowlisted(endpoint_context):
    issued = register_direct(endpoint_context)
    document = {
        "endpoint_id": issued.endpoint.endpoint_id,
        "device_name": issued.endpoint.device_name,
        "assigned_user_id": issued.endpoint.assigned_user_id,
        "platform": issued.endpoint.platform.value,
        "active": True,
        "credential_digest": issued.endpoint.credential_digest,
        "created_at": issued.endpoint.created_at,
        "created_by": issued.endpoint.created_by,
    }
    collection = UpdateCollection(document)
    repository = MongoEndpointRepository({"endpoints": collection})
    now = datetime.now(UTC)

    asyncio.run(
        repository.update_inventory(
            issued.endpoint.endpoint_id, inventory_payload(), now
        )
    )
    asyncio.run(
        repository.record_heartbeat(issued.endpoint.endpoint_id, "0.1.1", now)
    )

    inventory_query, inventory_update, _ = collection.calls[0]
    heartbeat_query, heartbeat_update, _ = collection.calls[1]
    assert inventory_query == {
        "endpoint_id": issued.endpoint.endpoint_id,
        "active": True,
    }
    assert set(inventory_update["$set"]) == {
        "reported_hostname",
        "windows_version",
        "os_build",
        "architecture",
        "agent_version",
        "inventory_updated_at",
    }
    assert heartbeat_query == inventory_query
    assert set(heartbeat_update["$set"]) == {"agent_version", "last_seen_at"}
    forbidden = {
        "endpoint_id",
        "assigned_user_id",
        "active",
        "credential_digest",
        "credential_version",
        "created_at",
        "created_by",
    }
    assert forbidden.isdisjoint(inventory_update["$set"])
    assert forbidden.isdisjoint(heartbeat_update["$set"])


def test_mongo_runtime_heartbeat_atomically_updates_only_latest_health_fields(
    endpoint_context,
):
    issued = register_direct(endpoint_context)
    document = {
        "endpoint_id": issued.endpoint.endpoint_id,
        "device_name": issued.endpoint.device_name,
        "assigned_user_id": issued.endpoint.assigned_user_id,
        "platform": issued.endpoint.platform.value,
        "active": True,
        "credential_digest": issued.endpoint.credential_digest,
        "created_at": issued.endpoint.created_at,
        "created_by": issued.endpoint.created_by,
    }
    collection = UpdateCollection(document)
    repository = MongoEndpointRepository({"endpoints": collection})
    now = datetime.now(UTC)
    report = runtime_health_payload()

    stored = asyncio.run(
        repository.record_runtime_heartbeat(
            issued.endpoint.endpoint_id, "0.2.0", now, report
        )
    )

    query, update, _ = collection.calls[0]
    assert query == {"endpoint_id": issued.endpoint.endpoint_id, "active": True}
    assert update == {
        "$set": {
            "agent_version": "0.2.0",
            "last_seen_at": now,
            "last_runtime_heartbeat_at": now,
            "runtime_health": report,
        }
    }
    assert stored.last_runtime_heartbeat_at == now
    assert stored.runtime_health == EndpointRuntimeHealth(**report)
    serialized = json.dumps(update, default=str)
    assert issued.credential not in serialized
    assert issued.endpoint.credential_digest not in serialized


@pytest.mark.parametrize("path", ["/service/v1/inventory", "/service/v1/heartbeat"])
@pytest.mark.parametrize("authentication", ["none", "browser"])
def test_agent_reporting_requires_machine_authentication(
    endpoint_context, path, authentication
):
    register_direct(endpoint_context)
    payload = (
        inventory_payload()
        if path.endswith("inventory")
        else {"agent_version": "0.1.0"}
    )
    with TestClient(app.main.app) as client:
        if authentication == "browser":
            sign_in(client, "team.member", EMPLOYEE_PASSWORD)
        response = client.request(
            "PUT" if path.endswith("inventory") else "POST", path, json=payload
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "Endpoint authentication failed."}


@pytest.mark.parametrize("path", ["/service/v1/inventory", "/service/v1/heartbeat"])
def test_disabled_endpoint_cannot_report(endpoint_context, path):
    service, users, _, _ = endpoint_context
    issued = register_direct(endpoint_context)
    asyncio.run(
        service.set_active(
            issued.endpoint.endpoint_id, False, "Device disabled", actor=users.admin
        )
    )
    payload = (
        inventory_payload()
        if path.endswith("inventory")
        else {"agent_version": "0.1.0"}
    )
    with TestClient(app.main.app) as client:
        response = client.request(
            "PUT" if path.endswith("inventory") else "POST",
            path,
            headers=machine_headers(issued.endpoint.endpoint_id, issued.credential),
            json=payload,
        )

    assert response.status_code == 401


def test_reenabled_endpoint_can_report_with_current_credential(endpoint_context):
    service, users, _, _ = endpoint_context
    issued = register_direct(endpoint_context)
    asyncio.run(
        service.set_active(issued.endpoint.endpoint_id, False, "Pause", actor=users.admin)
    )
    asyncio.run(
        service.set_active(issued.endpoint.endpoint_id, True, "Resume", actor=users.admin)
    )
    with TestClient(app.main.app) as client:
        inventory = client.put(
            "/service/v1/inventory",
            headers=machine_headers(issued.endpoint.endpoint_id, issued.credential),
            json=inventory_payload(),
        )
        heartbeat = client.post(
            "/service/v1/heartbeat",
            headers=machine_headers(issued.endpoint.endpoint_id, issued.credential),
            json={"agent_version": "0.1.0"},
        )

    assert inventory.status_code == 200
    assert heartbeat.status_code == 200


def test_inventory_updates_only_authenticated_endpoint_with_server_utc_time(
    endpoint_context,
):
    _, _, endpoints, audit = endpoint_context
    first = register_direct(endpoint_context, "ADMIN-NAME-ONE")
    second = register_direct(endpoint_context, "ADMIN-NAME-TWO")
    before = datetime.now(UTC)
    with TestClient(app.main.app) as client:
        response = client.put(
            "/service/v1/inventory",
            headers=machine_headers(first.endpoint.endpoint_id, first.credential),
            json=inventory_payload(),
        )
    after = datetime.now(UTC)

    assert response.status_code == 200
    stored = endpoints.items[first.endpoint.endpoint_id]
    untouched = endpoints.items[second.endpoint.endpoint_id]
    assert stored.reported_hostname == "REPORTED-HOST"
    assert stored.windows_version == "Windows 11 Pro"
    assert stored.os_build == "26100"
    assert stored.architecture == "AMD64"
    assert stored.agent_version == "0.1.0"
    assert before <= stored.inventory_updated_at <= after
    assert stored.inventory_updated_at.tzinfo is UTC
    assert response.json()["inventory_updated_at"] == stored.inventory_updated_at.isoformat()
    assert untouched.inventory_updated_at is None
    assert [event["event_type"] for event in audit.events] == [
        "endpoint.registered",
        "endpoint.registered",
    ]


@pytest.mark.parametrize(
    "changes",
    [
        {"endpoint_id": str(uuid4())},
        {"assigned_user_id": str(ObjectId())},
        {"active": False},
        {"credential_digest": "0" * 64},
        {"created_at": "2000-01-01T00:00:00Z"},
        {"inventory_updated_at": "2000-01-01T00:00:00Z"},
    ],
)
def test_inventory_payload_cannot_change_identity_lifecycle_or_security_fields(
    endpoint_context, changes
):
    _, _, endpoints, _ = endpoint_context
    issued = register_direct(endpoint_context)
    before = endpoints.items[issued.endpoint.endpoint_id]
    with TestClient(app.main.app) as client:
        response = client.put(
            "/service/v1/inventory",
            headers=machine_headers(issued.endpoint.endpoint_id, issued.credential),
            json=inventory_payload(**changes),
        )

    assert response.status_code == 422
    assert endpoints.items[issued.endpoint.endpoint_id] == before


@pytest.mark.parametrize(
    "payload",
    [
        {},
        inventory_payload(reported_hostname=""),
        inventory_payload(reported_hostname="x" * 256),
        inventory_payload(windows_version=123),
        inventory_payload(os_build=None),
        inventory_payload(architecture="x" * 51),
        inventory_payload(agent_version="x" * 51),
    ],
)
def test_inventory_rejects_malformed_or_unreasonable_input(endpoint_context, payload):
    issued = register_direct(endpoint_context)
    with TestClient(app.main.app) as client:
        response = client.put(
            "/service/v1/inventory",
            headers=machine_headers(issued.endpoint.endpoint_id, issued.credential),
            json=payload,
        )

    assert response.status_code == 422


def test_heartbeat_updates_server_generated_last_seen_without_audit(endpoint_context):
    _, _, endpoints, audit = endpoint_context
    issued = register_direct(endpoint_context)
    before = datetime.now(UTC)
    with TestClient(app.main.app) as client:
        response = client.post(
            "/service/v1/heartbeat",
            headers=machine_headers(issued.endpoint.endpoint_id, issued.credential),
            json={"agent_version": "0.1.1"},
        )
    after = datetime.now(UTC)

    assert response.status_code == 200
    stored = endpoints.items[issued.endpoint.endpoint_id]
    assert before <= stored.last_seen_at <= after
    assert stored.last_seen_at.tzinfo is UTC
    assert stored.agent_version == "0.1.1"
    assert response.json()["last_seen_at"] == stored.last_seen_at.isoformat()
    assert [event["event_type"] for event in audit.events] == ["endpoint.registered"]


def test_heartbeat_rejects_client_timestamp(endpoint_context):
    issued = register_direct(endpoint_context)
    with TestClient(app.main.app) as client:
        response = client.post(
            "/service/v1/heartbeat",
            headers=machine_headers(issued.endpoint.endpoint_id, issued.credential),
            json={
                "agent_version": "0.1.0",
                "last_seen_at": "2000-01-01T00:00:00Z",
            },
        )

    assert response.status_code == 422


def runtime_health_payload(**changes):
    payload = {
        "queue_pending_count": 3,
        "applied_policy_revision": 0,
        "protected_watchers_active_count": 1,
        "protected_folders_unavailable_count": 1,
        "removable_monitoring_active": True,
    }
    payload.update(changes)
    return payload


def test_structured_runtime_heartbeat_uses_authenticated_identity_and_server_time(
    endpoint_context,
):
    _, _, endpoints, audit = endpoint_context
    first = register_direct(endpoint_context, "FIRST")
    second = register_direct(endpoint_context, "SECOND")
    before = datetime.now(UTC)
    with TestClient(app.main.app) as client:
        response = client.post(
            "/service/v1/heartbeat",
            headers=machine_headers(first.endpoint.endpoint_id, first.credential),
            json={
                "agent_version": "0.2.0",
                "runtime_health": runtime_health_payload(),
            },
        )
    after = datetime.now(UTC)

    assert response.status_code == 200
    stored = endpoints.items[first.endpoint.endpoint_id]
    untouched = endpoints.items[second.endpoint.endpoint_id]
    assert before <= stored.last_runtime_heartbeat_at <= after
    assert stored.last_runtime_heartbeat_at.tzinfo is UTC
    assert stored.last_runtime_heartbeat_at == stored.last_seen_at
    assert stored.runtime_health == EndpointRuntimeHealth(**runtime_health_payload())
    assert untouched.last_runtime_heartbeat_at is None
    assert response.json()["last_runtime_heartbeat_at"] == stored.last_runtime_heartbeat_at.isoformat()
    assert [event["event_type"] for event in audit.events] == [
        "endpoint.registered",
        "endpoint.registered",
    ]


@pytest.mark.parametrize(
    "runtime_health",
    [
        runtime_health_payload(queue_pending_count=-1),
        runtime_health_payload(queue_pending_count=10_000_001),
        runtime_health_payload(applied_policy_revision=-1),
        runtime_health_payload(applied_policy_revision=2_147_483_648),
        runtime_health_payload(protected_watchers_active_count=11),
        runtime_health_payload(
            protected_watchers_active_count=6,
            protected_folders_unavailable_count=5,
        ),
        runtime_health_payload(protected_folders_unavailable_count=-1),
        runtime_health_payload(removable_monitoring_active="yes"),
        runtime_health_payload(unexpected="field"),
        {"queue_pending_count": 0},
    ],
)
def test_structured_runtime_heartbeat_rejects_invalid_or_unreasonable_health(
    endpoint_context, runtime_health
):
    issued = register_direct(endpoint_context)
    with TestClient(app.main.app) as client:
        response = client.post(
            "/service/v1/heartbeat",
            headers=machine_headers(issued.endpoint.endpoint_id, issued.credential),
            json={"agent_version": "0.2.0", "runtime_health": runtime_health},
        )
    assert response.status_code == 422


def test_runtime_heartbeat_rejects_body_identity(endpoint_context):
    issued = register_direct(endpoint_context)
    with TestClient(app.main.app) as client:
        response = client.post(
            "/service/v1/heartbeat",
            headers=machine_headers(issued.endpoint.endpoint_id, issued.credential),
            json={
                "agent_version": "0.2.0",
                "endpoint_id": str(uuid4()),
                "runtime_health": runtime_health_payload(),
            },
        )
    assert response.status_code == 422


def test_revision_zero_is_accepted_and_legacy_heartbeat_preserves_runtime_health(
    endpoint_context,
):
    _, _, endpoints, _ = endpoint_context
    issued = register_direct(endpoint_context)
    headers = machine_headers(issued.endpoint.endpoint_id, issued.credential)
    with TestClient(app.main.app) as client:
        structured = client.post(
            "/service/v1/heartbeat",
            headers=headers,
            json={
                "agent_version": "0.2.0",
                "runtime_health": runtime_health_payload(applied_policy_revision=0),
            },
        )
        first = endpoints.items[issued.endpoint.endpoint_id]
        legacy = client.post(
            "/service/v1/heartbeat",
            headers=headers,
            json={"agent_version": "0.2.1"},
        )
    stored = endpoints.items[issued.endpoint.endpoint_id]

    assert structured.status_code == legacy.status_code == 200
    assert "last_runtime_heartbeat_at" not in legacy.json()
    assert stored.last_seen_at >= first.last_seen_at
    assert stored.last_runtime_heartbeat_at == first.last_runtime_heartbeat_at
    assert stored.runtime_health == first.runtime_health


def test_health_snapshot_and_admin_health_pages_do_not_expose_secrets_or_paths(
    endpoint_context,
):
    _, _, endpoints, audit = endpoint_context
    issued = register_direct(endpoint_context, "HEALTH-DEVICE")
    headers = machine_headers(issued.endpoint.endpoint_id, issued.credential)
    with TestClient(app.main.app) as client:
        client.post(
            "/service/v1/heartbeat",
            headers=headers,
            json={
                "agent_version": "0.2.0",
                "runtime_health": runtime_health_payload(),
            },
        )
        sign_in(client)
        before_get = len(audit.events)
        listing = client.get("/administrator/endpoints")
        detail = client.get(
            f"/administrator/endpoints/{issued.endpoint.endpoint_id}"
        )

    secret_digest = endpoints.items[issued.endpoint.endpoint_id].credential_digest
    combined = listing.text + detail.text
    assert listing.status_code == detail.status_code == 200
    assert listing.headers["cache-control"] == detail.headers["cache-control"] == "no-store"
    assert "Runtime: Online" in listing.text
    assert "Synced" not in listing.text
    assert "Pending" in listing.text
    assert "Desired 0 · applied 0" in listing.text
    assert "Protected watchers active" in detail.text
    assert "Configured folders unavailable" in detail.text
    assert issued.credential not in combined
    assert secret_digest not in combined
    assert "C:\\" not in combined
    assert len(audit.events) == before_get


def test_endpoint_health_detail_is_administrator_only(endpoint_context):
    issued = register_direct(endpoint_context)
    path = f"/administrator/endpoints/{issued.endpoint.endpoint_id}"
    with TestClient(app.main.app) as client:
        unauthenticated = client.get(path, follow_redirects=False)
        sign_in(client, "team.member", EMPLOYEE_PASSWORD)
        employee = client.get(path)

    assert unauthenticated.status_code == 303
    assert unauthenticated.headers["location"] == "/login"
    assert employee.status_code == 403


def test_administrator_page_distinguishes_assigned_name_and_reported_hostname(
    endpoint_context,
):
    _, _, endpoints, _ = endpoint_context
    issued = register_direct(endpoint_context, "ADMIN-ASSIGNED-NAME")
    now = datetime.now(UTC)
    endpoints.items[issued.endpoint.endpoint_id] = replace(
        issued.endpoint,
        **inventory_payload(),
        inventory_updated_at=now,
        last_seen_at=now,
    )
    with TestClient(app.main.app) as client:
        sign_in(client)
        response = client.get("/administrator/endpoints")

    assert response.status_code == 200
    assert "ADMIN-ASSIGNED-NAME" in response.text
    assert "REPORTED-HOST" in response.text
    assert "Windows 11 Pro" in response.text
    assert "26100" in response.text
    assert "AMD64" in response.text
    assert "0.1.0" in response.text


class InMemoryRawEvents:
    def __init__(self):
        self.documents = {}

    async def store_idempotent(self, endpoint_id, envelope, received_at):
        identity = (endpoint_id, str(envelope.event_id))
        self.documents.setdefault(
            identity,
            {
                "endpoint_id": endpoint_id,
                "event_id": str(envelope.event_id),
                "event_type": envelope.event_type,
                "schema_version": envelope.schema_version,
                "occurred_at": envelope.occurred_at,
                "received_at": received_at,
                "payload": envelope.payload,
            },
        )

    async def list_recent(self, *, endpoint_ids=None, event_type=None, limit):
        items = self.documents.values()
        if endpoint_ids is not None:
            items = [item for item in items if item["endpoint_id"] in endpoint_ids]
        if event_type is not None:
            items = [item for item in items if item["event_type"] == event_type]
        return [
            RawEventEnvelopeDocument(item)
            for item in sorted(items, key=lambda item: item["received_at"], reverse=True)[:limit]
        ]

    async def find_by_identity(self, endpoint_id, event_id):
        item = self.documents.get((endpoint_id, event_id))
        return RawEventEnvelopeDocument(item) if item else None


class RawEventEnvelopeDocument:
    """Test stand-in matching the repository's safe stored-event record."""

    def __init__(self, item):
        self.endpoint_id = item["endpoint_id"]
        self.event_id = item["event_id"]
        self.event_type = item["event_type"]
        self.schema_version = item["schema_version"]
        self.occurred_at = item["occurred_at"]
        self.received_at = item["received_at"]
        self.payload = item["payload"]


@pytest.fixture
def raw_event_context(endpoint_context):
    repository = InMemoryRawEvents()
    service = RawEventService(repository)
    app.main.app.dependency_overrides[get_raw_event_service] = lambda: service
    try:
        yield endpoint_context, repository
    finally:
        app.main.app.dependency_overrides.pop(get_raw_event_service, None)


@pytest.fixture
def event_view_context(raw_event_context):
    context, repository = raw_event_context
    _, users, endpoints, _ = context
    view_service = AdministratorRawEventService(repository, endpoints, users)
    app.main.app.dependency_overrides[get_administrator_raw_event_service] = lambda: view_service
    try:
        yield context, repository
    finally:
        app.main.app.dependency_overrides.pop(get_administrator_raw_event_service, None)


def raw_event(event_id=None, **overrides):
    event = {
        "event_id": event_id or str(uuid4()),
        "event_type": "development.test",
        "schema_version": 1,
        "occurred_at": "2026-08-14T12:30:45+05:45",
        "payload": {"observation": "transport-only"},
    }
    event.update(overrides)
    return event


@pytest.mark.parametrize("authentication", ["none", "browser"])
def test_event_batch_requires_machine_authentication(raw_event_context, authentication):
    context, repository = raw_event_context
    register_direct(context)
    with TestClient(app.main.app) as client:
        if authentication == "browser":
            sign_in(client, "team.member", EMPLOYEE_PASSWORD)
        response = client.post(
            "/service/v1/events/batch", json={"events": [raw_event()]}
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "Endpoint authentication failed."}
    assert repository.documents == {}


def test_disabled_endpoint_cannot_ingest_raw_events(raw_event_context):
    context, repository = raw_event_context
    service, users, _, _ = context
    issued = register_direct(context)
    asyncio.run(
        service.set_active(issued.endpoint.endpoint_id, False, "Device disabled", actor=users.admin)
    )

    with TestClient(app.main.app) as client:
        response = client.post(
            "/service/v1/events/batch",
            headers=machine_headers(issued.endpoint.endpoint_id, issued.credential),
            json={"events": [raw_event()]},
        )

    assert response.status_code == 401
    assert repository.documents == {}


def test_authenticated_identity_is_authoritative_and_timestamps_are_separate(
    raw_event_context,
):
    context, repository = raw_event_context
    issued = register_direct(context)
    client_id = str(uuid4())
    before = datetime.now(UTC)

    with TestClient(app.main.app) as client:
        response = client.post(
            "/service/v1/events/batch",
            headers=machine_headers(issued.endpoint.endpoint_id, issued.credential),
            json={
                "events": [
                    raw_event(
                        client_id,
                        payload={
                            "endpoint_id": str(uuid4()),
                            "employee_id": str(ObjectId()),
                            "observation": "identity fields are untrusted payload data",
                        },
                    )
                ]
            },
        )
    after = datetime.now(UTC)

    assert response.status_code == 200
    assert response.json() == {"acknowledged_event_ids": [client_id]}
    stored = repository.documents[(issued.endpoint.endpoint_id, client_id)]
    assert stored["endpoint_id"] == issued.endpoint.endpoint_id
    assert stored["occurred_at"] == datetime(2026, 8, 14, 6, 45, 45, tzinfo=UTC)
    assert before <= stored["received_at"] <= after
    assert stored["received_at"] != stored["occurred_at"]


def test_duplicate_replay_for_same_endpoint_is_stored_once_but_acknowledged_again(
    raw_event_context,
):
    context, repository = raw_event_context
    issued = register_direct(context)
    event_id = str(uuid4())
    headers = machine_headers(issued.endpoint.endpoint_id, issued.credential)
    body = {"events": [raw_event(event_id)]}

    with TestClient(app.main.app) as client:
        first = client.post("/service/v1/events/batch", headers=headers, json=body)
        second = client.post("/service/v1/events/batch", headers=headers, json=body)

    assert first.json() == second.json() == {"acknowledged_event_ids": [event_id]}
    assert len(repository.documents) == 1


def test_same_client_event_uuid_is_distinct_for_two_authenticated_endpoints(
    raw_event_context,
):
    context, repository = raw_event_context
    first = register_direct(context, "FIRST-LAPTOP")
    second = register_direct(context, "SECOND-LAPTOP")
    event_id = str(uuid4())
    body = {"events": [raw_event(event_id)]}

    with TestClient(app.main.app) as client:
        first_response = client.post(
            "/service/v1/events/batch",
            headers=machine_headers(first.endpoint.endpoint_id, first.credential),
            json=body,
        )
        second_response = client.post(
            "/service/v1/events/batch",
            headers=machine_headers(second.endpoint.endpoint_id, second.credential),
            json=body,
        )

    assert first_response.status_code == second_response.status_code == 200
    assert set(repository.documents) == {
        (first.endpoint.endpoint_id, event_id),
        (second.endpoint.endpoint_id, event_id),
    }


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"events": []},
        {"events": [raw_event(event_id="not-a-uuid")]},
        {"events": [raw_event(event_type="USB.CONNECTED")]},
        {"events": [raw_event(event_type="x" * 65)]},
        {"events": [raw_event(schema_version=2)]},
        {"events": [raw_event(schema_version="1")]},
        {"events": [raw_event(occurred_at="2026-08-14T12:30:45")]},
        {"events": [raw_event(occurred_at=1_786_710_645)]},
        {"events": [raw_event(payload=[])]},
        {"events": [{**raw_event(), "unexpected": True}]},
        {"events": [raw_event()], "unexpected": True},
        {"events": [raw_event(payload={"value": "x" * 16_385})]},
        {"events": [raw_event() for _ in range(51)]},
        {
            "events": [
                raw_event(payload={"value": "x" * 14_000}) for _ in range(20)
            ]
        },
    ],
)
def test_raw_event_batch_validation_is_strict_and_bounded(raw_event_context, body):
    context, repository = raw_event_context
    issued = register_direct(context)

    with TestClient(app.main.app) as client:
        response = client.post(
            "/service/v1/events/batch",
            headers=machine_headers(issued.endpoint.endpoint_id, issued.credential),
            json=body,
        )

    assert response.status_code == 422
    assert repository.documents == {}


def test_raw_event_ingestion_does_not_create_audit_or_alert_noise(raw_event_context):
    context, repository = raw_event_context
    _, _, _, audit = context
    issued = register_direct(context)

    with TestClient(app.main.app) as client:
        response = client.post(
            "/service/v1/events/batch",
            headers=machine_headers(issued.endpoint.endpoint_id, issued.credential),
            json={
                "events": [
                    raw_event(
                        event_type="removable.volume_arrived",
                        payload={"drive_name": "E:", "drive_type": "removable_disk"},
                    )
                ]
            },
        )

    assert response.status_code == 200
    assert len(repository.documents) == 1
    assert [event["event_type"] for event in audit.events] == ["endpoint.registered"]


def store_raw_event(repository, endpoint_id, *, received_at, **overrides):
    envelope = RawEventEnvelope.model_validate(raw_event(**overrides))
    asyncio.run(repository.store_idempotent(endpoint_id, envelope, received_at))
    return envelope


def test_administrator_raw_event_page_is_role_restricted_and_read_only(event_view_context):
    context, repository = event_view_context
    issued = register_direct(context)
    store_raw_event(repository, issued.endpoint.endpoint_id, received_at=datetime.now(UTC))

    with TestClient(app.main.app) as client:
        unauthenticated = client.get("/administrator/events", follow_redirects=False)
        sign_in(client, "team.member", EMPLOYEE_PASSWORD)
        employee = client.get("/administrator/events")

    assert unauthenticated.status_code == 303
    assert unauthenticated.headers["location"] == "/login"
    assert employee.status_code == 403


def test_administrator_event_page_resolves_retained_context_and_only_safe_metadata(
    event_view_context,
):
    context, repository = event_view_context
    _, users, endpoints, audit = context
    issued = register_direct(context, "ASSIGNED-LAPTOP")
    endpoints.items[issued.endpoint.endpoint_id] = replace(
        issued.endpoint,
        active=False,
        reported_hostname="REPORTED-HOST",
    )
    asyncio.run(users.set_enabled(users.employee.id, False))
    event = store_raw_event(
        repository,
        issued.endpoint.endpoint_id,
        event_type="removable.volume_arrived",
        payload={
            "drive_name": "E:",
            "drive_type": "removable_disk",
            "volume_label": "THESIS_USB",
            "filesystem": "NTFS",
            "unexpected": "leaked-secret-value",
            "credential": "must-not-render",
        },
        received_at=datetime(2026, 8, 14, 8, 0, tzinfo=UTC),
    )

    with TestClient(app.main.app) as client:
        sign_in(client)
        page = client.get("/administrator/events")
        detail = client.get(
            f"/administrator/events/{issued.endpoint.endpoint_id}/{event.event_id}"
        )

    assert page.status_code == detail.status_code == 200
    assert "Removable volume connected" in page.text
    assert "ASSIGNED-LAPTOP" in page.text
    assert "REPORTED-HOST" in page.text
    assert "Endpoint assigned to: Team Member" in page.text
    assert "Disabled" in page.text
    assert "Drive: E:" in page.text
    assert "Drive type: removable_disk" in page.text
    assert "Volume label: THESIS_USB" in page.text
    assert "Filesystem: NTFS" in detail.text
    assert "leaked-secret-value" not in page.text
    assert "must-not-render" not in detail.text
    assert "credential_digest" not in detail.text
    assert not any(item["event_type"].startswith("removable.") for item in audit.events)


def test_administrator_filesystem_events_render_only_allowlisted_safe_metadata(
    event_view_context,
):
    context, repository = event_view_context
    issued = register_direct(context, "PROTECTED-LAPTOP")
    event = store_raw_event(
        repository,
        issued.endpoint.endpoint_id,
        event_type="filesystem.file_moved",
        payload={
            "monitored_root": "Thesis",
            "old_relative_path": "drafts/chapter-old.docx",
            "new_relative_path": "review/chapter.docx",
            "extension": ".docx",
            "absolute_path": "C:\\Users\\someone\\private\\chapter.docx",
            "content": "must-not-render",
        },
        received_at=datetime(2026, 8, 14, 8, 30, tzinfo=UTC),
    )
    malformed = store_raw_event(
        repository,
        issued.endpoint.endpoint_id,
        event_type="filesystem.file_created",
        payload={
            "monitored_root": "Thesis",
            "relative_path": "C:\\Windows\\System32\\config",
            "extension": ".docx",
        },
        received_at=datetime(2026, 8, 14, 8, 31, tzinfo=UTC),
    )

    with TestClient(app.main.app) as client:
        sign_in(client)
        page = client.get("/administrator/events")
        detail = client.get(
            f"/administrator/events/{issued.endpoint.endpoint_id}/{event.event_id}"
        )
        malformed_detail = client.get(
            f"/administrator/events/{issued.endpoint.endpoint_id}/{malformed.event_id}"
        )

    assert page.status_code == detail.status_code == malformed_detail.status_code == 200
    assert "File moved or renamed" in page.text
    assert "Old relative path: drafts/chapter-old.docx" in detail.text
    assert "New relative path: review/chapter.docx" in detail.text
    assert "Extension: .docx" in detail.text
    assert "Protected folder: Thesis" in detail.text
    assert "C:\\Users\\someone" not in page.text
    assert "must-not-render" not in detail.text
    assert "C:\\Windows\\System32" not in malformed_detail.text


def test_administrator_removable_file_events_use_labels_and_allowlisted_metadata(
    event_view_context,
):
    context, repository = event_view_context
    issued = register_direct(context, "REMOVABLE-LAPTOP")
    payloads = {
        "removable.file_created": {
            "drive_name": "E:",
            "volume_label": "THESIS_USB",
            "relative_path": "drafts/chapter.docx",
            "extension": ".docx",
            "size_bytes": 4096,
            "source_path": "C:\\Users\\someone\\private\\chapter.docx",
            "content": "must-not-render",
        },
        "removable.file_modified": {
            "drive_name": "E:",
            "relative_path": "drafts/chapter.docx",
        },
        "removable.file_deleted": {
            "drive_name": "E:",
            "relative_path": "old.txt",
        },
        "removable.file_moved": {
            "drive_name": "E:",
            "old_relative_path": "drafts/old.docx",
            "new_relative_path": "review/new.docx",
            "extension": ".docx",
        },
    }
    events = [
        store_raw_event(
            repository,
            issued.endpoint.endpoint_id,
            event_type=event_type,
            payload=payload,
            received_at=datetime(2026, 8, 14, 8, 40 + index, tzinfo=UTC),
        )
        for index, (event_type, payload) in enumerate(payloads.items())
    ]

    with TestClient(app.main.app) as client:
        sign_in(client)
        page = client.get("/administrator/events")
        created_detail = client.get(
            f"/administrator/events/{issued.endpoint.endpoint_id}/{events[0].event_id}"
        )

    assert page.status_code == created_detail.status_code == 200
    for label in (
        "File created on removable storage",
        "File modified on removable storage",
        "File deleted from removable storage",
        "File moved/renamed on removable storage",
    ):
        assert label in page.text
    assert "Endpoint assigned to: Team Member" in page.text
    assert "Drive: E:" in created_detail.text
    assert "Volume label: THESIS_USB" in created_detail.text
    assert "Relative path: drafts/chapter.docx" in created_detail.text
    assert "Extension: .docx" in created_detail.text
    assert "Observed size: 4096 bytes" in created_detail.text
    assert "C:\\Users\\someone" not in page.text + created_detail.text
    assert "must-not-render" not in page.text + created_detail.text
    assert "source_path" not in page.text + created_detail.text


def test_administrator_boundary_moves_render_without_external_path_leaks(
    event_view_context,
):
    context, repository = event_view_context
    issued = register_direct(context, "BOUNDARY-LAPTOP")
    moved_out = store_raw_event(
        repository,
        issued.endpoint.endpoint_id,
        event_type="filesystem.file_moved_out",
        payload={
            "monitored_root": "Thesis",
            "relative_path": "drafts/chapter.docx",
            "extension": ".docx",
            "destination_scope": "outside_protected_root",
            "external_destination_path": "C:\\Private\\leak-out.docx",
        },
        received_at=datetime(2026, 8, 14, 8, 32, tzinfo=UTC),
    )
    moved_in = store_raw_event(
        repository,
        issued.endpoint.endpoint_id,
        event_type="filesystem.file_moved_in",
        payload={
            "monitored_root": "Thesis",
            "relative_path": "received/source.pdf",
            "extension": ".pdf",
            "source_scope": "outside_protected_root",
            "external_source_path": "D:\\Unrelated\\leak-in.pdf",
        },
        received_at=datetime(2026, 8, 14, 8, 33, tzinfo=UTC),
    )

    with TestClient(app.main.app) as client:
        sign_in(client)
        page = client.get("/administrator/events")
        moved_out_detail = client.get(
            f"/administrator/events/{issued.endpoint.endpoint_id}/{moved_out.event_id}"
        )
        moved_in_detail = client.get(
            f"/administrator/events/{issued.endpoint.endpoint_id}/{moved_in.event_id}"
        )

    assert page.status_code == moved_out_detail.status_code == moved_in_detail.status_code == 200
    assert "File moved out of protected folder" in page.text
    assert "File moved into protected folder" in page.text
    assert "Relative source path: drafts/chapter.docx" in moved_out_detail.text
    assert "Destination: Outside protected folder" in moved_out_detail.text
    assert "Relative destination path: received/source.pdf" in moved_in_detail.text
    assert "Source: Outside protected folder" in moved_in_detail.text
    assert "C:\\Private\\leak-out.docx" not in page.text + moved_out_detail.text
    assert "D:\\Unrelated\\leak-in.pdf" not in page.text + moved_in_detail.text


def test_administrator_event_filters_order_and_unknown_types_are_safe(event_view_context):
    context, repository = event_view_context
    first = register_direct(context, "FIRST-LAPTOP")
    second = register_direct(context, "SECOND-LAPTOP")
    older = store_raw_event(
        repository,
        first.endpoint.endpoint_id,
        event_type="removable.volume_removed",
        payload={"drive_name": "D:"},
        received_at=datetime(2026, 8, 14, 7, 0, tzinfo=UTC),
    )
    newer = store_raw_event(
        repository,
        second.endpoint.endpoint_id,
        event_type="future.activity",
        payload={"secret": "do-not-show", "path": "C:\\private"},
        received_at=datetime(2026, 8, 14, 8, 0, tzinfo=UTC),
    )

    with TestClient(app.main.app) as client:
        sign_in(client)
        all_events = client.get("/administrator/events")
        endpoint_filtered = client.get(
            f"/administrator/events?endpoint={first.endpoint.endpoint_id}"
        )
        employee_filtered = client.get(
            f"/administrator/events?employee={context[1].employee.id}"
        )
        type_filtered = client.get("/administrator/events?event_type=removable.volume_removed")
        invalid = client.get("/administrator/events?event_type=INVALID.TYPE")

    assert all_events.status_code == 200
    assert all_events.text.index(str(newer.event_id)) < all_events.text.index(str(older.event_id))
    assert "future.activity" in all_events.text
    assert "do-not-show" not in all_events.text
    assert "C:\\private" not in all_events.text
    assert endpoint_filtered.status_code == 200
    assert str(older.event_id) in endpoint_filtered.text
    assert str(newer.event_id) not in endpoint_filtered.text
    assert employee_filtered.status_code == 200
    assert str(older.event_id) in employee_filtered.text and str(newer.event_id) in employee_filtered.text
    assert type_filtered.status_code == 200
    assert str(older.event_id) in type_filtered.text and str(newer.event_id) not in type_filtered.text
    assert invalid.status_code == 200
    assert "No matching endpoint events" in invalid.text


def test_administrator_event_results_are_bounded(event_view_context):
    context, repository = event_view_context
    issued = register_direct(context)
    for index in range(MAX_ADMIN_EVENT_RESULTS + 2):
        store_raw_event(
            repository,
            issued.endpoint.endpoint_id,
            event_type="future.activity",
            payload={},
            received_at=datetime(2026, 8, 14, 8, 0, index % 60, tzinfo=UTC),
        )

    with TestClient(app.main.app) as client:
        sign_in(client)
        response = client.get("/administrator/events")

    assert response.status_code == 200
    assert "100 shown" in response.text
    assert "Only the 100 newest matching events are shown" in response.text


def test_raw_event_repository_creates_endpoint_scoped_unique_index():
    collection = IndexCollection()
    repository = MongoRawEventRepository({"raw_endpoint_events": collection})

    asyncio.run(repository.ensure_indexes())

    unique = next(
        (keys, options)
        for keys, options in collection.create_calls
        if options.get("name") == "unique_endpoint_event"
    )
    assert unique == (
        [("endpoint_id", 1), ("event_id", 1)],
        {"unique": True, "name": "unique_endpoint_event"},
    )
    assert {options["name"] for _, options in collection.create_calls} == {
        "unique_endpoint_event",
        "endpoint_received_events",
        "recent_received_events",
        "event_type_received_events",
        "endpoint_type_occurred_events",
    }


class RawEventMongoCollection:
    def __init__(self):
        self.documents = {}

    async def update_one(self, identity, update, upsert):
        assert upsert is True
        key = (identity["endpoint_id"], identity["event_id"])
        self.documents.setdefault(key, dict(update["$setOnInsert"]))


def test_mongo_raw_event_document_uses_authenticated_endpoint_and_distinct_times():
    collection = RawEventMongoCollection()
    repository = MongoRawEventRepository({"raw_endpoint_events": collection})
    endpoint_id = str(uuid4())
    event_id = str(uuid4())
    envelope = RawEventEnvelope.model_validate(raw_event(event_id))
    received_at = datetime.now(UTC)

    asyncio.run(repository.store_idempotent(endpoint_id, envelope, received_at))
    document = collection.documents[(endpoint_id, event_id)]

    assert set(document) == {
        "endpoint_id",
        "event_id",
        "event_type",
        "schema_version",
        "occurred_at",
        "received_at",
        "payload",
    }
    assert document["endpoint_id"] == endpoint_id
    assert document["received_at"] == received_at
    assert document["occurred_at"] == envelope.occurred_at
