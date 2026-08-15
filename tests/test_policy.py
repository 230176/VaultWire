"""Task 16 endpoint-specific administrator monitoring policy tests."""

import asyncio
import json
import re
from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

import agent.__main__ as agent_cli
import agent.service as agent_service
import app.main
from agent.client import EndpointClient, EndpointPolicy
from agent.config import ConfigStore
from agent.service import enroll
from app.auth import AuditService, AuthService
from app.dependencies import (
    get_auth_service,
    get_endpoint_service,
    get_monitoring_policy_service,
)
from app.endpoints import EndpointService
from app.models import EndpointMonitoringPolicy, ManagedEndpoint, Role, User
from app.policies import InvalidMonitoringPolicy, MonitoringPolicyService, validate_protected_folders
from app.repositories import MongoMonitoringPolicyRepository
from app.security import PasswordManager

ADMIN_PASSWORD = "administrator-password"
EMPLOYEE_PASSWORD = "employee-password-2026"
PASSWORDS = PasswordManager()


class Users:
    def __init__(self):
        now = datetime.now(UTC)
        self.admin = User(
            ObjectId(),
            "admin.user",
            PASSWORDS.hash(ADMIN_PASSWORD),
            Role.ADMINISTRATOR,
            True,
            "Administrator",
            now,
        )
        self.employee = User(
            ObjectId(),
            "team.member",
            PASSWORDS.hash(EMPLOYEE_PASSWORD),
            Role.EMPLOYEE,
            True,
            "Team Member",
            now,
        )
        self.by_id = {self.admin.id: self.admin, self.employee.id: self.employee}
        self.by_username = {user.username: user for user in self.by_id.values()}

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


class Sessions:
    def __init__(self):
        self.items = {}

    async def create(self, token_digest, user_id, created_at, expires_at):
        self.items[token_digest] = {"user_id": user_id, "expires_at": expires_at}

    async def find_valid(self, token_digest, now):
        item = self.items.get(token_digest)
        return item if item and item["expires_at"] > now else None

    async def delete(self, token_digest):
        self.items.pop(token_digest, None)


class Audit:
    def __init__(self):
        self.events = []

    async def append(self, event):
        self.events.append(dict(event))


class Endpoints:
    def __init__(self):
        self.items = {}

    async def create(self, endpoint):
        self.items[endpoint.endpoint_id] = endpoint
        return endpoint

    async def find_by_endpoint_id(self, endpoint_id):
        return self.items.get(endpoint_id)

    async def list_all(self):
        return list(self.items.values())

    async def transition_active_state(
        self, endpoint_id, expected_active, active, changed_at, changed_by, reason
    ):
        endpoint = self.items.get(endpoint_id)
        if endpoint is None or endpoint.active is not expected_active:
            return None
        endpoint = replace(endpoint, active=active)
        self.items[endpoint_id] = endpoint
        return endpoint


class Policies:
    def __init__(self):
        self.items = {}

    async def find_by_endpoint_id(self, endpoint_id):
        return self.items.get(endpoint_id)

    async def save(
        self,
        endpoint_id,
        expected_revision,
        monitoring_enabled,
        removable_enabled,
        protected_folders,
        updated_at,
        updated_by,
    ):
        previous = self.items.get(endpoint_id)
        actual_revision = previous.revision if previous else 0
        if actual_revision != expected_revision:
            return None
        policy = EndpointMonitoringPolicy(
            endpoint_id=endpoint_id,
            revision=actual_revision + 1,
            monitoring_enabled=monitoring_enabled,
            removable_storage_monitoring_enabled=removable_enabled,
            protected_folders=tuple(protected_folders),
            created_at=previous.created_at if previous else updated_at,
            created_by=previous.created_by if previous else updated_by,
            updated_at=updated_at,
            updated_by=updated_by,
        )
        self.items[endpoint_id] = policy
        return policy


class NoopDatabase:
    database = None

    async def connect(self):
        pass

    async def close(self):
        pass

    async def ping(self):
        return True


@pytest.fixture
def policy_context(monkeypatch):
    users = Users()
    sessions = Sessions()
    audit_repository = Audit()
    endpoints = Endpoints()
    policies = Policies()
    audit = AuditService(audit_repository)
    auth = AuthService(users, sessions, audit, password_manager=PASSWORDS)
    endpoint_service = EndpointService(endpoints, users, audit, policies)
    policy_service = MonitoringPolicyService(policies, endpoints, users, audit)
    monkeypatch.setattr(app.main, "MongoDatabase", NoopDatabase)
    app.main.app.dependency_overrides[get_auth_service] = lambda: auth
    app.main.app.dependency_overrides[get_endpoint_service] = lambda: endpoint_service
    app.main.app.dependency_overrides[get_monitoring_policy_service] = lambda: policy_service
    try:
        yield endpoint_service, policy_service, users, endpoints, policies, audit_repository
    finally:
        app.main.app.dependency_overrides.clear()


def register(context, name="POLICY-LAPTOP"):
    endpoint_service, _, users, *_ = context
    return asyncio.run(endpoint_service.register(name, users.employee.id, actor=users.admin))


def test_endpoint_health_directory_uses_current_server_desired_policy_revision(
    policy_context,
):
    endpoint_service, policy_service, users, *_ = policy_context
    issued = register(policy_context)
    updated = asyncio.run(
        policy_service.update(
            issued.endpoint.endpoint_id,
            0,
            True,
            False,
            [r"C:\Approved"],
            actor=users.admin,
        )
    )

    entry = asyncio.run(
        endpoint_service.get_directory_entry(issued.endpoint.endpoint_id)
    )

    assert updated.revision == 1
    assert entry.health.desired_policy_revision == 1


def machine_headers(issued):
    return {
        "X-NepShield-Endpoint-ID": issued.endpoint.endpoint_id,
        "Authorization": f"Bearer {issued.credential}",
    }


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


def policy_form(token, revision=0, **overrides):
    data = {
        "csrf_token": token,
        "expected_revision": str(revision),
        "monitoring_enabled": "true",
        "removable_storage_monitoring_enabled": "true",
        "protected_folders": "C:\\Users\\Team Member\\Work\nD:\\Approved\\Research",
    }
    data.update(overrides)
    return data


def test_legacy_endpoint_receives_safe_revision_zero_without_persistence_or_audit(policy_context):
    issued = register(policy_context)
    _, _, _, _, policies, audit = policy_context
    lifecycle_audit_count = len(audit.events)
    with TestClient(app.main.app) as client:
        first = client.get("/service/v1/policy", headers=machine_headers(issued))
        second = client.get("/service/v1/policy", headers=machine_headers(issued))

    expected = {
        "revision": 0,
        "monitoring_enabled": False,
        "removable_storage_monitoring_enabled": False,
        "protected_folders": [],
        "updated_at": None,
    }
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json() == expected
    assert first.headers["cache-control"] == "no-store"
    assert policies.items == {}
    assert len(audit.events) == lifecycle_audit_count


def test_administrator_creates_revision_one_and_update_increments_with_ordered_flags(
    policy_context,
):
    issued = register(policy_context)
    _, _, _, _, policies, audit = policy_context
    path = f"/administrator/endpoints/{issued.endpoint.endpoint_id}/policy"
    with TestClient(app.main.app) as client:
        sign_in(client)
        created = client.post(
            path, data=policy_form(csrf_token(client, path)), follow_redirects=False
        )
        updated = client.post(
            path,
            data=policy_form(
                csrf_token(client, path),
                revision=1,
                monitoring_enabled=None,
                protected_folders="E:\\First\\Folder\nC:\\Second\\Folder",
            ),
            follow_redirects=False,
        )

    policy = policies.items[issued.endpoint.endpoint_id]
    assert created.status_code == updated.status_code == 303
    assert policy.revision == 2
    assert policy.monitoring_enabled is False
    assert policy.removable_storage_monitoring_enabled is True
    assert policy.protected_folders == ("E:\\First\\Folder", "C:\\Second\\Folder")
    events = [event for event in audit.events if event["event_type"] == "endpoint.policy_updated"]
    assert [event["context"]["new_revision"] for event in events] == [1, 2]
    assert events[-1]["context"]["previous_monitoring_enabled"] is True
    assert events[-1]["context"]["new_monitoring_enabled"] is False
    serialized = json.dumps(events, default=str).casefold()
    assert issued.credential.casefold() not in serialized
    assert "credential_digest" not in serialized
    assert "c:\\second" not in serialized


def test_identical_persisted_save_preserves_revision_metadata_and_audit(policy_context):
    issued = register(policy_context)
    _, policy_service, users, _, policies, audit = policy_context
    created = asyncio.run(
        policy_service.update(
            issued.endpoint.endpoint_id,
            0,
            True,
            True,
            [r"C:\Users\Team Member\Work", r"D:\Approved\Research"],
            actor=users.admin,
        )
    )
    original_policy_audits = len(
        [event for event in audit.events if event["event_type"] == "endpoint.policy_updated"]
    )
    path = f"/administrator/endpoints/{issued.endpoint.endpoint_id}/policy"

    with TestClient(app.main.app) as client:
        sign_in(client)
        response = client.post(
            path,
            data=policy_form(
                csrf_token(client, path),
                revision=1,
                protected_folders=(
                    "c:/Users/Team Member/Work/\n"
                    "d:/Approved/Research/"
                ),
            ),
            follow_redirects=False,
        )
        rendered = client.get(response.headers["location"])

    retained = policies.items[issued.endpoint.endpoint_id]
    assert response.status_code == 303
    assert response.headers["location"].endswith("success=unchanged")
    assert "No monitoring policy changes were needed." in rendered.text
    assert retained.revision == created.revision == 1
    assert retained.updated_at == created.updated_at
    assert retained.updated_by == created.updated_by
    assert len(
        [event for event in audit.events if event["event_type"] == "endpoint.policy_updated"]
    ) == original_policy_audits


def test_legacy_default_submission_stays_revision_zero_without_document_or_audit(
    policy_context,
):
    issued = register(policy_context)
    _, _, _, _, policies, audit = policy_context
    original_policy_audits = len(
        [event for event in audit.events if event["event_type"] == "endpoint.policy_updated"]
    )
    path = f"/administrator/endpoints/{issued.endpoint.endpoint_id}/policy"

    with TestClient(app.main.app) as client:
        sign_in(client)
        response = client.post(
            path,
            data={
                "csrf_token": csrf_token(client, path),
                "expected_revision": "0",
                "protected_folders": "",
            },
            follow_redirects=False,
        )
        rendered = client.get(response.headers["location"])

    assert response.status_code == 303
    assert response.headers["location"].endswith("success=unchanged")
    assert "No monitoring policy changes were needed." in rendered.text
    assert policies.items == {}
    assert len(
        [event for event in audit.events if event["event_type"] == "endpoint.policy_updated"]
    ) == original_policy_audits


@pytest.mark.parametrize(
    "folders",
    [
        [r"relative\work"],
        ["C:\\"],
        [r"C:\Work\*.docx"],
        ["C:\\Work\\bad\x01name"],
        [r"\\.\PhysicalDrive0"],
        [r"\\?\C:\Work"],
        [r"\\server\share\work"],
        ["https://files.example.test/work"],
        ["file:///C:/Work"],
        [r"C:\Work", r"c:\work\\"],
    ],
)
def test_protected_folder_unsafe_paths_are_rejected(folders):
    with pytest.raises(InvalidMonitoringPolicy):
        validate_protected_folders(folders)


def test_protected_folder_count_is_bounded():
    with pytest.raises(InvalidMonitoringPolicy, match="At most 10"):
        validate_protected_folders([f"C:\\Approved\\Folder{number}" for number in range(11)])


def test_agent_identity_is_authoritative_and_endpoint_cannot_select_another_policy(
    policy_context,
):
    first = register(policy_context, "FIRST")
    second = register(policy_context, "SECOND")
    _, policy_service, users, *_ = policy_context
    asyncio.run(
        policy_service.update(
            first.endpoint.endpoint_id, 0, True, False, [r"C:\First\Work"], actor=users.admin
        )
    )
    asyncio.run(
        policy_service.update(
            second.endpoint.endpoint_id, 0, False, True, [r"D:\Second\Work"], actor=users.admin
        )
    )
    with TestClient(app.main.app) as client:
        response = client.get(
            f"/service/v1/policy?endpoint_id={second.endpoint.endpoint_id}",
            headers=machine_headers(first),
        )

    assert response.status_code == 200
    assert response.json()["monitoring_enabled"] is True
    assert response.json()["protected_folders"] == [r"C:\First\Work"]
    assert second.endpoint.endpoint_id not in response.text


@pytest.mark.parametrize("authentication", ["missing", "wrong", "browser", "disabled"])
def test_policy_requires_current_machine_authentication(policy_context, authentication):
    issued = register(policy_context)
    endpoint_service, _, users, *_ = policy_context
    with TestClient(app.main.app) as client:
        if authentication == "browser":
            sign_in(client, users.employee.username, EMPLOYEE_PASSWORD)
            response = client.get("/service/v1/policy")
        elif authentication == "wrong":
            headers = machine_headers(issued)
            headers["Authorization"] = "Bearer wrong-credential"
            response = client.get("/service/v1/policy", headers=headers)
        elif authentication == "disabled":
            asyncio.run(
                endpoint_service.set_active(
                    issued.endpoint.endpoint_id, False, "Test disable", actor=users.admin
                )
            )
            response = client.get("/service/v1/policy", headers=machine_headers(issued))
        else:
            response = client.get("/service/v1/policy")
    assert response.status_code == 401
    assert response.json() == {"detail": "Endpoint authentication failed."}


def test_policy_admin_page_and_update_require_administrator_role_and_csrf(policy_context):
    issued = register(policy_context)
    path = f"/administrator/endpoints/{issued.endpoint.endpoint_id}/policy"
    with TestClient(app.main.app) as client:
        sign_in(client, "team.member", EMPLOYEE_PASSWORD)
        assert client.get(path).status_code == 403
        assert client.post(path, data={"expected_revision": "0"}).status_code == 403
    with TestClient(app.main.app) as client:
        sign_in(client)
        missing_csrf = client.post(path, data={"expected_revision": "0"})
    assert missing_csrf.status_code == 403


def test_stale_revision_is_conflict_and_does_not_overwrite_or_audit(policy_context):
    issued = register(policy_context)
    _, _, _, _, policies, audit = policy_context
    path = f"/administrator/endpoints/{issued.endpoint.endpoint_id}/policy"
    with TestClient(app.main.app) as client:
        sign_in(client)
        client.post(path, data=policy_form(csrf_token(client, path)))
        audit_count = len(audit.events)
        stale = client.post(
            path,
            data=policy_form(
                csrf_token(client, path), revision=0, protected_folders=r"E:\Stale\Value"
            ),
        )
        stale_default = client.post(
            path,
            data={
                "csrf_token": csrf_token(client, path),
                "expected_revision": "0",
                "protected_folders": "",
            },
        )
    assert stale.status_code == 409
    assert stale_default.status_code == 409
    assert "changed after the page was loaded" in stale.text
    assert "changed after the page was loaded" in stale_default.text
    assert policies.items[issued.endpoint.endpoint_id].revision == 1
    assert policies.items[issued.endpoint.endpoint_id].protected_folders[0].startswith("C:\\")
    assert len(audit.events) == audit_count


class IndexCollection:
    def __init__(self):
        self.calls = []

    async def create_index(self, keys, **options):
        self.calls.append((keys, options))


def test_monitoring_policy_repository_creates_relationship_and_update_indexes():
    collection = IndexCollection()
    repository = MongoMonitoringPolicyRepository(
        {"endpoint_monitoring_policies": collection}
    )
    asyncio.run(repository.ensure_indexes())
    assert collection.calls == [
        (
            "endpoint_id",
            {"unique": True, "name": "unique_endpoint_monitoring_policy"},
        ),
        ([('updated_at', -1)], {"name": "recent_endpoint_policy_updates"}),
    ]


class FakeProtector:
    def protect(self, plaintext):
        return b"protected:" + plaintext[::-1]

    def unprotect(self, protected):
        return protected.split(b":", 1)[1][::-1]


def test_policy_show_recovers_credential_fetches_only_and_never_exposes_it(
    tmp_path, monkeypatch, capsys
):
    credential = "policy-show-machine-secret"
    endpoint_id = str(uuid4())
    protector = FakeProtector()
    store = ConfigStore(tmp_path)
    enroll(store, protector, "https://server.test", endpoint_id, credential)
    captured = {}

    class PolicyOnlyClient:
        def __init__(self, config, recovered, transport=None):
            captured["config"] = config
            captured["credential"] = recovered

        def fetch_policy(self):
            return EndpointPolicy(3, True, False, (r"C:\Approved\Work",))

        def submit_inventory(self, inventory):
            raise AssertionError("policy-show must not submit inventory")

        def send_heartbeat(self, version):
            raise AssertionError("policy-show must not send heartbeat")

    monkeypatch.setattr(agent_cli, "WindowsDpapiProtector", lambda: protector)
    monkeypatch.setattr(agent_service, "EndpointClient", PolicyOnlyClient)
    result = agent_cli.main(["--config-dir", str(tmp_path), "policy-show"])
    output = capsys.readouterr().out
    assert result == 0
    assert captured["config"].endpoint_id == endpoint_id
    assert captured["credential"] == credential
    assert "Policy revision: 3" in output
    assert "Monitoring: enabled" in output
    assert r"C:\Approved\Work" in output
    assert credential not in output


def test_endpoint_client_policy_get_uses_machine_auth_and_has_no_request_body():
    endpoint_id = str(uuid4())
    credential = "fetch-policy-secret"

    class Transport:
        def __init__(self):
            self.call = None

        def request(self, method, url, headers, payload):
            self.call = (method, url, dict(headers), payload)
            return {
                "revision": 0,
                "monitoring_enabled": False,
                "removable_storage_monitoring_enabled": False,
                "protected_folders": [],
                "updated_at": None,
            }

    from agent.config import AgentConfig

    transport = Transport()
    policy = EndpointClient(
        AgentConfig("https://server.test", endpoint_id), credential, transport
    ).fetch_policy()
    assert policy.revision == 0
    assert transport.call == (
        "GET",
        "https://server.test/service/v1/policy",
        {
            "X-NepShield-Endpoint-ID": endpoint_id,
            "Authorization": f"Bearer {credential}",
        },
        None,
    )
