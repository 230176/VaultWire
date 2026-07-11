"""Authentication service and browser-route tests without an external MongoDB."""

import asyncio
import re
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

import app.main
from app.auth import AuthService, AuditService
from app.dependencies import get_auth_service
from app.models import Role, User
from app.repositories import UserAlreadyExistsError
from app.security import PasswordManager


class InMemoryUsers:
    def __init__(self) -> None:
        self.by_id: dict[int, User] = {}
        self.by_username: dict[str, User] = {}
        self.next_id = 1

    async def create(self, username, password_hash, role, created_at, display_name):
        if username in self.by_username:
            raise UserAlreadyExistsError(username)
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
        self._replace(self.by_id[user_id], password_hash=password_hash)

    async def set_enabled(self, user_id: int, enabled: bool) -> None:
        self._replace(self.by_id[user_id], enabled=enabled)

    async def list_users(self):
        return sorted(self.by_id.values(), key=lambda user: user.created_at, reverse=True)

    def _replace(self, user: User, **changes) -> None:
        updated = replace(user, **changes)
        self.by_id[user.id] = updated
        self.by_username[user.username] = updated


class InMemorySessions:
    def __init__(self) -> None:
        self.documents: dict[str, dict] = {}

    async def create(self, token_digest, user_id, created_at, expires_at):
        self.documents[token_digest] = {
            "token_digest": token_digest,
            "user_id": user_id,
            "created_at": created_at,
            "expires_at": expires_at,
        }

    async def find_valid(self, token_digest, now):
        document = self.documents.get(token_digest)
        if document is None or document["expires_at"] <= now:
            return None
        return document

    async def delete(self, token_digest):
        self.documents.pop(token_digest, None)


class InMemoryAudit:
    def __init__(self) -> None:
        self.events: list[dict] = []

    async def append(self, event):
        self.events.append(dict(event))


class NoopDatabase:
    database = None

    async def connect(self):
        pass

    async def ping(self):
        return True

    async def close(self):
        pass


@pytest.fixture
def auth_context(monkeypatch):
    users = InMemoryUsers()
    sessions = InMemorySessions()
    audit_repository = InMemoryAudit()
    service = AuthService(users, sessions, AuditService(audit_repository))

    monkeypatch.setattr(app.main, "MongoDatabase", NoopDatabase)
    app.main.app.dependency_overrides[get_auth_service] = lambda: service
    try:
        yield service, users, sessions, audit_repository
    finally:
        app.main.app.dependency_overrides.clear()


def create_user(service: AuthService, username: str, password: str, role: Role) -> User:
    return asyncio.run(service.create_user(username, password, role))


def csrf_token(client: TestClient, path: str = "/login") -> str:
    response = client.get(path)
    assert response.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match
    return match.group(1)


def post_with_csrf(client: TestClient, path: str, data: dict, csrf_path: str = "/login", **kwargs):
    return client.post(
        path,
        data={**data, "csrf_token": csrf_token(client, csrf_path)},
        **kwargs,
    )


def sign_in(client: TestClient, username: str, password: str):
    return post_with_csrf(
        client,
        "/login",
        {"username": username, "password": password},
        follow_redirects=False,
    )


def test_passwords_use_argon2id_and_never_contain_plaintext():
    passwords = PasswordManager()
    plaintext = "correct horse battery staple"

    stored_hash = passwords.hash(plaintext)

    assert stored_hash.startswith("$argon2id$")
    assert plaintext not in stored_hash
    assert passwords.verify(stored_hash, plaintext)
    assert not passwords.verify(stored_hash, "incorrect password")


def test_valid_employee_login_sets_opaque_cookie_and_opens_employee_page(auth_context):
    service, users, sessions, audit = auth_context
    password = "employee-password-2026"
    user = create_user(service, "ram.employee", password, Role.EMPLOYEE)

    with TestClient(app.main.app) as client:
        response = post_with_csrf(
            client,
            "/login",
            {"username": "RAM.Employee", "password": password},
            follow_redirects=False,
        )
        landing = client.get("/employee")

    assert response.status_code == 303
    assert response.headers["location"] == "/employee"
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "SameSite=lax" in response.headers["set-cookie"]
    assert landing.status_code == 200
    assert "Employee access verified" in landing.text
    assert user.password_hash != password
    assert len(sessions.documents) == 1
    stored_session = next(iter(sessions.documents))
    cookie_token = response.cookies["nepshield_session"]
    assert stored_session != cookie_token
    assert audit.events[-1]["event_type"] == "authentication.login_succeeded"


def test_invalid_password_is_rejected_and_audited(auth_context):
    service, _, sessions, audit = auth_context
    create_user(service, "sita.employee", "valid-password-2026", Role.EMPLOYEE)

    with TestClient(app.main.app) as client:
        response = post_with_csrf(
            client,
            "/login",
            {"username": "sita.employee", "password": "wrong-password"},
        )

    assert response.status_code == 401
    assert "incorrect, or the account is disabled" in response.text
    assert sessions.documents == {}
    event = audit.events[-1]
    assert event["event_type"] == "authentication.login_failed"
    assert event["outcome"] == "failure"
    assert event["reason"] == "invalid_credentials"
    assert isinstance(event["occurred_at"], datetime)
    assert event["occurred_at"].tzinfo is UTC


def test_disabled_account_cannot_login_and_existing_session_loses_access(auth_context):
    service, users, _, audit = auth_context
    password = "disabled-user-password"
    create_user(service, "disabled.user", password, Role.EMPLOYEE)

    with TestClient(app.main.app) as client:
        login = post_with_csrf(
            client,
            "/login",
            {"username": "disabled.user", "password": password},
            follow_redirects=False,
        )
        assert login.status_code == 303

        asyncio.run(users.set_enabled(1, False))
        protected = client.get("/employee", follow_redirects=False)
        second_login = post_with_csrf(
            client,
            "/login",
            {"username": "disabled.user", "password": password},
        )

    assert protected.status_code == 303
    assert protected.headers["location"] == "/login"
    assert second_login.status_code == 401
    assert audit.events[-1]["reason"] == "account_disabled"


@pytest.mark.parametrize("path", ["/employee", "/administrator"])
def test_unauthenticated_role_pages_redirect_to_login(auth_context, path):
    with TestClient(app.main.app) as client:
        response = client.get(path, follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


@pytest.mark.parametrize(
    ("role", "allowed_path", "forbidden_path"),
    [
        (Role.EMPLOYEE, "/employee", "/administrator"),
        (Role.ADMINISTRATOR, "/administrator", "/employee"),
    ],
)
def test_employee_and_administrator_routes_are_separated(
    auth_context, role, allowed_path, forbidden_path
):
    service, _, _, _ = auth_context
    password = "role-test-password"
    create_user(service, f"{role.value}.user", password, role)

    with TestClient(app.main.app) as client:
        login = post_with_csrf(
            client,
            "/login",
            {"username": f"{role.value}.user", "password": password},
            follow_redirects=False,
        )
        allowed = client.get(allowed_path)
        forbidden = client.get(forbidden_path)

    assert login.headers["location"] == allowed_path
    assert allowed.status_code == 200
    assert forbidden.status_code == 403


def test_logout_invalidates_session_clears_cookie_and_is_audited(auth_context):
    service, _, sessions, audit = auth_context
    password = "logout-test-password"
    create_user(service, "logout.user", password, Role.EMPLOYEE)

    with TestClient(app.main.app) as client:
        post_with_csrf(
            client,
            "/login",
            {"username": "logout.user", "password": password},
            follow_redirects=False,
        )
        response = post_with_csrf(client, "/logout", {}, "/employee", follow_redirects=False)
        protected = client.get("/employee", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert sessions.documents == {}
    assert protected.status_code == 303
    assert [event["event_type"] for event in audit.events] == [
        "authentication.login_succeeded",
        "authentication.logout",
    ]


def test_usernames_are_unique_after_case_normalization(auth_context):
    service, _, _, _ = auth_context
    create_user(service, "Unique.User", "first-user-password", Role.EMPLOYEE)

    with pytest.raises(UserAlreadyExistsError):
        create_user(service, "unique.user", "second-user-password", Role.ADMINISTRATOR)


def test_users_area_is_administrator_only(auth_context):
    service, _, _, _ = auth_context
    create_user(service, "employee.only", "employee-only-password", Role.EMPLOYEE)

    with TestClient(app.main.app) as client:
        sign_in(client, "employee.only", "employee-only-password")
        response = client.get("/administrator/users")

    assert response.status_code == 403


def test_administrator_can_create_employee_with_hashed_password_and_audit_event(auth_context):
    service, users, _, audit = auth_context
    create_user(service, "admin.user", "administrator-password", Role.ADMINISTRATOR)

    with TestClient(app.main.app) as client:
        sign_in(client, "admin.user", "administrator-password")
        response = post_with_csrf(
            client,
            "/administrator/users",
            {
                "display_name": "Sita Shrestha",
                "username": "sita.shrestha",
                "password": "employee-initial-password",
            },
            "/administrator/users",
            follow_redirects=False,
        )
        directory = client.get("/administrator/users")

    employee = users.by_username["sita.shrestha"]
    assert response.status_code == 303
    assert response.headers["location"] == "/administrator/users?success=created"
    assert employee.display_name == "Sita Shrestha"
    assert employee.role is Role.EMPLOYEE
    assert employee.password_hash.startswith("$argon2id$")
    assert "employee-initial-password" not in employee.password_hash
    assert "Sita Shrestha" in directory.text
    event = audit.events[-1]
    assert event["event_type"] == "user.created"
    assert event["username"] == "sita.shrestha"
    assert event["actor_username"] == "admin.user"


def test_duplicate_employee_username_is_validation_error(auth_context):
    service, users, _, _ = auth_context
    create_user(service, "admin.user", "administrator-password", Role.ADMINISTRATOR)
    create_user(service, "taken.name", "already-taken-password", Role.EMPLOYEE)

    with TestClient(app.main.app) as client:
        sign_in(client, "admin.user", "administrator-password")
        response = post_with_csrf(
            client,
            "/administrator/users",
            {"display_name": "Another Name", "username": "TAKEN.Name", "password": "another-valid-password"},
            "/administrator/users",
        )

    assert response.status_code == 422
    assert "That username is already in use" in response.text
    assert len(users.by_id) == 2


def test_administrator_can_disable_and_reenable_employee_and_status_is_audited(auth_context):
    service, users, _, audit = auth_context
    create_user(service, "admin.user", "administrator-password", Role.ADMINISTRATOR)
    create_user(service, "team.member", "team-member-password", Role.EMPLOYEE)

    with TestClient(app.main.app) as client:
        sign_in(client, "admin.user", "administrator-password")
        disabled = post_with_csrf(
            client,
            "/administrator/users/status",
            {"username": "team.member", "enabled": "false"},
            "/administrator/users",
            follow_redirects=False,
        )
        assert users.by_username["team.member"].enabled is False
        reenabled = post_with_csrf(
            client,
            "/administrator/users/status",
            {"username": "team.member", "enabled": "true"},
            "/administrator/users",
            follow_redirects=False,
        )

    assert disabled.headers["location"] == "/administrator/users?success=disabled"
    assert reenabled.headers["location"] == "/administrator/users?success=enabled"
    assert users.by_username["team.member"].enabled is True
    changes = [event for event in audit.events if event["event_type"] == "user.status_changed"]
    assert [event["reason"] for event in changes] == ["disabled", "enabled"]
    assert all(event["actor_username"] == "admin.user" for event in changes)


def test_administrator_cannot_disable_their_own_account(auth_context):
    service, users, _, audit = auth_context
    create_user(service, "admin.user", "administrator-password", Role.ADMINISTRATOR)

    with TestClient(app.main.app) as client:
        sign_in(client, "admin.user", "administrator-password")
        response = post_with_csrf(
            client,
            "/administrator/users/status",
            {"username": "admin.user", "enabled": "false"},
            "/administrator/users",
        )

    assert response.status_code == 422
    assert "cannot disable your own account" in response.text
    assert users.by_username["admin.user"].enabled is True
    assert not [event for event in audit.events if event["event_type"] == "user.status_changed"]


def test_state_changing_routes_require_server_issued_csrf_token(auth_context):
    service, _, _, _ = auth_context
    create_user(service, "admin.user", "administrator-password", Role.ADMINISTRATOR)

    with TestClient(app.main.app) as client:
        login = client.post("/login", data={"username": "admin.user", "password": "administrator-password"})
        assert login.status_code == 403
        sign_in(client, "admin.user", "administrator-password")
        creation = client.post(
            "/administrator/users",
            data={"display_name": "No Token", "username": "no.token", "password": "valid-password-2026"},
        )
        logout = client.post("/logout")

    assert creation.status_code == 403
    assert logout.status_code == 403
    assert "Request expired" in creation.text
