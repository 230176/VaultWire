"""Authentication, authorization, session, and audit services."""

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from app.models import Role, User
from app.security import PasswordManager, new_session_token, session_token_digest

USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
MINIMUM_PASSWORD_LENGTH = 12
MAXIMUM_PASSWORD_LENGTH = 1_024
MAXIMUM_DISPLAY_NAME_LENGTH = 100


class InvalidCredentialsError(Exception):
    """Login failed without revealing whether an account exists."""


class InvalidUsernameError(ValueError):
    pass


class WeakPasswordError(ValueError):
    pass


class InvalidDisplayNameError(ValueError):
    pass


class CannotDisableSelfError(ValueError):
    pass


def canonical_username(username: str) -> str:
    """Normalize usernames so uniqueness is case-insensitive."""
    return username.strip().casefold()


def validate_username(username: str) -> str:
    normalized = canonical_username(username)
    if not USERNAME_PATTERN.fullmatch(normalized):
        raise InvalidUsernameError(
            "Use 3-64 lowercase letters, numbers, dots, underscores, or hyphens."
        )
    return normalized


def validate_display_name(display_name: str) -> str:
    normalized = display_name.strip()
    if not normalized or len(normalized) > MAXIMUM_DISPLAY_NAME_LENGTH:
        raise InvalidDisplayNameError("Display name must be between 1 and 100 characters.")
    return normalized


class AuditService:
    """Create immutable security and workflow event records."""

    def __init__(self, repository: Any) -> None:
        self.repository = repository

    async def record(
        self,
        event_type: str,
        *,
        username: str,
        user_id: Any = None,
        source_ip: str | None = None,
        user_agent: str | None = None,
        outcome: str,
        reason: str | None = None,
        actor_username: str | None = None,
        actor_user_id: Any = None,
        resource_id: Any = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        event = {
            "event_type": event_type,
            "occurred_at": datetime.now(UTC),
            "username": username,
            "user_id": user_id,
            "source_ip": source_ip,
            "user_agent": user_agent,
            "outcome": outcome,
        }
        if reason is not None:
            event["reason"] = reason
        if actor_username is not None:
            event["actor_username"] = actor_username
            event["actor_user_id"] = actor_user_id
        if resource_id is not None:
            event["resource_id"] = resource_id
        if context:
            event["context"] = dict(context)
        await self.repository.append(event)


class AuthService:
    """Application-level authentication operations independent of FastAPI."""

    def __init__(
        self,
        users: Any,
        sessions: Any,
        audit: AuditService,
        password_manager: PasswordManager | None = None,
        session_lifetime: timedelta = timedelta(hours=8),
    ) -> None:
        self.users = users
        self.sessions = sessions
        self.audit = audit
        self.passwords = password_manager or PasswordManager()
        self.session_lifetime = session_lifetime

    async def create_user(
        self,
        username: str,
        password: str,
        role: Role,
        display_name: str | None = None,
    ) -> User:
        normalized = validate_username(username)
        name = validate_display_name(display_name if display_name is not None else normalized)
        if not MINIMUM_PASSWORD_LENGTH <= len(password) <= MAXIMUM_PASSWORD_LENGTH:
            raise WeakPasswordError(
                f"Password must be {MINIMUM_PASSWORD_LENGTH}-{MAXIMUM_PASSWORD_LENGTH} characters."
            )
        password_hash = self.passwords.hash(password)
        return await self.users.create(
            normalized, password_hash, Role(role), datetime.now(UTC), name
        )

    async def create_employee(
        self, display_name: str, username: str, password: str, *, actor: User
    ) -> User:
        user = await self.create_user(username, password, Role.EMPLOYEE, display_name)
        await self.audit.record(
            "user.created",
            username=user.username,
            user_id=user.id,
            outcome="success",
            reason="employee_account",
            actor_username=actor.username,
            actor_user_id=actor.id,
        )
        return user

    async def set_user_enabled(self, target_username: str, enabled: bool, *, actor: User) -> User:
        target = await self.users.find_by_username(canonical_username(target_username))
        if target is None:
            raise LookupError("User was not found.")
        if not enabled and target.id == actor.id:
            raise CannotDisableSelfError("You cannot disable your own account.")
        if target.enabled != enabled:
            await self.users.set_enabled(target.id, enabled)
            await self.audit.record(
                "user.status_changed",
                username=target.username,
                user_id=target.id,
                outcome="success",
                reason="enabled" if enabled else "disabled",
                actor_username=actor.username,
                actor_user_id=actor.id,
            )
        return target

    async def list_users(self) -> list[User]:
        return await self.users.list_users()

    async def login(
        self,
        username: str,
        password: str,
        *,
        source_ip: str | None,
        user_agent: str | None,
    ) -> tuple[User, str]:
        normalized = canonical_username(username)
        if (
            not USERNAME_PATTERN.fullmatch(normalized)
            or len(password) > MAXIMUM_PASSWORD_LENGTH
        ):
            self.passwords.verify_dummy(password[:MAXIMUM_PASSWORD_LENGTH])
            await self._record_failed_login(
                normalized[:64], None, source_ip, user_agent, "invalid_credentials"
            )
            raise InvalidCredentialsError

        user = await self.users.find_by_username(normalized)

        if user is None:
            self.passwords.verify_dummy(password)
            await self._record_failed_login(
                normalized, None, source_ip, user_agent, "invalid_credentials"
            )
            raise InvalidCredentialsError

        password_valid = self.passwords.verify(user.password_hash, password)
        if not password_valid or not user.enabled:
            reason = "account_disabled" if not user.enabled else "invalid_credentials"
            await self._record_failed_login(
                normalized, user.id, source_ip, user_agent, reason
            )
            raise InvalidCredentialsError

        if self.passwords.needs_rehash(user.password_hash):
            refreshed_hash = self.passwords.hash(password)
            await self.users.update_password_hash(user.id, refreshed_hash)

        token = new_session_token()
        now = datetime.now(UTC)
        await self.sessions.create(
            session_token_digest(token), user.id, now, now + self.session_lifetime
        )
        await self.audit.record(
            "authentication.login_succeeded",
            username=user.username,
            user_id=user.id,
            source_ip=source_ip,
            user_agent=user_agent,
            outcome="success",
        )
        return user, token

    async def resolve_session(self, token: str | None) -> User | None:
        if not token:
            return None
        digest = session_token_digest(token)
        session = await self.sessions.find_valid(digest, datetime.now(UTC))
        if session is None:
            return None
        user = await self.users.find_by_id(session["user_id"])
        if user is None or not user.enabled:
            await self.sessions.delete(digest)
            return None
        return user

    async def logout(
        self,
        token: str | None,
        *,
        source_ip: str | None,
        user_agent: str | None,
    ) -> None:
        if not token:
            return
        user = await self.resolve_session(token)
        await self.sessions.delete(session_token_digest(token))
        if user is not None:
            await self.audit.record(
                "authentication.logout",
                username=user.username,
                user_id=user.id,
                source_ip=source_ip,
                user_agent=user_agent,
                outcome="success",
            )

    async def _record_failed_login(
        self,
        username: str,
        user_id: Any,
        source_ip: str | None,
        user_agent: str | None,
        reason: str,
    ) -> None:
        await self.audit.record(
            "authentication.login_failed",
            username=username,
            user_id=user_id,
            source_ip=source_ip,
            user_agent=user_agent,
            outcome="failure",
            reason=reason,
        )
