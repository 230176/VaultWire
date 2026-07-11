"""Password and opaque-session security primitives."""

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type


class PasswordManager:
    """Hash and verify passwords with Argon2id."""

    def __init__(self) -> None:
        self._hasher = PasswordHasher(
            time_cost=3,
            memory_cost=65_536,
            parallelism=4,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        # Used when a username does not exist to reduce timing differences.
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(32))

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, password_hash: str, password: str) -> bool:
        try:
            return self._hasher.verify(password_hash, password)
        except (InvalidHashError, VerificationError):
            return False

    def verify_dummy(self, password: str) -> None:
        """Spend normal verification effort for a missing account."""
        self.verify(self._dummy_hash, password)

    def needs_rehash(self, password_hash: str) -> bool:
        try:
            return self._hasher.check_needs_rehash(password_hash)
        except InvalidHashError:
            return False


def new_session_token() -> str:
    """Return a 256-bit, URL-safe opaque session identifier."""
    return secrets.token_urlsafe(32)


def session_token_digest(token: str) -> str:
    """Hash a session token before storing or querying it in MongoDB."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class CsrfValidationError(Exception):
    """A state-changing request did not carry a valid CSRF token."""


class CsrfService:
    """Small, server-side store of short-lived form CSRF tokens.

    Tokens are opaque random values and exist only in process memory. They are
    intentionally independent of authentication sessions so the login form is
    protected too. A server restart simply requires loading the form again.
    """

    def __init__(self, lifetime: timedelta = timedelta(hours=2)) -> None:
        self.lifetime = lifetime
        self._tokens: dict[str, datetime] = {}

    def issue(self) -> str:
        now = datetime.now(UTC)
        self._tokens = {
            token: expires_at
            for token, expires_at in self._tokens.items()
            if expires_at > now
        }
        token = secrets.token_urlsafe(32)
        self._tokens[token] = now + self.lifetime
        return token

    def validate(self, token: str | None) -> None:
        if not token:
            raise CsrfValidationError()
        now = datetime.now(UTC)
        for candidate, expires_at in list(self._tokens.items()):
            if expires_at <= now:
                del self._tokens[candidate]
                continue
            if hmac.compare_digest(candidate, token):
                return
        raise CsrfValidationError()
