"""Managed endpoint lifecycle and machine authentication services."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from app.auth import AuditService
from app.endpoint_health import EndpointOperationalHealth, derive_endpoint_health
from app.models import EndpointPlatform, ManagedEndpoint, Role, User
from app.repositories import EndpointAlreadyExistsError
from app.security import (
    endpoint_credential_digest,
    endpoint_credential_matches,
    new_endpoint_credential,
)

MAXIMUM_DEVICE_NAME_LENGTH = 100
MAXIMUM_LIFECYCLE_REASON_LENGTH = 500
MAXIMUM_ENDPOINT_CREDENTIAL_LENGTH = 512
ENDPOINT_CREATION_ATTEMPTS = 5


class InvalidEndpointData(ValueError):
    pass


class EndpointNotFound(LookupError):
    pass


class EndpointStateTransitionError(ValueError):
    pass


class EndpointAuthenticationError(Exception):
    """Machine authentication failed without identifying the failure detail."""


@dataclass(frozen=True)
class IssuedEndpointCredential:
    endpoint: ManagedEndpoint
    credential: str


@dataclass(frozen=True)
class EndpointDirectoryEntry:
    endpoint: ManagedEndpoint
    assigned_user: User | None
    health: EndpointOperationalHealth


def validate_device_name(value: str) -> str:
    name = value.strip()
    if not name or len(name) > MAXIMUM_DEVICE_NAME_LENGTH:
        raise InvalidEndpointData("Device name must be between 1 and 100 characters.")
    return name


def validate_lifecycle_reason(value: str) -> str:
    reason = value.strip()
    if not reason:
        raise InvalidEndpointData("A reason is required.")
    if len(reason) > MAXIMUM_LIFECYCLE_REASON_LENGTH:
        raise InvalidEndpointData("Reason must be 500 characters or fewer.")
    return reason


def canonical_endpoint_id(value: str) -> str:
    try:
        return str(UUID(value))
    except (AttributeError, TypeError, ValueError) as exc:
        raise EndpointAuthenticationError from exc


class EndpointService:
    """Register, manage, and authenticate durable machine identities."""

    def __init__(
        self,
        endpoints: Any,
        users: Any,
        audit: AuditService,
        policies: Any | None = None,
    ) -> None:
        self.endpoints = endpoints
        self.users = users
        self.audit = audit
        self.policies = policies

    async def register(
        self, device_name: str, assigned_user_id: Any, *, actor: User
    ) -> IssuedEndpointCredential:
        name = validate_device_name(device_name)
        employee = await self._require_employee(assigned_user_id)
        now = datetime.now(UTC)
        credential = new_endpoint_credential()
        digest = endpoint_credential_digest(credential)

        for _ in range(ENDPOINT_CREATION_ATTEMPTS):
            endpoint = ManagedEndpoint(
                endpoint_id=str(uuid4()),
                device_name=name,
                assigned_user_id=employee.id,
                platform=EndpointPlatform.WINDOWS,
                active=True,
                credential_digest=digest,
                created_at=now,
                created_by=actor.id,
            )
            try:
                await self.endpoints.create(endpoint)
                break
            except EndpointAlreadyExistsError:
                continue
        else:
            raise RuntimeError("Could not allocate a unique endpoint identifier.")

        await self._audit_lifecycle(
            "endpoint.registered", endpoint, employee, actor, "endpoint_registration"
        )
        return IssuedEndpointCredential(endpoint, credential)

    async def list_directory(self) -> list[EndpointDirectoryEntry]:
        entries: list[EndpointDirectoryEntry] = []
        now = datetime.now(UTC)
        for endpoint in await self.endpoints.list_all():
            desired_revision = await self._desired_policy_revision(
                endpoint.endpoint_id
            )
            entries.append(
                EndpointDirectoryEntry(
                    endpoint,
                    await self.users.find_by_id(endpoint.assigned_user_id),
                    derive_endpoint_health(
                        endpoint, desired_revision, now=now
                    ),
                )
            )
        return entries

    async def get_directory_entry(self, endpoint_id: str) -> EndpointDirectoryEntry:
        normalized_id = self._validated_management_id(endpoint_id)
        endpoint = await self.endpoints.find_by_endpoint_id(normalized_id)
        if endpoint is None:
            raise EndpointNotFound
        desired_revision = await self._desired_policy_revision(normalized_id)
        return EndpointDirectoryEntry(
            endpoint,
            await self.users.find_by_id(endpoint.assigned_user_id),
            derive_endpoint_health(endpoint, desired_revision),
        )

    async def list_employees(self) -> list[User]:
        return [
            user for user in await self.users.list_users() if user.role is Role.EMPLOYEE
        ]

    async def set_active(
        self, endpoint_id: str, active: bool, reason: str, *, actor: User
    ) -> ManagedEndpoint:
        normalized_id = self._validated_management_id(endpoint_id)
        normalized_reason = validate_lifecycle_reason(reason)
        now = datetime.now(UTC)
        endpoint = await self.endpoints.transition_active_state(
            normalized_id, not active, active, now, actor.id, normalized_reason
        )
        if endpoint is None:
            existing = await self.endpoints.find_by_endpoint_id(normalized_id)
            if existing is None:
                raise EndpointNotFound
            state = "active" if existing.active else "disabled"
            raise EndpointStateTransitionError(f"Endpoint is already {state}.")
        employee = await self.users.find_by_id(endpoint.assigned_user_id)
        await self._audit_lifecycle(
            "endpoint.enabled" if active else "endpoint.disabled",
            endpoint,
            employee,
            actor,
            normalized_reason,
        )
        return endpoint

    async def rotate_credential(
        self, endpoint_id: str, reason: str, *, actor: User
    ) -> IssuedEndpointCredential:
        normalized_id = self._validated_management_id(endpoint_id)
        normalized_reason = validate_lifecycle_reason(reason)
        credential = new_endpoint_credential()
        endpoint = await self.endpoints.rotate_credential(
            normalized_id,
            endpoint_credential_digest(credential),
            datetime.now(UTC),
            actor.id,
            normalized_reason,
        )
        if endpoint is None:
            raise EndpointNotFound
        employee = await self.users.find_by_id(endpoint.assigned_user_id)
        await self._audit_lifecycle(
            "endpoint.credential_rotated",
            endpoint,
            employee,
            actor,
            normalized_reason,
        )
        return IssuedEndpointCredential(endpoint, credential)

    async def authenticate(
        self, endpoint_id: str | None, authorization: str | None
    ) -> ManagedEndpoint:
        if not endpoint_id or not authorization:
            raise EndpointAuthenticationError
        scheme, separator, credential = authorization.partition(" ")
        if (
            not separator
            or scheme.casefold() != "bearer"
            or not credential
            or len(credential) > MAXIMUM_ENDPOINT_CREDENTIAL_LENGTH
        ):
            raise EndpointAuthenticationError
        normalized_id = canonical_endpoint_id(endpoint_id)
        endpoint = await self.endpoints.find_by_endpoint_id(normalized_id)
        stored_digest = endpoint.credential_digest if endpoint is not None else "0" * 64
        credential_valid = endpoint_credential_matches(stored_digest, credential)
        if endpoint is None or not endpoint.active or not credential_valid:
            raise EndpointAuthenticationError
        return endpoint

    async def identity_payload(self, endpoint: ManagedEndpoint) -> dict[str, Any]:
        employee = await self.users.find_by_id(endpoint.assigned_user_id)
        assigned_employee: dict[str, str] = {"id": str(endpoint.assigned_user_id)}
        if employee is not None:
            assigned_employee.update(
                {"username": employee.username, "display_name": employee.display_name}
            )
        return {
            "endpoint_id": endpoint.endpoint_id,
            "device_name": endpoint.device_name,
            "assigned_employee": assigned_employee,
            "platform": endpoint.platform.value,
            "status": "active" if endpoint.active else "disabled",
        }

    async def update_inventory(
        self, endpoint: ManagedEndpoint, inventory: dict[str, str]
    ) -> ManagedEndpoint:
        """Persist allowlisted descriptive data for the authenticated endpoint."""
        updated = await self.endpoints.update_inventory(
            endpoint.endpoint_id, inventory, datetime.now(UTC)
        )
        if updated is None:
            raise EndpointAuthenticationError
        return updated

    async def heartbeat(
        self,
        endpoint: ManagedEndpoint,
        agent_version: str,
        runtime_health: dict[str, Any] | None = None,
    ) -> ManagedEndpoint:
        """Record the server's receipt time; client clocks are never accepted."""
        received_at = datetime.now(UTC)
        if runtime_health is None:
            updated = await self.endpoints.record_heartbeat(
                endpoint.endpoint_id, agent_version, received_at
            )
        else:
            updated = await self.endpoints.record_runtime_heartbeat(
                endpoint.endpoint_id,
                agent_version,
                received_at,
                runtime_health,
            )
        if updated is None:
            raise EndpointAuthenticationError
        return updated

    async def _desired_policy_revision(self, endpoint_id: str) -> int:
        if self.policies is None:
            return 0
        policy = await self.policies.find_by_endpoint_id(endpoint_id)
        return policy.revision if policy is not None else 0

    async def _require_employee(self, user_id: Any) -> User:
        user = await self.users.find_by_id(user_id)
        if user is None or user.role is not Role.EMPLOYEE:
            raise InvalidEndpointData("Choose a valid employee account.")
        return user

    @staticmethod
    def _validated_management_id(value: str) -> str:
        try:
            return str(UUID(value))
        except (AttributeError, TypeError, ValueError) as exc:
            raise EndpointNotFound from exc

    async def _audit_lifecycle(
        self,
        event_type: str,
        endpoint: ManagedEndpoint,
        employee: User | None,
        actor: User,
        reason: str,
    ) -> None:
        await self.audit.record(
            event_type,
            username=employee.username if employee else "unknown-employee",
            user_id=endpoint.assigned_user_id,
            outcome="success",
            reason=reason,
            actor_username=actor.username,
            actor_user_id=actor.id,
            resource_id=endpoint.endpoint_id,
            context={
                "endpoint_id": endpoint.endpoint_id,
                "device_name": endpoint.device_name,
                "assigned_user_id": str(endpoint.assigned_user_id),
                "assigned_username": employee.username if employee else None,
                "platform": endpoint.platform.value,
                "active": endpoint.active,
                "credential_version": endpoint.credential_version,
                "occurred_at_utc": datetime.now(UTC),
            },
        )
