"""Pure server-side derivation of current endpoint operational health."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from app.models import EndpointRuntimeHealth, ManagedEndpoint

RUNTIME_ONLINE_THRESHOLD = timedelta(seconds=90)
RUNTIME_STALE_THRESHOLD = timedelta(minutes=5)


class RuntimeStatus(StrEnum):
    NEVER_REPORTED = "never_reported"
    ONLINE = "online"
    STALE = "stale"
    OFFLINE = "offline"


class SynchronizationStatus(StrEnum):
    SYNCED = "synced"
    PENDING = "pending"
    UNKNOWN = "unknown"


class PolicySynchronizationStatus(StrEnum):
    CURRENT = "current"
    OUT_OF_DATE = "out_of_date"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class EndpointOperationalHealth:
    """Server-derived status plus the desired policy revision used to derive it."""

    runtime_status: RuntimeStatus
    synchronization_status: SynchronizationStatus
    policy_synchronization_status: PolicySynchronizationStatus
    desired_policy_revision: int


def runtime_status(
    last_runtime_heartbeat_at: datetime | None, *, now: datetime | None = None
) -> RuntimeStatus:
    """Classify a server-recorded runtime heartbeat using explicit UTC thresholds."""
    if last_runtime_heartbeat_at is None:
        return RuntimeStatus.NEVER_REPORTED
    current = now or datetime.now(UTC)
    age = current.astimezone(UTC) - last_runtime_heartbeat_at.astimezone(UTC)
    if age <= RUNTIME_ONLINE_THRESHOLD:
        return RuntimeStatus.ONLINE
    if age <= RUNTIME_STALE_THRESHOLD:
        return RuntimeStatus.STALE
    return RuntimeStatus.OFFLINE


def synchronization_status(
    current_runtime_status: RuntimeStatus,
    snapshot: EndpointRuntimeHealth | None,
) -> SynchronizationStatus:
    """Never claim current synchronization from an old or absent report."""
    if current_runtime_status is not RuntimeStatus.ONLINE or snapshot is None:
        return SynchronizationStatus.UNKNOWN
    if snapshot.queue_pending_count == 0:
        return SynchronizationStatus.SYNCED
    return SynchronizationStatus.PENDING


def policy_synchronization_status(
    current_runtime_status: RuntimeStatus,
    snapshot: EndpointRuntimeHealth | None,
    desired_policy_revision: int,
) -> PolicySynchronizationStatus:
    """Compare reported/applied and desired revisions only for an online runtime."""
    if current_runtime_status is not RuntimeStatus.ONLINE or snapshot is None:
        return PolicySynchronizationStatus.UNKNOWN
    if snapshot.applied_policy_revision == desired_policy_revision:
        return PolicySynchronizationStatus.CURRENT
    return PolicySynchronizationStatus.OUT_OF_DATE


def derive_endpoint_health(
    endpoint: ManagedEndpoint,
    desired_policy_revision: int,
    *,
    now: datetime | None = None,
) -> EndpointOperationalHealth:
    derived_runtime = runtime_status(endpoint.last_runtime_heartbeat_at, now=now)
    return EndpointOperationalHealth(
        runtime_status=derived_runtime,
        synchronization_status=synchronization_status(
            derived_runtime, endpoint.runtime_health
        ),
        policy_synchronization_status=policy_synchronization_status(
            derived_runtime, endpoint.runtime_health, desired_policy_revision
        ),
        desired_policy_revision=desired_policy_revision,
    )
