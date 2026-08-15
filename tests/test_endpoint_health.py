"""Deterministic server-derived endpoint operational status tests."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from bson import ObjectId

from app.endpoint_health import (
    PolicySynchronizationStatus,
    RuntimeStatus,
    SynchronizationStatus,
    derive_endpoint_health,
    runtime_status,
)
from app.models import (
    EndpointPlatform,
    EndpointRuntimeHealth,
    ManagedEndpoint,
)


NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
SNAPSHOT = EndpointRuntimeHealth(0, 0, 0, 0, False)


def endpoint(**changes):
    item = ManagedEndpoint(
        endpoint_id=str(uuid4()),
        device_name="HEALTH-LAPTOP",
        assigned_user_id=ObjectId(),
        platform=EndpointPlatform.WINDOWS,
        active=True,
        credential_digest="a" * 64,
        created_at=NOW,
        created_by=ObjectId(),
    )
    return replace(item, **changes)


@pytest.mark.parametrize(
    ("age", "expected"),
    [
        (timedelta(0), RuntimeStatus.ONLINE),
        (timedelta(seconds=90), RuntimeStatus.ONLINE),
        (timedelta(seconds=90, microseconds=1), RuntimeStatus.STALE),
        (timedelta(minutes=5), RuntimeStatus.STALE),
        (timedelta(minutes=5, microseconds=1), RuntimeStatus.OFFLINE),
    ],
)
def test_runtime_status_boundaries_use_injected_server_time(age, expected):
    assert runtime_status(NOW - age, now=NOW) is expected


def test_runtime_never_reported_state():
    assert runtime_status(None, now=NOW) is RuntimeStatus.NEVER_REPORTED


@pytest.mark.parametrize(
    ("runtime_age", "pending", "expected"),
    [
        (timedelta(seconds=1), 0, SynchronizationStatus.SYNCED),
        (timedelta(seconds=1), 4, SynchronizationStatus.PENDING),
        (timedelta(minutes=2), 0, SynchronizationStatus.UNKNOWN),
        (timedelta(minutes=6), 0, SynchronizationStatus.UNKNOWN),
    ],
)
def test_synchronization_derivation(runtime_age, pending, expected):
    report = replace(SNAPSHOT, queue_pending_count=pending)
    item = endpoint(last_runtime_heartbeat_at=NOW - runtime_age, runtime_health=report)
    assert derive_endpoint_health(item, 0, now=NOW).synchronization_status is expected


def test_synchronization_is_unknown_without_structured_snapshot():
    item = endpoint(last_runtime_heartbeat_at=NOW)
    assert (
        derive_endpoint_health(item, 0, now=NOW).synchronization_status
        is SynchronizationStatus.UNKNOWN
    )


@pytest.mark.parametrize(
    ("age", "desired", "applied", "expected"),
    [
        (timedelta(seconds=1), 0, 0, PolicySynchronizationStatus.CURRENT),
        (timedelta(seconds=1), 3, 2, PolicySynchronizationStatus.OUT_OF_DATE),
        (timedelta(minutes=2), 3, 3, PolicySynchronizationStatus.UNKNOWN),
        (timedelta(minutes=6), 3, 3, PolicySynchronizationStatus.UNKNOWN),
    ],
)
def test_policy_synchronization_derivation(age, desired, applied, expected):
    report = replace(SNAPSHOT, applied_policy_revision=applied)
    item = endpoint(last_runtime_heartbeat_at=NOW - age, runtime_health=report)
    assert (
        derive_endpoint_health(item, desired, now=NOW).policy_synchronization_status
        is expected
    )


def test_disabled_trust_is_distinct_from_runtime_connectivity():
    item = endpoint(
        active=False,
        last_runtime_heartbeat_at=NOW,
        runtime_health=SNAPSHOT,
    )
    health = derive_endpoint_health(item, 0, now=NOW)
    assert item.active is False
    assert health.runtime_status is RuntimeStatus.ONLINE
    assert health.synchronization_status is SynchronizationStatus.SYNCED
