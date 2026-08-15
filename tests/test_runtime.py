"""Deterministic coverage for the unified Task 17 agent runtime."""

from __future__ import annotations

import json
from dataclasses import replace
from uuid import uuid4

import pytest

from agent.client import AgentAuthenticationRejected, EndpointPolicy
from agent.config import AgentConfig, AgentConfigurationError, ConfigStore
from agent.credentials import CredentialProtectionError
from agent.events import SQLiteEventQueue
from agent.inventory import WindowsInventory
from agent.policy_cache import POLICY_CACHE_SCHEMA_VERSION, PolicyCache
from agent.runtime import (
    AgentRuntime,
    RuntimeAlreadyRunningError,
    RuntimeInstanceLock,
    RuntimeIntervals,
)
from agent.service import enroll


class FakeProtector:
    def protect(self, value):
        return b"protected:" + value[::-1]

    def unprotect(self, value):
        prefix, secret = value.split(b":", 1)
        assert prefix == b"protected"
        return secret[::-1]


class FailingProtector(FakeProtector):
    def unprotect(self, value):
        raise CredentialProtectionError("DPAPI recovery failed")


class FakeLock:
    def __init__(self):
        self.acquired = 0
        self.released = 0

    def acquire(self):
        self.acquired += 1

    def release(self):
        self.released += 1


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeClient:
    def __init__(self, config, policies):
        self.config = config
        self.policies = list(policies)
        self.policy_calls = 0
        self.heartbeats = 0
        self.inventories = 0
        self.event_calls = 0
        self.event_failure = None
        self.health_reports = []

    def fetch_policy(self):
        self.policy_calls += 1
        action = self.policies.pop(0) if len(self.policies) > 1 else self.policies[0]
        if isinstance(action, BaseException):
            raise action
        return action

    def send_heartbeat(self, agent_version, runtime_health=None):
        self.heartbeats += 1
        self.health_reports.append(runtime_health)
        return {"status": "accepted"}

    def submit_inventory(self, inventory):
        self.inventories += 1
        return {"status": "accepted"}

    def submit_events(self, events):
        self.event_calls += 1
        if self.event_failure is not None:
            raise self.event_failure
        return {"acknowledged_event_ids": [event.event_id for event in events]}


class FakeCollector:
    def __init__(self, name, record, fail=False):
        self.name = name
        self.record = record
        self.fail = fail
        self.alive = False

    def start(self):
        self.record.append(("start", self.name))
        if self.fail:
            raise OSError("unavailable")
        self.alive = True

    def stop(self):
        self.record.append(("stop", self.name))
        self.alive = False

    def is_alive(self):
        return self.alive


class CollectorFactories:
    def __init__(self, bad=()):
        self.record = []
        self.bad = {item.casefold() for item in bad}

    def protected(self, path, queue, status):
        return FakeCollector(path, self.record, path.casefold() in self.bad)

    def removable(self, queue, status):
        return FakeCollector("removable", self.record)


ONLINE = EndpointPolicy(1, True, True, (r"C:\A", r"C:\B"))
DISABLED = EndpointPolicy(2, False, False, ())


def inventory():
    return WindowsInventory("HOST", "Windows 11", "1", "AMD64", "test")


def intervals():
    return RuntimeIntervals(
        queue_flush_seconds=2,
        heartbeat_seconds=5,
        policy_refresh_seconds=10,
        inventory_refresh_seconds=100,
        collector_retry_seconds=3,
        policy_retry_initial_seconds=1,
        policy_retry_max_seconds=4,
        shutdown_join_seconds=1,
    )


def make_runtime(tmp_path, policies, *, factories=None, cache_policy=None):
    endpoint_id = str(uuid4())
    config = AgentConfig("https://server.test", endpoint_id)
    queue = SQLiteEventQueue.in_directory(tmp_path)
    cache = PolicyCache(tmp_path)
    if cache_policy is not None:
        cache.save(endpoint_id, cache_policy)
    client = FakeClient(config, policies)
    clock = Clock()
    lock = FakeLock()
    factories = factories or CollectorFactories()
    output = []
    runtime = AgentRuntime(
        config,
        client,
        queue,
        cache,
        lock,
        intervals=intervals(),
        status=output.append,
        monotonic_clock=clock,
        inventory_collector=inventory,
        protected_watcher_factory=factories.protected,
        removable_worker_factory=factories.removable,
    )
    return runtime, client, queue, clock, lock, factories, output


def test_run_requires_enrollment_and_credential_recovery(tmp_path):
    with pytest.raises(AgentConfigurationError, match="not enrolled"):
        AgentRuntime.from_store(ConfigStore(tmp_path), FakeProtector())

    store = ConfigStore(tmp_path / "enrolled")
    enroll(store, FakeProtector(), "https://server.test", str(uuid4()), "credential")
    with pytest.raises(CredentialProtectionError, match="DPAPI"):
        AgentRuntime.from_store(store, FailingProtector())


def test_run_cli_checks_enrollment_before_dpapi(tmp_path, monkeypatch, capsys):
    import agent.__main__ as agent_cli

    def unexpected_dpapi():
        raise AssertionError("DPAPI must not start before enrollment is validated")

    monkeypatch.setattr(agent_cli, "WindowsDpapiProtector", unexpected_dpapi)
    assert agent_cli.main(["--config-dir", str(tmp_path), "run"]) == 1
    assert "not enrolled" in capsys.readouterr().out


def test_only_one_runtime_instance_can_hold_enrollment_lock(tmp_path):
    endpoint_id = str(uuid4())
    first = RuntimeInstanceLock(tmp_path, endpoint_id)
    second = RuntimeInstanceLock(tmp_path, endpoint_id)
    first.acquire()
    try:
        with pytest.raises(RuntimeAlreadyRunningError, match="already running"):
            second.acquire()
    finally:
        first.release()
    second.acquire()
    second.release()


def test_policy_cache_is_atomic_allowlisted_and_endpoint_bound(tmp_path, monkeypatch):
    cache = PolicyCache(tmp_path)
    endpoint_id = str(uuid4())
    replacements = []
    import agent.policy_cache as cache_module

    real_replace = cache_module.os.replace

    def record_replace(source, destination):
        replacements.append((source, destination))
        real_replace(source, destination)

    monkeypatch.setattr(cache_module.os, "replace", record_replace)
    cache.save(endpoint_id, ONLINE)

    raw = json.loads(cache.path.read_text())
    assert replacements and replacements[0][1] == cache.path
    assert raw == {
        "cache_schema_version": POLICY_CACHE_SCHEMA_VERSION,
        "endpoint_id": endpoint_id,
        "revision": 1,
        "monitoring_enabled": True,
        "removable_storage_monitoring_enabled": True,
        "protected_folders": [r"C:\A", r"C:\B"],
    }
    serialized = cache.path.read_text().casefold()
    assert "credential" not in serialized
    assert "token" not in serialized
    assert cache.load(endpoint_id) == ONLINE
    assert cache.load(str(uuid4())) is None


@pytest.mark.parametrize(
    "content",
    ["not-json", "{}", '{"cache_schema_version":999}'],
)
def test_corrupt_or_incompatible_cache_is_ignored(tmp_path, content):
    cache = PolicyCache(tmp_path)
    cache.path.write_text(content)
    assert cache.load(str(uuid4())) is None


def test_startup_online_applies_policy_inventory_heartbeat_and_queue(tmp_path):
    runtime, client, queue, _, lock, factories, _ = make_runtime(tmp_path, [ONLINE])
    queue.enqueue("development.test", {"value": 1})
    runtime.start()
    assert client.policy_calls == client.inventories == client.heartbeats == client.event_calls == 1
    assert queue.pending_count() == 0
    assert ("start", r"C:\A") in factories.record
    assert ("start", r"C:\B") in factories.record
    assert ("start", "removable") in factories.record
    assert runtime.policy_cache.load(runtime.config.endpoint_id) == ONLINE
    assert client.health_reports[-1] == {
        "queue_pending_count": 1,
        "applied_policy_revision": 1,
        "protected_watchers_active_count": 2,
        "protected_folders_unavailable_count": 0,
        "removable_monitoring_active": True,
    }
    runtime.shutdown()
    assert lock.released == 1


def test_startup_offline_uses_cache_but_no_cache_starts_nothing(tmp_path):
    offline = RuntimeError("network down")
    cached_runtime, _, _, _, _, cached_factories, _ = make_runtime(
        tmp_path / "cached", [offline], cache_policy=ONLINE
    )
    cached_runtime.start()
    assert ("start", r"C:\A") in cached_factories.record
    cached_runtime.shutdown()

    empty_runtime, _, _, _, _, empty_factories, _ = make_runtime(
        tmp_path / "empty", [offline]
    )
    empty_runtime.start()
    assert empty_factories.record == []
    empty_runtime.shutdown()


def test_invalid_server_policy_is_never_applied_over_valid_cache(tmp_path):
    invalid = EndpointPolicy(2, True, True, ("relative-path",))
    runtime, _, _, _, _, factories, _ = make_runtime(
        tmp_path, [invalid], cache_policy=ONLINE
    )
    runtime.start()
    assert runtime.policy == ONLINE
    assert ("start", r"C:\A") in factories.record
    runtime.shutdown()


def test_lower_server_revision_is_authoritative_with_rollback_diagnostic(tmp_path):
    cached = replace(ONLINE, revision=9)
    server = replace(DISABLED, revision=2)
    runtime, _, _, _, _, factories, output = make_runtime(
        tmp_path, [server], cache_policy=cached
    )
    runtime.start()
    assert runtime.policy == server
    assert factories.record == []
    assert any("lower than the cached revision" in message for message in output)
    runtime.shutdown()


def test_transient_failures_keep_cached_collectors_and_queue_rows(tmp_path):
    runtime, client, queue, clock, _, factories, _ = make_runtime(
        tmp_path, [ONLINE, RuntimeError("offline")]
    )
    runtime.start()
    queue.enqueue("development.test", {"value": 1})
    client.event_failure = RuntimeError("offline")
    clock.advance(10)
    runtime.tick()
    assert not any(action == "stop" for action, _ in factories.record)
    assert queue.pending_count() == 1
    runtime.shutdown()


def test_auth_rejection_suspends_retains_and_recovery_restarts_without_restart(tmp_path):
    rejected = AgentAuthenticationRejected("policy rejected")
    recovered = replace(ONLINE, revision=2)
    runtime, client, queue, clock, _, factories, output = make_runtime(
        tmp_path, [ONLINE, rejected, recovered]
    )
    runtime.start()
    queue.enqueue("development.test", {"value": 1})
    clock.advance(10)
    runtime.tick()
    assert runtime.authenticated is False
    assert queue.pending_count() == 1
    assert ("stop", r"C:\A") in factories.record
    rejected_event_calls = client.event_calls

    clock.advance(10)
    runtime.tick()
    assert runtime.authenticated is True
    assert queue.pending_count() == 0
    assert client.event_calls == rejected_event_calls + 1
    assert factories.record.count(("start", r"C:\A")) == 2
    assert any("restored" in message for message in output)
    runtime.shutdown()


def test_running_runtime_reloads_rotated_dpapi_credential_on_existing_retry_cycle(tmp_path):
    store = ConfigStore(tmp_path)
    protector = FakeProtector()
    endpoint_id = str(uuid4())
    old_secret = "rotated-out-secret"
    replacement = "current-replacement-secret"
    enroll(store, protector, "https://server.test", endpoint_id, old_secret)
    clock = Clock()
    output = []

    class RotationAwareTransport:
        def __init__(self):
            self.authorization = []

        def request(self, method, url, headers, payload):
            authorization = headers["Authorization"]
            self.authorization.append(authorization)
            if authorization != f"Bearer {replacement}":
                raise AgentAuthenticationRejected("rejected")
            if url.endswith("/service/v1/policy"):
                return {
                    "revision": 1,
                    "monitoring_enabled": False,
                    "removable_storage_monitoring_enabled": False,
                    "protected_folders": [],
                }
            if url.endswith("/service/v1/events/batch"):
                return {"acknowledged_event_ids": []}
            return {"status": "accepted"}

    transport = RotationAwareTransport()
    runtime = AgentRuntime.from_store(
        store,
        protector,
        transport,
        intervals=intervals(),
        status=output.append,
        monotonic_clock=clock,
        inventory_collector=inventory,
        protected_watcher_factory=CollectorFactories().protected,
        removable_worker_factory=CollectorFactories().removable,
    )

    runtime.start()
    assert runtime.authenticated is False
    assert transport.authorization == [f"Bearer {old_secret}"]

    store.replace_protected_credential(protector.protect(replacement.encode()))
    clock.advance(10)
    runtime.tick()

    assert runtime.authenticated is True
    assert runtime.client.config == AgentConfig("https://server.test", endpoint_id)
    assert f"Bearer {replacement}" in transport.authorization
    assert any("authentication restored" in message for message in output)
    assert old_secret not in "\n".join(output)
    assert replacement not in "\n".join(output)
    runtime.shutdown()


def test_monitoring_disabled_stops_collectors_but_keeps_runtime_delivery_and_heartbeat(tmp_path):
    runtime, client, queue, clock, _, factories, _ = make_runtime(
        tmp_path, [ONLINE, DISABLED]
    )
    runtime.start()
    queue.enqueue("development.test", {"value": 1})
    clock.advance(10)
    runtime.tick()
    assert runtime.policy == DISABLED
    assert ("stop", r"C:\A") in factories.record
    assert ("stop", "removable") in factories.record
    assert client.heartbeats >= 2
    assert client.health_reports[-1] == {
        "queue_pending_count": 1,
        "applied_policy_revision": 2,
        "protected_watchers_active_count": 0,
        "protected_folders_unavailable_count": 0,
        "removable_monitoring_active": False,
    }
    assert queue.pending_count() == 0
    runtime.shutdown()


def test_policy_diff_only_changes_requested_collectors_and_same_policy_does_not_churn(tmp_path):
    changed = EndpointPolicy(2, True, False, (r"C:\B", r"C:\C"))
    runtime, _, _, clock, _, factories, _ = make_runtime(
        tmp_path, [ONLINE, changed, changed]
    )
    runtime.start()
    clock.advance(10)
    runtime.tick()
    assert factories.record.count(("start", r"C:\B")) == 1
    assert ("stop", r"C:\A") in factories.record
    assert ("start", r"C:\C") in factories.record
    assert ("stop", "removable") in factories.record
    snapshot = list(factories.record)
    clock.advance(10)
    runtime.tick()
    assert factories.record == snapshot
    runtime.shutdown()


def test_bad_folder_isolated_and_retried_when_it_becomes_available(tmp_path):
    factories = CollectorFactories(bad={r"C:\A"})
    runtime, _, _, clock, _, _, output = make_runtime(
        tmp_path, [ONLINE], factories=factories
    )
    runtime.start()
    assert ("start", r"C:\B") in factories.record
    assert any("unavailable" in message for message in output)
    assert runtime.runtime_health_snapshot().as_payload() == {
        "queue_pending_count": 0,
        "applied_policy_revision": 1,
        "protected_watchers_active_count": 1,
        "protected_folders_unavailable_count": 1,
        "removable_monitoring_active": True,
    }
    factories.bad.clear()
    clock.advance(3)
    runtime.tick()
    assert factories.record.count(("start", r"C:\A")) == 2
    runtime.shutdown()


def test_periodic_scheduling_uses_injected_monotonic_clock(tmp_path):
    runtime, client, _, clock, _, _, _ = make_runtime(tmp_path, [ONLINE])
    runtime.start()
    clock.advance(4)
    runtime.tick()
    assert client.heartbeats == 1
    assert client.inventories == 1
    clock.advance(1)
    runtime.tick()
    assert client.heartbeats == 2
    assert client.inventories == 1
    clock.advance(95)
    runtime.tick()
    assert client.inventories == 2
    runtime.shutdown()


def test_reenrollment_never_applies_different_endpoint_cache(tmp_path):
    cache = PolicyCache(tmp_path)
    cache.save(str(uuid4()), ONLINE)
    runtime, _, _, _, _, factories, output = make_runtime(
        tmp_path, [RuntimeError("offline")]
    )
    runtime.start()
    assert factories.record == []
    assert any("cache was ignored" in message for message in output)
    runtime.shutdown()


def test_reenrollment_cannot_silently_reassign_pending_queue_events(tmp_path):
    store = ConfigStore(tmp_path)
    protector = FakeProtector()
    enroll(store, protector, "https://server.test", str(uuid4()), "first-credential")
    SQLiteEventQueue.in_directory(tmp_path).enqueue("development.test", {"value": 1})

    with pytest.raises(AgentConfigurationError, match="queued events belong"):
        enroll(store, protector, "https://server.test", str(uuid4()), "second-credential")


def test_transient_heartbeat_failure_does_not_stop_cached_policy_collectors(tmp_path):
    runtime, client, _, clock, _, factories, _ = make_runtime(tmp_path, [ONLINE])
    original = client.send_heartbeat
    runtime.start()

    def fail_heartbeat(agent_version, runtime_health=None):
        client.heartbeats += 1
        raise RuntimeError("offline")

    client.send_heartbeat = fail_heartbeat
    clock.advance(5)
    runtime.tick()
    assert not any(action == "stop" for action, _ in factories.record)
    client.send_heartbeat = original
    runtime.shutdown()


def test_health_report_construction_failure_does_not_crash_collectors(tmp_path):
    runtime, client, queue, _, _, factories, output = make_runtime(tmp_path, [ONLINE])

    def fail_pending_count():
        raise OSError("sqlite temporarily unavailable")

    queue.pending_count = fail_pending_count
    runtime.start()

    assert client.heartbeats == 0
    assert ("start", r"C:\A") in factories.record
    assert ("start", r"C:\B") in factories.record
    assert not any(action == "stop" for action, _ in factories.record)
    assert any("temporarily unavailable" in message for message in output)
    runtime.shutdown()


def test_event_delivery_auth_rejection_retains_queue_and_suspends(tmp_path):
    runtime, client, queue, clock, _, factories, _ = make_runtime(tmp_path, [ONLINE])
    runtime.start()
    queue.enqueue("development.test", {"value": 1})
    client.event_failure = AgentAuthenticationRejected("rejected")
    clock.advance(2)
    runtime.tick()
    assert runtime.authenticated is False
    assert queue.pending_count() == 1
    assert ("stop", r"C:\A") in factories.record
    runtime.shutdown()


def test_shutdown_stops_collectors_releases_lock_and_never_prints_secret(tmp_path):
    secret = "never-print-runtime-secret"
    runtime, client, _, _, lock, factories, output = make_runtime(
        tmp_path, [RuntimeError(secret)], cache_policy=ONLINE
    )
    runtime.start()
    runtime.shutdown()
    assert ("stop", r"C:\A") in factories.record
    assert ("stop", "removable") in factories.record
    assert lock.released == 1
    assert secret not in "\n".join(output)


def test_manual_command_parser_keeps_all_diagnostics_and_adds_run():
    from agent.__main__ import build_parser

    parser = build_parser()
    for command in (
        "enroll",
        "check",
        "policy-show",
        "queue-status",
        "queue-flush",
        "monitor-removable",
        "monitor-files",
        "run",
    ):
        assert command in parser._subparsers._group_actions[0].choices
