"""Local Windows agent enrollment, protection, and mocked HTTP tests."""

import json
from io import BytesIO
from pathlib import Path
import sys
from urllib.error import HTTPError
from uuid import uuid4

import pytest

import agent.__main__ as agent_cli
import agent.service as agent_service
from agent import __version__
from agent.client import AgentCommunicationError, EndpointClient, UrllibJsonTransport
from agent.config import AgentConfig, AgentConfigurationError, ConfigStore
from agent.credentials import WindowsDpapiProtector
from agent.events import EventEnvelope, SQLiteEventQueue
from agent.inventory import WindowsInventory
from agent.removable import VolumeObservation
from agent.service import enroll, run_once


class FakeProtector:
    def __init__(self):
        self.protected_values = []
        self.unprotected_values = []

    def protect(self, plaintext):
        self.protected_values.append(plaintext)
        return b"fake-protected:" + plaintext[::-1]

    def unprotect(self, protected):
        self.unprotected_values.append(protected)
        prefix, reversed_secret = protected.split(b":", 1)
        assert prefix == b"fake-protected"
        return reversed_secret[::-1]


class FakeTransport:
    def __init__(self):
        self.calls = []

    def request(self, method, url, headers, payload):
        self.calls.append((method, url, dict(headers), dict(payload)))
        return {"status": "accepted"}


def sample_inventory():
    return WindowsInventory(
        "TEST-HOST", "Windows 11", "26100", "AMD64", __version__
    )


def test_enrollment_is_configuration_driven_and_plaintext_is_not_persisted(tmp_path):
    endpoint_id = str(uuid4())
    credential = "one-time-endpoint-secret-value"
    protector = FakeProtector()
    store = ConfigStore(tmp_path)

    config = enroll(
        store,
        protector,
        "https://nepshield.example.test/base/",
        endpoint_id,
        credential,
    )

    assert config.server_url == "https://nepshield.example.test/base"
    assert store.load_config() == AgentConfig(config.server_url, endpoint_id)
    assert json.loads(store.config_path.read_text()) == {
        "server_url": "https://nepshield.example.test/base",
        "endpoint_id": endpoint_id,
    }
    assert credential.encode() not in store.credential_path.read_bytes()
    assert credential not in store.config_path.read_text()
    assert protector.protected_values == [credential.encode()]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI test")
def test_dpapi_protector_round_trip_does_not_expose_plaintext():
    credential = b"dpapi-test-endpoint-secret"
    protector = WindowsDpapiProtector()

    protected = protector.protect(credential)

    assert credential not in protected
    assert protector.unprotect(protected) == credential


def test_run_once_recovers_secret_only_for_configured_authenticated_requests(
    tmp_path, monkeypatch
):
    endpoint_id = str(uuid4())
    credential = "run-once-endpoint-secret"
    store = ConfigStore(tmp_path)
    protector = FakeProtector()
    transport = FakeTransport()
    enroll(store, protector, "http://server.test:9000", endpoint_id, credential)
    monkeypatch.setattr(agent_service, "collect_windows_inventory", sample_inventory)

    run_once(store, protector, transport)

    assert protector.unprotected_values == [store.credential_path.read_bytes()]
    assert [(call[0], call[1]) for call in transport.calls] == [
        ("PUT", "http://server.test:9000/service/v1/inventory"),
        ("POST", "http://server.test:9000/service/v1/heartbeat"),
    ]
    assert all(call[2]["X-NepShield-Endpoint-ID"] == endpoint_id for call in transport.calls)
    assert all(call[2]["Authorization"] == f"Bearer {credential}" for call in transport.calls)
    assert transport.calls[0][3] == sample_inventory().as_payload()
    assert transport.calls[1][3] == {"agent_version": __version__}


def test_endpoint_client_attaches_allowlisted_runtime_health_to_normal_heartbeat():
    transport = FakeTransport()
    client = EndpointClient(
        AgentConfig("https://server.test", str(uuid4())), "credential", transport
    )
    report = {
        "queue_pending_count": 2,
        "applied_policy_revision": 0,
        "protected_watchers_active_count": 1,
        "protected_folders_unavailable_count": 0,
        "removable_monitoring_active": False,
    }

    client.send_heartbeat(__version__, report)

    assert transport.calls[0][3] == {
        "agent_version": __version__,
        "runtime_health": report,
    }
    serialized = json.dumps(transport.calls[0][3])
    assert "credential" not in serialized
    assert "C:\\" not in serialized


def test_transport_failure_and_cli_output_do_not_reveal_credential(
    tmp_path, monkeypatch, capsys
):
    endpoint_id = str(uuid4())
    credential = "never-print-this-endpoint-secret"

    class LeakyTransport:
        def request(self, method, url, headers, payload):
            raise RuntimeError(f"failed with {headers['Authorization']}")

    client = EndpointClient(
        AgentConfig("https://server.test", endpoint_id), credential, LeakyTransport()
    )
    with pytest.raises(
        AgentCommunicationError, match="Inventory submission failed: agent request failed"
    ) as error:
        client.submit_inventory(sample_inventory())
    assert credential not in str(error.value)

    fake = FakeProtector()
    monkeypatch.setattr(agent_cli, "WindowsDpapiProtector", lambda: fake)
    monkeypatch.setattr(agent_cli.getpass, "getpass", lambda prompt: credential)
    result = agent_cli.main(
        [
            "--config-dir",
            str(tmp_path),
            "enroll",
            "--server-url",
            "http://127.0.0.1:8000",
            "--endpoint-id",
            endpoint_id,
        ]
    )
    output = capsys.readouterr().out
    assert result == 0
    assert "enrollment saved successfully" in output
    assert credential not in output


@pytest.mark.parametrize(
    "url",
    [
        "127.0.0.1:8000",
        "ftp://server.test",
        "https://user:password@server.test",
        "https://server.test/?token=secret",
        "https://server.test/#fragment",
    ],
)
def test_enrollment_rejects_unsafe_or_malformed_server_urls(tmp_path, url):
    with pytest.raises(AgentConfigurationError):
        enroll(ConfigStore(tmp_path), FakeProtector(), url, str(uuid4()), "credential")


def test_reenrollment_safely_replaces_local_endpoint_credential(tmp_path):
    store = ConfigStore(tmp_path)
    protector = FakeProtector()
    endpoint_id = str(uuid4())
    enroll(store, protector, "https://first.test", endpoint_id, "old-credential")

    enroll(store, protector, "https://second.test", endpoint_id, "new-credential")

    assert store.load_config().server_url == "https://second.test"
    recovered = protector.unprotect(store.load_protected_credential()).decode()
    assert recovered == "new-credential"
    assert b"old-credential" not in store.load_protected_credential()


def test_enrollment_rejects_literal_windows_ctrl_v_instead_of_storing_it(tmp_path):
    """Windows getpass can receive Ctrl+V (0x16) instead of pasted clipboard text."""
    store = ConfigStore(tmp_path)
    protector = FakeProtector()

    with pytest.raises(AgentConfigurationError, match="URL-safe characters"):
        enroll(
            store,
            protector,
            "http://127.0.0.1:8000",
            str(uuid4()),
            "\x16",
        )

    assert protector.protected_values == []
    assert not store.config_path.exists()
    assert not store.credential_path.exists()


def test_run_once_rejects_previously_stored_ctrl_v_before_any_http_request(tmp_path):
    store = ConfigStore(tmp_path)
    protector = FakeProtector()
    transport = FakeTransport()
    config = AgentConfig("http://127.0.0.1:8000", str(uuid4()))
    store.save(config, protector.protect(b"\x16"))

    with pytest.raises(AgentConfigurationError, match="URL-safe characters"):
        run_once(store, protector, transport)

    assert transport.calls == []


def test_validation_error_names_operation_and_safe_reason_without_secret():
    credential = "safe-test-credential"
    validation_body = json.dumps(
        {
            "detail": [
                {
                    "loc": ["body", "architecture"],
                    "msg": f"String is too long; diagnostic token {credential}",
                    "type": "string_too_long",
                }
            ]
        }
    ).encode()

    class RejectingOpener:
        def open(self, request, timeout):
            raise HTTPError(request.full_url, 422, "Unprocessable", {}, BytesIO(validation_body))

    transport = UrllibJsonTransport()
    transport._opener = RejectingOpener()
    client = EndpointClient(
        AgentConfig("https://server.test", str(uuid4())), credential, transport
    )

    with pytest.raises(AgentCommunicationError) as error:
        client.submit_inventory(sample_inventory())

    message = str(error.value)
    assert message.startswith("Inventory submission failed:")
    assert "HTTP 422" in message
    assert "body.architecture: String is too long" in message
    assert credential not in message
    assert "[redacted]" in message


def test_endpoint_client_submits_event_envelope_with_machine_authentication():
    endpoint_id = str(uuid4())
    credential = "event-delivery-credential"
    transport = FakeTransport()
    client = EndpointClient(
        AgentConfig("https://server.test", endpoint_id), credential, transport
    )
    envelope = EventEnvelope(
        event_id=str(uuid4()),
        event_type="development.test",
        schema_version=1,
        occurred_at="2026-08-14T12:00:00+00:00",
        payload={"value": 1},
    )

    client.submit_events([envelope])

    method, url, headers, payload = transport.calls[0]
    assert method == "POST"
    assert url == "https://server.test/service/v1/events/batch"
    assert headers["X-NepShield-Endpoint-ID"] == endpoint_id
    assert headers["Authorization"] == f"Bearer {credential}"
    assert payload == {"events": [envelope.as_payload()]}


def test_queue_status_cli_initializes_and_reports_without_loading_dpapi(
    tmp_path, monkeypatch, capsys
):
    def unexpected_dpapi():
        raise AssertionError("queue status must not load an endpoint credential")

    monkeypatch.setattr(agent_cli, "WindowsDpapiProtector", unexpected_dpapi)

    result = agent_cli.main(["--config-dir", str(tmp_path), "queue-status"])

    assert result == 0
    assert capsys.readouterr().out.strip() == "NepShield pending event count: 0"
    assert (tmp_path / "events.sqlite3").is_file()


def test_queue_flush_cli_attempts_one_authenticated_batch_and_removes_acknowledged(
    tmp_path, monkeypatch, capsys
):
    endpoint_id = str(uuid4())
    credential = "queue-flush-credential"
    protector = FakeProtector()
    store = ConfigStore(tmp_path)
    enroll(store, protector, "https://server.test", endpoint_id, credential)
    queue = SQLiteEventQueue.in_directory(tmp_path)
    queued = queue.enqueue("development.test", {"value": 1})

    class AcknowledgingTransport(FakeTransport):
        def request(self, method, url, headers, payload):
            self.calls.append((method, url, dict(headers), dict(payload)))
            return {
                "acknowledged_event_ids": [
                    event["event_id"] for event in payload["events"]
                ]
            }

    transport = AcknowledgingTransport()
    monkeypatch.setattr(agent_cli, "WindowsDpapiProtector", lambda: protector)
    monkeypatch.setattr(
        agent_service,
        "EndpointClient",
        lambda config, recovered, ignored=None: EndpointClient(config, recovered, transport),
    )

    result = agent_cli.main(["--config-dir", str(tmp_path), "queue-flush"])

    assert result == 0
    assert "submitted=1, acknowledged=1, pending=0" in capsys.readouterr().out
    assert queue.pending_count() == 0
    assert transport.calls[0][3]["events"][0]["event_id"] == queued.event_id


def test_monitor_removable_cli_queues_then_stops_cleanly_on_ctrl_c(
    tmp_path, monkeypatch, capsys
):
    store = ConfigStore(tmp_path)
    store.save(
        AgentConfig("https://server.test", str(uuid4())),
        b"protected-but-not-loaded-with-no-flush",
    )

    class FakeSource:
        def observations(self):
            yield VolumeObservation("arrival", "E:", "removable_disk", "TEST", "exFAT")
            raise KeyboardInterrupt

    monkeypatch.setattr(agent_cli, "WindowsWmiVolumeEventSource", FakeSource)

    result = agent_cli.main(
        ["--config-dir", str(tmp_path), "monitor-removable", "--no-flush"]
    )

    output = capsys.readouterr().out
    queued = SQLiteEventQueue.in_directory(tmp_path).oldest()[0]
    assert result == 0
    assert queued.envelope.event_type == "removable.volume_arrived"
    assert "monitoring started" in output
    assert "event queued" in output
    assert "monitoring stopped" in output
    assert "protected-but-not-loaded" not in output


def test_monitor_files_cli_validates_explicit_path_queues_and_stops_cleanly(
    tmp_path, monkeypatch, capsys
):
    from agent.filesystem import FilesystemObservation

    protected_root = tmp_path / "Protected"
    protected_root.mkdir()
    store = ConfigStore(tmp_path / "config")
    store.save(
        AgentConfig("https://server.test", str(uuid4())),
        b"protected-but-not-loaded-with-no-flush",
    )

    class FakeSource:
        def __init__(self, monitored_root):
            self.monitored_root = Path(monitored_root).resolve()

        def run(self, callback):
            callback(FilesystemObservation("created", self.monitored_root / "draft.docx"))
            raise KeyboardInterrupt

    monkeypatch.setattr(agent_cli, "WindowsWatchdogFilesystemEventSource", FakeSource)

    result = agent_cli.main(
        [
            "--config-dir",
            str(store.directory),
            "monitor-files",
            "--path",
            str(protected_root),
            "--no-flush",
        ]
    )

    output = capsys.readouterr().out
    queued = SQLiteEventQueue.in_directory(store.directory).oldest()[0]
    assert result == 0
    assert queued.envelope.event_type == "filesystem.file_created"
    assert queued.envelope.payload["relative_path"] == "draft.docx"
    assert str(tmp_path) not in str(queued.envelope.payload)
    assert "monitoring started" in output
    assert "event queued" in output
    assert "monitoring stopped" in output
    assert "protected-but-not-loaded" not in output
