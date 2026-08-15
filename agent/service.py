"""Enrollment and run-once orchestration independent from the CLI."""

from __future__ import annotations

from agent.client import EndpointClient, JsonTransport
from agent.config import (
    AgentConfig,
    AgentConfigurationError,
    ConfigStore,
    normalize_endpoint_id,
    normalize_server_url,
    validate_credential,
)
from agent.credentials import CredentialProtector
from agent.events import DEFAULT_BATCH_SIZE, FlushResult, SQLiteEventQueue, flush_event_queue
from agent.inventory import collect_windows_inventory


def enroll(
    store: ConfigStore,
    protector: CredentialProtector,
    server_url: str,
    endpoint_id: str,
    credential: str,
) -> AgentConfig:
    """Validate and replace local enrollment without registering server state."""
    config = AgentConfig(
        server_url=normalize_server_url(server_url),
        endpoint_id=normalize_endpoint_id(endpoint_id),
    )
    secret = validate_credential(credential)
    # Existing queue rows have no endpoint-id column because server identity is
    # derived from machine authentication at delivery. Do not silently submit
    # those rows as a newly enrolled endpoint.
    try:
        previous = store.load_config()
    except AgentConfigurationError:
        previous = None
    if previous is not None and previous.endpoint_id != config.endpoint_id:
        queue_path = store.directory / "events.sqlite3"
        if queue_path.exists():
            try:
                pending = SQLiteEventQueue(queue_path).pending_count()
            except Exception:
                raise AgentConfigurationError(
                    "Cannot safely change endpoint enrollment while the local event queue is unreadable."
                ) from None
            if pending:
                raise AgentConfigurationError(
                    "Cannot change endpoint enrollment while queued events belong to the current endpoint; flush them first."
                )
    protected = protector.protect(secret.encode("utf-8"))
    store.save(config, protected)
    return config


def run_once(
    store: ConfigStore,
    protector: CredentialProtector,
    transport: JsonTransport | None = None,
) -> None:
    config = store.load_config()
    protected = store.load_protected_credential()
    try:
        credential = protector.unprotect(protected).decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Stored endpoint credential is invalid; re-enroll this endpoint.") from None
    validate_credential(credential)
    inventory = collect_windows_inventory()
    client = EndpointClient(config, credential, transport)
    client.submit_inventory(inventory)
    client.send_heartbeat(inventory.agent_version)


def authenticated_client(
    store: ConfigStore,
    protector: CredentialProtector,
    transport: JsonTransport | None = None,
) -> EndpointClient:
    """Recover the DPAPI-protected secret only to construct the machine client."""
    config = store.load_config()
    protected = store.load_protected_credential()
    try:
        credential = protector.unprotect(protected).decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Stored endpoint credential is invalid; re-enroll this endpoint.") from None
    validate_credential(credential)
    return EndpointClient(config, credential, transport)


def flush_pending_events(
    store: ConfigStore,
    protector: CredentialProtector,
    transport: JsonTransport | None = None,
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> FlushResult:
    """Deliver at most one oldest-first batch and never loop automatically."""
    queue = SQLiteEventQueue.in_directory(store.directory)
    return flush_event_queue(
        queue,
        authenticated_client(store, protector, transport),
        batch_size=batch_size,
    )
