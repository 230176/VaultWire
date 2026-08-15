"""Authenticated agent-to-server communication."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from agent.config import AgentConfig
from agent.inventory import WindowsInventory
from agent.events import EventEnvelope
from agent.policy import AgentPolicyValidationError, validate_policy_values


class AgentCommunicationError(RuntimeError):
    """A sanitized communication failure safe for concise CLI output."""


class AgentAuthenticationRejected(AgentCommunicationError):
    """The server explicitly rejected the enrolled machine identity."""

    authentication_rejected = True


@dataclass(frozen=True)
class EndpointPolicy:
    """Configuration fields returned by the authenticated policy endpoint."""

    revision: int
    monitoring_enabled: bool
    removable_storage_monitoring_enabled: bool
    protected_folders: tuple[str, ...]


def _safe_server_reason(body: bytes, sensitive_values: tuple[str, ...]) -> str | None:
    """Extract bounded FastAPI error detail without echoing request data or headers."""
    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        try:
            plain_reason = body.decode("utf-8")
        except UnicodeDecodeError:
            return None
        messages = [plain_reason]
        decoded = None
    else:
        detail = decoded.get("detail") if isinstance(decoded, dict) else None
        messages = []
        if isinstance(detail, list):
            for error in detail[:3]:
                if not isinstance(error, dict) or not isinstance(error.get("msg"), str):
                    continue
                location = error.get("loc", [])
                safe_location = ".".join(
                    str(part) for part in location if isinstance(part, (str, int))
                )
                messages.append(
                    f"{safe_location}: {error['msg']}" if safe_location else error["msg"]
                )
        elif isinstance(detail, str):
            messages.append(detail)
    if not messages:
        return None
    reason = " ".join(" ".join(message.split()) for message in messages)
    for value in sensitive_values:
        if value:
            reason = reason.replace(value, "[redacted]")
    return reason[:240]


class JsonTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]: ...


class _NoRedirectHandler(HTTPRedirectHandler):
    """Never forward a bearer credential to a redirected destination."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


class UrllibJsonTransport:
    """Standard-library HTTPS client using the platform's default TLS validation."""

    def __init__(self, timeout_seconds: float = 15.0) -> None:
        self.timeout_seconds = timeout_seconds
        self._opener = build_opener(_NoRedirectHandler())

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]:
        request_headers = dict(headers)
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        request = Request(
            url,
            data=data,
            headers=request_headers,
            method=method,
        )
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                body = response.read()
        except HTTPError as exc:
            sensitive_values = list(headers.values())
            authorization = headers.get("Authorization", "")
            if authorization.casefold().startswith("bearer "):
                sensitive_values.append(authorization[7:])
            reason = _safe_server_reason(
                exc.read(4096),
                tuple(sensitive_values),
            )
            suffix = f" Reason: {reason}" if reason else ""
            error_type = (
                AgentAuthenticationRejected
                if exc.code in {401, 403}
                else AgentCommunicationError
            )
            raise error_type(
                f"Server rejected the agent request (HTTP {exc.code}).{suffix}"
            ) from None
        except (URLError, OSError, TimeoutError):
            raise AgentCommunicationError("Could not reach the configured NepShield server.") from None
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AgentCommunicationError("Server returned an invalid response.") from None
        if not isinstance(decoded, dict):
            raise AgentCommunicationError("Server returned an invalid response.")
        return decoded


class EndpointClient:
    def __init__(
        self, config: AgentConfig, credential: str, transport: JsonTransport | None = None
    ) -> None:
        self.config = config
        self._credential = credential
        self._transport = transport or UrllibJsonTransport()

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "X-NepShield-Endpoint-ID": self.config.endpoint_id,
            "Authorization": f"Bearer {self._credential}",
        }

    def submit_inventory(self, inventory: WindowsInventory) -> dict[str, Any]:
        return self._send(
            "Inventory submission", "PUT", "/service/v1/inventory", inventory.as_payload()
        )

    def send_heartbeat(
        self,
        agent_version: str,
        runtime_health: Mapping[str, int | bool] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"agent_version": agent_version}
        if runtime_health is not None:
            payload["runtime_health"] = dict(runtime_health)
        return self._send(
            "Heartbeat",
            "POST",
            "/service/v1/heartbeat",
            payload,
        )

    def submit_events(self, events: Sequence[EventEnvelope]) -> dict[str, Any]:
        return self._send(
            "Event batch submission",
            "POST",
            "/service/v1/events/batch",
            {"events": [event.as_payload() for event in events]},
        )

    def fetch_policy(self) -> EndpointPolicy:
        payload = self._send("Policy retrieval", "GET", "/service/v1/policy", None)
        try:
            validated = validate_policy_values(
                payload.get("revision"),
                payload.get("monitoring_enabled"),
                payload.get("removable_storage_monitoring_enabled"),
                payload.get("protected_folders"),
            )
        except AgentPolicyValidationError:
            raise AgentCommunicationError("Policy retrieval failed: server returned an invalid policy.")
        return EndpointPolicy(
            revision=validated.revision,
            monitoring_enabled=validated.monitoring_enabled,
            removable_storage_monitoring_enabled=(
                validated.removable_storage_monitoring_enabled
            ),
            protected_folders=validated.protected_folders,
        )

    def _send(
        self,
        operation: str,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]:
        try:
            return self._transport.request(
                method, f"{self.config.server_url}{path}", self._headers, payload
            )
        except AgentAuthenticationRejected as exc:
            raise AgentAuthenticationRejected(f"{operation} failed: {exc}") from None
        except AgentCommunicationError as exc:
            raise AgentCommunicationError(f"{operation} failed: {exc}") from None
        except Exception:
            # A custom transport must not accidentally expose authorization data.
            raise AgentCommunicationError(f"{operation} failed: agent request failed.") from None
