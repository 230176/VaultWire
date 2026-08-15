"""Non-secret local agent configuration and enrollment persistence."""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID


class AgentConfigurationError(ValueError):
    """Local configuration is absent or invalid."""


@dataclass(frozen=True)
class AgentConfig:
    server_url: str
    endpoint_id: str


def default_config_directory() -> Path:
    """Use per-user local application data for the thesis prototype."""
    base = os.getenv("LOCALAPPDATA")
    if base:
        return Path(base) / "NepShield" / "Agent"
    return Path.home() / ".nepshield" / "agent"


def normalize_server_url(value: str) -> str:
    candidate = value.strip()
    parsed = urlsplit(candidate)
    try:
        parsed.port
    except ValueError as exc:
        raise AgentConfigurationError("Server URL contains an invalid port.") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or not parsed.hostname
        or any(character.isspace() for character in candidate)
    ):
        raise AgentConfigurationError("Server URL must be an absolute HTTP or HTTPS URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise AgentConfigurationError(
            "Server URL must not contain credentials, a query, or a fragment."
        )
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def normalize_endpoint_id(value: str) -> str:
    try:
        return str(UUID(value.strip()))
    except (AttributeError, TypeError, ValueError) as exc:
        raise AgentConfigurationError("Endpoint ID must be a valid UUID.") from exc


def validate_credential(value: str) -> str:
    if (
        not value
        or len(value) > 512
        or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
    ):
        raise AgentConfigurationError(
            "Endpoint credential must be 1-512 URL-safe characters using only letters, numbers, '-' or '_'."
        )
    return value


class ConfigStore:
    """Keep public settings in JSON and the DPAPI blob in a separate binary file."""

    def __init__(self, directory: Path | None = None) -> None:
        self.directory = Path(directory) if directory else default_config_directory()
        self.config_path = self.directory / "config.json"
        self.credential_path = self.directory / "endpoint-credential.dpapi"

    def save(self, config: AgentConfig, protected_credential: bytes) -> None:
        if not protected_credential:
            raise AgentConfigurationError("Credential protection returned no data.")
        self.directory.mkdir(parents=True, exist_ok=True)
        self._replace_bytes(self.credential_path, protected_credential)
        self._replace_bytes(
            self.config_path,
            (json.dumps(asdict(config), indent=2) + "\n").encode("utf-8"),
        )

    def load_config(self) -> AgentConfig:
        try:
            raw = json.loads(self.config_path.read_text(encoding="utf-8"))
            if set(raw) != {"server_url", "endpoint_id"}:
                raise AgentConfigurationError("Agent configuration has unexpected fields.")
            return AgentConfig(
                normalize_server_url(raw["server_url"]),
                normalize_endpoint_id(raw["endpoint_id"]),
            )
        except AgentConfigurationError:
            raise
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise AgentConfigurationError(
                "Agent is not enrolled or its configuration is unreadable."
            ) from exc

    def load_protected_credential(self) -> bytes:
        try:
            protected = self.credential_path.read_bytes()
        except OSError as exc:
            raise AgentConfigurationError(
                "Agent credential is missing or unreadable; re-enroll this endpoint."
            ) from exc
        if not protected:
            raise AgentConfigurationError(
                "Agent credential is missing or unreadable; re-enroll this endpoint."
            )
        return protected

    def replace_protected_credential(self, protected_credential: bytes) -> None:
        """Atomically replace only the credential blob of an intact enrollment."""
        if not protected_credential:
            raise AgentConfigurationError("Credential protection returned no data.")
        # A credential repair is not enrollment and must never create or rewrite
        # public identity configuration. Both existing files are prerequisites.
        self.load_config()
        self.load_protected_credential()
        self._replace_bytes(self.credential_path, protected_credential)

    @staticmethod
    def _replace_bytes(path: Path, value: bytes) -> None:
        temporary = path.with_name(f".{path.name}.tmp")
        try:
            temporary.write_bytes(value)
            os.replace(temporary, path)
        except OSError as exc:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise AgentConfigurationError("Could not save agent configuration.") from exc
