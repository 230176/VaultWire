"""Endpoint-bound, non-secret last-known-good policy persistence."""

from __future__ import annotations

import json
import os
from pathlib import Path

from agent.client import EndpointPolicy
from agent.config import normalize_endpoint_id
from agent.policy import AgentPolicyValidationError, validate_policy_values

POLICY_CACHE_SCHEMA_VERSION = 1
POLICY_CACHE_FILENAME = "policy-cache.json"
_CACHE_FIELDS = {
    "cache_schema_version",
    "endpoint_id",
    "revision",
    "monitoring_enabled",
    "removable_storage_monitoring_enabled",
    "protected_folders",
}


class PolicyCache:
    """Read and atomically replace one endpoint's last valid policy."""

    def __init__(self, directory: Path) -> None:
        self.path = Path(directory) / POLICY_CACHE_FILENAME

    def load(self, endpoint_id: str) -> EndpointPolicy | None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or set(raw) != _CACHE_FIELDS:
                return None
            if raw["cache_schema_version"] != POLICY_CACHE_SCHEMA_VERSION:
                return None
            if normalize_endpoint_id(raw["endpoint_id"]) != normalize_endpoint_id(endpoint_id):
                return None
            validated = validate_policy_values(
                raw["revision"],
                raw["monitoring_enabled"],
                raw["removable_storage_monitoring_enabled"],
                raw["protected_folders"],
            )
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return None
        return EndpointPolicy(
            validated.revision,
            validated.monitoring_enabled,
            validated.removable_storage_monitoring_enabled,
            validated.protected_folders,
        )

    def save(self, endpoint_id: str, policy: EndpointPolicy) -> None:
        canonical_endpoint_id = normalize_endpoint_id(endpoint_id)
        validated = validate_policy_values(
            policy.revision,
            policy.monitoring_enabled,
            policy.removable_storage_monitoring_enabled,
            policy.protected_folders,
        )
        document = {
            "cache_schema_version": POLICY_CACHE_SCHEMA_VERSION,
            "endpoint_id": canonical_endpoint_id,
            "revision": validated.revision,
            "monitoring_enabled": validated.monitoring_enabled,
            "removable_storage_monitoring_enabled": (
                validated.removable_storage_monitoring_enabled
            ),
            "protected_folders": list(validated.protected_folders),
        }
        encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        try:
            with temporary.open("wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except OSError:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise AgentPolicyValidationError("Could not update the local policy cache.") from None
