"""Local validation helpers for authenticated endpoint monitoring policy."""

from __future__ import annotations

from dataclasses import dataclass

from agent.protected_folders import (
    ProtectedFolderValidationError,
    validate_protected_folders,
)


class AgentPolicyValidationError(ValueError):
    """A server or cache policy is not safe for the runtime to apply."""


@dataclass(frozen=True)
class ValidatedPolicy:
    revision: int
    monitoring_enabled: bool
    removable_storage_monitoring_enabled: bool
    protected_folders: tuple[str, ...]


def validate_policy_values(
    revision: object,
    monitoring_enabled: object,
    removable_storage_monitoring_enabled: object,
    protected_folders: object,
) -> ValidatedPolicy:
    """Validate shape and Task 16 Windows path semantics without filesystem access."""
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise AgentPolicyValidationError("Policy revision is invalid.")
    if type(monitoring_enabled) is not bool:
        raise AgentPolicyValidationError("Policy monitoring flag is invalid.")
    if type(removable_storage_monitoring_enabled) is not bool:
        raise AgentPolicyValidationError("Policy removable-monitoring flag is invalid.")
    if not isinstance(protected_folders, (list, tuple)):
        raise AgentPolicyValidationError("Policy protected folders are invalid.")

    try:
        folders = validate_protected_folders(protected_folders)
    except (ProtectedFolderValidationError, TypeError) as exc:
        raise AgentPolicyValidationError("Policy protected folders are invalid.") from exc
    return ValidatedPolicy(
        revision,
        monitoring_enabled,
        removable_storage_monitoring_enabled,
        tuple(folders),
    )
