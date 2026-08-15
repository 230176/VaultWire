"""Allowlisted operational health facts reported by the unified runtime."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RuntimeHealthSnapshot:
    queue_pending_count: int
    applied_policy_revision: int
    protected_watchers_active_count: int
    protected_folders_unavailable_count: int
    removable_monitoring_active: bool

    def as_payload(self) -> dict[str, int | bool]:
        return {
            "queue_pending_count": self.queue_pending_count,
            "applied_policy_revision": self.applied_policy_revision,
            "protected_watchers_active_count": self.protected_watchers_active_count,
            "protected_folders_unavailable_count": (
                self.protected_folders_unavailable_count
            ),
            "removable_monitoring_active": self.removable_monitoring_active,
        }
