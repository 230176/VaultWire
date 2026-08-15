"""Small, descriptive Windows inventory allowlist."""

from __future__ import annotations

import platform
import socket
import sys
from dataclasses import dataclass

from agent import __version__


@dataclass(frozen=True)
class WindowsInventory:
    reported_hostname: str
    windows_version: str
    os_build: str
    architecture: str
    agent_version: str

    def as_payload(self) -> dict[str, str]:
        return {
            "reported_hostname": self.reported_hostname,
            "windows_version": self.windows_version,
            "os_build": self.os_build,
            "architecture": self.architecture,
            "agent_version": self.agent_version,
        }


def _bounded(value: object, fallback: str, maximum: int) -> str:
    normalized = str(value).strip() if value is not None else ""
    return (normalized or fallback)[:maximum]


def collect_windows_inventory() -> WindowsInventory:
    """Collect only the fields approved for the first endpoint-agent milestone."""
    release, version, service_pack, _ = platform.win32_ver()
    if sys.platform == "win32":
        windows = sys.getwindowsversion()
        build = str(windows.build)
    else:
        # Keeps collection testable on developer systems; the shipped target is Windows.
        build = version or platform.version()
    version_label = " ".join(part for part in ("Windows", release, service_pack) if part)
    return WindowsInventory(
        reported_hostname=_bounded(socket.gethostname(), "unknown-host", 255),
        windows_version=_bounded(version_label, "Windows", 200),
        os_build=_bounded(build, "unknown", 100),
        architecture=_bounded(platform.machine(), "unknown", 50),
        agent_version=__version__,
    )
