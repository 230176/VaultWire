"""Per-user Windows startup registration for the packaged agent."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Protocol


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE_NAME = "NepShieldAgent"
EXECUTABLE_NAME = "NepShieldAgent.exe"


class StartupRegistrationError(RuntimeError):
    """The current-user startup registration could not be read or changed."""


class RegistryBackend(Protocol):
    def read(self, key: str, name: str) -> str | None: ...

    def write(self, key: str, name: str, value: str) -> None: ...

    def delete(self, key: str, name: str) -> None: ...


class WindowsCurrentUserRegistry:
    """Small winreg boundary kept injectable for tests."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise StartupRegistrationError("Windows startup registration is available only on Windows.")
        import winreg

        self._winreg = winreg

    def read(self, key: str, name: str) -> str | None:
        try:
            with self._winreg.OpenKey(self._winreg.HKEY_CURRENT_USER, key) as handle:
                value, value_type = self._winreg.QueryValueEx(handle, name)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise StartupRegistrationError("Could not read automatic-startup settings.") from exc
        if value_type != self._winreg.REG_SZ or not isinstance(value, str):
            return None
        return value

    def write(self, key: str, name: str, value: str) -> None:
        try:
            with self._winreg.CreateKeyEx(
                self._winreg.HKEY_CURRENT_USER,
                key,
                0,
                self._winreg.KEY_SET_VALUE,
            ) as handle:
                self._winreg.SetValueEx(handle, name, 0, self._winreg.REG_SZ, value)
        except OSError as exc:
            raise StartupRegistrationError("Could not configure automatic startup.") from exc

    def delete(self, key: str, name: str) -> None:
        try:
            with self._winreg.OpenKey(
                self._winreg.HKEY_CURRENT_USER,
                key,
                0,
                self._winreg.KEY_SET_VALUE,
            ) as handle:
                self._winreg.DeleteValue(handle, name)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise StartupRegistrationError("Could not remove automatic startup.") from exc


def default_install_directory() -> Path:
    """Return the stable application location for the current Windows user."""
    base = os.getenv("LOCALAPPDATA")
    if base:
        return Path(base) / "Programs" / "NepShield" / "Agent"
    return Path.home() / "AppData" / "Local" / "Programs" / "NepShield" / "Agent"


def background_command(executable: Path) -> str:
    """Build a shell-free, correctly quoted HKCU Run command."""
    resolved = Path(executable).resolve()
    return f'"{resolved}" --background'


class StartupManager:
    def __init__(self, registry: RegistryBackend, executable: Path) -> None:
        self.registry = registry
        self.executable = Path(executable)

    @property
    def expected_command(self) -> str:
        return background_command(self.executable)

    def current_command(self) -> str | None:
        return self.registry.read(RUN_KEY, RUN_VALUE_NAME)

    def is_installed_correctly(self) -> bool:
        return self.current_command() == self.expected_command

    def install_or_repair(self) -> bool:
        """Install only when needed; return whether the registry changed."""
        if self.is_installed_correctly():
            return False
        self.registry.write(RUN_KEY, RUN_VALUE_NAME, self.expected_command)
        return True

    def restore(self, previous: str | None) -> None:
        if previous is None:
            self.registry.delete(RUN_KEY, RUN_VALUE_NAME)
        else:
            self.registry.write(RUN_KEY, RUN_VALUE_NAME, previous)
