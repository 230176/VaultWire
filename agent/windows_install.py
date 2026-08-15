"""Stable per-user installation of the PyInstaller onedir application."""

from __future__ import annotations

import shutil
from pathlib import Path

from agent.windows_startup import EXECUTABLE_NAME, default_install_directory


class AgentInstallationError(RuntimeError):
    """The packaged application could not be installed for this user."""


class PackagedApplicationInstaller:
    def __init__(
        self,
        source_directory: Path,
        *,
        install_directory: Path | None = None,
        executable_name: str = EXECUTABLE_NAME,
    ) -> None:
        self.source_directory = Path(source_directory)
        self.install_directory = Path(install_directory or default_install_directory())
        self.executable_name = executable_name

    @property
    def installed_executable(self) -> Path:
        return self.install_directory / self.executable_name

    def is_installed(self) -> bool:
        return self.installed_executable.is_file()

    def ensure_installed(self) -> Path:
        """Copy a complete onedir bundle once and safely repair missing bundle files."""
        source_executable = self.source_directory / self.executable_name
        try:
            if self.source_directory.resolve() == self.install_directory.resolve():
                if not source_executable.is_file():
                    raise AgentInstallationError("The installed NepShield executable is missing.")
                return source_executable
            if not source_executable.is_file():
                raise AgentInstallationError("The NepShield application bundle is incomplete.")
            self.install_directory.mkdir(parents=True, exist_ok=True)
            shutil.copytree(
                self.source_directory,
                self.install_directory,
                dirs_exist_ok=True,
                copy_function=shutil.copy2,
            )
            if not self.installed_executable.is_file():
                raise AgentInstallationError("The NepShield application could not be installed completely.")
            return self.installed_executable
        except AgentInstallationError:
            raise
        except OSError as exc:
            raise AgentInstallationError("Could not install NepShield for the current Windows user.") from exc
