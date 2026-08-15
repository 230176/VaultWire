"""Windowed PyInstaller entrypoint for setup and automatic background runtime."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Callable

from agent import __version__
from agent.config import AgentConfigurationError, ConfigStore
from agent.credentials import WindowsDpapiProtector
from agent.enrollment_setup import EnrollmentCoordinator
from agent.operational_log import OperationalLogger
from agent.runtime import AgentRuntime, RuntimeAlreadyRunningError
from agent.setup_ui import SetupWindow
from agent.windows_install import PackagedApplicationInstaller
from agent.windows_startup import (
    EXECUTABLE_NAME,
    StartupManager,
    WindowsCurrentUserRegistry,
    default_install_directory,
)


def packaged_directory() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


def build_enrollment_coordinator(store: ConfigStore | None = None) -> EnrollmentCoordinator:
    store = store or ConfigStore()
    install_directory = default_install_directory()
    installer = PackagedApplicationInstaller(
        packaged_directory(),
        install_directory=install_directory,
        executable_name=EXECUTABLE_NAME,
    )
    startup = StartupManager(
        WindowsCurrentUserRegistry(),
        install_directory / EXECUTABLE_NAME,
    )
    return EnrollmentCoordinator(store, WindowsDpapiProtector(), installer, startup)


def show_setup(coordinator_factory: Callable[[], EnrollmentCoordinator] = build_enrollment_coordinator) -> int:
    SetupWindow(coordinator_factory()).run()
    return 0


def run_background(
    store: ConfigStore | None = None,
    *,
    protector_factory=WindowsDpapiProtector,
    runtime_factory=AgentRuntime.from_store,
    logger_factory=OperationalLogger,
) -> int:
    """Invoke the existing unified runtime with safe file diagnostics."""
    store = store or ConfigStore()
    logger = logger_factory(store.directory)
    try:
        # Missing configuration is checked before DPAPI and creates no identity,
        # queue, or retry loop.
        store.load_config()
    except AgentConfigurationError:
        logger("Background startup skipped because enrollment is missing or unreadable.")
        logger.close()
        return 2

    try:
        runtime = runtime_factory(store, protector_factory(), status=logger)
        runtime.run()
    except RuntimeAlreadyRunningError:
        logger("Duplicate agent runtime launch ignored.")
        return 0
    except Exception as exc:
        logger.runtime_error(exc)
        return 1
    finally:
        logger.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="NepShieldAgent", add_help=False)
    parser.add_argument("--background", action="store_true")
    parser.add_argument("--version", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args, unknown = build_parser().parse_known_args(argv)
    if unknown:
        return 2
    if args.version:
        # Useful for deployment verification. The windowed build has no visible
        # stdout during normal operation, but the source entry remains testable.
        print(__version__)
        return 0
    if args.background:
        return run_background()
    return show_setup()


if __name__ == "__main__":
    raise SystemExit(main())
