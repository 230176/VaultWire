"""Bounded, privacy-preserving diagnostics for the windowless agent runtime."""

from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path


LOG_FILENAME = "agent.log"
MAX_LOG_BYTES = 512 * 1024
LOG_BACKUP_COUNT = 3

_EXACT_MESSAGES = {
    "NepShield agent runtime started.",
    "NepShield agent runtime shutdown complete.",
    "NepShield connectivity and authentication restored.",
    "NepShield connectivity restored.",
    "NepShield authentication rejected; collectors suspended.",
    "NepShield monitoring disabled by policy.",
    "NepShield protected-folder watcher started.",
    "NepShield protected-folder watcher stopped.",
    "NepShield removable monitoring started.",
    "NepShield removable monitoring stopped.",
    "NepShield removable monitoring could not start; retry is scheduled.",
    "Removable monitoring stopped unexpectedly; retry is scheduled.",
    "A configured protected folder is unavailable; retry is scheduled.",
    "Invalid or incompatible local policy cache was ignored.",
    "The valid server policy could not be cached locally.",
    "NepShield server temporarily unavailable; no monitoring policy is available.",
    "NepShield server temporarily unavailable using cached policy.",
    "Background startup skipped because enrollment is missing or unreadable.",
    "Duplicate agent runtime launch ignored.",
}
_POLICY = re.compile(r"^NepShield policy revision ([0-9]{1,18}) applied\.$")
_QUEUE = re.compile(
    r"^NepShield queued events delivered: ([0-9]{1,18}); pending: ([0-9]{1,18})\.$"
)
_COLLECTORS = re.compile(
    r"^NepShield collector state: protected=([0-9]{1,6}); removable=([01])\.$"
)
_QUEUE_REPLAY = re.compile(
    r"^NepShield queue replay: submitted=([0-9]{1,18}); "
    r"acknowledged=([0-9]{1,18}); pending=([0-9]{1,18}); "
    r"state=(ok|deferred|authentication_rejected)\.$"
)


def sanitize_operational_message(message: object) -> str | None:
    """Allow only fixed diagnostics and numeric operational summaries."""
    if not isinstance(message, str):
        return None
    if message in _EXACT_MESSAGES:
        return message
    policy = _POLICY.fullmatch(message)
    if policy:
        return f"NepShield policy revision {int(policy.group(1))} applied."
    queue = _QUEUE.fullmatch(message)
    if queue:
        return (
            f"NepShield queued events delivered: {int(queue.group(1))}; "
            f"pending: {int(queue.group(2))}."
        )
    collectors = _COLLECTORS.fullmatch(message)
    if collectors:
        return (
            f"NepShield collector state: protected={int(collectors.group(1))}; "
            f"removable={collectors.group(2)}."
        )
    replay = _QUEUE_REPLAY.fullmatch(message)
    if replay:
        return (
            f"NepShield queue replay: submitted={int(replay.group(1))}; "
            f"acknowledged={int(replay.group(2))}; pending={int(replay.group(3))}; "
            f"state={replay.group(4)}."
        )
    if message.startswith("Server policy revision is lower than the cached revision"):
        return "Server policy rollback received and applied."
    return None


class OperationalLogger:
    def __init__(
        self,
        directory: Path,
        *,
        max_bytes: int = MAX_LOG_BYTES,
        backup_count: int = LOG_BACKUP_COUNT,
    ) -> None:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / LOG_FILENAME
        self._logger = logging.Logger(f"nepshield.agent.{id(self)}", level=logging.INFO)
        self._logger.propagate = False
        handler = RotatingFileHandler(
            self.path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
            delay=True,
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        self._logger.addHandler(handler)

    def __call__(self, message: object) -> None:
        safe = sanitize_operational_message(message)
        if safe is not None:
            self._logger.info(safe)

    def runtime_error(self, error: BaseException) -> None:
        """Record error class only; exception text can contain secrets or paths."""
        safe_types = {
            "AgentCommunicationError",
            "AgentConfigurationError",
            "CredentialProtectionError",
            "RuntimeAlreadyRunningError",
            "StartupRegistrationError",
            "AgentInstallationError",
        }
        name = type(error).__name__
        category = name if name in safe_types else "UnexpectedRuntimeError"
        self._logger.error("Sanitized agent runtime error (%s).", category)

    def close(self) -> None:
        for handler in list(self._logger.handlers):
            handler.close()
            self._logger.removeHandler(handler)
