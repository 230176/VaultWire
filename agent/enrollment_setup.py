"""Interactive enrollment orchestration around existing agent services."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from agent.client import AgentAuthenticationRejected, AgentCommunicationError, EndpointClient
from agent.config import (
    AgentConfig,
    AgentConfigurationError,
    ConfigStore,
    normalize_endpoint_id,
    normalize_server_url,
    validate_credential,
)
from agent.credentials import CredentialProtectionError, CredentialProtector
from agent.service import enroll
from agent.windows_install import AgentInstallationError
from agent.windows_startup import StartupManager, StartupRegistrationError


class ExistingEnrollmentError(AgentConfigurationError):
    """Interactive setup must not replace enrollment without an explicit admin flow."""


class CredentialUpdateConfirmationRequired(AgentConfigurationError):
    """Credential-only repair requires an explicit user confirmation."""


class ApplicationInstaller(Protocol):
    @property
    def installed_executable(self) -> Path: ...

    def is_installed(self) -> bool: ...

    def ensure_installed(self) -> Path: ...


@dataclass(frozen=True)
class EnrollmentStatus:
    enrolled: bool
    server_url: str | None = None
    endpoint_id: str | None = None
    startup_installed: bool = False
    application_installed: bool = False


def friendly_setup_error(error: BaseException) -> str:
    """Return bounded UI text without echoing server bodies, paths, or credentials."""
    if isinstance(error, ExistingEnrollmentError):
        return "This Windows user is already enrolled. Existing enrollment was not changed."
    if isinstance(error, AgentAuthenticationRejected):
        return "Enrollment was rejected. Check the Endpoint ID and machine credential."
    if isinstance(error, AgentCommunicationError):
        return "The NepShield server could not verify enrollment. Check the Server URL and connection."
    if isinstance(error, CredentialProtectionError):
        return "Windows could not protect the credential for this user. Enrollment was not saved."
    if isinstance(error, AgentInstallationError):
        return "NepShield could not be installed in this user's application folder."
    if isinstance(error, StartupRegistrationError):
        return "NepShield could not configure automatic startup for this Windows user."
    if isinstance(error, AgentConfigurationError):
        # These messages are produced by local allowlisted validators and contain
        # no submitted values. Avoid reflecting unknown subclasses.
        if type(error) is AgentConfigurationError:
            return str(error)[:240]
    return "Enrollment could not be completed. No credential was saved."


def friendly_credential_update_error(error: BaseException) -> str:
    """Return safe credential-repair UI text without reflecting submitted data."""
    if isinstance(error, CredentialUpdateConfirmationRequired):
        return "Confirm the credential update before replacing the protected credential."
    if isinstance(error, AgentAuthenticationRejected):
        return "The replacement credential was rejected for this enrolled endpoint. The existing credential was not changed."
    if isinstance(error, AgentCommunicationError):
        return "The server could not verify the replacement credential. The existing credential was not changed."
    if isinstance(error, CredentialProtectionError):
        return "Windows could not protect the replacement credential. The existing credential was not changed."
    if type(error) is AgentConfigurationError:
        return str(error)[:240]
    return "The machine credential was not updated. The existing credential was not changed."


class EnrollmentCoordinator:
    """Verify machine auth, then commit through the existing DPAPI/config format."""

    def __init__(
        self,
        store: ConfigStore,
        protector: CredentialProtector,
        installer: ApplicationInstaller,
        startup: StartupManager,
        *,
        client_factory: Callable[[AgentConfig, str], EndpointClient] = EndpointClient,
    ) -> None:
        self.store = store
        self.protector = protector
        self.installer = installer
        self.startup = startup
        self.client_factory = client_factory

    def status(self) -> EnrollmentStatus:
        application_installed = self.installer.is_installed()
        startup_installed = (
            application_installed and self.startup.is_installed_correctly()
        )
        try:
            config = self.store.load_config()
            self.store.load_protected_credential()
        except AgentConfigurationError:
            return EnrollmentStatus(
                enrolled=False,
                startup_installed=startup_installed,
                application_installed=application_installed,
            )
        return EnrollmentStatus(
            enrolled=True,
            server_url=config.server_url,
            endpoint_id=config.endpoint_id,
            startup_installed=startup_installed,
            application_installed=application_installed,
        )

    def enroll(self, server_url: str, endpoint_id: str, credential: str) -> AgentConfig:
        # Any pre-existing half or complete identity requires deliberate repair;
        # the friendly setup never silently overwrites it.
        if self.store.config_path.exists() or self.store.credential_path.exists():
            raise ExistingEnrollmentError("Existing enrollment was not changed.")

        config = AgentConfig(
            normalize_server_url(server_url),
            normalize_endpoint_id(endpoint_id),
        )
        secret = validate_credential(credential)

        # The policy endpoint is the existing authenticated, read-only machine
        # endpoint. Verification therefore creates no server identity/state.
        self.client_factory(config, secret).fetch_policy()

        installed_executable = self.installer.ensure_installed()
        if Path(installed_executable).resolve() != self.startup.executable.resolve():
            raise AgentInstallationError("Installed application path did not match startup target.")

        previous_startup = self.startup.current_command()
        self.startup.install_or_repair()
        try:
            return enroll(
                self.store,
                self.protector,
                config.server_url,
                config.endpoint_id,
                secret,
            )
        except Exception:
            # This method only reaches commit when neither identity file existed,
            # so cleanup cannot destroy a prior enrollment.
            try:
                self.store.config_path.unlink(missing_ok=True)
                self.store.credential_path.unlink(missing_ok=True)
            finally:
                self.startup.restore(previous_startup)
            raise

    def check_connection(self) -> None:
        self._stored_client().fetch_policy()

    def update_machine_credential(
        self, replacement_credential: str, *, confirmed: bool = False
    ) -> AgentConfig:
        """Verify and atomically replace only the current endpoint's DPAPI secret."""
        if not confirmed:
            raise CredentialUpdateConfirmationRequired(
                "Confirm the credential update before continuing."
            )

        # Identity comes exclusively from the existing immutable config in this
        # flow. No caller can submit a different endpoint ID or server URL.
        config = self.store.load_config()
        self.store.load_protected_credential()
        secret = validate_credential(replacement_credential)

        # Verification is read-only and must succeed before DPAPI or disk state
        # is touched. Server endpoint creation/rotation remains administrator-only.
        self.client_factory(config, secret).fetch_policy()

        protected = self.protector.protect(secret.encode("utf-8"))
        self.store.replace_protected_credential(protected)
        return config

    def _stored_client(self) -> EndpointClient:
        config = self.store.load_config()
        protected = self.store.load_protected_credential()
        try:
            credential = self.protector.unprotect(protected).decode("utf-8")
        except UnicodeDecodeError:
            raise AgentConfigurationError(
                "Stored endpoint credential is invalid; update the machine credential."
            ) from None
        return self.client_factory(config, validate_credential(credential))

    def repair_startup(self) -> bool:
        if not self.status().enrolled:
            raise AgentConfigurationError("Enroll this Windows user before enabling automatic startup.")
        if not self.installer.is_installed():
            installed_executable = self.installer.ensure_installed()
            if Path(installed_executable).resolve() != self.startup.executable.resolve():
                raise AgentInstallationError("Installed application path did not match startup target.")
        return self.startup.install_or_repair()
