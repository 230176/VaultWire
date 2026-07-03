"""Environment-based application configuration."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Runtime settings read from environment variables."""

    app_env: str = os.getenv("APP_ENV", "development")
    mongodb_uri: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    mongodb_database: str = os.getenv("MONGODB_DATABASE", "nepshield")
    session_cookie_name: str = "nepshield_session"
    session_lifetime_hours: int = 8
    vault_encryption_key: str | None = os.getenv("VAULT_ENCRYPTION_KEY")
    vault_storage_dir: str = os.getenv("VAULT_STORAGE_DIR", "./vault_storage")
    vault_max_file_size_bytes: int = int(
        os.getenv("VAULT_MAX_FILE_SIZE_BYTES", str(1024 * 1024))
    )

    @property
    def session_cookie_secure(self) -> bool:
        """Only permit plain HTTP cookies in local development and tests."""
        configured = os.getenv("SESSION_COOKIE_SECURE")
        if configured is not None:
            return configured.lower() in {"1", "true", "yes"}
        return self.app_env not in {"development", "testing"}


settings = Settings()
