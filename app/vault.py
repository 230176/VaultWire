"""Encrypted employee vault domain services."""

import base64
import binascii
import io
import os
import re
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from bson import ObjectId
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.auth import AuditService
from app.models import DocumentAccessKind, User, VaultDocument

NONCE_BYTES = 12
STORAGE_NAME_PATTERN = re.compile(r"^[0-9a-f]{32}\.vault$")
ALLOWED_MEDIA_TYPES = {
    ".pdf": {"application/pdf", "application/octet-stream"},
    ".docx": {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/zip",
        "application/octet-stream",
    },
    ".xlsx": {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/zip",
        "application/octet-stream",
    },
    ".csv": {
        "text/csv",
        "application/csv",
        "application/vnd.ms-excel",
        "text/plain",
        "application/octet-stream",
    },
    ".txt": {"text/plain", "application/octet-stream"},
}


class VaultConfigurationError(RuntimeError):
    pass


class InvalidVaultUpload(ValueError):
    pass


class VaultDocumentNotFound(LookupError):
    pass


class VaultIntegrityError(RuntimeError):
    pass


class VaultCipher:
    """AES-256-GCM encryption with one fresh 96-bit nonce per operation."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise VaultConfigurationError(
                "VAULT_ENCRYPTION_KEY must decode to exactly 32 bytes."
            )
        self._cipher = AESGCM(key)

    @classmethod
    def from_base64(cls, encoded_key: str | None) -> "VaultCipher":
        if not encoded_key:
            raise VaultConfigurationError("VAULT_ENCRYPTION_KEY is not configured.")
        try:
            key = base64.b64decode(encoded_key, altchars=b"-_", validate=True)
        except (binascii.Error, ValueError) as exc:
            raise VaultConfigurationError(
                "VAULT_ENCRYPTION_KEY must be valid URL-safe base64."
            ) from exc
        return cls(key)

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(NONCE_BYTES)
        return nonce, self._cipher.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, nonce: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
        try:
            return self._cipher.decrypt(nonce, ciphertext, associated_data)
        except (InvalidTag, ValueError) as exc:
            raise VaultIntegrityError("The encrypted document failed authentication.") from exc


class VaultStorage:
    """Filesystem storage that accepts and returns ciphertext only."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def write(self, ciphertext: bytes) -> str:
        storage_name = f"{uuid.uuid4().hex}.vault"
        temporary_name = f"{uuid.uuid4().hex}.vault"
        temporary_path = self.root / temporary_name
        final_path = self.root / storage_name
        try:
            with temporary_path.open("xb") as stored_file:
                stored_file.write(ciphertext)
                stored_file.flush()
                os.fsync(stored_file.fileno())
            temporary_path.replace(final_path)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
        return storage_name

    def read(self, storage_name: str) -> bytes:
        return self._path(storage_name).read_bytes()

    def delete(self, storage_name: str) -> None:
        self._path(storage_name).unlink(missing_ok=True)

    def _path(self, storage_name: str) -> Path:
        if not STORAGE_NAME_PATTERN.fullmatch(storage_name):
            raise VaultIntegrityError("Invalid vault storage reference.")
        return self.root / storage_name


class VaultService:
    def __init__(
        self,
        repository: Any,
        storage: VaultStorage,
        cipher: VaultCipher,
        audit: AuditService,
        authorization: Any,
        *,
        max_file_size: int,
    ) -> None:
        if max_file_size <= 0:
            raise VaultConfigurationError("VAULT_MAX_FILE_SIZE_BYTES must be positive.")
        self.repository = repository
        self.storage = storage
        self.cipher = cipher
        self.audit = audit
        self.authorization = authorization
        self.max_file_size = max_file_size

    async def list_documents(self, owner: User) -> list[VaultDocument]:
        return await self.repository.list_for_owner(owner.id)

    async def upload(
        self,
        owner: User,
        filename: str | None,
        media_type: str | None,
        plaintext: bytes,
        *,
        source_ip: str | None,
        user_agent: str | None,
    ) -> VaultDocument:
        safe_name, normalized_type = validate_upload(
            filename, media_type, plaintext, self.max_file_size
        )
        document_id = ObjectId()
        associated_data = self._associated_data(document_id, owner.id)
        nonce, ciphertext = self.cipher.encrypt(plaintext, associated_data)
        storage_name = self.storage.write(ciphertext)
        document = VaultDocument(
            id=document_id,
            owner_id=owner.id,
            original_filename=safe_name,
            media_type=normalized_type,
            plaintext_size=len(plaintext),
            storage_name=storage_name,
            nonce=nonce,
            created_at=datetime.now(UTC),
        )
        try:
            await self.repository.create(document)
        except Exception:
            self.storage.delete(storage_name)
            raise
        await self.audit.record(
            "vault.document_uploaded",
            username=owner.username,
            user_id=owner.id,
            source_ip=source_ip,
            user_agent=user_agent,
            outcome="success",
            resource_id=document.id,
        )
        return document

    async def download(
        self,
        actor: User,
        document_id: str,
        *,
        source_ip: str | None,
        user_agent: str | None,
    ) -> tuple[VaultDocument, bytes]:
        try:
            parsed_id = ObjectId(document_id)
        except Exception as exc:
            raise VaultDocumentNotFound from exc
        decision = await self.authorization.authorize_read(actor, parsed_id)
        if decision.kind not in {
            DocumentAccessKind.OWNER,
            DocumentAccessKind.SHARED,
        } or decision.document is None:
            raise VaultDocumentNotFound
        document = decision.document
        try:
            ciphertext = self.storage.read(document.storage_name)
        except OSError as exc:
            raise VaultIntegrityError("The encrypted document is unavailable.") from exc
        plaintext = self.cipher.decrypt(
            document.nonce,
            ciphertext,
            self._associated_data(document.id, document.owner_id),
        )
        event_type = (
            "vault.shared_document_downloaded"
            if decision.kind is DocumentAccessKind.SHARED
            else "vault.document_downloaded"
        )
        await self.audit.record(
            event_type,
            username=actor.username,
            user_id=actor.id,
            source_ip=source_ip,
            user_agent=user_agent,
            outcome="success",
            resource_id=document.id,
            context=(
                {
                    "permission_id": decision.permission.id,
                    "grantee_id": actor.id,
                    "document_owner_id": document.owner_id,
                }
                if decision.permission is not None
                else None
            ),
        )
        return document, plaintext

    @staticmethod
    def _associated_data(document_id: Any, owner_id: Any) -> bytes:
        return f"nepshield-vault-v1\0{document_id}\0{owner_id}".encode("utf-8")


def validate_upload(
    filename: str | None,
    media_type: str | None,
    content: bytes,
    max_file_size: int,
) -> tuple[str, str]:
    """Validate filename, declared type, size, and basic file structure."""
    safe_name = (filename or "").replace("\\", "/").rsplit("/", 1)[-1].strip()
    if (
        not safe_name
        or safe_name in {".", ".."}
        or len(safe_name) > 255
        or any(ord(character) < 32 for character in safe_name)
    ):
        raise InvalidVaultUpload("Choose a file with a valid filename.")
    if not content:
        raise InvalidVaultUpload("The selected file is empty.")
    if len(content) > max_file_size:
        raise InvalidVaultUpload(
            f"The file exceeds the {format_file_size(max_file_size)} research-build limit."
        )

    extension = Path(safe_name).suffix.casefold()
    if extension not in ALLOWED_MEDIA_TYPES:
        raise InvalidVaultUpload("Allowed file types are PDF, DOCX, XLSX, CSV, and TXT.")
    normalized_type = (media_type or "application/octet-stream").split(";", 1)[0].strip().casefold()
    if normalized_type not in ALLOWED_MEDIA_TYPES[extension]:
        raise InvalidVaultUpload("The file type does not match its filename extension.")

    if extension == ".pdf" and not content.startswith(b"%PDF-"):
        raise InvalidVaultUpload("The selected file is not a valid PDF document.")
    if extension in {".docx", ".xlsx"}:
        _validate_office_file(content, extension)
    if extension in {".csv", ".txt"}:
        try:
            content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise InvalidVaultUpload("Text and CSV uploads must use UTF-8 encoding.") from exc
        if b"\x00" in content:
            raise InvalidVaultUpload("The selected text file contains binary data.")
    return safe_name, normalized_type


def _validate_office_file(content: bytes, extension: str) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = set(archive.namelist())
            expected_prefix = "word/" if extension == ".docx" else "xl/"
            if "[Content_Types].xml" not in names or not any(
                name.startswith(expected_prefix) for name in names
            ):
                raise InvalidVaultUpload(
                    f"The selected file is not a valid {extension[1:].upper()} document."
                )
    except (zipfile.BadZipFile, OSError) as exc:
        raise InvalidVaultUpload(
            f"The selected file is not a valid {extension[1:].upper()} document."
        ) from exc


def format_file_size(size: int) -> str:
    if size < 1024:
        return f"{size} bytes"
    if size < 1024 * 1024:
        return f"{size / 1024:.0f} KiB"
    return f"{size / (1024 * 1024):g} MiB"
