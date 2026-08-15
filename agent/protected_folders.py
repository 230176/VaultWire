"""Dependency-free Windows protected-folder syntax shared by server and agent."""

from __future__ import annotations

import ntpath
import re
from collections.abc import Iterable


MAXIMUM_PROTECTED_FOLDERS = 10
MAXIMUM_PROTECTED_FOLDER_LENGTH = 260
_LOCAL_ABSOLUTE_PATH = re.compile(r"^[A-Za-z]:\\")
_WINDOWS_DEVICE_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}


class ProtectedFolderValidationError(ValueError):
    """A configured Windows protected-folder path is unsafe or malformed."""


def canonical_protected_folder(value: str) -> str:
    if not isinstance(value, str):
        raise ProtectedFolderValidationError("Protected folders must be Windows paths.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ProtectedFolderValidationError(
            "Protected folder paths cannot contain control characters."
        )
    path = value.strip(" ")
    if not path:
        raise ProtectedFolderValidationError("Protected folder paths cannot be empty.")
    if len(path) > MAXIMUM_PROTECTED_FOLDER_LENGTH:
        raise ProtectedFolderValidationError(
            f"Protected folder paths must be {MAXIMUM_PROTECTED_FOLDER_LENGTH} characters or fewer."
        )
    if "*" in path or "?" in path:
        raise ProtectedFolderValidationError("Protected folder paths cannot contain wildcards.")
    if any(character in path for character in '<>"|'):
        raise ProtectedFolderValidationError(
            "Protected folder paths contain invalid Windows characters."
        )
    path = path.replace("/", "\\")
    if path.startswith("\\\\"):
        raise ProtectedFolderValidationError(
            "UNC, network-share, and Windows device namespace paths are not supported."
        )
    if not _LOCAL_ABSOLUTE_PATH.match(path):
        raise ProtectedFolderValidationError(
            r"Protected folders must be absolute local Windows paths such as C:\Users\Name\Work."
        )
    if ":" in path[2:]:
        raise ProtectedFolderValidationError(
            "Protected folder paths contain an invalid drive separator."
        )

    parts = path[3:].split("\\")
    if any(part == ".." for part in parts):
        raise ProtectedFolderValidationError(
            "Protected folder paths cannot contain parent traversal."
        )
    normalized = ntpath.normpath(path)
    if normalized == f"{normalized[0]}:\\":
        raise ProtectedFolderValidationError("A bare drive root cannot be a protected folder.")
    for part in normalized[3:].split("\\"):
        if part.endswith((" ", ".")):
            raise ProtectedFolderValidationError(
                "Protected folder components cannot end with a space or period."
            )
        device_name = part.rstrip(" .").split(".", 1)[0].casefold()
        if device_name in _WINDOWS_DEVICE_NAMES:
            raise ProtectedFolderValidationError(
                "Protected folder paths cannot use Windows device names."
            )
    return normalized[0].upper() + normalized[1:]


def validate_protected_folders(values: Iterable[str]) -> tuple[str, ...]:
    raw_folders = tuple(values)
    if len(raw_folders) > MAXIMUM_PROTECTED_FOLDERS:
        raise ProtectedFolderValidationError(
            f"At most {MAXIMUM_PROTECTED_FOLDERS} protected work folders are allowed."
        )
    folders = tuple(canonical_protected_folder(value) for value in raw_folders)
    folded = [folder.casefold() for folder in folders]
    if len(set(folded)) != len(folded):
        raise ProtectedFolderValidationError(
            "Protected work folders cannot contain case-insensitive duplicates."
        )
    return folders
