"""Windows DPAPI protection for the endpoint credential."""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from typing import Protocol


class CredentialProtectionError(RuntimeError):
    """DPAPI could not protect or recover the local credential."""


class CredentialProtector(Protocol):
    def protect(self, plaintext: bytes) -> bytes: ...

    def unprotect(self, protected: bytes) -> bytes: ...


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


class WindowsDpapiProtector:
    """Protect data for the currently logged-on Windows user.

    This deliberately uses DPAPI user scope. A future Windows-service package
    must revisit account/protection scope because another service identity will
    not be able to decrypt a blob enrolled by the interactive administrator.
    """

    _UI_FORBIDDEN = 0x1
    _DESCRIPTION = "NepShield endpoint credential"
    _ENTROPY = b"NepShield endpoint credential v1"

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise CredentialProtectionError("Windows DPAPI is available only on Windows.")
        self._crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._configure_functions()

    def protect(self, plaintext: bytes) -> bytes:
        if not plaintext:
            raise CredentialProtectionError("Cannot protect an empty credential.")
        return self._transform("CryptProtectData", plaintext, protect=True)

    def unprotect(self, protected: bytes) -> bytes:
        if not protected:
            raise CredentialProtectionError("Protected credential is empty.")
        return self._transform("CryptUnprotectData", protected, protect=False)

    def _configure_functions(self) -> None:
        pointer = ctypes.POINTER(_DataBlob)
        self._crypt32.CryptProtectData.argtypes = [
            pointer,
            wintypes.LPCWSTR,
            pointer,
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.DWORD,
            pointer,
        ]
        self._crypt32.CryptProtectData.restype = wintypes.BOOL
        self._crypt32.CryptUnprotectData.argtypes = [
            pointer,
            ctypes.POINTER(wintypes.LPWSTR),
            pointer,
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.DWORD,
            pointer,
        ]
        self._crypt32.CryptUnprotectData.restype = wintypes.BOOL
        self._kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
        self._kernel32.LocalFree.restype = wintypes.HLOCAL

    @staticmethod
    def _blob(value: bytes) -> tuple[_DataBlob, ctypes.Array]:
        buffer = ctypes.create_string_buffer(value, len(value))
        blob = _DataBlob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
        return blob, buffer

    def _transform(self, function_name: str, value: bytes, *, protect: bool) -> bytes:
        source, source_buffer = self._blob(value)
        entropy, entropy_buffer = self._blob(self._ENTROPY)
        output = _DataBlob()
        description = wintypes.LPWSTR()
        function = getattr(self._crypt32, function_name)
        if protect:
            succeeded = function(
                ctypes.byref(source),
                self._DESCRIPTION,
                ctypes.byref(entropy),
                None,
                None,
                self._UI_FORBIDDEN,
                ctypes.byref(output),
            )
        else:
            succeeded = function(
                ctypes.byref(source),
                ctypes.byref(description),
                ctypes.byref(entropy),
                None,
                None,
                self._UI_FORBIDDEN,
                ctypes.byref(output),
            )
        # Retain references until the native call completes.
        _ = source_buffer, entropy_buffer
        if not succeeded:
            raise CredentialProtectionError(
                f"Windows DPAPI operation failed (error {ctypes.get_last_error()})."
            )
        try:
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            if output.pbData:
                self._kernel32.LocalFree(ctypes.cast(output.pbData, wintypes.HLOCAL))
            if description:
                self._kernel32.LocalFree(ctypes.cast(description, wintypes.HLOCAL))
