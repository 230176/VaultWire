"""Windows WMI adapter for mounted/local volume arrival and removal events."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from datetime import datetime
from threading import Event
from typing import Any, Callable

from agent.events import utc_now
from agent.removable import MountedVolume, VolumeObservation

_WMI_MONIKER = r"winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2"
_VOLUME_CHANGE_QUERY = (
    "SELECT * FROM Win32_VolumeChangeEvent "
    "WHERE EventType = 2 OR EventType = 3"
)
_LOGICAL_DISK_QUERY = (
    "SELECT DeviceID, DriveType, VolumeName, FileSystem FROM Win32_LogicalDisk"
)
_DRIVE_TYPES = {
    0: "unknown",
    1: "no_root_directory",
    2: "removable_disk",
    3: "local_disk",
    4: "network_drive",
    5: "compact_disc",
    6: "ram_disk",
}
_WMI_TIMEOUT_CODES = {0x00040004, 0x80043001}


class WindowsVolumeObservationError(RuntimeError):
    """The Windows WMI observation mechanism could not be started or continued."""


def _load_wmi_runtime() -> tuple[Any, Callable[[str], Any]]:
    """Load pywin32 lazily so non-Windows tests need no COM installation."""
    import pythoncom
    import win32com.client

    return pythoncom, win32com.client.GetObject


def _exception_codes(error: BaseException) -> set[int]:
    codes: set[int] = set()

    def visit(value: object) -> None:
        if isinstance(value, int) and not isinstance(value, bool):
            codes.add(value & 0xFFFFFFFF)
        elif isinstance(value, (tuple, list)):
            for nested in value:
                visit(nested)

    visit(getattr(error, "hresult", None))
    visit(error.args)
    return codes


def _is_timeout(error: BaseException) -> bool:
    message = str(error).casefold()
    return bool(_exception_codes(error).intersection(_WMI_TIMEOUT_CODES)) or any(
        phrase in message for phrase in ("timed out", "timeout")
    )


class WindowsWmiVolumeEventSource:
    """Use Win32_VolumeChangeEvent; metadata lookup never opens volume files."""

    def __init__(
        self,
        *,
        timeout_ms: int = 1_000,
        service_factory: Callable[[], Any] | None = None,
        clock: Callable[[], datetime] = utc_now,
        stop_event: Event | None = None,
    ) -> None:
        self.timeout_ms = timeout_ms
        self._service_factory = service_factory
        self._clock = clock
        self._stop_event = stop_event

    def mounted_volumes(self) -> list[MountedVolume]:
        """Snapshot logical-disk metadata without traversing any volume files."""
        if sys.platform != "win32" and self._service_factory is None:
            raise WindowsVolumeObservationError(
                "Removable-volume monitoring is available only on Windows."
            )

        com_initialized = False
        pythoncom = None
        service = None
        disks = None
        disk = None
        mounted: list[MountedVolume] = []
        interrupted = False
        try:
            try:
                if self._service_factory is None:
                    try:
                        pythoncom, get_object = _load_wmi_runtime()
                    except ImportError as exc:
                        raise WindowsVolumeObservationError(
                            "Windows WMI support requires the pywin32 dependency."
                        ) from exc
                    pythoncom.CoInitialize()
                    com_initialized = True
                    service = get_object(_WMI_MONIKER)
                else:
                    service = self._service_factory()
                disks = service.ExecQuery(_LOGICAL_DISK_QUERY)
                for disk in disks:
                    mapped = self._map_disk(disk)
                    if mapped is not None:
                        mounted.append(mapped)
            except KeyboardInterrupt:
                # Clear the COM call's traceback before balancing CoInitialize.
                interrupted = True
            except WindowsVolumeObservationError:
                raise
            except Exception as exc:
                raise WindowsVolumeObservationError(
                    "Mounted-volume discovery failed unexpectedly."
                ) from exc
        finally:
            disk = None
            disks = None
            service = None
            if com_initialized and pythoncom is not None:
                pythoncom.CoUninitialize()
        if interrupted:
            raise KeyboardInterrupt
        return mounted

    def observations(self) -> Iterator[VolumeObservation]:
        if sys.platform != "win32" and self._service_factory is None:
            raise WindowsVolumeObservationError(
                "Removable-volume monitoring is available only on Windows."
            )

        com_initialized = False
        pythoncom = None
        service = None
        watcher = None
        event = None
        interrupted = False
        try:
            try:
                if self._service_factory is None:
                    try:
                        pythoncom, get_object = _load_wmi_runtime()
                    except ImportError as exc:
                        raise WindowsVolumeObservationError(
                            "Windows WMI support requires the pywin32 dependency."
                        ) from exc
                    pythoncom.CoInitialize()
                    com_initialized = True
                    service = get_object(_WMI_MONIKER)
                else:
                    service = self._service_factory()
                watcher = service.ExecNotificationQuery(_VOLUME_CHANGE_QUERY)

                while self._stop_event is None or not self._stop_event.is_set():
                    try:
                        event = watcher.NextEvent(self.timeout_ms)
                    except Exception as exc:
                        if _is_timeout(exc):
                            continue
                        raise WindowsVolumeObservationError(
                            "Windows WMI volume monitoring stopped unexpectedly."
                        ) from exc
                    observed_at = self._clock()
                    if self._stop_event is not None and self._stop_event.is_set():
                        break
                    observation = self._map_event(service, event, observed_at)
                    if observation is not None:
                        yield observation
            except KeyboardInterrupt:
                # A pywin32 generated-method traceback retains its CDispatch self.
                # Finish this handler so that traceback is cleared before entering
                # the COM teardown below, then propagate a fresh interrupt later.
                interrupted = True
        finally:
            # CPython releases these pywin32 wrappers when their last references are
            # dropped. Clear every proxy owned by this frame before balancing this
            # thread's successful CoInitialize call.
            event = None
            watcher = None
            service = None
            if com_initialized and pythoncom is not None:
                pythoncom.CoUninitialize()
        if interrupted:
            raise KeyboardInterrupt

    @staticmethod
    def _map_event(
        service: Any, event: Any, observed_at: datetime
    ) -> VolumeObservation | None:
        try:
            event_type = int(event.EventType)
            drive_name = event.DriveName
        except (AttributeError, TypeError, ValueError):
            return None
        if event_type == 3:
            return VolumeObservation("removal", drive_name, observed_at=observed_at)
        if event_type != 2:
            return None

        metadata: dict[str, object] = {}
        try:
            disks = service.ExecQuery(_LOGICAL_DISK_QUERY)
            disk = next(
                (
                    item
                    for item in disks
                    if str(getattr(item, "DeviceID", "")).casefold()
                    == str(drive_name).casefold()
                ),
                None,
            )
            if disk is not None:
                mapped = WindowsWmiVolumeEventSource._map_disk(disk)
                if mapped is not None:
                    metadata["drive_type"] = mapped.drive_type
                    metadata["volume_label"] = mapped.volume_label
                    metadata["filesystem"] = mapped.filesystem
        except Exception:
            # Arrival remains useful with only DriveName if WMI metadata disappears
            # during a mount race or is unavailable to the current Windows user.
            pass
        return VolumeObservation("arrival", drive_name, observed_at=observed_at, **metadata)

    @staticmethod
    def _map_disk(disk: Any) -> MountedVolume | None:
        drive_name = getattr(disk, "DeviceID", None)
        if not isinstance(drive_name, str) or not drive_name:
            return None
        try:
            drive_type_number = int(disk.DriveType)
        except (AttributeError, TypeError, ValueError):
            drive_type_number = None
        return MountedVolume(
            drive_name=drive_name,
            drive_type=_DRIVE_TYPES.get(drive_type_number),
            volume_label=getattr(disk, "VolumeName", None),
            filesystem=getattr(disk, "FileSystem", None),
        )
