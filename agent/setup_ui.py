"""Small tkinter enrollment/status window for non-technical employees."""

from __future__ import annotations

import getpass
import tkinter as tk
from tkinter import messagebox, ttk

from agent import __version__
from agent.enrollment_setup import (
    EnrollmentCoordinator,
    friendly_credential_update_error,
    friendly_setup_error,
)


class SetupWindow:
    def __init__(self, coordinator: EnrollmentCoordinator) -> None:
        self.coordinator = coordinator
        self.root = tk.Tk()
        self.root.title("NepShield Agent")
        self.root.resizable(False, False)
        self.root.geometry("540x430")
        self.frame = ttk.Frame(self.root, padding=20)
        self.frame.pack(fill="both", expand=True)
        self.feedback = tk.StringVar(value="")
        self.credential = tk.StringVar(value="")
        self.server_url = tk.StringVar(value="")
        self.endpoint_id = tk.StringVar(value="")
        self._render()

    def run(self) -> None:
        self.root.mainloop()

    def _clear(self) -> None:
        for child in self.frame.winfo_children():
            child.destroy()

    def _heading(self) -> None:
        ttk.Label(
            self.frame,
            text="NepShield Agent",
            font=("Segoe UI", 16, "bold"),
        ).pack(anchor="w")
        ttk.Label(self.frame, text=f"Version {__version__}").pack(anchor="w", pady=(0, 14))

    def _render(self) -> None:
        self._clear()
        self._heading()
        status = self.coordinator.status()
        if status.enrolled:
            self._render_status(status)
        else:
            self._render_enrollment()

    def _render_enrollment(self) -> None:
        username = getpass.getuser()
        ttk.Label(
            self.frame,
            text=(
                f"Set up monitoring for Windows user: {username}\n"
                "Enrollment and its protected credential belong only to this Windows user."
            ),
            wraplength=490,
            justify="left",
        ).pack(anchor="w", pady=(0, 14))
        self._field("Server URL", self.server_url)
        self._field("Endpoint ID", self.endpoint_id)
        self._field("Machine credential", self.credential, show="•")
        ttk.Label(
            self.frame,
            text="Use the credential shown once by the NepShield Administrator interface.",
            wraplength=490,
        ).pack(anchor="w", pady=(0, 10))
        ttk.Button(self.frame, text="Enroll", command=self._enroll).pack(anchor="e")
        ttk.Label(
            self.frame,
            textvariable=self.feedback,
            wraplength=490,
            foreground="#8b1a1a",
        ).pack(anchor="w", pady=(12, 0))

    def _field(self, label: str, variable: tk.StringVar, *, show: str = "") -> None:
        ttk.Label(self.frame, text=label).pack(anchor="w")
        ttk.Entry(self.frame, textvariable=variable, show=show, width=68).pack(
            anchor="w", pady=(2, 10)
        )

    def _enroll(self) -> None:
        try:
            self.coordinator.enroll(
                self.server_url.get(),
                self.endpoint_id.get(),
                self.credential.get(),
            )
        except Exception as exc:
            self.feedback.set(friendly_setup_error(exc))
        else:
            self.feedback.set("Enrollment succeeded. NepShield will start automatically at Windows logon.")
            self._render()
        finally:
            # Do not retain or render the one-time secret after any attempt.
            self.credential.set("")

    def _render_status(self, status) -> None:
        ttk.Label(
            self.frame,
            text=f"Enrolled for Windows user: {getpass.getuser()}",
            wraplength=490,
        ).pack(anchor="w", pady=(0, 12))
        ttk.Label(self.frame, text=f"Endpoint ID: {status.endpoint_id}").pack(anchor="w")
        ttk.Label(self.frame, text=f"Server URL: {status.server_url}", wraplength=490).pack(
            anchor="w", pady=(4, 0)
        )
        ttk.Label(self.frame, text="Enrollment: Ready").pack(anchor="w", pady=(12, 0))
        startup = "Installed" if status.startup_installed else "Needs repair"
        ttk.Label(self.frame, text=f"Automatic startup: {startup}").pack(anchor="w", pady=(4, 16))
        actions = ttk.Frame(self.frame)
        actions.pack(fill="x")
        ttk.Button(actions, text="Check Connection", command=self._check).pack(side="left")
        ttk.Button(
            actions,
            text="Update Machine Credential",
            command=lambda: self._render_credential_update(status),
        ).pack(side="left", padx=(10, 0))
        if not status.startup_installed:
            ttk.Button(actions, text="Repair Automatic Startup", command=self._repair).pack(
                side="left", padx=(10, 0)
            )
        ttk.Label(self.frame, textvariable=self.feedback, wraplength=490).pack(
            anchor="w", pady=(16, 0)
        )

    def _check(self) -> None:
        try:
            self.coordinator.check_connection()
        except Exception as exc:
            self.feedback.set(friendly_setup_error(exc))
        else:
            self.feedback.set("Connection and machine authentication succeeded.")

    def _render_credential_update(self, status) -> None:
        self.feedback.set("")
        self.credential.set("")
        self._clear()
        self._heading()
        ttk.Label(
            self.frame,
            text=(
                "Update only the machine credential for this existing enrollment. "
                "Use an administrator-issued replacement for the endpoint shown below."
            ),
            wraplength=490,
            justify="left",
        ).pack(anchor="w", pady=(0, 12))
        ttk.Label(self.frame, text=f"Endpoint ID: {status.endpoint_id}").pack(anchor="w")
        ttk.Label(
            self.frame,
            text=f"Server URL: {status.server_url}",
            wraplength=490,
        ).pack(anchor="w", pady=(4, 12))
        self._field("New machine credential", self.credential, show="•")
        ttk.Label(
            self.frame,
            text="The Endpoint ID and Server URL cannot be changed by this repair.",
            wraplength=490,
        ).pack(anchor="w", pady=(0, 10))
        actions = ttk.Frame(self.frame)
        actions.pack(fill="x")
        ttk.Button(
            actions,
            text="Confirm Credential Update",
            command=lambda: self._update_credential(status),
        ).pack(side="left")
        ttk.Button(actions, text="Cancel", command=self._cancel_credential_update).pack(
            side="left", padx=(10, 0)
        )
        ttk.Label(
            self.frame,
            textvariable=self.feedback,
            wraplength=490,
            foreground="#8b1a1a",
        ).pack(anchor="w", pady=(14, 0))

    def _update_credential(self, status) -> None:
        replacement = self.credential.get()
        confirmed = messagebox.askyesno(
            "Confirm machine credential update",
            (
                "Replace the protected machine credential for the displayed endpoint?\n\n"
                "The replacement will be verified before the existing credential is changed."
            ),
            parent=self.root,
        )
        try:
            if not confirmed:
                self.feedback.set("Machine credential update cancelled.")
                return
            self.coordinator.update_machine_credential(
                replacement,
                confirmed=True,
            )
        except Exception as exc:
            self.feedback.set(friendly_credential_update_error(exc))
        else:
            self.feedback.set(
                "Machine credential updated. The running agent will retry authentication automatically."
            )
            self._render()
        finally:
            # Never retain or render the replacement after the confirmation attempt.
            self.credential.set("")

    def _cancel_credential_update(self) -> None:
        self.credential.set("")
        self.feedback.set("Machine credential update cancelled.")
        self._render()

    def _repair(self) -> None:
        try:
            changed = self.coordinator.repair_startup()
        except Exception as exc:
            self.feedback.set(friendly_setup_error(exc))
        else:
            self.feedback.set(
                "Automatic startup repaired." if changed else "Automatic startup is already correct."
            )
            self._render()
