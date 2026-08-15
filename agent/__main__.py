"""Development CLI for enrolling and checking the Windows endpoint agent."""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path
from threading import RLock

from agent.client import AgentCommunicationError
from agent.config import AgentConfigurationError, ConfigStore
from agent.credentials import CredentialProtectionError, WindowsDpapiProtector
from agent.events import DEFAULT_BATCH_SIZE, MAX_BATCH_SIZE, SQLiteEventQueue
from agent.filesystem import FilesystemCollector, FilesystemConfigurationError
from agent.removable import RemovableVolumeCollector
from agent.runtime import AgentRuntime, RuntimeAlreadyRunningError
from agent.service import authenticated_client, enroll, flush_pending_events, run_once
from agent.windows_filesystem import (
    WindowsFilesystemObservationError,
    WindowsWatchdogFilesystemEventSource,
)
from agent.windows_removable import WindowsVolumeObservationError, WindowsWmiVolumeEventSource
from agent.windows_removable_filesystem import (
    WindowsRemovableFilesystemWatcherManager,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m agent")
    parser.add_argument(
        "--config-dir",
        type=Path,
        default=None,
        help="Override the per-user NepShield agent configuration directory.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    enrollment = commands.add_parser(
        "enroll", help="Store or replace an administrator-issued endpoint credential."
    )
    enrollment.add_argument("--server-url", required=True)
    enrollment.add_argument("--endpoint-id", required=True)
    commands.add_parser("check", help="Submit inventory and one heartbeat, then exit.")
    commands.add_parser(
        "run", help="Run the supervised policy-driven endpoint agent in the foreground."
    )
    commands.add_parser(
        "policy-show",
        help="Retrieve and display this enrolled endpoint's policy without applying it.",
    )
    commands.add_parser("queue-status", help="Report the number of pending raw events.")
    flush = commands.add_parser(
        "queue-flush", help="Attempt one authenticated oldest-first event batch."
    )
    flush.add_argument(
        "--batch-size", type=int, choices=range(1, MAX_BATCH_SIZE + 1), default=DEFAULT_BATCH_SIZE
    )
    monitor = commands.add_parser(
        "monitor-removable",
        help=(
            "Monitor Windows removable-volume lifecycle and metadata-only file "
            "activity in the foreground."
        ),
    )
    monitor.add_argument(
        "--batch-size", type=int, choices=range(1, MAX_BATCH_SIZE + 1), default=DEFAULT_BATCH_SIZE
    )
    monitor.add_argument(
        "--no-flush",
        action="store_true",
        help="Queue observations without attempting delivery after each new event.",
    )
    files = commands.add_parser(
        "monitor-files",
        help="Monitor one explicitly selected protected directory in the foreground.",
    )
    files.add_argument("--path", type=Path, required=True)
    files.add_argument(
        "--batch-size", type=int, choices=range(1, MAX_BATCH_SIZE + 1), default=DEFAULT_BATCH_SIZE
    )
    files.add_argument(
        "--no-flush",
        action="store_true",
        help="Queue observations without attempting delivery after each new event.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = ConfigStore(args.config_dir)
    try:
        if args.command == "queue-status":
            queue = SQLiteEventQueue.in_directory(store.directory)
            print(f"NepShield pending event count: {queue.pending_count()}")
        elif args.command == "enroll":
            protector = WindowsDpapiProtector()
            credential = getpass.getpass(
                "One-time endpoint credential (paste with right-click or Ctrl+Shift+V): "
            )
            enroll(store, protector, args.server_url, args.endpoint_id, credential)
            print("NepShield endpoint enrollment saved successfully.")
        elif args.command == "check":
            protector = WindowsDpapiProtector()
            run_once(store, protector)
            print("NepShield agent check succeeded: inventory and heartbeat accepted.")
        elif args.command == "run":
            # Fail on missing enrollment before initializing platform DPAPI.
            store.load_config()
            protector = WindowsDpapiProtector()
            AgentRuntime.from_store(store, protector).run()
        elif args.command == "policy-show":
            protector = WindowsDpapiProtector()
            policy = authenticated_client(store, protector).fetch_policy()
            print(f"Policy revision: {policy.revision}")
            print(
                "Monitoring: " + ("enabled" if policy.monitoring_enabled else "disabled")
            )
            print(
                "Removable-storage monitoring: "
                + (
                    "enabled"
                    if policy.removable_storage_monitoring_enabled
                    else "disabled"
                )
            )
            print("Protected folders:")
            if policy.protected_folders:
                for folder in policy.protected_folders:
                    print(f"  - {folder}")
            else:
                print("  (none)")
        elif args.command == "monitor-removable":
            # Loading configuration first makes enrollment a prerequisite even when
            # --no-flush deliberately avoids recovering the endpoint credential.
            store.load_config()
            queue = SQLiteEventQueue.in_directory(store.directory)
            client = None
            if not args.no_flush:
                protector = WindowsDpapiProtector()
                client = authenticated_client(store, protector)
            processing_lock = RLock()
            filesystem_watchers = WindowsRemovableFilesystemWatcherManager(
                queue,
                client=client,
                batch_size=args.batch_size,
                status=print,
                processing_lock=processing_lock,
            )
            collector = RemovableVolumeCollector(
                queue,
                client=client,
                batch_size=args.batch_size,
                status=print,
                filesystem_watchers=filesystem_watchers,
                processing_lock=processing_lock,
            )
            print(
                "NepShield removable-volume and file-activity monitoring started. "
                "Press Ctrl+C to stop."
            )
            try:
                collector.run(WindowsWmiVolumeEventSource())
            except KeyboardInterrupt:
                print("NepShield removable-volume monitoring stopped.")
        elif args.command == "monitor-files":
            source = WindowsWatchdogFilesystemEventSource(args.path)
            # Enrollment remains a prerequisite even when delivery is disabled.
            store.load_config()
            queue = SQLiteEventQueue.in_directory(store.directory)
            client = None
            if not args.no_flush:
                protector = WindowsDpapiProtector()
                client = authenticated_client(store, protector)
            collector = FilesystemCollector(
                queue,
                source.monitored_root,
                client=client,
                batch_size=args.batch_size,
                status=print,
            )
            print(
                "NepShield filesystem monitoring started for one protected folder "
                f"({collector.root_label}). Press Ctrl+C to stop."
            )
            try:
                collector.run(source)
            except KeyboardInterrupt:
                print("NepShield filesystem monitoring stopped.")
        else:
            protector = WindowsDpapiProtector()
            result = flush_pending_events(
                store, protector, batch_size=args.batch_size
            )
            print(
                "NepShield event flush completed: "
                f"submitted={result.submitted_count}, "
                f"acknowledged={result.acknowledged_count}, "
                f"pending={result.pending_count}."
            )
            if result.error:
                print(result.error)
                return 1
    except (
        AgentConfigurationError,
        AgentCommunicationError,
        CredentialProtectionError,
        FilesystemConfigurationError,
        WindowsFilesystemObservationError,
        WindowsVolumeObservationError,
        RuntimeAlreadyRunningError,
        ValueError,
    ) as exc:
        print(f"NepShield agent command failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
