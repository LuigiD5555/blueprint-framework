"""Command line interface for BPFW Core MVP."""

import argparse
import getpass
import json
import subprocess
from pathlib import Path

from bpfw.authority.reshard import ReshardMode, synchronize_authority_shards
from bpfw.catalog.paths import CANONICAL_BLUEPRINT_FILE
from bpfw.catalog.verify import run_verify
from bpfw.catalog.writer import run_init
from bpfw.protection.authority import (
    MISSING_BLUEPRINT_STATUS,
    ProtectionResult,
    get_authority_protection_status,
    lock_authority,
    unlock_authority,
)
from bpfw.protection.runtime_lease import runtime_blueprint_write_lease
from bpfw.reports.status_report import run_status
from bpfw.reports.verify_report import VERIFY_FINDING_FILTERS, render_verify_report
from bpfw.shared.text import normalize_text_command
from bpfw.watch import WatchDependencyError, run_watch


MVP_COMMANDS = (
    "init",
    "verify",
    "status",
    "lock",
    "unlock",
    "watch",
    "reshard",
)


MAIN_HELP_TEXT = """Blueprint Framework Core

Usage:
  bpfw <command> [options]

Commands:
  init        Create or update bpfw/blueprint.yaml and shard authority files.
  verify      Check blueprint authority against the real code.
  status      Show project authority, drift, and lock status.
  lock        Lock protected authority files.
  unlock      Unlock protected authority files.
  watch       Watch project changes and print drift feedback.
  reshard     Rebuild and synchronize block shards.

Global options:
  -h, --help              Show this help message.
  --project-root PATH     Run BPFW from a specific project root.
  --json                  Print machine-readable output when supported.

Examples:
  bpfw init
  bpfw verify
  bpfw verify undeclared
  bpfw verify --all
  bpfw status
  bpfw watch
  bpfw reshard
  bpfw lock
  bpfw unlock

Verify filters:
  bpfw verify [all|undeclared|missing|duplicate|secret|invalid]
  bpfw verify --all
  bpfw verify --max N
"""


class BpfwArgumentParser(argparse.ArgumentParser):
    """Argument parser that renders the curated BPFW Core help."""

    def format_help(self) -> str:
        """Return the curated top-level BPFW help text."""

        return f"{MAIN_HELP_TEXT}\n"

    def format_usage(self) -> str:
        """Return concise command usage for parser errors."""

        return "Usage:\n  bpfw <command> [options]\n"


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser for BPFW Core commands.

    Returns:
        Configured argument parser for the public command surface.
    """

    parser = BpfwArgumentParser(prog="bpfw")
    parser.add_argument("command", choices=MVP_COMMANDS)
    parser.add_argument("subcommand", nargs="?")
    parser.add_argument("--project-root", default=".", metavar="PATH")
    parser.add_argument("--accept-scan", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--force-new", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--allow-unprotected",
        action="store_true",
        help="Allow init to complete without OS authority protection.",
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--once", action="store_true", dest="watch_once", help=argparse.SUPPRESS)
    parser.add_argument("--debounce-ms", type=int, default=800, dest="watch_debounce_ms", help=argparse.SUPPRESS)
    parser.add_argument("-a", "--all", action="store_true", dest="verify_all", help=argparse.SUPPRESS)
    parser.add_argument("--max", type=int, default=8, dest="verify_max_items", help=argparse.SUPPRESS)
    return parser


def resolve_cli_command(command: str, subcommand: str | None) -> str:
    """Map CLI tokens into public BPFW Core command names.

    Args:
        command: Raw command token from argv.
        subcommand: Optional raw subcommand token from argv.

    Returns:
        Normalized command name.

    Raises:
        ValueError: If the command or subcommand is not supported.
    """

    normalized_command = normalize_text_command(command)
    normalized_subcommand = normalize_text_command(subcommand) if subcommand is not None else None

    if normalized_command == "lock":
        if normalized_subcommand is not None:
            raise ValueError("lock does not accept subcommands")
        return "lock"
    if normalized_command == "unlock":
        if normalized_subcommand is not None and normalized_subcommand != "blueprint":
            raise ValueError("unlock only supports blueprint resource in MVP. Usage: bpfw unlock [blueprint]")
        return "unlock"
    if normalized_command == "init":
        if normalized_subcommand is not None:
            raise ValueError("init does not accept subcommands")
        return "init"
    if normalized_command == "verify":
        if normalized_subcommand is not None and normalized_subcommand not in VERIFY_FINDING_FILTERS:
            valid_filters = ", ".join(sorted(VERIFY_FINDING_FILTERS))
            raise ValueError(
                f"unknown verify filter: {normalized_subcommand}. "
                f"Supported filters: {valid_filters}"
            )
        return "verify"
    if normalized_command == "watch":
        if normalized_subcommand is not None:
            raise ValueError("watch does not accept subcommands")
        return "watch"
    if normalized_command == "status":
        if normalized_subcommand is not None:
            raise ValueError("status does not accept subcommands")
        return "status"
    if normalized_command == "reshard":
        if normalized_subcommand is not None:
            raise ValueError("reshard does not accept subcommands")
        return "reshard"

    raise ValueError(f"Unknown command: {normalized_command}")


def _format_protected_resources(result: ProtectionResult) -> str:
    """Format protected resources for CLI output.

    Args:
        result: Protection operation result.

    Returns:
        Multi-line protected resource list.
    """

    lines = []
    for resource in result.protected_resources:
        lines.append(f"  {resource.path}")
    for resource in result.skipped_resources:
        lines.append(f"  {resource.path} (skipped: missing)")
    return "\n".join(lines)



def _print_human(payload: dict) -> None:
    """Print a normalized engine payload as human-readable output.

    Args:
        payload: JSON-friendly command payload.
    """

    if payload["command_name"] == "verify":
        if payload.get("status") in {"ok", "info", "warning"}:
            print("OK")
            return
        if payload.get("message"):
            print(payload["message"])
            return
        print(payload.get("status", "").upper())
        return

    if payload.get("message"):
        print(payload["message"])
        return

    print(payload.get("status", "").upper())


def _attempt_permission_fix(project_root: Path, error: PermissionError) -> bool:
    """Try to fix authority file ownership or permissions via sudo.

    Args:
        project_root: Root directory containing BPFW authority files.
        error: Permission error that triggered the fix attempt.

    Returns:
        True when every sudo command succeeds, otherwise False.
    """

    target_path = Path(error.filename) if error.filename else (project_root / "bpfw" / "blueprint.yaml")
    blocks_path = project_root / "bpfw" / "blocks"
    current_user = getpass.getuser()

    print("Reshard requires elevated permission access.")
    print("Authorizing sudo will continue automatically after permissions are updated.")

    commands = [
        ["sudo", "-v"],
        ["sudo", "chown", f"{current_user}:{current_user}", str(target_path)],
        ["sudo", "chmod", "u+rw", str(target_path)],
    ]

    if blocks_path.exists():
        commands.append(["sudo", "chown", "-R", f"{current_user}:{current_user}", str(blocks_path)])
        commands.append(["sudo", "chmod", "-R", "u+rw", str(blocks_path)])

    for command in commands:
        completed = subprocess.run(command, cwd=project_root, check=False)
        if completed.returncode != 0:
            return False
    return True


def _run_init(parsed_arguments: argparse.Namespace) -> int:
    """Execute the init command from parsed arguments."""

    project_root = Path(parsed_arguments.project_root).resolve()
    try:
        with runtime_blueprint_write_lease(project_root=project_root, tool_name="init"):
            _success, message, exit_code = run_init(
                project_root=project_root,
                allow_unprotected=parsed_arguments.allow_unprotected,
            )
    except (ImportError, OSError, PermissionError, ValueError) as error:
        print(f"Init error: {error}")
        return 1
    print(message)
    return exit_code


def _run_verify(parsed_arguments: argparse.Namespace) -> int:
    """Execute the verify command from parsed arguments."""

    project_root = Path(parsed_arguments.project_root).resolve()
    selected_filter = normalize_text_command(parsed_arguments.subcommand) if parsed_arguments.subcommand else None
    if parsed_arguments.verify_all:
        selected_filter = "all"
    selected_codes = None if selected_filter in {None, "all"} else sorted(VERIFY_FINDING_FILTERS[selected_filter])
    max_items = 0 if parsed_arguments.verify_all else parsed_arguments.verify_max_items
    report, exit_code = run_verify(project_root=project_root)
    output = render_verify_report(
        report,
        finding_codes=selected_codes,
        max_items_per_group=max_items,
    )
    print(output)
    return exit_code


def _run_watch(parsed_arguments: argparse.Namespace) -> int:
    """Execute the watch command from parsed arguments."""

    project_root = Path(parsed_arguments.project_root).resolve()
    try:
        return run_watch(
            project_root=project_root,
            debounce_ms=parsed_arguments.watch_debounce_ms,
            once=parsed_arguments.watch_once,
        )
    except WatchDependencyError as error:
        print(str(error))
        return 1


def _run_status(parsed_arguments: argparse.Namespace) -> int:
    """Execute the status command from parsed arguments."""

    project_root = Path(parsed_arguments.project_root).resolve()
    output, exit_code = run_status(project_root=project_root)
    print(output)
    return exit_code


def _run_reshard(parsed_arguments: argparse.Namespace) -> int:
    """Execute one-shot shard synchronization from parsed arguments."""

    project_root = Path(parsed_arguments.project_root).resolve()
    permission_fix_attempted = False
    while True:
        try:
            with runtime_blueprint_write_lease(project_root=project_root, tool_name="reshard"):
                sync_result = synchronize_authority_shards(
                    project_root=project_root,
                    allow_large_migration=True,
                )

                if parsed_arguments.as_json:
                    result_payload = {
                        "mode": sync_result.mode,
                        "moved_blocks": [
                            {
                                "block_id": move.block_id,
                                "from_shard": str(move.from_shard),
                                "to_shard": str(move.to_shard),
                                "reason": move.reason,
                            }
                            for move in sync_result.moved_blocks
                        ],
                        "migrated_root_blocks": sync_result.migrated_root_blocks,
                        "skipped_root_blocks": sync_result.skipped_root_blocks,
                        "created_shards": [str(path) for path in sync_result.created_shards],
                        "removed_shards": [str(path) for path in sync_result.removed_shards],
                        "updated_includes": sync_result.updated_includes,
                        "skipped_reason": sync_result.skipped_reason,
                    }
                    print(json.dumps(result_payload, indent=2))
                    return 0

                if sync_result.skipped_reason:
                    print(f"Reshard skipped: {sync_result.skipped_reason}")
                    return 1

                if sync_result.mode == ReshardMode.NO_DRIFT and not sync_result.has_changes():
                    print("No shard drift detected. Blueprint structure is already synchronized.")
                    return 0

                if sync_result.mode == ReshardMode.SMALL:
                    return 0

                print("Reshard synchronization complete.")
                print(f"Moved {len(sync_result.moved_blocks)} blocks.")
                if sync_result.migrated_root_blocks or sync_result.skipped_root_blocks:
                    print(
                        "Migrated root-level blocks into shard storage: "
                        f"{sync_result.migrated_root_blocks} moved, "
                        f"{sync_result.skipped_root_blocks} skipped."
                    )
                if sync_result.updated_includes:
                    print("Updated shard includes.")
            return 0
        except PermissionError as error:
            if permission_fix_attempted:
                print(f"Reshard error: {error}")
                return 1
            permission_fix_attempted = True
            if not _attempt_permission_fix(project_root=project_root, error=error):
                print(f"Reshard error: {error}")
                return 1
            print("Permission update completed. Retrying reshard...")
        except (ImportError, OSError, ValueError) as error:
            print(f"Reshard error: {error}")
            return 1


def _run_lock(parsed_arguments: argparse.Namespace) -> int:
    """Execute the lock command from parsed arguments."""

    project_root = Path(parsed_arguments.project_root).resolve()
    lock_result = lock_authority(project_root=project_root)
    if lock_result.status == MISSING_BLUEPRINT_STATUS:
        print(
            "BPFW blueprint does not exist:\n"
            f"  {CANONICAL_BLUEPRINT_FILE}\n\n"
            "Run bpfw init first."
        )
        return 1
    if lock_result.status == "unsupported":
        print(
            "BPFW could not lock authority resources.\n\n"
            "Protected:\n"
            f"{_format_protected_resources(result=lock_result)}\n\n"
            "Status:\n"
            "  UNSUPPORTED\n\n"
            "Try running from a terminal where file permissions can be changed."
        )
        return 1
    if lock_result.status == "degraded":
        print(
            "Blueprint partially locked.\n\n"
            "Protected:\n"
            f"{_format_protected_resources(result=lock_result)}\n\n"
            "Status:\n"
            "  DEGRADED\n\n"
            "Reason:\n"
            "  Strong OS protection is unavailable, but read-only protection was applied."
        )
        return 0
    if lock_result.status != "locked":
        print(
            "BPFW authority protection is incomplete.\n\n"
            "Protected:\n"
            f"{_format_protected_resources(result=lock_result)}\n\n"
            "Status:\n"
            f"  {lock_result.status.upper()}"
        )
        return 1
    print(
        "Blueprint locked.\n\n"
        "Protected:\n"
        f"{_format_protected_resources(result=lock_result)}\n\n"
        "Status:\n"
        "  LOCKED"
    )
    return 0


def _run_unlock(parsed_arguments: argparse.Namespace) -> int:
    """Execute the unlock command from parsed arguments."""

    project_root = Path(parsed_arguments.project_root).resolve()
    current_lock_state = get_authority_protection_status(project_root=project_root).status
    if current_lock_state == MISSING_BLUEPRINT_STATUS:
        print(
            "BPFW blueprint does not exist:\n"
            f"  {CANONICAL_BLUEPRINT_FILE}\n\n"
            "Run bpfw init first."
        )
        return 1
    unlock_result = unlock_authority(project_root=project_root)
    if unlock_result.status == "unsupported":
        print(
            "BPFW could not unlock authority resources.\n\n"
            "Protected:\n"
            f"{_format_protected_resources(result=unlock_result)}\n\n"
            "Status:\n"
            "  UNSUPPORTED\n\n"
            "Try running from a terminal where file permissions can be changed."
        )
        return 1
    print(
        "Blueprint unlocked.\n\n"
        "Protected:\n"
        f"{_format_protected_resources(result=unlock_result)}\n\n"
        "Status:\n"
        f"  {unlock_result.status.upper()}\n\n"
        "Reminder:\n"
        "  Run bpfw verify before locking again."
    )
    return 0


def main() -> int:
    """Entry point for the BPFW Core CLI.

    Returns:
        Process exit code.
    """

    parser = build_parser()
    parsed_arguments = parser.parse_args()

    try:
        normalized_command = resolve_cli_command(
            command=parsed_arguments.command,
            subcommand=parsed_arguments.subcommand,
        )
    except ValueError as error:
        parser.error(str(error))

    command_handlers = {
        "init": _run_init,
        "verify": _run_verify,
        "watch": _run_watch,
        "status": _run_status,
        "reshard": _run_reshard,
        "lock": _run_lock,
        "unlock": _run_unlock,
    }
    return command_handlers[normalized_command](parsed_arguments)


if __name__ == "__main__":
    raise SystemExit(main())
