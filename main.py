"""
main.py - Sentra entry point.
Thin dispatcher: parse args → route to command handler or drop into shell.
This replaces the monolithic sentra_cli.py.
"""
from __future__ import annotations
import sys

from cli.parser import build_parser
from cli.auth import cmd_login, cmd_lock
from cli.shell import run_shell
from cli.ui import print_error
from cli.colors import colors

def main():
    from src.config import DB_PATH
    print(f"DEBUG: Using database at: {DB_PATH}")
    parser = build_parser()
    
    # Custom sync action parsing
    # Parse all arguments using the defined parser. Subcommands for 'sync' are handled via argparse.
    args = parser.parse_args()

    # Early exit for no-arg shell
    if args.command is None and len(sys.argv) == 1:
        cli = _build_cli()
        run_shell(cli, parser)
        return

    if args.no_color:
        colors.disable()

    # Dispatch logic
    if args.command == "daemon":
        from cli.daemon.network_daemon import NetworkDaemon
        daemon = NetworkDaemon(host=args.host, port=args.port)
        try:
            daemon.run()
        except KeyboardInterrupt:
            daemon.stop()
        return

    if args.command == "sync":
        from cli.commands.sync_commands import cmd_sync
        cmd_sync(args)
        return

    if not args.command:
        parser.print_help()
        return

    cli = _build_cli()
    _dispatch(cli, args, parser)


def _build_cli():
    """Instantiate the CLI controller (vault + auth + helpers)."""
    from cli.auth import SentraCLI
    return SentraCLI()


def _dispatch(cli, args, parser):
    """Route parsed args to the correct command handler."""
    from cli.commands.entries import (
        cmd_add, cmd_get, cmd_update, cmd_delete, cmd_restore, cmd_search,
    )
    from cli.commands.entries_p2 import cmd_list
    from cli.commands.generator import cmd_genpass
    from cli.commands.totp import cmd_totp
    from cli.commands.backup import cmd_backup, cmd_import, cmd_export
    from cli.commands.vaults import cmd_vaults, cmd_switch
    from cli.commands.recovery import cmd_recovery, cmd_forget_masterpass
    from cli.commands.security import cmd_status, cmd_audit, cmd_security, cmd_self_destruct
    from cli.commands.tools import cmd_copy
    from cli.commands.config import cmd_config

    dispatch = {
        "login":             lambda: cmd_login(cli, args),
        "lock":              lambda: cmd_lock(cli, args),
        "add":               lambda: cmd_add(cli, args),
        "list":              lambda: cmd_list(cli, args),
        "get":               lambda: cmd_get(cli, args),
        "search":            lambda: cmd_search(cli, args),
        "update":            lambda: cmd_update(cli, args),
        "delete":            lambda: cmd_delete(cli, args),
        "restore":           lambda: cmd_restore(cli, args),
        "genpass":           lambda: cmd_genpass(cli, args),
        "totp":              lambda: cmd_totp(cli, args),
        "backup":            lambda: cmd_backup(cli, args),
        "import":            lambda: cmd_import(cli, args),
        "export":            lambda: cmd_export(cli, args),
        "vaults":            lambda: cmd_vaults(cli, args),
        "switch":            lambda: cmd_switch(cli, args),
        "recovery":          lambda: cmd_recovery(cli, args),
        "forget-masterpass": lambda: cmd_forget_masterpass(cli, args),
        "status":            lambda: cmd_status(cli, args),
        "audit":             lambda: cmd_audit(cli, args),
        "security":          lambda: cmd_security(cli, args),
        "self-destruct":     lambda: cmd_self_destruct(cli, args),
        "copy":              lambda: cmd_copy(cli, args),
        "config":            lambda: cmd_config(cli, args),
    }

    handler = dispatch.get(args.command)
    if handler:
        try:
            handler()
        except KeyboardInterrupt:
            print()
        except Exception as e:
            print_error("Command failed: " + str(e))
            sys.exit(1)
    else:
        print_error("Unknown command: " + args.command)
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()