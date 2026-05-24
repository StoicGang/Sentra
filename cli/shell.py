"""
cli/shell.py - interactive REPL loop for Sentra.
Provides a persistent shell session so users don't re-authenticate per command.
"""
from __future__ import annotations
import shlex

from cli.ui import print_error, print_info
from cli.colors import colors


SHELL_BANNER = """
  ███████╗███████╗███╗   ██╗████████╗██████╗  █████╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██╔══██║
  ███████║███████╗██║ ╚████║   ██║   ██║  ██║██║  ██║
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
"""

SHELL_HELP = """
Available commands:
  login          Unlock vault
  lock           Lock vault
  add            Add new entry
  list           List entries
  get            Get entry details
  search         Search entries
  update         Update entry
  delete         Delete entry
  restore        Recover from trash
  genpass        Generate password
  totp           Generate TOTP code
  backup         Create encrypted backup
  import         Import from backup
  export         Export to CSV
  vaults         Manage vaults
  switch         Switch vault
  recovery       Manage recovery settings
  forget-masterpass  Recover forgotten master password
  status         Show vault status
  audit          View audit log
  security       Security health check
  self-destruct  Configure self-destruct
  copy           Copy last viewed password
  config         Application configuration
  sync           P2P Synchronization
  help           Show this help
  exit / quit    Exit Sentra
"""


def run_shell(cli, parser):
    print(colors.success(SHELL_BANNER))
    print(colors.info("  Sentra Interactive Shell — type 'help' for commands\n"))

    while True:
        try:
            vault_label = _vault_label(cli)
            prompt = colors.dim("sentra") + colors.info(vault_label) + colors.dim(" > ")
            try:
                line = input(prompt).strip()
            except EOFError:
                print()
                break

            if not line:
                continue

            if line.lower() in ("exit", "quit", "q"):
                print(colors.dim("Goodbye."))
                break

            if line.lower() in ("help", "?"):
                print(SHELL_HELP)
                continue

            try:
                tokens = shlex.split(line)
            except ValueError as e:
                print_error("Parse error: " + str(e))
                continue

            try:
                args = parser.parse_args(tokens)
            except SystemExit:
                    print(colors.dim("  Unknown command. Type 'help' for available commands."))
                    continue

            if not args.command:
                print_info("Type 'help' for available commands.")
                continue

            _dispatch(cli, args)

        except KeyboardInterrupt:
            print()
            print(colors.dim("Use 'exit' to quit."))
            continue
        except Exception as e:
            print_error("Unexpected error: " + str(e))


def _vault_label(cli) -> str:
    try:
        name = getattr(cli.vault, "active_vault_name", None) or "vault"
        locked = not getattr(cli, "_unlocked", False)
        icon = "🔒" if locked else "🔓"
        return " [" + str(name) + " " + icon + "]"
    except Exception:
        return ""


def _dispatch(cli, args):
    from cli.commands.entries import cmd_add, cmd_get, cmd_update, cmd_delete, cmd_restore, cmd_search, cmd_list
    
    from cli.commands.generator import cmd_genpass
    from cli.commands.totp import cmd_totp
    from cli.commands.backup import cmd_backup, cmd_import, cmd_export
    from cli.commands.vaults import cmd_vaults
    from cli.commands.recovery import cmd_recovery, cmd_forget_masterpass
    from cli.commands.security import cmd_status, cmd_audit, cmd_security, cmd_self_destruct
    from cli.commands.tools import cmd_copy
    from cli.commands.config import cmd_config
    from cli.auth import cmd_login, cmd_lock
    from cli.commands.sync_commands import cmd_sync

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
        "switch":            lambda: cmd_vaults(cli, args),
        "recovery":          lambda: cmd_recovery(cli, args),
        "forget-masterpass": lambda: cmd_forget_masterpass(cli, args),
        "status":            lambda: cmd_status(cli, args),
        "audit":             lambda: cmd_audit(cli, args),
        "security":          lambda: cmd_security(cli, args),
        "self-destruct":     lambda: cmd_self_destruct(cli, args),
        "copy":              lambda: cmd_copy(cli, args),
        "config":            lambda: cmd_config(cli, args),
        "sync":              lambda: cmd_sync(args),
    }

    handler = dispatch.get(args.command)
    if handler:
        handler()
    else:
        print_error("Unknown command: " + args.command)
