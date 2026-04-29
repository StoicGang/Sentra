"""
cli/commands/vaults.py - vault info command.
Multi-vault management is not supported in this version.
"""
from __future__ import annotations
import os

from cli.ui import print_error, print_success, print_info
from cli.colors import colors


def cmd_vaults(cli, args):
    if not cli.ensure_unlocked():
        return
    subcmd = getattr(args, "subcmd", None) or "list"
    if subcmd in ("list", None):
        _show_vault_info(cli)
    else:
        print_info("Multi-vault management is not available in this version.")
        print_info("Current vault info:")
        _show_vault_info(cli)


def cmd_switch(cli, args):
    print_info("Vault switching is not available in this version.")
    print_info("Current vault:")
    _show_vault_info(cli)


def _show_vault_info(cli):
    try:
        db_path = getattr(cli.vault.db, "db_path", "unknown")
        abs_path = os.path.abspath(db_path) if db_path != "unknown" else "unknown"
        exists = os.path.exists(abs_path) if abs_path != "unknown" else False
        size_kb = round(os.path.getsize(abs_path) / 1024, 1) if exists else 0

        print("\n" + colors.info("--- Active Vault ---"))
        print("  Path   : " + colors.dim(abs_path))
        print("  Status : " + (colors.success("exists") if exists else colors.error("missing")))
        if exists:
            print("  Size   : " + colors.dim(str(size_kb) + " KB"))
        try:
            entries = cli.vault.list_entries()
            print("  Entries: " + str(len(entries)))
        except Exception:
            pass
        print()
    except Exception as e:
        print_error("Could not read vault info: " + str(e))
