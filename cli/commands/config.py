"""
cli/commands/config.py - application configuration command.
"""
from __future__ import annotations
from src.secure_display import CLIPBOARD_CLEAR_SECS
from cli.ui import print_error, print_success, print_info
from cli.colors import colors


def cmd_config(cli, args):
    if not cli.ensure_unlocked():
        return
    if args.clipboard_timeout is not None:
        if args.clipboard_timeout < 0:
            print_error("Timeout cannot be negative.")
            return
        cli.vault.set_config("clipboard_timeout", args.clipboard_timeout)
        print_success("Clipboard timeout set to " + str(args.clipboard_timeout) + "s.")
        return
    timeout_raw = cli.vault.get_config("clipboard_timeout")
    timeout = int(timeout_raw) if timeout_raw else CLIPBOARD_CLEAR_SECS
    print("\n" + colors.info("--- Sentra Configuration ---"))
    print("Clipboard Timeout: " + str(timeout) + "s")
