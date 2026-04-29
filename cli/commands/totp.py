"""
cli/commands/totp.py - TOTP code generation command.
Wraps src/totp_generator.py — no vault unlock required for --secret flag.
"""
from __future__ import annotations
import time

from cli.ui import print_error, print_info
from cli.colors import colors


def cmd_totp(cli, args):
    secret = getattr(args, "secret", None)
    watch = getattr(args, "watch", False)

    if not secret:
        if not cli.ensure_unlocked():
            return
        try:
            query = input("Search entry for TOTP: ").strip()
            if not query:
                return
            matches = cli.vault.search_entries(query)
            if not matches:
                print_error("No entries found.")
                return
            entry = None
            for m in matches:
                full = cli.vault.get_password(m["id"])
                if full and full.get("totp_secret"):
                    entry = full
                    break
            if not entry:
                print_error("No TOTP secret found for that entry.")
                return
            secret = entry["totp_secret"]
            label = entry.get("title", "Entry")
        except Exception as e:
            print_error("Failed to retrieve TOTP secret: " + str(e))
            return
    else:
        label = "Manual"

    try:
        if watch:
            _totp_watch(cli, secret, label)
        else:
            _totp_once(cli, secret, label)
    except KeyboardInterrupt:
        print()
    except Exception as e:
        print_error("TOTP generation failed: " + str(e))


def _totp_once(cli, secret: str, label: str):
    code, remaining = cli.totp.generate(secret)
    print("\n" + colors.info("TOTP — " + label))
    print("  Code:    " + colors.success(code))
    print("  Expires: " + str(remaining) + "s")
    print()


def _totp_watch(cli, secret: str, label: str):
    print(colors.info("Watching TOTP for " + label + " — Ctrl+C to stop\n"))
    last_code = None
    try:
        while True:
            code, remaining = cli.totp.generate(secret)
            print("\r  " + colors.success(code) + "  (" + str(remaining) + "s remaining)   ", end="", flush=True)
            last_code = code
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n" + colors.dim("Stopped."))
