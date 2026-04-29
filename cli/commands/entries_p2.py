"""cli/commands/entries_p2.py - cmd_list and paginated entry views."""
from __future__ import annotations
import getpass

from cli.ui import (
    print_error, print_success, print_info,
    sanitize_input, confirm_action, choose_from_list,
    display_password_strength, _default_display,
)
from cli.colors import colors
from src.config import DEFAULT_PASSWORD_LENGTH, REVEAL_DURATION_SECS
from src.secure_display import timed_reveal


def cmd_list(cli, args):
    if not cli.ensure_unlocked():
        return
    last_ts = last_id = None
    limit = 20
    page_num = 1
    try:
        while True:
            entries = cli.vault.list_entries(
                include_deleted=args.trash,
                category=args.category,
                favorite=args.favorite,
                limit=limit,
                last_timestamp=last_ts,
                last_id=last_id
            )
            if not entries:
                if page_num == 1:
                    print_info("No entries found.")
                break
            # --totp filter: keep only entries that have a totp_secret
            if getattr(args, 'totp', False):
                entries = [e for e in entries if e.get("has_totp")]
                if not entries:
                    if page_num == 1:
                        print_info("No entries with TOTP found.")
                    break
            if args.sort == "title":
                entries.sort(key=lambda x: (x.get("title") or "").lower())
            header = "Trash" if args.trash else "Vault Entries"
            if getattr(args, 'totp', False):
                header += " (TOTP only)"
            print("\n" + colors.info("--- " + header + " (Page " + str(page_num) + ") ---") + "\n")
            for entry in entries:
                cat = entry.get("category", "General")
                print(" " + _default_display(entry) + " " + colors.dim("[" + cat + "]"))
            if len(entries) < limit:
                total_shown = (page_num - 1) * limit + len(entries)
                noun = "entry" if total_shown == 1 else "entries"
                print(colors.dim(f"--- {total_shown} {noun} total ---"))
                break
            last_entry = entries[-1]
            last_ts = last_entry["modified_at"]
            last_id = last_entry["id"]
            if input("\nShow next page? [Y/n] ").strip().lower() == "n":
                break
            page_num += 1
    except Exception as e:
        print_error("Failed to list entries: " + str(e))