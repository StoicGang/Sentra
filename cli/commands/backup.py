"""
cli/commands/backup.py - backup, import, export commands.
OWASP A02: export warns plaintext. OWASP A03: CSV injection neutralized.
"""
from __future__ import annotations
import os
from datetime import datetime

from cli.ui import (
    print_error, print_success, print_warning, print_info,
    sanitize_input, confirm_action, show_progress
)
from cli.colors import colors


def cmd_backup(cli, args):
    if not cli.ensure_unlocked():
        return
    filename = args.output or "sentra_backup_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".enc"
    if os.path.exists(filename) and not confirm_action("File exists. Overwrite?"):
        return
    try:
        print_info("Creating backup: " + filename)
        cli.vault.create_backup_manager().create_backup(filename)
        try:
            os.chmod(filename, 0o600)
        except Exception:
            pass
        print_success("Backup created: " + filename)
        print_info("Store this file securely.")
    except Exception as e:
        print_error("Backup failed: " + str(e))


def cmd_import(cli, args):
    if not cli.ensure_unlocked():
        return
    filename = args.input or sanitize_input(input("Backup file path: "))
    is_csv = filename.lower().endswith(".csv")
    warn = ("Importing from CSV. Duplicates may occur." if is_csv
            else "DANGER: Binary restore will OVERWRITE matching entries.")
    print("\n" + colors.warning(warn))
    if not confirm_action("Proceed with import?", dangerous=True):
        print_info("Import cancelled.")
        return
    try:
        if is_csv:
            success, failed = cli.vault.import_csv(filename)
            print_success("Import complete: " + str(success) + " imported, " + str(failed) + " failed.")
        else:
            cli.vault.create_backup_manager().restore_backup(filename)
            print_success("Vault restored from backup.")
    except Exception as e:
        print_error("Import failed: " + str(e))


def _sanitize_csv_field(text: str) -> str:
    if not text:
        return ""
    if text.lstrip().startswith(("=", "+", "-", "@", "|", "%")):
        return "'" + text
    return text.replace("\t", " ").replace("\r", " ").replace("\n", " ")


def cmd_export(cli, args):
    if not cli.ensure_unlocked():
        return
    filename = args.output or "sentra_export_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".csv"
    print("\n" + colors.error("SECURITY WARNING: Exports ALL passwords in PLAIN TEXT."))
    if not confirm_action("Export to unencrypted CSV?", dangerous=True):
        return
    try:
        import csv
        entries = cli.vault.list_entries()
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "title", "url", "username", "password", "notes", "category", "tags"
            ])
            writer.writeheader()
            total = len(entries)
            for i, meta in enumerate(entries, 1):
                show_progress(i, total, "Exporting")
                full = cli.vault.get_password(meta["id"])
                if full:
                    writer.writerow({k: _sanitize_csv_field(full.get(k, ""))
                                     for k in ["title","url","username","password","notes","category","tags"]})
        print_success("\nExported to: " + filename)
        print_warning("DELETE this file after use!")
    except Exception as e:
        print_error("Export failed: " + str(e))
