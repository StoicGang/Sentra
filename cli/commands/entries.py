"""
cli/commands/entries.py - CRUD entry commands.
OWASP A03: all user inputs pass through sanitize_input before use.
"""
from __future__ import annotations
import getpass

from src.vault_controller import VaultError
from src.secure_display import timed_reveal, REVEAL_DURATION_SECS
from cli.ui import (
    print_error, print_success, print_warning, print_info,
    sanitize_input, confirm_action, choose_from_list,
    display_password_strength, _default_display
)
from cli.colors import colors

DEFAULT_PASSWORD_LENGTH = 16


def cmd_add(cli, args):
    if not cli.ensure_unlocked():
        return
    print("" + colors.info("--- Add New Entry ---"))
    title = args.title or sanitize_input(input("Title (required): "))
    if not title:
        print_error("Title is required.")
        return
    url = args.url
    username = args.username
    if not args.batch:
        if not url:
            url = sanitize_input(input("URL (optional): ")) or None
        if not username:
            username = sanitize_input(input("Username (optional): ")) or None
    password = args.password
    if not password:
        if args.gen:
            length = args.length or DEFAULT_PASSWORD_LENGTH
            password, warn = cli.passgen.generate_password(length=length)
            if warn:
                print_warning(warn)
            if args.show:
                print("Generated: " + colors.warning(password))
            else:
                print_success("Generated secure password (" + str(length) + " chars)")
        elif not args.batch:
            while True:
                choice = input("Password: [E]nter / [G]enerate / [B]lank? ").strip().lower()
                if choice == "g":
                    length = args.length or DEFAULT_PASSWORD_LENGTH
                    password, _ = cli.passgen.generate_password(length=length)
                    if args.show:
                        print("Generated: " + colors.warning(password))
                    else:
                        print_success("Generated secure password (" + str(length) + " chars)")
                    break
                elif choice == "e":
                    password = getpass.getpass("Password: ")
                    if password:
                        try:
                            score, _, _ = cli.passgen.calculate_strength(
                                password,
                                user_inputs=[x for x in [title, username] if x]
                            )
                        except Exception:
                            print_warning("Could not calculate password strength.")
                            score = 50
                        if score < 30 and not confirm_action("Very weak password. Use anyway?", dangerous=True):
                            password = None
                            continue
                    break
                elif choice == "b":
                    password = None
                    break
                else:
                    print_error("Invalid choice. Enter 'e', 'g', or 'b'.")
    notes = args.notes
    if not notes and not args.batch:
        notes = sanitize_input(input("Notes (optional): ")) or None
    totp_secret = None
    if not args.batch:
        totp_input = sanitize_input(input("TOTP Secret (optional, press Enter to skip): ")) or None
        if totp_input:
            # Handle otpauth:// URIs
            if totp_input.startswith("otpauth://"):
                extracted = cli.totp.parse_totp_uri(totp_input)
                if not extracted:
                    print_error("Invalid otpauth:// URI — could not extract secret.")
                    return
                totp_input = extracted
            # Normalize: strip spaces, uppercase
            totp_input = totp_input.replace(" ", "").upper()
            # Validate it's usable Base32 before storing
            try:
                cli.totp.generate_totp(totp_input)
                totp_secret = totp_input
            except ValueError:
                print_error("Invalid TOTP secret. Must be a Base32 string (A-Z, 2-7) or an otpauth:// URI.")
                return
    try:
        entry_id = cli.vault.add_password(
            title=title, url=url, username=username,
            password=password, notes=notes,
            tags=args.tags, category=args.category or "General",
            favorite=args.favorite,
            totp_secret=totp_secret
        )
        print_success("Entry '" + title + "' added successfully!")
        print_info("ID: " + entry_id[:16] + "...")
    except VaultError as e:
        print_error("Failed to add entry: " + str(e))
    except Exception as e:
        print_error("Unexpected error: " + str(e))

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


def cmd_get(cli, args):
    if not cli.ensure_unlocked():
        return
    query = args.title or sanitize_input(input("Search (title/URL/tag): "))
    if not query:
        return
    try:
        matches = cli.vault.search_entries(query)
        entry_id = choose_from_list(matches)
        if not entry_id:
            return
        entry = cli.vault.get_password(entry_id)
        if not entry:
            print_error("Entry not found or corrupted.")
            return
        fav = " ⭐" if entry.get("favorite") else ""
        print("\n" + "=" * 60)
        print(" " + colors.info("Title: ") + str(entry.get("title")) + fav)
        print(" " + colors.info("Category:") + " " + str(entry.get("category")))
        if entry.get("url"):
            print("  " + colors.info("URL:     ") + str(entry.get("url")))
        if entry.get("username"):
            print("  " + colors.info("Username:") + " " + str(entry.get("username")))
        pw = entry.get("password")
        if pw:
            if not args.show:
                print("  " + colors.dim("Password:") + " " + ("●" * 12) + "  [" + colors.info("Copy (c)") + "]")
            else:
                print("  " + colors.dim("Password:") + " [Revealing below...]")
            cli._last_password_secret = pw
            cli._last_password_title = entry.get("title")
            cli._last_totp_secret = entry.get("totp_secret") or None
            if getattr(args, "copy", False):
                from cli.commands.tools import cmd_copy
                cmd_copy(cli, None)
            strength = entry.get("password_strength", 0)
            if strength < 30:
                label = colors.error("Weak")
            elif strength < 70:
                label = colors.warning("Fair")
            else:
                label = colors.success("Strong")
            print("  " + colors.info("Strength:") + " " + label + " (" + str(strength) + "/100)")
        if entry.get("tags"):
            print("  " + colors.info("Tags:") + " " + str(entry.get("tags")))
        print("-" * 60)
        if entry.get("notes"):
            print("  " + colors.info("Notes:"))
            for line in entry.get("notes", "").split("\n"):
                print("    " + line)
        if pw and args.show:
            print("-" * 60)
            timed_reveal(pw, label="Password", duration=REVEAL_DURATION_SECS)
        print("=" * 60)
        print(colors.dim("Created:  " + str(entry.get("created_at"))))
        print(colors.dim("Modified: " + str(entry.get("modified_at"))))
    except Exception as e:
        print_error("Failed to retrieve entry: " + str(e))


def cmd_update(cli, args):
    if not cli.ensure_unlocked():
        return
    query = args.title or sanitize_input(input("Search entry to update: "))
    if not query:
        return
    try:
        matches = cli.vault.search_entries(query)
        entry_id = choose_from_list(matches)
        if not entry_id:
            return
        current = cli.vault.get_password(entry_id)
        if not current:
            print_error("Entry not found.")
            return
        print("\n" + colors.info("Updating: ") + str(current.get("title")))
        print(colors.dim("Leave blank to keep current value\n"))
        updates = {}
        if args.username:
            updates["username"] = args.username
        elif not args.batch:
            new_user = sanitize_input(input("Username [" + str(current.get("username", "")) + "]: "))
            if new_user:
                updates["username"] = new_user
        if args.password:
            updates["password"] = args.password
            display_password_strength(args.password, cli.passgen)
        elif not args.batch:
            choice = input("Update password? [y/N/g (generate)]: ").strip().lower()
            if choice == "g":
                length = args.length or DEFAULT_PASSWORD_LENGTH
                pw, _ = cli.passgen.generate_password(length=length)
                updates["password"] = pw
                print_success("Generated new password (" + str(length) + " chars)")
            elif choice == "y":
                pw = getpass.getpass("New password: ")
                if pw:
                    score, _ = display_password_strength(pw, cli.passgen)
                    if score >= 30 or confirm_action("Weak password. Continue?"):
                        updates["password"] = pw
        if args.url:
            updates["url"] = args.url
        elif not args.batch:
            current_url = current.get("url") or ""
            if current_url:
                print(colors.dim(f"  Current URL: {current_url}"))
            new_url = sanitize_input(input("URL [keep current]: "))
            if new_url:
                updates["url"] = new_url
        if args.notes:
            updates["notes"] = args.notes
        elif not args.batch:
            current_notes = current.get("notes") or ""
            if current_notes:
                print(colors.dim("  Current Notes:"))
                for line in current_notes.split("\n"):
                    print(colors.dim(f"    {line}"))
            if confirm_action("Update notes?"):
                updates["notes"] = sanitize_input(input("Notes: "))
        if not updates:
            print_info("No changes made.")
            return
        cli.vault.update_entry(entry_id, **updates)
        print_success("Entry '" + str(current.get("title")) + "' updated successfully!")
    except Exception as e:
        print_error("Failed to update entry: " + str(e))


def cmd_delete(cli, args):
    if not cli.ensure_unlocked():
        return
    query = args.title or sanitize_input(input("Search entry to delete: "))
    if not query:
        return
    try:
        matches = cli.vault.search_entries(query, include_deleted=args.permanent)
        entry_id = choose_from_list(matches)
        if not entry_id:
            return
        entry = cli.vault.get_password(entry_id, include_deleted=args.permanent)
        if not entry:
            print_error("Entry not found.")
            return
        if args.permanent:
            print("\n" + colors.error("PERMANENT DELETE WARNING"))
            print("  Title: " + str(entry.get("title")))
            print("  This action is " + colors.error("IRREVERSIBLE") + ".")
            prompt_text = "Permanently delete this entry?"
        else:
            print("\n" + colors.warning("DELETING: ") + str(entry.get("title")))
            print("  " + colors.info("Entry will be moved to trash (recoverable)"))
            prompt_text = "Delete this entry?"
        if not confirm_action(prompt_text, dangerous=True):
            print_info("Deletion cancelled.")
            return
        if args.permanent:
            cli.vault.hard_delete_entry(entry_id)
            print_success("Entry '" + str(entry.get("title")) + "' permanently deleted.")
        else:
            cli.vault.delete_entry(entry_id)
            print_success("Entry '" + str(entry.get("title")) + "' moved to trash.")
            print_info("Use 'restore' to recover if needed.")
    except Exception as e:
        print_error("Failed to delete entry: " + str(e))


def cmd_restore(cli, _=None):
    if not cli.ensure_unlocked():
        return
    try:
        trash = [e for e in cli.vault.list_entries(include_deleted=True) if e.get("is_deleted")]
        if not trash:
            print_info("Trash is empty.")
            return
        print("\n" + colors.info("--- Trash Recovery ---") + "\n")
        entry_id = choose_from_list(trash)
        if not entry_id:
            return
        if cli.vault.restore_entry(entry_id):
            print_success("Entry recovered successfully!")
        else:
            print_error("Failed to recover entry.")
    except Exception as e:
        print_error("Recovery failed: " + str(e))


def cmd_search(cli, args):
    if not cli.ensure_unlocked():
        return
    query = args.query or sanitize_input(input("Search query: "))
    if not query:
        return
    try:
        matches = cli.vault.search_entries(query, include_deleted=args.trash)
        if not matches:
            print_info("No results for '" + query + "'")
            return
        print("\n" + colors.success("Found") + " " + str(len(matches)) + " matches for '" + query + "':\n")
        for entry in matches:
            print("  " + _default_display(entry))
            cat = entry.get("category", "General")
            mod = entry.get("modified_at", "")[:10]
            print("  " + colors.dim("Category: " + cat + " | Modified: " + mod))
            print()
    except Exception as e:
        print_error("Search failed: " + str(e))
