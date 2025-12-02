#!/usr/bin/env python3
"""
sentra_cli.py  (root-level)
Hybrid CLI for Sentra Vault:
 - First-time setup wizard (master password, vault init)
 - Master-password unlock (Argon2 via crypto_engine)
 - Hybrid mode: one-shot commands OR interactive shell after login
 - CRUD operations via DatabaseManager (encrypted storage)
 - Password generation via PasswordGenerator
 - TOTP generation via TOTPGenerator
 - Adaptive lockout checked via AdaptiveLockout
"""

from __future__ import annotations
import argparse
import getpass
import sys
import shlex
import textwrap
import sqlite3
from typing import Optional, List, Tuple

# project modules
from src.vault_controller import VaultController, VaultError, VaultLockedError  # :contentReference[oaicite:7]{index=7}
from src.password_generator import PasswordGenerator  # :contentReference[oaicite:8]{index=8}
from src.totp_generator import TOTPGenerator  # :contentReference[oaicite:9]{index=9}
from src.adaptive_lockout import AdaptiveLockout  # :contentReference[oaicite:10]{index=10}

# Note: direct DB usage for flexible lookups (DatabaseManager provides methods too)
from src.database_manager import DatabaseManager, DatabaseError  # :contentReference[oaicite:11]{index=11}

PROG = "sentra"

# ----------------- Helpers -----------------

def confirm_prompt(prompt: str = "Confirm", hide: bool = True) -> str:
    if hide:
        return getpass.getpass(prompt + ": ")
    else:
        return input(prompt + ": ")


def choose_from_list(items: List[Tuple[str, str]]) -> Optional[str]:
    """
    items: list of (id, title). Return selected id or None
    """
    if not items:
        print("No matches.")
        return None
    if len(items) == 1:
        return items[0][0]

    print("Multiple matches — pick index:")
    for i, (eid, title) in enumerate(items, start=1):
        print(f" {i}) {title} (id: {eid})")
    while True:
        sel = input("Choice (number or q): ").strip()
        if sel.lower() in ("q", "quit", "exit"):
            return None
        try:
            idx = int(sel)
            if 1 <= idx <= len(items):
                return items[idx - 1][0]
        except ValueError:
            pass
        print("Invalid selection.")


# ----------------- CLI Class -----------------

class SentraCLI:
    def __init__(self, db_path: str = "data/vault.db"):
        self.vault = VaultController(db_path=db_path)  # uses SecureMemory, AdaptiveLockout, Crypto Engine. :contentReference[oaicite:12]{index=12}
        self.db = self.vault.db  # DatabaseManager instance. :contentReference[oaicite:13]{index=13}
        self.passgen = PasswordGenerator()  # :contentReference[oaicite:14]{index=14}
        self.totp = TOTPGenerator()  # :contentReference[oaicite:15]{index=15}
        self.adaptive = self.vault.adaptive_lockout  # :contentReference[oaicite:16]{index=16}
        self.logged_in = False

    # ---------- Setup / Login ----------

    def is_vault_initialized(self) -> bool:
        try:
            meta = self.db.load_vault_metadata()
            return meta is not None
        except Exception:
            # If DB not initialized at all, treat as not initialized
            return False

    def setup_wizard(self) -> bool:
        """
        First-time setup:
         - prompt for master password twice
         - pass to vault.unlock_vault() which creates vault metadata
        """
        print("\n=== Sentra first-time setup ===")
        while True:
            p1 = getpass.getpass("Create master password: ")
            if len(p1) < 8:
                print("Choose a password at least 8 characters long.")
                continue
            p2 = getpass.getpass("Confirm master password: ")
            if p1 != p2:
                print("Passwords do not match; try again.")
                continue
            # Optionally ask to run Argon2 benchmarking in future — skipping for now
            try:
                # unlock_vault() will detect missing metadata and create vault metadata.
                ok = self.vault.unlock_vault(p1)
                if ok:
                    print("Vault initialized and unlocked.")
                    self.logged_in = True
                    return True
            except Exception as e:
                print(f"Failed to initialize vault: {e}")
                return False

    def prompt_login(self) -> bool:
        """
        Prompt the user for master password and unlock vault.
        Uses adaptive lockout under-the-hood via VaultController.
        """
        for _ in range(3):
            pw = getpass.getpass("Master Password: ")
            try:
                ok = self.vault.unlock_vault(pw)
                if ok:
                    self.logged_in = True
                    return True
            except Exception as e:
                # If adaptive lockout blocked, show message and exit
                print(f"Unlock failed: {e}")
                return False
        print("Failed to login after attempts.")
        return False

    def ensure_unlocked(self) -> bool:
        """
        Ensures vault is unlocked; handles first-time setup if necessary.
        """
        if self.logged_in and self.vault.is_unlocked:
            return True

        # Ensure DB schema exists (initialize_database is idempotent)
        try:
            self.db.initialize_database()
        except Exception:
            # ignore if already initialized or issues handled below
            pass

        if not self.is_vault_initialized():
            # First-time flow
            return self.setup_wizard()
        else:
            return self.prompt_login()

    # ---------- DB helpers ----------

    def _vault_key_bytes(self) -> bytes:
        """Return vault_key as bytes (vault.vault_key_secure is bytearray while unlocked)"""
        if not self.vault.is_unlocked or not self.vault.vault_key_secure:
            raise VaultLockedError("Vault locked")
        return bytes(self.vault.vault_key_secure)

    def search_entries_by_title(self, pattern: str) -> List[Tuple[str, str]]:
        """
        Return list of tuples (entry_id, title) matching pattern.
        Uses SQL LIKE; pattern can be substring (we use %pattern%).
        """
        conn = self.db.connect()
        cur = conn.execute(
            "SELECT id, title FROM entries WHERE is_deleted = 0 AND title LIKE ? ORDER BY title",
            (f"%{pattern}%",),
        )
        return [(row["id"], row["title"]) for row in cur.fetchall()]

    # ---------- Command Handlers ----------

    def cmd_add(self, args):
        if not self.ensure_unlocked():
            return
        title = args.title or input("Title: ").strip()
        username = args.username or input("Username (optional): ").strip() or None

        # Password: provided OR generate OR prompt
        if args.password:
            password = args.password
        elif args.gen:
            password, warn = self.passgen.generate_password(length=args.length or 16)
            if warn:
                print(warn)
            print("Generated password:", password)
        else:
            password = getpass.getpass("Password (leave blank to generate): ")
            if not password:
                password, warn = self.passgen.generate_password(length=args.length or 16)
                if warn:
                    print(warn)
                print("Generated password:", password)

        notes = args.notes or (input("Notes (optional): ").strip() or None)
        tags = args.tags or (input("Tags (comma separated, optional): ").strip() or None)
        category = args.category or "General"

        try:
            vault_key = self._vault_key_bytes()
            eid = self.db.add_entry(
                vault_key=vault_key,
                title=title,
                url=args.url,
                username=username,
                password=password,
                notes=notes,
                tags=tags,
                category=category,
            )
            print(f"Entry added: id={eid}, title={title}")
        except Exception as e:
            print(f"Failed to add entry: {e}")

    def cmd_list(self, args):
        if not self.ensure_unlocked():
            return
        try:
            conn = self.db.connect()
            cur = conn.execute(
                "SELECT id, title, username, created_at FROM entries WHERE is_deleted = 0 ORDER BY title"
            )
            rows = cur.fetchall()
            if not rows:
                print("No entries.")
                return
            for r in rows:
                print(f"- {r['title']}  (user: {r['username'] or '-'}, id: {r['id']})")
        except Exception as e:
            print(f"Failed to list entries: {e}")

    def cmd_get(self, args):
        if not self.ensure_unlocked():
            return
        pattern = args.title or input("Title (or substring): ").strip()
        matches = self.search_entries_by_title(pattern)
        eid = choose_from_list(matches)
        if not eid:
            return
        try:
            entry = self.db.get_entry(eid, self._vault_key_bytes())
            if not entry:
                print("Entry missing or cannot decrypt.")
                return
            print("---- ENTRY ----")
            print(f"Title: {entry.get('title')}")
            print(f"URL: {entry.get('url')}")
            print(f"Username: {entry.get('username')}")
            print(f"Password: {entry.get('password')}")
            print(f"Notes: {entry.get('notes')}")
            print(f"Tags: {entry.get('tags')}")
            print(f"Category: {entry.get('category')}")
            print("----------------")
        except Exception as e:
            print(f"Failed to retrieve entry: {e}")

    def cmd_update(self, args):
        if not self.ensure_unlocked():
            return
        pattern = args.title or input("Title (or substring to find): ").strip()
        matches = self.search_entries_by_title(pattern)
        eid = choose_from_list(matches)
        if not eid:
            return
        fields = {}
        if args.username is not None:
            fields["username"] = args.username
        if args.password is not None:
            fields["password"] = args.password
        if args.notes is not None:
            fields["notes"] = args.notes
        if args.tags is not None:
            fields["tags"] = args.tags
        if args.category is not None:
            fields["category"] = args.category

        # If nothing provided, interactively ask
        if not fields:
            new_user = input("New username (leave blank to keep): ").strip()
            if new_user:
                fields["username"] = new_user
            new_pass = getpass.getpass("New password (leave blank to keep / blank->generate): ")
            if new_pass == "":
                # leave as-is
                pass
            elif new_pass is None or new_pass == "":
                pass
            else:
                fields["password"] = new_pass
            if "password" not in fields:
                gen = input("Generate password? (y/N): ").strip().lower()
                if gen == "y":
                    pwd, warn = self.passgen.generate_password(length=args.length or 16)
                    if warn:
                        print(warn)
                    print("Generated password:", pwd)
                    fields["password"] = pwd
            new_notes = input("New notes (leave blank to keep): ").strip()
            if new_notes:
                fields["notes"] = new_notes
            new_tags = input("New tags (leave blank to keep): ").strip()
            if new_tags:
                fields["tags"] = new_tags
            new_cat = input("New category (leave blank to keep): ").strip()
            if new_cat:
                fields["category"] = new_cat

        try:
            updated = self.db.update_entry(
                entry_id=eid,
                vault_key=self._vault_key_bytes(),
                title=None,
                url=None,
                username=fields.get("username"),
                password=fields.get("password"),
                notes=fields.get("notes"),
                tags=fields.get("tags"),
                category=fields.get("category"),
            )
            if updated:
                print("Entry updated.")
            else:
                print("Entry not found or not updated.")
        except Exception as e:
            print(f"Update failed: {e}")

    def cmd_delete(self, args):
        if not self.ensure_unlocked():
            return
        pattern = args.title or input("Title (or substring): ").strip()
        matches = self.search_entries_by_title(pattern)
        eid = choose_from_list(matches)
        if not eid:
            return
        confirm = input("Delete entry permanently? (type YES to confirm): ")
        if confirm != "YES":
            print("Aborted.")
            return
        try:
            # Try DatabaseManager.delete_entry if present, else soft-delete
            try:
                deleted = self.db.delete_entry(eid, self._vault_key_bytes())
                if deleted:
                    print("Entry deleted.")
                    return
            except AttributeError:
                # fallback to SQL soft delete
                conn = self.db.connect()
                conn.execute("UPDATE entries SET is_deleted = 1 WHERE id = ?", (eid,))
                conn.commit()
                print("Entry soft-deleted.")
        except Exception as e:
            print(f"Delete failed: {e}")

    def cmd_genpass(self, args):
        length = args.length or 16
        try:
            pwd, warn = self.passgen.generate_password(length=length)
            if warn:
                print(warn)
            print("Password:", pwd)
        except Exception as e:
            print(f"Failed to generate password: {e}")

    def cmd_totp(self, args):
        # TOTP generator expects a secret (Base32). We don't fetch secret from vault automatically.
        secret = args.secret or input("TOTP secret (base32): ").strip()
        if not secret:
            print("No secret provided.")
            return
        try:
            code = self.totp.generate_totp(secret)
            remain = self.totp.get_time_remaining()
            print(f"TOTP: {code}  (valid for {remain}s)")
        except Exception as e:
            print(f"TOTP error: {e}")

    def cmd_lock(self, args):
        try:
            ok = self.vault.lock_vault()
            if ok:
                self.logged_in = False
                print("Vault locked.")
            else:
                print("Vault lock returned False (check logs).")
        except Exception as e:
            print(f"Failed to lock vault: {e}")

    # ---------- Interactive processing ----------

    def build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog=PROG, add_help=True)
        sub = parser.add_subparsers(dest="command")

        sub.add_parser("login", help="Login (prompt master password)")

        add = sub.add_parser("add", help="Add entry")
        add.add_argument("--title", "-t")
        add.add_argument("--username", "-u")
        add.add_argument("--password", "-p")
        add.add_argument("--gen", action="store_true", help="Generate password")
        add.add_argument("--length", type=int, help="Password length when generating")
        add.add_argument("--notes")
        add.add_argument("--tags")
        add.add_argument("--category")
        add.add_argument("--url")

        sub.add_parser("list", help="List entries")

        get = sub.add_parser("get", help="Get entry")
        get.add_argument("--title", "-t")

        upd = sub.add_parser("update", help="Update entry")
        upd.add_argument("--title", "-t")
        upd.add_argument("--username")
        upd.add_argument("--password")
        upd.add_argument("--notes")
        upd.add_argument("--tags")
        upd.add_argument("--category")
        upd.add_argument("--length", type=int)

        delete = sub.add_parser("delete", help="Delete entry")
        delete.add_argument("--title", "-t")

        gen = sub.add_parser("genpass", help="Generate password")
        gen.add_argument("--length", "-l", type=int, help="Length")

        totp = sub.add_parser("totp", help="Generate TOTP (needs secret)")
        totp.add_argument("--secret", "-s")

        sub.add_parser("lock", help="Lock vault and exit")

        return parser

    def dispatch(self, args):
        cmd = args.command
        if cmd == "login":
            if self.ensure_unlocked():
                print("Unlocked.")
            return
        handlers = {
            "add": self.cmd_add,
            "list": self.cmd_list,
            "get": self.cmd_get,
            "update": self.cmd_update,
            "delete": self.cmd_delete,
            "genpass": self.cmd_genpass,
            "totp": self.cmd_totp,
            "lock": self.cmd_lock,
        }
        if cmd in handlers:
            return handlers[cmd](args)
        else:
            print("Unknown command or empty input.")

    def interactive_shell(self):
        print(textwrap.dedent(
            """
            Sentra Interactive Shell
            Type 'help' for a quick list.
            Commands: login, add, get, update, delete, list, genpass, totp, lock, exit
            """
        ).strip())
        parser = self.build_parser()

        while True:
            try:
                line = input("> ").strip()
            except (KeyboardInterrupt, EOFError):
                print()
                break
            if not line:
                continue
            if line in ("exit", "quit"):
                break
            if line == "help":
                parser.print_help()
                continue
            try:
                tokens = shlex.split(line)
                args = parser.parse_args(tokens)
                # For interactive commands require login unless it's login
                if args.command != "login" and not (self.logged_in and self.vault.is_unlocked):
                    print("Not logged in. Use 'login' or run CLI to initialize.")
                    continue
                self.dispatch(args)
            except SystemExit:
                # argparse may call sys.exit inside parse_args for bad input; ignore
                continue

# ----------------- Entry point -----------------

def main():
    cli = SentraCLI()
    parser = cli.build_parser()

    # If no args -> interactive shell but ensure setup/login first
    if len(sys.argv) == 1:
        # perform ensure_unlocked to do first-time setup automatically,
        # but if user prefers to skip unlocking until inside shell, comment this.
        if not cli.ensure_unlocked():
            # allow entering shell even if not unlocked (user can 'login' inside)
            print("Entering interactive shell (vault locked). Use 'login' to unlock.")
        cli.interactive_shell()
        return

    # One-shot mode
    args = parser.parse_args()
    # If login requested, run login and exit
    if args.command == "login":
        if cli.ensure_unlocked():
            print("Unlocked.")
        return

    # For other one-shot commands: ensure unlocked before running
    if not cli.ensure_unlocked():
        return

    cli.dispatch(args)


if __name__ == "__main__":
    main()
