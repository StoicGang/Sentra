#!/usr/bin/env python3
"""
sentra_cli.py (Final Architecture)
Modular CLI for Sentra Vault.
Strictly follows the Controller pattern: No direct DB access, no raw key handling.
"""

from __future__ import annotations
import argparse
import getpass
import sys
import shlex
import textwrap
from typing import Optional, List, Dict

# Project modules
from src.vault_controller import VaultController, VaultError, VaultLockedError, VaultAlreadyUnlockedError
from src.password_generator import PasswordGenerator
from src.totp_generator import TOTPGenerator

PROG = "sentra"

# ----------------- UI Helpers -----------------

def print_error(msg: str):
    print(f"\033[91m[ERROR]\033[0m {msg}")

def print_success(msg: str):
    print(f"\033[92m[SUCCESS]\033[0m {msg}")

def choose_from_list(items: List[Dict]) -> Optional[str]:
    """
    Helper to select an entry from a list of dicts (id, title, username).
    Returns the entry ID or None.
    """
    if not items:
        print("No matches found.")
        return None
    
    if len(items) == 1:
        return items[0]["id"]

    print(f"\nFound {len(items)} matches:")
    for i, item in enumerate(items, start=1):
        user = item.get('username') or 'No User'
        # Handle cases where keys might be missing if metadata is minimal
        title = item.get('title', 'Untitled')
        eid = item.get('id', '???')
        print(f" {i}) {title} [{user}] (ID: {eid[:8]}...)")
    
    while True:
        sel = input("\nSelect number (or 'q' to quit): ").strip()
        if sel.lower() in ("q", "quit", "exit"):
            return None
        try:
            idx = int(sel)
            if 1 <= idx <= len(items):
                return items[idx - 1]["id"]
        except ValueError:
            pass
        print("Invalid selection.")

# ----------------- CLI Class -----------------

class SentraCLI:
    def __init__(self):
        # Initialize VaultController. It handles DB connection and SecureMemory.
        try:
            self.vault = VaultController()
        except Exception as e:
            print_error(f"Could not initialize Vault Controller: {e}")
            sys.exit(1)
            
        self.passgen = PasswordGenerator()
        self.totp = TOTPGenerator()
        
        # Local state to track session in interactive mode
        self.session_active = False

    # ---------- Authentication Flow ----------

    def ensure_unlocked(self) -> bool:
        """
        Ensures the vault is unlocked.
        - Checks session state
        - Prompts for password if locked
        - Handles both Login and First-Run (Implicitly via Controller)
        """
        # If the controller says we are unlocked, we are good.
        if self.session_active and self.vault.is_unlocked:
            return True
        
        print("\n=== Sentra Vault Auth ===")
        print("Enter Master Password to unlock (or create new vault).")
        
        for attempt in range(3):
            pw = getpass.getpass("Master Password: ")
            if not pw: continue
            
            try:
                # unlock_vault() in Controller automatically handles:
                # 1. Loading metadata
                # 2. Creating new vault if metadata is missing
                # 3. Deriving keys and unlocking
                self.vault.unlock_vault(pw)
                self.session_active = True
                print_success("Vault unlocked.")
                return True
                
            except VaultLockedError:
                pass
            except VaultAlreadyUnlockedError:
                self.session_active = True
                return True
            except VaultError as e:
                if "Invalid password" in str(e):
                    print_error(f"Authentication failed. {e}")
                else:
                    print_error(f"Error: {e}")
            except Exception as e:
                print_error(f"System error: {e}")
                return False

        print_error("Too many failed attempts.")
        return False

    # ---------- Command Handlers ----------

    def cmd_add(self, args):
        if not self.ensure_unlocked(): return

        print("\n--- Add New Entry ---")
        title = args.title or input("Title: ").strip()
        if not title:
            print_error("Title is required.")
            return

        username = args.username or input("Username (optional): ").strip() or None
        
        # Password handling
        password = args.password
        if not password:
            if args.gen:
                password, _ = self.passgen.generate_password(length=args.length or 16)
                # UX/Security: Mask output unless --show is used
                display_pw = password if args.show else "******** (saved)"
                print(f"Generated Password: {display_pw}")
            else:
                choice = input("Password [E]nter manually, [G]enerate, or [B]lank? ").strip().lower()
                if choice == 'g':
                    password, _ = self.passgen.generate_password(length=args.length or 16)
                    # UX/Security: Mask output unless --show is used
                    display_pw = password if args.show else "******** (saved)"
                    print(f"Generated Password: {display_pw}")
                elif choice == 'e':
                    password = getpass.getpass("Password: ")
                else:
                    password = None

        try:
            # Delegate to VaultController
            eid = self.vault.add_password(
                title=title,
                url=args.url,
                username=username,
                password=password,
                notes=args.notes,
                tags=args.tags,
                category=args.category or "General"
            )
            print_success(f"Entry added! ID: {eid}")
        except Exception as e:
            print_error(str(e))

    def cmd_list(self, args):
        if not self.ensure_unlocked(): return
        
        try:
            # Delegate to VaultController
            entries = self.vault.list_entries(include_deleted=False)
            if not entries:
                print("Vault is empty.")
                return
            
            print(f"\n--- Vault Entries ({len(entries)}) ---")
            for e in entries:
                print(f"- {e['title']} (User: {e['username'] or '-'}) [ID: {e['id'][:8]}...]")
        except Exception as e:
            print_error(str(e))

    def cmd_get(self, args):
        if not self.ensure_unlocked(): return
        
        # 1. Resolve ID via Search
        entry_id = None
        if args.title:
            matches = self.vault.search_entries(args.title)
            entry_id = choose_from_list(matches)
        else:
            q = input("Search query (Title/URL/Tag): ").strip()
            matches = self.vault.search_entries(q)
            entry_id = choose_from_list(matches)

        if not entry_id:
            return

        # 2. Fetch Details via Controller
        try:
            entry = self.vault.get_password(entry_id)
            if not entry:
                print_error("Entry not found or corrupt.")
                return

            print("\n" + "="*30)
            print(f" Title:    {entry.get('title')}")
            print(f" Category: {entry.get('category')}")
            print(f" URL:      {entry.get('url')}")
            print(f" Username: {entry.get('username')}")
            pw = entry.get('password')
            if not args.show and pw:
                pw = "******** (use --show to reveal)"
            print(f" Password: {pw}")  # Decrypted by Controller
            print(f" Strength: {entry.get('password_strength')}/100")
            print(f" Tags:     {entry.get('tags')}")
            print("-" * 30)
            print(f" Notes:\n {entry.get('notes')}")
            print("="*30 + "\n")

        except Exception as e:
            print_error(str(e))

    def cmd_update(self, args):
        if not self.ensure_unlocked(): return

        # 1. Search
        q = args.title or input("Search entry to update: ").strip()
        matches = self.vault.search_entries(q)
        entry_id = choose_from_list(matches)
        if not entry_id: return

        print("\nUpdating entry (press Enter to keep current value)")
        
        def get_update(label):
            val = input(f"{label}: ").strip()
            return val if val else None

        updates = {}
        
        # 2. Collect Inputs
        if args.username: updates['username'] = args.username
        else: 
            u = get_update("New Username")
            if u: updates['username'] = u

        if args.password: 
            updates['password'] = args.password
        else:
            p_choice = input("Update Password? [y/N/g]: ").lower()
            if p_choice == 'g':
                pw, _ = self.passgen.generate_password()
                print(f"New Password: {pw}")
                updates['password'] = pw
            elif p_choice == 'y':
                updates['password'] = getpass.getpass("New Password: ")

        if args.notes: updates['notes'] = args.notes
        else:
            n = get_update("New Notes")
            if n: updates['notes'] = n

        # 3. Delegate to Controller
        if not updates:
            print("No changes detected.")
            return

        try:
            self.vault.update_entry(entry_id, **updates)
            print_success("Entry updated.")
        except Exception as e:
            print_error(str(e))

    def cmd_delete(self, args):
        if not self.ensure_unlocked(): return

        q = args.title or input("Search entry to delete: ").strip()
        matches = self.vault.search_entries(q)
        entry_id = choose_from_list(matches)
        if not entry_id: return

        confirm = input("Type 'DELETE' to confirm deletion: ")
        if confirm == "DELETE":
            try:
                # Delegate to Controller
                self.vault.delete_entry(entry_id)
                print_success("Entry deleted (moved to trash).")
            except Exception as e:
                print_error(str(e))
        else:
            print("Operation cancelled.")

    def cmd_genpass(self, args):
        # Does not require vault unlock
        length = args.length or 16
        pwd, warn = self.passgen.generate_password(length)
        if warn:
            print(f"\033[93m{warn}\033[0m")
        print(f"Password: {pwd}")

    def cmd_totp(self, args):
        # Does not require vault unlock for manual secret entry
        secret = args.secret or input("TOTP Secret (Base32): ").strip()
        if not secret: return
        try:
            code = self.totp.generate_totp(secret)
            remain = self.totp.get_time_remaining()
            print(f"Code: {code} ({remain}s remaining)")
        except Exception as e:
            print_error(f"Invalid secret: {e}")

    def cmd_lock(self, args):
        if self.vault.lock_vault():
            self.session_active = False
            print_success("Vault locked.")

    # ---------- Main Dispatch ----------

    def build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog=PROG)
        sub = parser.add_subparsers(dest="command")

        # Login
        sub.add_parser("login", help="Unlock vault")
        
        # Add
        add = sub.add_parser("add", help="Add entry")
        add.add_argument("--title", "-t")
        add.add_argument("--username", "-u")
        add.add_argument("--password", "-p")
        add.add_argument("--gen", action="store_true")
        add.add_argument("--length", type=int)
        add.add_argument("--url")
        add.add_argument("--notes")
        add.add_argument("--tags")
        add.add_argument("--category")
        add.add_argument("--show", "-s", action="store_true", help="Show generated password") 

        # List
        sub.add_parser("list", help="List all entries")

        # Get
        get = sub.add_parser("get", help="Get/Show entry details")
        get.add_argument("--title", "-t", help="Search by title")
        get.add_argument("--show", "-s", action="store_true", help="Reveal password")

        # Update
        upd = sub.add_parser("update", help="Update entry")
        upd.add_argument("--title", "-t")
        upd.add_argument("--username")
        upd.add_argument("--password")
        upd.add_argument("--notes")

        # Delete
        dele = sub.add_parser("delete", help="Delete entry")
        dele.add_argument("--title", "-t")

        # Tools
        gen = sub.add_parser("genpass", help="Generate password")
        gen.add_argument("--length", "-l", type=int)

        totp = sub.add_parser("totp", help="Generate 2FA code")
        totp.add_argument("--secret", "-s")

        sub.add_parser("lock", help="Lock vault")

        return parser

    def interactive_shell(self):
        print(textwrap.dedent("""
            \033[1mSentra Interactive Shell\033[0m
            Commands: login, add, list, get, update, delete, genpass, totp, lock, exit, help
        """))
        parser = self.build_parser()
        
        while True:
            try:
                text = input("sentra> ").strip()
                if not text: continue
                if text in ('exit', 'quit', 'q'):
                    self.cmd_lock(None)
                    break
                if text == 'help':
                    parser.print_help()
                    continue
                
                parts = shlex.split(text)
                args = parser.parse_args(parts)
                self.dispatch(args)

            except SystemExit:
                pass 
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit.")
            except Exception as e:
                print_error(f"Shell error: {e}")

    def dispatch(self, args):
        cmd = args.command
        # Handlers map
        handlers = {
            "login": lambda x: self.ensure_unlocked(),
            "add": self.cmd_add,
            "list": self.cmd_list,
            "get": self.cmd_get,
            "update": self.cmd_update,
            "delete": self.cmd_delete,
            "genpass": self.cmd_genpass,
            "totp": self.cmd_totp,
            "lock": self.cmd_lock
        }
        
        if cmd in handlers:
            handlers[cmd](args)
        else:
            # No command (just 'sentra' in interactive) - do nothing
            pass

def main():
    cli = SentraCLI()
    parser = cli.build_parser()
    
    # 1. Interactive Mode (No arguments provided)
    if len(sys.argv) == 1:
        cli.interactive_shell()
        return

    # 2. One-shot Mode (Arguments provided)
    try:
        args = parser.parse_args()
        if not args.command:
            parser.print_help()
            return
        cli.dispatch(args)
    except SystemExit:
        pass
    except Exception as e:
        print_error(f"Fatal: {e}")

if __name__ == "__main__":
    main()