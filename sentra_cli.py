#!/usr/bin/env python3
"""
sentra_cli.py - Improved Version
Addresses QA issues: UX, error handling, accessibility, security
"""

from __future__ import annotations
import argparse
import getpass
import sys
import shlex
from datetime import datetime
import os
from typing import Optional, List, Dict
from enum import Enum

# Project modules
from src.vault_controller import (
    VaultController, VaultError, VaultLockedError, VaultAlreadyUnlockedError
)
from src.password_generator import PasswordGenerator
from src.totp_generator import TOTPGenerator

# ============ Configuration Constants ============
PROG = "sentra"
MAX_LOGIN_ATTEMPTS = 3
MIN_PASSWORD_LENGTH = 12
MAX_INPUT_LENGTH = 1000
DEFAULT_PASSWORD_LENGTH = 16

# ============ ANSI Color Control ============
class ColorMode(Enum):
    AUTO = "auto"
    ALWAYS = "always"
    NEVER = "never"

class Colors:
    """Centralized color management with accessibility support"""
    
    def __init__(self, mode: ColorMode = ColorMode.AUTO):
        self._enabled = self._should_enable_colors(mode)
    
    def _should_enable_colors(self, mode: ColorMode) -> bool:
        if mode == ColorMode.NEVER:
            return False
        if mode == ColorMode.ALWAYS:
            return True
        # AUTO: detect terminal capability
        return sys.stdout.isatty() and os.getenv("TERM") != "dumb"
    
    def _wrap(self, text: str, code: str) -> str:
        if not self._enabled:
            return text
        return f"\033[{code}m{text}\033[0m"
    
    def error(self, text: str) -> str:
        return self._wrap(text, "91")  # Bright red
    
    def success(self, text: str) -> str:
        return self._wrap(text, "92")  # Bright green
    
    def warning(self, text: str) -> str:
        return self._wrap(text, "93")  # Bright yellow
    
    def info(self, text: str) -> str:
        return self._wrap(text, "94")  # Bright blue
    
    def dim(self, text: str) -> str:
        return self._wrap(text, "2")   # Dim

# Global color instance (configured by main)
colors = Colors()

# ============ UI Helpers ============

def print_error(msg: str, prefix: str = "ERROR"):
    """Print error message with consistent formatting"""
    print(f"[{colors.error(prefix)}] {msg}", file=sys.stderr)

def print_success(msg: str, prefix: str = "SUCCESS"):
    """Print success message"""
    print(f"[{colors.success(prefix)}] {msg}")

def print_warning(msg: str, prefix: str = "WARNING"):
    """Print warning message"""
    print(f"[{colors.warning(prefix)}] {msg}")

def print_info(msg: str):
    """Print informational message"""
    print(colors.info(msg))

def sanitize_input(text: str, max_length: int = MAX_INPUT_LENGTH) -> str:
    """Sanitize user input: strip, limit length, remove control chars"""
    text = text.strip()[:max_length]
    # Remove control characters except newline/tab
    return ''.join(c for c in text if c.isprintable() or c in '\n\t')

def confirm_action(prompt: str, dangerous: bool = False) -> bool:
    """
    Get user confirmation for actions.
    
    Args:
        prompt: Question to ask
        dangerous: If True, require explicit 'yes' instead of 'y'
    """
    if dangerous:
        response = input(f"{prompt} Type 'yes' to confirm: ").strip().lower()
        return response == "yes"
    else:
        response = input(f"{prompt} [y/N]: ").strip().lower()
        return response in ('y', 'yes')

def choose_from_list(
    items: List[Dict],
    id_key: str = "id",
    display_fn = None,
    allow_cancel: bool = True
) -> Optional[str]:
    """
    Interactive list selection with improved UX.
    
    Args:
        items: List of items to choose from
        id_key: Key to extract ID from items
        display_fn: Function to format each item (default: show title/username)
        allow_cancel: Allow user to cancel selection
    
    Returns:
        Selected item ID or None
    """
    if not items:
        print_info("No matches found.")
        return None
    
    # Auto-select if only one match, but show what was selected
    if len(items) == 1:
        item = items[0]
        display = display_fn(item) if display_fn else _default_display(item)
        print_info(f"Found: {display}")
        if not confirm_action("Use this entry?"):
            return None
        return item.get(id_key)

    # Multiple matches - show list
    print(f"\n{colors.info('Found')} {len(items)} matches:\n")
    
    for i, item in enumerate(items, start=1):
        display = display_fn(item) if display_fn else _default_display(item)
        print(f"  {colors.dim(str(i)+')')} {display}")
    
    # Selection loop
    while True:
        prompt = "\nSelect number"
        if allow_cancel:
            prompt += " (or 'c' to cancel)"
        prompt += ": "
        
        sel = input(prompt).strip().lower()
        
        if allow_cancel and sel in ('c', 'cancel', 'q', 'quit'):
            return None
        
        try:
            idx = int(sel)
            if 1 <= idx <= len(items):
                return items[idx - 1].get(id_key)
            else:
                print_error(f"Please enter a number between 1 and {len(items)}")
        except ValueError:
            print_error("Invalid input. Enter a number.")

def _default_display(item: Dict) -> str:
    """Default display format for list items"""
    title = item.get('title', 'Untitled')
    username = item.get('username', '')
    user_part = f" ({username})" if username else ""
    
    # Show strength indicator if available
    strength = item.get('password_strength')
    if strength is not None:
        if strength < 30:
            indicator = colors.error("●")
        elif strength < 70:
            indicator = colors.warning("●")
        else:
            indicator = colors.success("●")
        return f"{indicator} {title}{user_part}"
    
    return f"{title}{user_part}"

def display_password_strength(password: str, passgen: PasswordGenerator) -> tuple[int, str]:
    """
    Display password strength with visual feedback.
    Returns (score, label) tuple.
    """
    score, label, diagnostics = passgen.calculate_strength(password)
    
    # Visual strength bar
    bars = "█" * (score // 10)
    empty = "░" * (10 - score // 10)
    
    if score < 30:
        color_fn = colors.error
    elif score < 70:
        color_fn = colors.warning
    else:
        color_fn = colors.success
    
    print(f"\nPassword Strength: {color_fn(label)} ({score}/100)")
    print(f"[{color_fn(bars)}{empty}]")
    
    # Show issues if weak
    if score < 70:
        issues = []
        if diagnostics.get('dictionary_matches'):
            issues.append("Contains common words")
        if diagnostics.get('repeat_deductions', 0) > 5:
            issues.append("Contains repeated characters or sequences")
        if diagnostics.get('length', 0) < MIN_PASSWORD_LENGTH:
            issues.append(f"Too short (minimum {MIN_PASSWORD_LENGTH} characters)")
        
        if issues:
            print(colors.warning("Issues: ") + ", ".join(issues))
    
    return score, label

def show_progress(current: int, total: int, label: str = "Progress"):
    """
    Display progress bar (for long operations).
    Overwrites same line for cleaner output.
    """
    if total == 0:
        return
    
    percent = int((current / total) * 100)
    bar_length = 30
    filled = int((current / total) * bar_length)
    bar = "█" * filled + "░" * (bar_length - filled)
    
    # Use \r to overwrite line
    print(f"\r{label}: [{bar}] {percent}% ({current}/{total})", end="", flush=True)
    
    if current == total:
        print()  # New line when complete

# ============ Main CLI Class ============

class SentraCLI:
    def __init__(self, color_mode: ColorMode = ColorMode.AUTO):
        global colors
        colors = Colors(color_mode)
        
        try:
            self.vault = VaultController()
        except Exception as e:
            print_error(f"Failed to initialize vault: {e}")
            sys.exit(1)
        
        self.passgen = PasswordGenerator()
        self.totp = TOTPGenerator()
        self.session_active = False
    
    # ======== Authentication ========
    
    def ensure_unlocked(self) -> bool:
        """
        Ensures vault is unlocked with improved first-run detection.
        """
        if self.session_active and self.vault.is_unlocked:
            return True
        
        # Check if this is first run via Controller API
        if not self.vault.vault_exists():
            return self._first_time_setup()
        else:
            return self._unlock_existing_vault()
    
    def _first_time_setup(self) -> bool:
        """Handle first-time vault creation with proper UX"""
        print("\n" + "="*50)
        print(colors.info("🔐 WELCOME TO SENTRA - FIRST TIME SETUP"))
        print("="*50)
        print("\nYou're creating a new vault. Choose a strong master password.")
        print(f"Requirements: At least {MIN_PASSWORD_LENGTH} characters")
        print(colors.warning("⚠️  This password CANNOT be recovered if lost!"))
        print("="*50 + "\n")
        
        for attempt in range(MAX_LOGIN_ATTEMPTS):
            pw1 = getpass.getpass("Master Password: ")
            
            if len(pw1) < MIN_PASSWORD_LENGTH:
                print_error(f"Password too short. Minimum {MIN_PASSWORD_LENGTH} characters.")
                continue
            
            # Show strength before confirmation
            score, label = display_password_strength(pw1, self.passgen)
            
            if score < 50:
                if not confirm_action("\nPassword is weak. Continue anyway?"):
                    continue
            
            pw2 = getpass.getpass("Confirm Password: ")
            
            if pw1 != pw2:
                print_error("Passwords don't match. Try again.")
                continue
            
            # Attempt unlock (will create vault)
            try:
                self.vault.unlock_vault(pw1)
                self.session_active = True
                print_success("✓ Vault created and unlocked!")
                print_info("Remember: Keep your master password safe!")
                return True
            except Exception as e:
                print_error(f"Setup failed: {e}")
                return False
        
        print_error("Too many failed attempts.")
        return False
    
    def _unlock_existing_vault(self) -> bool:
        """Unlock existing vault with adaptive lockout-friendly retry loop"""
        print("\n" + "="*50)
        print(colors.info("🔓 UNLOCK VAULT"))
        print("="*50 + "\n")

        attempt = 1
        while True:
            try:
                pw = getpass.getpass("Master Password: ")
            except (KeyboardInterrupt, EOFError):
                print()  # newline after ^C/^D
                return False

            if not pw:
                # Empty input — prompt again without counting as an attempt
                continue

            try:
                self.vault.unlock_vault(pw)
                self.session_active = True
                print_success("✓ Vault unlocked")
                return True

            except VaultLockedError as e:
                # Adaptive lockout: inform user, allow retry after delay expires
                print_error(str(e))
                attempt += 1
                continue

            except VaultError as e:
                # Authentication failed or other vault problems
                if "Invalid password" in str(e):
                    # Give a short hint but don't force exit — adaptive lockout will throttle
                    print_error("Invalid password. Try again (wait if you see a lockout message).")
                else:
                    print_error(str(e))
                    # If it's a non-auth VaultError, break to avoid a tight loop
                    return False

            except Exception as e:
                print_error(f"System error: {e}")
                return False

            attempt += 1

    
    # ======== Command Handlers ========
    
    def cmd_add(self, args):
        """Add new entry with improved validation and UX"""
        if not self.ensure_unlocked():
            return
        
        print("\n" + colors.info("--- Add New Entry ---"))
        
        # Title (required)
        title = args.title
        if not title:
            title = sanitize_input(input("Title (required): "))
        if not title:
            print_error("Title is required.")
            return
        
        # URL (optional)
        url = args.url
        if not url and not args.batch:
            url = sanitize_input(input("URL (optional): ")) or None
        
        # Username (optional)
        username = args.username
        if not username and not args.batch:
            username = sanitize_input(input("Username (optional): ")) or None
        
        # Password handling with strength validation
        password = args.password
        if not password:
            if args.gen:
                length = args.length or DEFAULT_PASSWORD_LENGTH
                password, warn = self.passgen.generate_password(length=length)
                if warn:
                    print_warning(warn)
                if not args.show:
                    print_success(f"Generated secure password ({length} chars)")
                else:
                    print(f"Generated Password: {colors.warning(password)}")
            elif not args.batch:
                choice = input("\nPassword: [E]nter / [G]enerate / [B]lank? ").strip().lower()
                
                if choice == 'g':
                    length = args.length or DEFAULT_PASSWORD_LENGTH
                    password, _ = self.passgen.generate_password(length=length)
                    
                    if not args.show:
                        print_success(f"Generated secure password ({length} chars)")
                    else:
                        print(f"Generated: {colors.warning(password)}")
                
                elif choice == 'e':
                    password = getpass.getpass("Password: ")
                    if password:
                        context = []
                        if title: context.append(title)
                        if username: context.append(username)
                        score, label, _ = self.passgen.calculate_strength(password, user_inputs=context)
                        if score < 30:
                            if not confirm_action("Very weak password. Use anyway?", dangerous=True):
                                return
                else:
                    password = None
        
        # Notes (optional)
        notes = args.notes
        if not notes and not args.batch:
            notes = sanitize_input(input("Notes (optional): ")) or None
        
        # Save entry
        try:
            entry_id = self.vault.add_password(
                title=title,
                url=url,
                username=username,
                password=password,
                notes=notes,
                tags=args.tags,
                category=args.category or "General",
                favorite=args.favorite
            )
            print_success(f"Entry '{title}' added successfully!")
            print_info(f"ID: {entry_id[:16]}...")
        
        except VaultError as e:
            print_error(f"Failed to add entry: {e}")
        except Exception as e:
            print_error(f"Unexpected error: {e}")
    
    def cmd_list(self, args):
        """List entries with sorting and filtering"""
        offset = 0
        limit = 20
        if not self.ensure_unlocked():
            return
        
        try:
            while True:
                # FIX: Use Controller API inside a loop for pagination
                entries = self.vault.list_entries(
                    include_deleted=args.trash, 
                    limit=limit, 
                    offset=offset
                )
                
                # Store the raw count from DB to determine if we are at the end
                fetched_count = len(entries)
                
                if not entries:
                    if offset == 0:
                        print_info("No entries found.")
                    break
                
                # Apply filters (Client-side)
                if args.category:
                    entries = [e for e in entries if e.get('category') == args.category]
                if args.favorite:
                    entries = [e for e in entries if e.get('favorite')]
                
                # Sorting
                if args.sort == 'title':
                    entries.sort(key=lambda x: x.get('title', '').lower())
                elif args.sort == 'modified':
                    entries.sort(key=lambda x: x.get('modified_at', ''), reverse=True)
                
                # Display
                header = "Trash" if args.trash else "Vault Entries"
                page_info = f" (Page {offset // limit + 1})"
                print(f"\n{colors.info(f'--- {header}{page_info} ---')}\n")
                
                for entry in entries:
                    display = _default_display(entry)
                    cat = entry.get('category', 'General')
                    print(f"  {display} {colors.dim(f'[{cat}]')}")

                # If we fetched fewer than limit, we are at the end of the DB
                if fetched_count < limit:
                    break
                    
                # Ask for next page
                user_input = input("\nShow next page? [Y/n] ").strip().lower()
                if user_input == 'n':
                    break
                
                offset += limit
        
        except Exception as e:
            print_error(f"Failed to list entries: {e}")
    
    def cmd_get(self, args):
        """Get entry details with safety checks"""
        if not self.ensure_unlocked():
            return
        
        # Search for entry
        if args.title:
            query = args.title
        else:
            query = sanitize_input(input("Search (title/URL/tag): "))
        
        if not query:
            return
        
        try:
            matches = self.vault.search_entries(query)
            entry_id = choose_from_list(matches)
            
            if not entry_id:
                return
            
            # Fetch full entry
            entry = self.vault.get_password(entry_id)
            if not entry:
                print_error("Entry not found or corrupted.")
                return
            
            # Display with formatting
            print("\n" + "="*60)
            print(f"  {colors.info('Title:')}    {entry.get('title')}")
            print(f"  {colors.info('Category:')} {entry.get('category')}")
            
            if entry.get('url'):
                print(f"  {colors.info('URL:')}      {entry.get('url')}")
            
            if entry.get('username'):
                print(f"  {colors.info('Username:')} {entry.get('username')}")
            
            # Password handling
            pw = entry.get('password')
            if pw:
                if args.show:
                    print(f"  {colors.warning('Password:')} {pw}")
                else:
                    masked = "●" * 12
                    print(f"  {colors.dim('Password:')} {masked} {colors.dim('(use --show to reveal)')}")
                
                # Show strength
                strength = entry.get('password_strength', 0)
                if strength < 30:
                    label = colors.error("Weak")
                elif strength < 70:
                    label = colors.warning("Fair")
                else:
                    label = colors.success("Strong")
                print(f"  {colors.info('Strength:')} {label} ({strength}/100)")
            
            if entry.get('tags'):
                print(f"  {colors.info('Tags:')}     {entry.get('tags')}")
            
            print("-" * 60)
            
            if entry.get('notes'):
                print(f"  {colors.info('Notes:')}")
                for line in entry.get('notes', '').split('\n'):
                    print(f"    {line}")
            
            print("=" * 60 + "\n")
            
            # Show metadata
            print(colors.dim(f"Created: {entry.get('created_at')}"))
            print(colors.dim(f"Modified: {entry.get('modified_at')}"))
        
        except Exception as e:
            print_error(f"Failed to retrieve entry: {e}")
    
    def cmd_update(self, args):
        """Update entry with improved UX"""
        if not self.ensure_unlocked():
            return
        
        # Find entry
        query = args.title or sanitize_input(input("Search entry to update: "))
        if not query:
            return
        
        try:
            matches = self.vault.search_entries(query)
            entry_id = choose_from_list(matches)
            
            if not entry_id:
                return
            
            # Get current entry
            current = self.vault.get_password(entry_id)
            if not current:
                print_error("Entry not found.")
                return
            
            print(f"\n{colors.info('Updating:')} {current.get('title')}")
            print(colors.dim("Leave blank to keep current value\n"))
            
            updates = {}
            
            # Username
            if args.username:
                updates['username'] = args.username
            elif not args.batch:
                current_user = current.get('username', '')
                new_user = sanitize_input(input(f"Username [{current_user}]: "))
                if new_user:
                    updates['username'] = new_user
            
            # Password
            if args.password:
                updates['password'] = args.password
                display_password_strength(args.password, self.passgen)
            elif not args.batch:
                choice = input("Update password? [y/N/g (generate)]: ").strip().lower()
                
                if choice == 'g':
                    length = args.length or DEFAULT_PASSWORD_LENGTH
                    pw, _ = self.passgen.generate_password(length=length)
                    updates['password'] = pw
                    print_success(f"Generated new password ({length} chars)")
                
                elif choice == 'y':
                    pw = getpass.getpass("New password: ")
                    if pw:
                        score, _ = display_password_strength(pw, self.passgen)
                        if score < 30 and not confirm_action("Weak password. Continue?"):
                            pw = None
                        if pw:
                            updates['password'] = pw
            
            # URL
            if args.url:
                updates['url'] = args.url
            elif not args.batch:
                current_url = current.get('url', '')
                new_url = sanitize_input(input(f"URL [{current_url}]: "))
                if new_url:
                    updates['url'] = new_url
            
            # Notes
            if args.notes:
                updates['notes'] = args.notes
            elif not args.batch:
                if confirm_action("Update notes?"):
                    updates['notes'] = sanitize_input(input("Notes: "))
            
            # Apply updates
            if not updates:
                print_info("No changes made.")
                return
            
            self.vault.update_entry(entry_id, **updates)
            print_success(f"Entry '{current.get('title')}' updated successfully!")
        
        except Exception as e:
            print_error(f"Failed to update entry: {e}")
    
    def cmd_delete(self, args):
        """Delete entry with safety confirmation"""
        if not self.ensure_unlocked():
            return
        
        # Find entry
        query = args.title or sanitize_input(input("Search entry to delete: "))
        if not query:
            return
        
        try:
            matches = self.vault.search_entries(query)
            entry_id = choose_from_list(matches)
            
            if not entry_id:
                return
            
            # Get entry details for confirmation
            entry = self.vault.get_password(entry_id)
            if not entry:
                print_error("Entry not found.")
                return
            
            # Show what will be deleted
            print(f"\n{colors.warning('⚠️  DELETING:')}")
            print(f"  Title: {entry.get('title')}")
            print(f"  Username: {entry.get('username', 'N/A')}")
            print(f"\n{colors.info('ℹ️  Entry will be moved to trash (recoverable)')}\n")
            
            # Confirmation
            if not confirm_action("Delete this entry?", dangerous=True):
                print_info("Deletion cancelled.")
                return
            
            self.vault.delete_entry(entry_id)
            print_success(f"Entry '{entry.get('title')}' moved to trash.")
            print_info("Use 'sentra recover' to recover if needed.")
        
        except Exception as e:
            print_error(f"Failed to delete entry: {e}")
    
    def cmd_recover(self, args):
        """Recover (undelete) an entry from trash."""
        if not self.ensure_unlocked():
            return
        
        try:
            # List trash items
            trash_entries = self.vault.list_entries(include_deleted=True)
            trash_entries = [e for e in trash_entries if e.get('is_deleted')]
            
            if not trash_entries:
                print_info("Trash is empty.")
                return
            
            print(f"\n{colors.info('--- Trash Recovery ---')}\n")
            
            # Choose entry to recover
            entry_id = choose_from_list(trash_entries)
            
            if not entry_id:
                return
            
            # Execute Recovery
            if self.vault.restore_entry(entry_id):
                print_success("Entry recovered successfully!")
            else:
                print_error("Failed to recover entry.")
        
        except Exception as e:
            print_error(f"Recovery failed: {e}")
    
    def cmd_search(self, args):
        """Search with improved result display"""
        if not self.ensure_unlocked():
            return
        
        query = args.query or sanitize_input(input("Search query: "))
        if not query:
            return
        
        try:
            matches = self.vault.search_entries(query, include_deleted=args.trash)
            
            if not matches:
                print_info(f"No results found for '{query}'")
                return
            
            print(f"\n{colors.success('Found')} {len(matches)} matches for '{query}':\n")
            
            for entry in matches:
                display = _default_display(entry)
                category = entry.get('category', 'General')
                modified = entry.get('modified_at', '')[:10]  # Just date
                
                print(f"  {display}")
                print(f"    {colors.dim(f'Category: {category} | Modified: {modified}')}")
                print()
        
        except Exception as e:
            print_error(f"Search failed: {e}")
    
    def cmd_genpass(self, args):
        """Generate password with improved display"""
        length = args.length or DEFAULT_PASSWORD_LENGTH
        
        if length < 8:
            print_error("Password length must be at least 8 characters.")
            return
        
        try:
            password, warn = self.passgen.generate_password(length=length)
            
            if warn:
                print_warning(warn)
            
            # Show strength
            score, label = display_password_strength(password, self.passgen)
            
            print(f"\n{colors.success('Generated Password:')}")
            print(f"  {password}\n")
            
            # Offer to copy to clipboard (if available)
            if args.copy:
                try:
                    import pyperclip
                    pyperclip.copy(password)
                    print_success("Password copied to clipboard!")
                except ImportError:
                    print_info("Install 'pyperclip' for clipboard support")
        
        except Exception as e:
            print_error(f"Password generation failed: {e}")
    
    def cmd_totp(self, args):
        """Generate TOTP code with countdown"""
        secret = args.secret
        
        if not secret:
            secret = sanitize_input(input("TOTP Secret (Base32): "))
        
        if not secret:
            return
        
        try:
            code = self.totp.generate_totp(secret)
            remaining = self.totp.get_time_remaining()
            
            # Visual countdown indicator
            bar_length = 30
            filled = int((remaining / 30) * bar_length)
            bar = "█" * filled + "░" * (bar_length - filled)
            
            print(f"\n{colors.success('TOTP Code:')}")
            print(f"  {code}")
            print(f"\n  Valid for: [{bar}] {remaining}s\n")
            
            if args.watch:
                print_info("Press Ctrl+C to stop watching...")
                try:
                    import time
                    while True:
                        time.sleep(1)
                        code = self.totp.generate_totp(secret)
                        remaining = self.totp.get_time_remaining()
                        filled = int((remaining / 30) * bar_length)
                        bar = "█" * filled + "░" * (bar_length - filled)
                        print(f"\r  {code}  [{bar}] {remaining}s ", end='', flush=True)
                except KeyboardInterrupt:
                    print("\n")
        
        except Exception as e:
            print_error(f"Invalid TOTP secret: {e}")
    
    def cmd_backup(self, args):
        """Create encrypted backup with progress"""
        if not self.ensure_unlocked():
            return
        
        filename = args.output or f"sentra_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.enc"
        
        # Confirm overwrite if file exists
        if os.path.exists(filename):
            if not confirm_action(f"File '{filename}' exists. Overwrite?"):
                return
        
        try:
            print_info(f"Creating backup: {filename}")
            
            backup_mgr = self.vault.create_backup_manager()
            
            backup_mgr.create_backup(filename)

            try:
                os.chmod(filename, 0o600)
            except Exception:
                pass
            
            print_success(f"Backup created: {filename}")
            print_info(f"Store this file securely. It contains ALL your passwords.")
        
        except Exception as e:
            print_error(f"Backup failed: {e}")
    
    def cmd_import(self, args):
        """Import data from a backup file."""
        if not self.ensure_unlocked():
            return
        
        from src.backup_manager import BackupManager
        
        filename = args.input
        if not filename:
            filename = sanitize_input(input("Backup file path to import: "))
        
        if not filename or not os.path.exists(filename):
            print_error("File not found.")
            return
        
        print(f"\n{colors.warning('⚠️  DANGER: IMPORTING BACKUP')}")
        print("  This will overwrite existing entries with the same IDs.")
        print("  This action cannot be undone.")
        print()
        
        if not confirm_action("Proceed with import?", dangerous=True):
            return
        
        try:
            print_info(f"Restoring from: {filename}")
            
            backup_mgr = self.vault.create_backup_manager()
            
            # Restore with progress output
            backup_mgr.restore_backup(filename)
            
            print_success("Backup restored successfully!")
        
        except Exception as e:
            print_error(f"Restore failed: {e}")
    
    def cmd_audit(self, args):
        """View security audit log"""
        if not self.ensure_unlocked():
            return
        
        try:
            logs = self.vault.view_audit_log()
            
            if not logs:
                print_info("No audit entries yet.")
                return
            
            limit = args.limit or 50
            logs = logs[:limit]
            
            print(f"\n{colors.info(f'--- Security Audit Log (last {len(logs)} events) ---')}\n")
            
            for log in logs:
                timestamp = log.get('timestamp', '')[:19]  # Remove microseconds
                action = log.get('action_type', 'UNKNOWN')
                title = log.get('title', 'N/A')
                
                # Color-code by action type
                if 'DELETE' in action:
                    action_colored = colors.error(action)
                elif 'ADD' in action:
                    action_colored = colors.success(action)
                elif 'UPDATE' in action:
                    action_colored = colors.warning(action)
                else:
                    action_colored = action
                
                print(f"  {colors.dim(timestamp)} | {action_colored} | {title}")
        
        except Exception as e:
            print_error(f"Failed to retrieve audit log: {e}")
    
    def cmd_security(self, args):
        """Security health check"""
        if not self.ensure_unlocked():
            return
        
        print(f"\n{colors.info('=== Security Health Check ===')}\n")
        
        try:
            # Check 1: Weak passwords
            entries = self.vault.list_entries()
            weak_count = 0
            old_count = 0
            
            for entry in entries:
                # This requires fetching full entries (slow)
                full_entry = self.vault.get_password(entry['id'])
                if full_entry:
                    strength = full_entry.get('password_strength', 100)
                    age = full_entry.get('password_age_days', 0)
                    
                    if strength < 50:
                        weak_count += 1
                    if age > 90:
                        old_count += 1
            
            # Display results
            print(f"📊 {colors.info('Total Entries:')} {len(entries)}")
            
            if weak_count > 0:
                print(f"⚠️  {colors.warning('Weak Passwords:')} {weak_count}")
            else:
                print(f"✓ {colors.success('Weak Passwords:')} 0")
            
            if old_count > 0:
                print(f"⚠️  {colors.warning('Old Passwords (>90 days):')} {old_count}")
            else:
                print(f"✓ {colors.success('Old Passwords:')} 0")
            
            # Check 2: Duplicates
            usernames = [e.get('username') for e in entries if e.get('username')]
            duplicate_count = len(usernames) - len(set(usernames))
            
            if duplicate_count > 0:
                print(f"⚠️  {colors.warning('Duplicate Usernames:')} {duplicate_count}")
            else:
                print(f"✓ {colors.success('Duplicate Usernames:')} 0")
            
            # Check 3: Missing 2FA
            no_totp = len([e for e in entries if not (e.get('tags') or '').lower().__contains__('2fa')])
            print(f"ℹ️  {colors.info('Entries without 2FA tag:')} {no_totp}")
            
            print()
            
            if weak_count > 0 or old_count > 0:
                print(colors.warning("💡 Tip: Run 'sentra update <entry>' to strengthen weak/old passwords"))
        
        except Exception as e:
            print_error(f"Security check failed: {e}")
    
    def cmd_lock(self, args):
        """Lock vault securely"""
        if not self.session_active:
            print_info("Vault is already locked.")
            return
        
        try:
            self.vault.lock_vault()
            self.session_active = False
            print_success("✓ Vault locked securely.")
        except Exception as e:
            print_error(f"Failed to lock vault: {e}")
    
    def cmd_export(self, args):
        """Export to CSV (DANGEROUS - plaintext)"""
        if not self.ensure_unlocked():
            return
        
        filename = args.output or f"sentra_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        # STRONG WARNING
        print(f"\n{colors.error('⚠️  SECURITY WARNING ⚠️')}")
        print(f"  This exports ALL passwords in {colors.error('PLAIN TEXT')}!")
        print(f"  The CSV file is {colors.error('NOT ENCRYPTED')}.")
        print(f"  Only use for migration or manual backup.")
        print()
        
        if not confirm_action("Export to unencrypted CSV?", dangerous=True):
            return
        
        def sanitize_csv_field(text: str) -> str:
            if not text: return ""
            # If field starts with formula trigger, prepend single quote
            if text.startswith(('=', '+', '-', '@')):
                return "'" + text 
            return text
        
        try:
            import csv
            
            entries = self.vault.list_entries()
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'title', 'url', 'username', 'password', 'notes', 'category', 'tags'
                ])
                writer.writeheader()
                
                total = len(entries)
                for i, entry_meta in enumerate(entries, 1):
                    show_progress(i, total, "Exporting")
                    
                    # Fetch full entry with decrypted password
                    full_entry = self.vault.get_password(entry_meta['id'])
                    if full_entry:
                        writer.writerow({
                            'title': sanitize_csv_field(full_entry.get('title', '')),
                            'url': sanitize_csv_field(full_entry.get('url', '')),
                            'username': sanitize_csv_field(full_entry.get('username', '')),
                            'password': sanitize_csv_field(full_entry.get('password', '')),
                            'notes': sanitize_csv_field(full_entry.get('notes', '')),
                            'category': sanitize_csv_field(full_entry.get('category', '')),
                            'tags': sanitize_csv_field(full_entry.get('tags', ''))
                        })
            
            print_success(f"\n✓ Exported to: {filename}")
            print_warning("⚠️  DELETE this file after use!")
        
        except Exception as e:
            print_error(f"Export failed: {e}")
    
    # ======== Parser & Dispatcher ========
    
    def build_parser(self) -> argparse.ArgumentParser:
        """Build argument parser with all commands"""
        parser = argparse.ArgumentParser(
            prog=PROG,
            description="Sentra - Secure Password Manager",
            epilog="For detailed help: sentra <command> --help"
        )
        
        # Global flags
        parser.add_argument('--no-color', action='store_true', 
                          help='Disable colored output')
        parser.add_argument('--version', action='version', 
                          version='Sentra 1.0.0')
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # ---- Authentication ----
        login = subparsers.add_parser('login', help='Unlock vault')
        
        lock = subparsers.add_parser('lock', help='Lock vault')
        
        # ---- Entry Management ----
        add = subparsers.add_parser('add', help='Add new entry')
        add.add_argument('--title', '-t', help='Entry title')
        add.add_argument('--username', '-u', help='Username/email')
        add.add_argument('--password', '-p', help='Password')
        add.add_argument('--url', help='Website URL')
        add.add_argument('--notes', '-n', help='Additional notes')
        add.add_argument('--tags', help='Comma-separated tags')
        add.add_argument('--category', '-c', default='General', help='Category')
        add.add_argument('--favorite', '-f', action='store_true', help='Mark as favorite')
        add.add_argument('--gen', '-g', action='store_true', help='Generate password')
        add.add_argument('--length', '-l', type=int, help='Generated password length')
        add.add_argument('--show', '-s', action='store_true', help='Show generated password')
        add.add_argument('--batch', action='store_true', help='Non-interactive mode')
        
        list_cmd = subparsers.add_parser('list', help='List all entries')
        list_cmd.add_argument('--trash', action='store_true', help='Show deleted entries')
        list_cmd.add_argument('--category', '-c', help='Filter by category')
        list_cmd.add_argument('--favorite', '-f', action='store_true', help='Show only favorites')
        list_cmd.add_argument('--sort', choices=['title', 'modified'], default='title',
                            help='Sort order')
        
        get = subparsers.add_parser('get', help='Get entry details')
        get.add_argument('--title', '-t', help='Search by title')
        get.add_argument('--show', '-s', action='store_true', help='Reveal password')
        
        search = subparsers.add_parser('search', help='Search entries')
        search.add_argument('query', nargs='?', help='Search query')
        search.add_argument('--trash', action='store_true', help='Include deleted entries')
        
        update = subparsers.add_parser('update', help='Update entry')
        update.add_argument('--title', '-t', help='Search entry by title')
        update.add_argument('--username', '-u', help='New username')
        update.add_argument('--password', '-p', help='New password')
        update.add_argument('--url', help='New URL')
        update.add_argument('--notes', '-n', help='New notes')
        update.add_argument('--length', '-l', type=int, help='Length for generated password')
        update.add_argument('--batch', action='store_true', help='Non-interactive mode')
        
        delete = subparsers.add_parser('delete', help='Delete entry (move to trash)')
        delete.add_argument('--title', '-t', help='Search entry by title')
        
        recover = subparsers.add_parser('recover', help='Recover deleted entry from trash')
        
        # ---- Tools ----
        genpass = subparsers.add_parser('genpass', help='Generate secure password')
        genpass.add_argument('--length', '-l', type=int, help='Password length')
        genpass.add_argument('--copy', '-c', action='store_true', help='Copy to clipboard')
        
        totp = subparsers.add_parser('totp', help='Generate 2FA/TOTP code')
        totp.add_argument('--secret', '-s', help='Base32 TOTP secret')
        totp.add_argument('--watch', '-w', action='store_true', help='Watch and auto-refresh')
        
        # ---- Backup/Restore ----
        backup = subparsers.add_parser('backup', help='Create encrypted backup')
        backup.add_argument('--output', '-o', help='Output filename')
        
        imp = subparsers.add_parser('import', help='Import entries from an encrypted backup file')
        imp.add_argument('--input', '-i', help='Backup filename', required=True)
        
        # ---- Security ----
        audit = subparsers.add_parser('audit', help='View security audit log')
        audit.add_argument('--limit', '-l', type=int, help='Number of entries to show')
        
        security = subparsers.add_parser('security', 
                                        help='Run security health check')
        
        export = subparsers.add_parser('export', 
                                      help='Export to CSV (PLAINTEXT - use with caution)')
        export.add_argument('--output', '-o', help='Output filename')
        
        return parser
    
    def dispatch(self, args):
        """Dispatch command to appropriate handler"""
        handlers = {
            'login': lambda a: self.ensure_unlocked(),
            'lock': self.cmd_lock,
            'add': self.cmd_add,
            'list': self.cmd_list,
            'get': self.cmd_get,
            'search': self.cmd_search,
            'update': self.cmd_update,
            'delete': self.cmd_delete,
            'genpass': self.cmd_genpass,
            'totp': self.cmd_totp,
            'recover': self.cmd_recover,
            'backup': self.cmd_backup,     
            'import': self.cmd_import,
            'audit': self.cmd_audit,
            'security': self.cmd_security,
            'export': self.cmd_export
        }
        
        if args.command in handlers:
            handlers[args.command](args)
        else:
            # No command specified
            pass
    
    def interactive_shell(self):
        """Interactive REPL with improved UX"""
        print(colors.info("\n╔════════════════════════════════════╗"))
        print(colors.info("║  SENTRA Interactive Shell v1.0     ║"))
        print(colors.info("╚════════════════════════════════════╝"))
        print("\nType 'help' for commands, 'exit' to quit\n")
        
        parser = self.build_parser()
        
        while True:
            try:
                # Status indicator
                status = colors.success("🔓") if self.session_active else colors.error("🔒")
                prompt = f"{status} sentra> "
                
                text = input(prompt).strip()
                
                if not text:
                    continue
                
                if text in ('exit', 'quit', 'q'):
                    if self.session_active:
                        self.cmd_lock(None)
                    print(colors.success("\nGoodbye! Stay secure. 🔐\n"))
                    break
                
                if text == 'help':
                    parser.print_help()
                    continue
                
                if text == 'clear':
                    os.system('clear' if os.name != 'nt' else 'cls')
                    continue
                
                # Parse and execute
                try:
                    parts = shlex.split(text)
                    args = parser.parse_args(parts)
                    self.dispatch(args)
                except SystemExit:
                    # argparse calls sys.exit on error
                    pass
                
                print()  # Blank line for readability
            
            except KeyboardInterrupt:
                print(f"\n{colors.dim('(Use \"exit\" to quit)')}")
            except EOFError:
                break
            except Exception as e:
                print_error(f"Unexpected error: {e}")

# ============ Main Entry Point ============

def main():
    """Main entry point with improved error handling"""
    
    # Parse global flags first
    import sys
    color_mode = ColorMode.AUTO
    if '--no-color' in sys.argv:
        color_mode = ColorMode.NEVER
        sys.argv.remove('--no-color')
    
    try:
        cli = SentraCLI(color_mode=color_mode)
        parser = cli.build_parser()
        
        # Interactive mode (no arguments)
        if len(sys.argv) == 1:
            cli.interactive_shell()
            return
        
        # One-shot command mode
        try:
            args = parser.parse_args()
            
            if not args.command:
                parser.print_help()
                return
            
            cli.dispatch(args)
        
        except SystemExit as e:
            # argparse exits on --help or invalid args
            if e.code != 0:
                sys.exit(e.code)
    
    except KeyboardInterrupt:
        print(f"\n{colors.error('Interrupted by user.')}")
        sys.exit(130)
    
    except Exception as e:
        print_error(f"Fatal error: {e}")
        sys.exit(1)
    
    finally:
        # Ensure vault is locked on exit
        try:
            if 'cli' in locals() and cli.session_active:
                cli.vault.lock_vault()
        except:
            pass

if __name__ == "__main__":
    from datetime import datetime
    main()