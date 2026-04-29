"""
cli/auth.py - Authentication and vault unlock logic.
OWASP A07: Identification and Authentication Failures.
- Adaptive lockout enforced before every unlock attempt
- Empty passwords rejected without counting as failed attempts
- Master password never logged or stored in variables beyond immediate use
"""
from __future__ import annotations
import getpass
import os
import sys

from src.vault_controller import (
    VaultController, VaultError, VaultLockedError,
    AccountLockedError, VaultDestroyedError
)
from cli.ui import (
    print_error, print_success, print_warning, print_info,
    confirm_action, display_password_strength, MIN_PASSWORD_LENGTH
)

MAX_LOGIN_ATTEMPTS  = 3
MAX_UNLOCK_ATTEMPTS = 10


def format_duration(seconds: int) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, mins = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {mins}m"
    days, hrs = divmod(hours, 24)
    return f"{days}d {hrs}h"


def first_time_system_setup(system_vault: VaultController, passgen) -> bool:
    """Create the global manager vault on first run."""
    print("\n" + "=" * 50)
    print("🔐 SENTRA GLOBAL SETUP")
    print("=" * 50)
    print(f"\nRequirements: At least {MIN_PASSWORD_LENGTH} characters\n")

    for _ in range(MAX_LOGIN_ATTEMPTS):
        pw1 = getpass.getpass("New Overall Master Password: ")
        if len(pw1) < MIN_PASSWORD_LENGTH:
            print_error("Too short.")
            continue
        pw2 = getpass.getpass("Confirm: ")
        if pw1 != pw2:
            print_error("Mismatch.")
            continue
        try:
            system_vault.unlock_vault(pw1, create_if_missing=True)
            print_success("✓ Global setup complete!")
            return True
        except Exception as e:
            print_error(f"Global setup failed: {e}")
            return False
    return False


def first_time_setup(vault: VaultController, passgen, setup_recovery_fn) -> bool:
    """Create a new vault with master password and optional recovery."""
    print("\n" + "=" * 50)
    print("�� WELCOME TO SENTRA - FIRST TIME SETUP")
    print("=" * 50)
    print(f"\nRequirements: At least {MIN_PASSWORD_LENGTH} characters")
    print("⚠️  This password CANNOT be recovered if lost!\n")

    for _ in range(MAX_LOGIN_ATTEMPTS):
        pw1 = getpass.getpass("Master Password: ")
        if len(pw1) < MIN_PASSWORD_LENGTH:
            print_error(f"Minimum {MIN_PASSWORD_LENGTH} characters.")
            continue

        score, _ = display_password_strength(pw1, passgen)
        if score < 50 and not confirm_action("\nPassword is weak. Continue anyway?"):
            continue

        pw2 = getpass.getpass("Confirm Password: ")
        if pw1 != pw2:
            print_error("Passwords don't match.")
            continue

        try:
            vault.unlock_vault(pw1, create_if_missing=True)
            print_success("\n✓ Vault created and unlocked!")
            setup_recovery_fn()
            return True
        except Exception as e:
            print_error(f"Setup failed: {e}")
            return False

    print_error("Too many failed attempts.")
    return False


def unlock_existing_vault(vault: VaultController) -> bool:
    """Unlock an existing vault with adaptive lockout enforcement."""
    print("\n" + "=" * 50)
    print("🔓 UNLOCK VAULT")
    print("=" * 50 + "\n")

    for attempt in range(1, MAX_UNLOCK_ATTEMPTS + 1):
        # Pre-check lockout state before prompting
        try:
            status = vault.adaptive_lockout.get_status()
            if not status["allowed"]:
                remaining = status["delay_seconds"]
                if status["hard_locked"]:
                    next_at = status.get("next_allowed_at", "")
                    msg = (f"🔒 Account locked.\n"
                           f"  Locked for {format_duration(remaining)}.")
                    if next_at:
                        msg += f"\n  Try again after: {next_at}"
                else:
                    msg = f"⏳ Wait {format_duration(remaining)} before next attempt."
                print_error(msg)
                return False
        except Exception:
            pass  # Non-fatal — don't block unlock if status check fails

        try:
            pw = getpass.getpass("Master Password: ")
        except (KeyboardInterrupt, EOFError):
            print()
            return False

        if not pw:
            continue  # Empty input — don't count as attempt

        try:
            vault.unlock_vault(pw, create_if_missing=False)
            print_success("✓ Vault unlocked")
            return True

        except VaultDestroyedError as e:
            print("\n" + "!" * 60)
            print(f" CRITICAL SECURITY ALERT: VAULT DESTROYED\n {e}")
            print("!" * 60 + "\n")
            sys.exit(1)

        except AccountLockedError as e:
            if e.hard_locked:
                msg = (f"🔒 Account locked: too many failed attempts.\n"
                       f"  Locked for {format_duration(e.delay_seconds)}.")
                if e.next_allowed_at:
                    msg += f"\n  Try again after: {e.next_allowed_at}"
            else:
                msg = (f"⏳ Rate-limited: wait "
                       f"{format_duration(e.delay_seconds)} before retrying.")
            print_error(msg)
            return False

        except VaultError as e:
            if "Invalid password" in str(e):
                try:
                    st = vault.adaptive_lockout.get_status()
                    soft_rem = st.get("attempts_before_hard_lockout", 0)
                    failures = st.get("failures", 0)
                    if soft_rem > 0:
                        print_error(
                            f"Invalid password ({failures} failed attempt"
                            f"{'s' if failures != 1 else ''}).\n"
                            f"  ⚠ {soft_rem} attempt"
                            f"{'s' if soft_rem != 1 else ''} remaining before 24h lockout."
                        )
                    else:
                        print_error("Invalid password.")
                except Exception:
                    print_error("Invalid password. Try again.")
            else:
                print_error(str(e))
            return False

        except Exception as e:
            print_error(f"System error: {e}")
            return False

    print_error("Too many failed attempts. Exiting...")
    return False

class SentraCLI:
    """Central CLI controller — holds vault, auth state, and helpers."""

    def __init__(self):
        from src.vault_controller import VaultController
        from src.password_generator import PasswordGenerator
        from src.totp_generator import TOTPGenerator

        self.vault = VaultController()
        self.passgen = PasswordGenerator()
        self.totp = TOTPGenerator()
        self._unlocked = False
        self._last_password_secret = None
        self._last_password_title = None

    def ensure_unlocked(self) -> bool:
        """Return True if vault is unlocked, else prompt unlock."""
        if self._unlocked:
            return True
        if not self.vault.vault_exists():
            success = first_time_setup(
                self.vault, self.passgen, self._setup_recovery
            )
        else:
            success = unlock_existing_vault(self.vault)
        if success:
            self._unlocked = True
        return success

    def _setup_recovery(self):
        """Called after first-time setup to optionally configure recovery."""
        self._unlocked = True  # vault already open, skip re-auth
        from cli.commands.recovery import cmd_recovery
        try:
            if confirm_action("Set up recovery options now? (recommended)"):
                import argparse
                args = argparse.Namespace(subcmd="change", type="passphrase")
                cmd_recovery(self, args)
        except Exception:
            pass


def cmd_login(cli, _args=None):
    """Unlock the vault (login command)."""
    if cli._unlocked:
        print_info("Vault is already unlocked.")
        return
    if not cli.vault.vault_exists():
        success = first_time_setup(cli.vault, cli.passgen, cli._setup_recovery)
    else:
        success = unlock_existing_vault(cli.vault)
    if success:
        cli._unlocked = True


def cmd_lock(cli, _args=None):
    """Lock the vault."""
    try:
        cli.vault.lock_vault()
        cli._unlocked = False
        print_success("Vault locked.")
    except Exception as e:
        print_error("Failed to lock vault: " + str(e))

