"""
cli/commands/tools.py - genpass, totp, copy commands.
OWASP A02: clipboard auto-clear enforced on all copy operations.
"""
from __future__ import annotations
from src.secure_display import clipboard_copy_with_clear, CLIPBOARD_CLEAR_SECS
from cli.ui import print_error, print_success, print_warning, print_info, sanitize_input
from cli.colors import colors

DEFAULT_PASSWORD_LENGTH = 16


def cmd_genpass(cli, args):
    length = args.length or DEFAULT_PASSWORD_LENGTH
    if length < 8:
        print_error("Password length must be at least 8 characters.")
        return
    try:
        password, warn = cli.passgen.generate_password(length=length)
        if warn:
            print_warning(warn)
        from cli.ui import display_password_strength
        score, label = display_password_strength(password, cli.passgen)
        print(f"\n{colors.success('Generated Password:')}")
        print(f"  {password}\n")
        if args.copy:
            clipboard_copy_with_clear(password, timeout=CLIPBOARD_CLEAR_SECS, label="Generated password")
    except Exception as e:
        print_error(f"Password generation failed: {e}")


def cmd_totp(cli, args):
    secret = args.secret or sanitize_input(input("TOTP Secret (Base32): "))
    if not secret:
        return
    try:
        code      = cli.totp.generate_totp(secret)
        remaining = cli.totp.get_time_remaining()
        filled    = int((remaining / 30) * 30)
        bar       = "█" * filled + "░" * (30 - filled)
        print(f"\n{colors.success('TOTP Code:')}")
        print(f"  {code}")
        print(f"\n  Valid for: [{bar}] {remaining}s\n")
        if args.watch:
            print_info("Press Ctrl+C to stop watching...")
            try:
                import time
                while True:
                    time.sleep(1)
                    code      = cli.totp.generate_totp(secret)
                    remaining = cli.totp.get_time_remaining()
                    filled    = int((remaining / 30) * 30)
                    bar       = "█" * filled + "░" * (30 - filled)
                    print(f"\r  {code} [{bar}] {remaining}s ", end="", flush=True)
            except KeyboardInterrupt:
                print()
    except Exception as e:
        print_error(f"Invalid TOTP secret: {e}")


def cmd_copy(cli, args=None):
    if not cli.ensure_unlocked():
        return
    has_password = bool(cli._last_password_secret)
    has_totp = bool(getattr(cli, '_last_totp_secret', None))
    if not has_password and not has_totp:
        print_error("No entry viewed yet. Run 'get' first.")
        return
    timeout_raw = cli.vault.get_config("clipboard_timeout")
    timeout = int(timeout_raw) if timeout_raw else CLIPBOARD_CLEAR_SECS
    # --totp flag: copy TOTP code instead of password
    copy_totp = getattr(args, 'totp', False) if args else False
    if copy_totp and not has_totp:
        print_error("Last viewed entry has no TOTP secret.")
        return
    if copy_totp or (has_totp and not has_password):
        try:
            code = cli.totp.generate_totp(cli._last_totp_secret)
            remaining = cli.totp.get_time_remaining()
            clipboard_copy_with_clear(
                code,
                timeout=min(timeout, remaining),
                label=f"TOTP code for '{cli._last_password_title}'"
            )
            print_info(f"TOTP code copied — valid for {remaining}s, will clear from clipboard.")
        except Exception as e:
            print_error(f"Failed to generate TOTP code: {e}")
        return
    # Default: copy password
    clipboard_copy_with_clear(
        cli._last_password_secret,
        timeout=timeout,
        label=f"Password for '{cli._last_password_title}'"
    )
    if has_totp:
        print_info("Tip: use 'copy --totp' to copy the TOTP code instead.")
