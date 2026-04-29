"""
cli/commands/recovery.py - recovery commands.
OWASP A07: credential recovery flow with strict validation.
"""
from __future__ import annotations
import getpass

from src.recovery_manager import RecoveryError, RecoveryNotEnabledError, RecoveryCredentialError
from cli.ui import print_error, print_success, print_warning, print_info, confirm_action
from cli.colors import colors
from cli.auth import MIN_PASSWORD_LENGTH


def cmd_forget_masterpass(cli, _=None):
    if cli.vault.is_unlocked:
        print_error("Vault is already unlocked. Use this only when locked out.")
        return
    try:
        status = cli.vault.get_recovery_status()
    except Exception as e:
        print_error("Could not check recovery status: " + str(e))
        return
    if not status["enabled"]:
        print_error("No recovery configured. Set it up while vault is unlocked.")
        return
    print("\n" + colors.warning("FORGOTTEN MASTER PASSWORD RECOVERY"))
    print("Type: " + str(status["type"]))
    if status["type"] in ("codes", "both"):
        print("Codes remaining: " + str(status["codes_remaining"]) + "/" + str(status["codes_total"]))
    has_pp   = status["type"] in ("passphrase", "both")
    has_code = status["type"] in ("codes", "both")
    if has_pp and has_code:
        print("  [1] Recovery Passphrase")
        print("  [2] One-Time Code")
        ctype = "passphrase" if input("Choose [1/2]: ").strip() == "1" else "code"
    elif has_pp:
        ctype = "passphrase"
    else:
        ctype = "code"
    try:
        if ctype == "passphrase":
            credential = getpass.getpass("Recovery Passphrase: ")
        else:
            credential = input("Recovery Code: ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return
    if not credential:
        print_error("Credential cannot be empty.")
        return
    for _ in range(3):
        try:
            np1 = getpass.getpass("New Master Password: ")
            if len(np1) < MIN_PASSWORD_LENGTH:
                print_error("Too short — minimum " + str(MIN_PASSWORD_LENGTH) + " characters.")
                continue
            np2 = getpass.getpass("Confirm Password: ")
            if np1 != np2:
                print_error("Passwords do not match.")
                continue
            cli.vault.recover_vault(credential=credential, credential_type=ctype, new_password=np1)
            cli.session_active = True
            print_success("Recovery successful! Vault unlocked with new master password.")
            return
        except RecoveryCredentialError as e:
            print_error("Invalid recovery credential: " + str(e))
            return
        except RecoveryNotEnabledError as e:
            print_error(str(e))
            return
        except (KeyboardInterrupt, EOFError):
            print()
            return
        except Exception as e:
            print_error("Recovery failed: " + str(e))
            return


def cmd_recovery(cli, args):
    if not cli.ensure_unlocked():
        return
    subcmd = getattr(args, "subcmd", None) or "status"
    if subcmd == "status":
        _recovery_show_status(cli)
    elif subcmd == "change":
        ctype = getattr(args, "type", None)
        if not ctype:
            print("  [1] Recovery Passphrase")
            print("  [2] One-Time Codes")
            ctype = "passphrase" if input("Choose [1/2]: ").strip() == "1" else "codes"
        if ctype == "passphrase":
            _do_setup_recovery_passphrase(cli)
        else:
            _do_setup_recovery_codes(cli)
    elif subcmd == "disable":
        if confirm_action("Remove ALL recovery credentials?", dangerous=True):
            try:
                cli.vault.disable_recovery()
                print_success("Recovery disabled.")
            except Exception as e:
                print_error("Could not disable recovery: " + str(e))
    else:
        print_error("Unknown subcommand: " + str(subcmd))
        print_info("Usage: recovery [status|change|disable]")


def _recovery_show_status(cli) -> None:
    try:
        s = cli.vault.get_recovery_status()
    except Exception as e:
        print_error("Could not read recovery status: " + str(e))
        return
    print("\n" + colors.info("=== Recovery Status ==="))
    if not s["enabled"]:
        print(colors.warning("  Recovery: NOT configured"))
    else:
        print(colors.success("  Recovery: Enabled (" + str(s["type"]) + ")"))
        if s["type"] in ("codes", "both"):
            rem   = s["codes_remaining"]
            total = s["codes_total"]
            col   = colors.success if rem > 2 else colors.warning
            print(col("  Codes: " + str(rem) + "/" + str(total) + " remaining"))
            if rem == 0:
                print(colors.error("  All codes used — run 'recovery change' to regenerate."))


def _do_setup_recovery_passphrase(cli) -> None:
    print("\nChoose a recovery passphrase — different from your master password.")
    for _ in range(3):
        try:
            rp1 = getpass.getpass("Recovery Passphrase: ")
            if not rp1.strip():
                print_error("Passphrase cannot be empty.")
                continue
            rp2 = getpass.getpass("Confirm Passphrase: ")
            if rp1 != rp2:
                print_error("Passphrases do not match.")
                continue
            cli.vault.setup_recovery_passphrase(rp1)
            print_success("Recovery passphrase saved.")
            return
        except (KeyboardInterrupt, EOFError):
            print()
            return
        except Exception as e:
            print_error("Could not save: " + str(e))


def _do_setup_recovery_codes(cli, count: int = 8) -> None:
    try:
        codes = cli.vault.setup_recovery_codes(count)
    except Exception as e:
        print_error("Could not generate codes: " + str(e))
        return
    print("\n" + "=" * 50)
    print(colors.info("  YOUR ONE-TIME RECOVERY CODES"))
    print("  Save these in a SECURE OFFLINE location:")
    print("=" * 50)
    for i, code in enumerate(codes, 1):
        print("  " + str(i) + ". " + code)
    print("=" * 50)
    print(colors.warning("  Each code works ONCE only."))
    input("  Press Enter once you have saved these codes...")
