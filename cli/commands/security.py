"""
cli/commands/security.py - audit, self-destruct, security check, status commands.
OWASP A09: security logging and monitoring via audit log.
"""
from __future__ import annotations
import os
import sys

from src.vault_controller import VaultDestroyedError
from cli.ui import print_error, print_success, print_warning, print_info, confirm_action
from cli.colors import colors
from cli.auth import format_duration


def cmd_audit(cli, args):
    if not cli.ensure_unlocked():
        return
    try:
        logs = cli.vault.view_audit_log()
        if not logs:
            print_info("No audit entries yet.")
            return
        limit = args.limit or 50
        logs = logs[:limit]
        print("\n" + colors.info("--- Audit Log (last " + str(len(logs)) + " events) ---") + "\n")
        for log in logs:
            ts     = log.get("timestamp", "")[:19]
            action = log.get("event_type", log.get("action_type", "UNKNOWN"))
            title  = log.get("entry_title", log.get("title", "N/A"))
            if "DELETE" in action:
                action_c = colors.error(action)
            elif "ADD" in action:
                action_c = colors.success(action)
            elif "UPDATE" in action:
                action_c = colors.warning(action)
            else:
                action_c = action
            print("  " + colors.dim(ts) + " | " + action_c + " | " + title)
    except Exception as e:
        print_error("Failed to retrieve audit log: " + str(e))


def cmd_security(cli, _=None):
    if not cli.ensure_unlocked():
        return
    print("\n" + colors.info("=== Security Health Check ===") + "\n")
    try:
        sd_threshold = cli.vault.get_config("auto_self_destruct_threshold")
        if sd_threshold:
            print(colors.warning("NOTICE: Auto-self-destruct ENABLED (threshold: " + str(sd_threshold) + ")"))
        entries   = cli.vault.list_entries()
        weak      = sum(1 for e in entries if (e.get("password_strength") or 100) < 50)
        old       = len(cli.vault.get_old_entries(90))
        usernames = [e.get("username") for e in entries if e.get("username")]
        dupes     = len(usernames) - len(set(usernames))
        no_totp   = len([e for e in entries if "2fa" not in (e.get("tags") or "").lower()])
        print("Total Entries:          " + str(len(entries)))
        print(("⚠️  " if weak  else "✓  ") + "Weak Passwords:         " + str(weak))
        print(("⚠️  " if old   else "✓  ") + "Old Passwords (>90d):   " + str(old))
        print(("⚠️  " if dupes else "✓  ") + "Duplicate Usernames:    " + str(dupes))
        print("ℹ️   Entries without 2FA: " + str(no_totp))
        if weak or old:
            print("\n" + colors.warning("Tip: Run 'update <entry>' to strengthen weak/old passwords"))
    except Exception as e:
        print_error("Security check failed: " + str(e))


def cmd_status(cli, _=None):
    print("\n" + colors.info("=== Vault Status ==="))
    if cli.vault.is_unlocked:
        print(colors.success("  Session: Unlocked"))
    else:
        print(colors.warning("  Session: Locked"))
    try:
        st        = cli.vault.adaptive_lockout.get_status()
        failures  = st["failures"]
        hard      = st["hard_locked"]
        allowed   = st["allowed"]
        delay     = st["delay_seconds"]
        next_at   = st.get("next_allowed_at")
        soft_rem  = st.get("attempts_before_hard_lockout", 0)
        threshold = cli.vault.adaptive_lockout.hard_lockout_threshold
        win_min   = cli.vault.adaptive_lockout.history_window // 60
        print("  Failures: " + str(failures) + " (in last " + str(win_min) + " min window)")
        if failures == 0:
            print(colors.success("  Lockout: None"))
        elif hard:
            print(colors.error("  Lockout: HARD-LOCKED (" + str(failures) + "/" + str(threshold) + ")"))
            if delay > 0:
                print(colors.error("  Remaining: " + format_duration(delay)))
            if next_at:
                print(colors.error("  Unlocks: " + str(next_at)))
        elif not allowed:
            print(colors.warning("  Lockout: Rate-limited (backoff: " + format_duration(delay) + ")"))
            print(colors.warning("  " + str(soft_rem) + " attempts before hard lockout"))
        else:
            if soft_rem < threshold:
                print(colors.warning("  Lockout: " + str(failures) + " failures. " + str(soft_rem) + " more before hard lockout."))
            else:
                print(colors.success("  Lockout: None active"))
    except Exception as e:
        print_error("Could not read lockout state: " + str(e))


def cmd_self_destruct(cli, args):
    if args.threshold or args.disable or args.status:
        if not cli.ensure_unlocked():
            return
        if args.threshold:
            if args.threshold < 1:
                print_error("Threshold must be at least 1.")
                return
            cli.vault.set_config("auto_self_destruct_threshold", args.threshold)
            print_success("Auto-self-destruct enabled at " + str(args.threshold) + " failed logins.")
        if args.disable:
            cli.vault.set_config("auto_self_destruct_threshold", None)
            print_success("Auto-self-destruct disabled.")
        if args.status:
            t = cli.vault.get_config("auto_self_destruct_threshold")
            if t:
                print(colors.warning("Self-Destruct: ENABLED (threshold: " + str(t) + ")"))
            else:
                print(colors.success("Self-Destruct: DISABLED"))
        return

    print("\n" + colors.error("DANGER: MANUAL SELF-DESTRUCT"))
    print(colors.error("This will PERMANENTLY DELETE your entire password database."))
    if not cli.ensure_unlocked():
        return
    if input("Type 'DESTROY' to confirm: ").strip().upper() != "DESTROY":
        print_info("Cancelled.")
        return
    if input("Type 'YES DELETE EVERYTHING' to finish: ").strip().upper() != "YES DELETE EVERYTHING":
        print_info("Cancelled.")
        return
    try:
        v_list  = cli.system_vault.get_registered_vaults() if cli.system_session_active else []
        cur_path = os.path.abspath(cli.active_vault.db.db_path)
        nickname = next((v["nickname"] for v in v_list if os.path.abspath(v["path"]) == cur_path), None)
        cli.vault.self_destruct()
        if nickname and cli.system_session_active:
            try:
                cli.system_vault.unregister_vault(nickname)
            except Exception:
                pass
        cli.active_vault  = None
        cli.session_active = False
    except VaultDestroyedError as e:
        cli.active_vault  = None
        cli.session_active = False
        print("\n" + colors.error(str(e)))
    except Exception as e:
        print_error("Self-destruct failed: " + str(e))

