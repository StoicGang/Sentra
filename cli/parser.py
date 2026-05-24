"""
cli/parser.py - argument parser. Security boundary: all input validation starts here.
OWASP A03: parser enforces types and choices before any command handler runs.
"""
from __future__ import annotations
import argparse
from src.secure_display import REVEAL_DURATION_SECS, CLIPBOARD_CLEAR_SECS

PROG = "sentra"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Sentra - Secure Password Manager",
        epilog="For help: sentra <command> --help"
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--version", action="version", version="Sentra 1.0.0")
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # vaults
    vaults = sub.add_parser("vaults", help="Manage multiple vaults")
    vaults.add_argument("subcmd", nargs="?", choices=["list","create","add","remove","switch"], default="list")
    vaults.add_argument("name", nargs="?")
    vaults.add_argument("--path")
    vaults.add_argument("--delete", action="store_true")

    sub.add_parser("login",  help="Unlock vault")
    sub.add_parser("lock",   help="Lock vault")

    # add
    add = sub.add_parser("add", help="Add new entry")
    add.add_argument("--title",    "-t")
    add.add_argument("--username", "-u")
    add.add_argument("--password", "-p")
    add.add_argument("--url")
    add.add_argument("--notes",    "-n")
    add.add_argument("--tags")
    add.add_argument("--category", "-c", default="General")
    add.add_argument("--favorite", "-f", action="store_true")
    add.add_argument("--gen",      "-g", action="store_true")
    add.add_argument("--length",   "-l", type=int)
    add.add_argument("--show",     "-s", action="store_true")
    add.add_argument("--batch",          action="store_true")

    # list
    lst = sub.add_parser("list", help="List entries")
    lst.add_argument("--trash", action="store_true")
    lst.add_argument("--category", "-c")
    lst.add_argument("--favorite", "-f", action="store_true")
    lst.add_argument("--sort", choices=["title","modified"], default="title")
    lst.add_argument("--totp", action="store_true", help="Show only entries with TOTP enabled")

    # get
    get = sub.add_parser("get", help="Get entry details")
    get.add_argument("--title", "-t")
    get.add_argument("--show",  "-s", action="store_true",
                     help="Timed reveal for " + str(REVEAL_DURATION_SECS) + "s")
    get.add_argument("--copy",  "-c", action="store_true",
                     help="Copy to clipboard, clears after " + str(CLIPBOARD_CLEAR_SECS) + "s")

    # search
    srch = sub.add_parser("search", help="Search entries")
    srch.add_argument("query", nargs="?")
    srch.add_argument("--trash", action="store_true")

    # update
    upd = sub.add_parser("update", help="Update entry")
    upd.add_argument("--title",    "-t")
    upd.add_argument("--username", "-u")
    upd.add_argument("--password", "-p")
    upd.add_argument("--url")
    upd.add_argument("--notes",  "-n")
    upd.add_argument("--length", "-l", type=int)
    upd.add_argument("--batch",        action="store_true")

    # delete
    dlt = sub.add_parser("delete", help="Delete entry")
    dlt.add_argument("--title",     "-t")
    dlt.add_argument("--permanent",       action="store_true")

    sub.add_parser("restore", help="Recover from trash")

    # genpass
    gp = sub.add_parser("genpass", help="Generate password")
    gp.add_argument("--length", "-l", type=int)
    gp.add_argument("--copy",   "-c", action="store_true")

    # totp
    totp = sub.add_parser("totp", help="Generate TOTP code")
    totp.add_argument("--secret", "-s")
    totp.add_argument("--watch",  "-w", action="store_true")

    # backup / import / export
    bkp = sub.add_parser("backup", help="Create encrypted backup")
    bkp.add_argument("--output", "-o")

    imp = sub.add_parser("import", help="Import from backup")
    imp.add_argument("--input", "-i", required=True)

    exp = sub.add_parser("export", help="Export to CSV (plaintext)")
    exp.add_argument("--output", "-o")

    # recovery
    sub.add_parser("forget-masterpass", help="Recover when master password forgotten")
    rec = sub.add_parser("recovery", help="Manage recovery settings")
    rec.add_argument("subcmd", nargs="?", choices=["status","change","disable"], default="status")
    rec.add_argument("--type", choices=["passphrase","codes"])

    # security
    sub.add_parser("status",   help="Show vault status")
    aud = sub.add_parser("audit",    help="View audit log")
    aud.add_argument("--limit", "-l", type=int)
    sub.add_parser("security", help="Security health check")

    sd = sub.add_parser("self-destruct", help="Configure or trigger self-destruct")
    sd.add_argument("--threshold", "-t", type=int)
    sd.add_argument("--disable",         action="store_true")
    sd.add_argument("--status",          action="store_true")

    copy_cmd = sub.add_parser("copy", help="Copy last viewed password or TOTP code")
    copy_cmd.add_argument("--totp", action="store_true", help="Copy TOTP code instead of password")

    cfg = sub.add_parser("config", help="Application configuration")
    cfg.add_argument("--clipboard-timeout", type=int)

    sw = sub.add_parser("switch", help="Switch vault")
    sw.add_argument("name", nargs="?")

    # sync
    sync = sub.add_parser("sync", help="P2P Synchronization")
    sync_sub = sync.add_subparsers(dest="action")
    sync_sub.add_parser("pair", help="Generate pairing token")
    confirm = sync_sub.add_parser("confirm", help="Confirm pairing")
    confirm.add_argument("payload", help="Pairing JSON payload")
    sync_sub.add_parser("list", help="List trusted devices")
    sync_sub.add_parser("status", help="Show sync status")
    now_parser = sync_sub.add_parser("now", help="Trigger immediate sync")
    now_parser.add_argument("--host", required=True, help="IP address of the peer daemon")
    now_parser.add_argument("--port", "-p", type=int, default=5555, help="Port of the peer daemon")
    unpair_parser = sync_sub.add_parser("unpair", help="Unpair/remove a trusted device")
    unpair_parser.add_argument("device_id", help="Device ID or prefix of the device to unpair")

    # daemon
    daemon_parser = sub.add_parser("daemon", help="Start sync daemon")
    daemon_parser.add_argument("--host", default="0.0.0.0", help="Host IP to bind to")
    daemon_parser.add_argument("--port", "-p", type=int, default=5555, help="Port to bind to")
    daemon_parser.add_argument("--allow-ip", action="append", help="IP address allowed to connect (can be specified multiple times)")

    # debug-transport
    dt = sub.add_parser("debug-transport", help="Debug transport reachability")
    dt.add_argument("--host", default="127.0.0.1", help="Target host IP")
    dt.add_argument("--port", "-p", type=int, default=5555, help="Target port")

    return parser
