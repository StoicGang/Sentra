"""
src/secure_display.py
Utilities for safe password display and clipboard handling.

Mitigations:
  - Screen capture: timed_reveal() shows a password for a fixed duration,
    then overwrites the terminal line so it cannot be read from scrollback.
  - Clipboard snooping: clipboard_copy_with_clear() clears the clipboard
    after a configurable timeout using a non-blocking background thread.

No third-party dependencies beyond pyperclip (optional; graceful fallback).
"""

from __future__ import annotations

import sys
import time
import threading
from typing import Optional

# ─── Defaults ────────────────────────────────────────────────────────────────
REVEAL_DURATION_SECS: int = 20    # seconds a revealed password stays visible
CLIPBOARD_CLEAR_SECS: int = 30    # seconds before clipboard auto-wipe

# ─── Colour constants (simple ANSI; no external dep) ─────────────────────────
_ANSI_RESET  = "\x1b[0m"
_ANSI_DIM    = "\x1b[2m"
_ANSI_YELLOW = "\x1b[33m"
_ANSI_GREEN  = "\x1b[32m"
_ANSI_RED    = "\x1b[31m"
_ERASE_LINE  = "\x1b[2K"       # erase entire current line
_CR          = "\r"            # return to start of line

# Whether the terminal supports ANSI (simplistic check)
_ANSI_OK: bool = sys.stdout.isatty() and sys.platform != "win32" or (
    sys.platform == "win32" and "ANSICON" in __import__("os").environ
    or __import__("os").environ.get("TERM_PROGRAM") in ("vscode", "mintty")
    or __import__("os").environ.get("WT_SESSION") is not None  # Windows Terminal
)


def _erase_current_line() -> None:
    """Overwrite the current terminal line with blank space."""
    if _ANSI_OK:
        sys.stdout.write(f"{_CR}{_ERASE_LINE}")
    else:
        # Fallback: overwrite with spaces then return to start
        sys.stdout.write(f"{_CR}{' ' * 80}{_CR}")
    sys.stdout.flush()


def _dim(text: str) -> str:
    return f"{_ANSI_DIM}{text}{_ANSI_RESET}" if _ANSI_OK else text


def _yellow(text: str) -> str:
    return f"{_ANSI_YELLOW}{text}{_ANSI_RESET}" if _ANSI_OK else text


def _green(text: str) -> str:
    return f"{_ANSI_GREEN}{text}{_ANSI_RESET}" if _ANSI_OK else text


def _red(text: str) -> str:
    return f"{_ANSI_RED}{text}{_ANSI_RESET}" if _ANSI_OK else text


# ─── Timed password reveal ────────────────────────────────────────────────────

def timed_reveal(
    password: str,
    label: str = "Password",
    duration: int = REVEAL_DURATION_SECS,
) -> None:
    """
    Print `password` with `label`, then count down and erase it from the
    terminal after `duration` seconds.  Pressing Ctrl-C clears immediately.

    Args:
        password: The plaintext password to display.
        label:    Column label shown alongside the password.
        duration: Seconds to leave the password visible (default 20).
    """
    # Print the password line
    pw_line = f"  {_yellow(label + ':')} {password}"
    print(pw_line)

    # Separator so the status line sits on its own row
    status_prefix = "  "
    try:
        for remaining in range(duration, 0, -1):
            msg = (
                f"{status_prefix}{_dim(f'(screen clears in {remaining}s — press Ctrl-C to clear now)')}"
            )
            sys.stdout.write(f"{_CR}{msg}")
            sys.stdout.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        pass  # user pressed Ctrl-C — fall through to clear
    finally:
        # Move up one line and erase the password line, then erase status line
        # Move cursor up 1 line (only for terminals that support it)
        if _ANSI_OK:
            sys.stdout.write(f"\x1b[1A")   # cursor up 1
        _erase_current_line()
        if _ANSI_OK:
            sys.stdout.write(f"\x1b[1A")   # cursor up again (erase pw line)
        _erase_current_line()
        print(_dim(f"  ({label} cleared from display)"))
        sys.stdout.flush()


# ─── Clipboard copy with auto-clear ──────────────────────────────────────────

#: Module-level slot for the active clear timer so tests can inspect it.
_active_clear_timer: Optional[threading.Timer] = None


def _try_import_pyperclip():
    """Import pyperclip or return None if unavailable."""
    try:
        import pyperclip
        return pyperclip
    except ImportError:
        return None


def clipboard_copy_with_clear(
    text: str,
    timeout: int = CLIPBOARD_CLEAR_SECS,
    label: str = "Password",
) -> bool:
    """
    Copy `text` to the system clipboard, then clear it after `timeout` seconds.

    A live countdown is printed on a single line (non-blocking — the countdown
    updates run in a separate daemon thread so the CLI remains interactive).

    Args:
        text:    The secret to copy.
        timeout: Seconds until the clipboard is wiped (default 30).
        label:   Human-readable description of what was copied.

    Returns:
        True if the clipboard copy succeeded; False if pyperclip is unavailable.
    """
    global _active_clear_timer

    pyperclip = _try_import_pyperclip()
    if pyperclip is None:
        print(
            f"  {_dim('Install pyperclip for clipboard support:')}"
            f"  pip install pyperclip"
        )
        return False

    # Cancel any previous pending clear
    if _active_clear_timer is not None and _active_clear_timer.is_alive():
        _active_clear_timer.cancel()

    try:
        pyperclip.copy(text)
    except Exception as e:
        print(f"  {_red('Clipboard error:')} {e}")
        return False

    # Print initial confirmation
    print(f"  {_green('✓')} {label} copied to clipboard.")

    # Start background countdown + clear
    _active_clear_timer = threading.Timer(
        interval=timeout,
        function=_clipboard_clear_job,
        args=(pyperclip, label, timeout),
    )
    _active_clear_timer.daemon = True
    _active_clear_timer.start()

    # Launch a non-blocking display thread for the countdown
    display_thread = threading.Thread(
        target=_countdown_display,
        args=(timeout, label),
        daemon=True,
    )
    display_thread.start()

    return True


def _clipboard_clear_job(pyperclip, label: str, timeout: int) -> None:
    """Called by the Timer thread to wipe the clipboard."""
    try:
        pyperclip.copy("")
    except Exception:
        pass  # best-effort


def _countdown_display(timeout: int, label: str) -> None:
    """
    Display a inline countdown on a single terminal line, then print a
    'cleared' confirmation.  Runs in a daemon thread.
    """
    try:
        for remaining in range(timeout, 0, -1):
            msg = _dim(f"  (clipboard clears in {remaining}s)")
            sys.stdout.write(f"{_CR}{msg}")
            sys.stdout.flush()
            time.sleep(1)
    except Exception:
        pass
    finally:
        _erase_current_line()
        print(_dim(f"  ({label} cleared from clipboard)"))
        sys.stdout.flush()


# ─── Convenience: check clipboard availability ────────────────────────────────

def clipboard_available() -> bool:
    """Return True if pyperclip is installed and a clipboard backend exists."""
    pyperclip = _try_import_pyperclip()
    if pyperclip is None:
        return False
    try:
        pyperclip.copy("")
        return True
    except Exception:
        return False
