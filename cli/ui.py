"""
cli/ui.py - UI helpers: printing, input sanitization, selection, progress.
OWASP A03: sanitize_input strips control characters at every entry point.
"""
from __future__ import annotations
import sys
from typing import Optional, List, Dict

from cli.colors import colors

MAX_INPUT_LENGTH = 1000
MIN_PASSWORD_LENGTH = 12


def print_error(msg: str, prefix: str = "ERROR"):
    print(f"[{colors.error(prefix)}] {msg}", file=sys.stderr)

def print_success(msg: str, prefix: str = "SUCCESS"):
    print(f"[{colors.success(prefix)}] {msg}")

def print_warning(msg: str, prefix: str = "WARNING"):
    print(f"[{colors.warning(prefix)}] {msg}")

def print_info(msg: str):
    print(colors.info(msg))

def sanitize_input(text: str, max_length: int = MAX_INPUT_LENGTH) -> str:
    """Strip, length-limit, remove control chars. Call at every user input boundary."""
    text = text.strip()[:max_length]
    return ''.join(c for c in text if c.isprintable() or c in '\n\t')

def confirm_action(prompt: str, dangerous: bool = False) -> bool:
    """Require explicit 'yes' for dangerous actions, 'y' otherwise."""
    if dangerous:
        response = input(f"{prompt} Type 'yes' to confirm: ").strip().lower()
        return response == "yes"
    response = input(f"{prompt} [y/N]: ").strip().lower()
    return response in ('y', 'yes')

def choose_from_list(
    items: List[Dict],
    id_key: str = "id",
    display_fn=None,
    allow_cancel: bool = True
) -> Optional[str]:
    """Interactive list selection. Returns selected item ID or None."""
    if not items:
        print_info("No matches found.")
        return None

    if len(items) == 1:
        item = items[0]
        display = display_fn(item) if display_fn else _default_display(item)
        print_info(f"Found: {display}")
        if not confirm_action("Use this entry?"):
            return None
        return item.get(id_key)

    print(f"\n{colors.info('Found')} {len(items)} matches:\n")
    for i, item in enumerate(items, start=1):
        display = display_fn(item) if display_fn else _default_display(item)
        print(f"  {colors.dim(str(i)+')')} {display}")

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
            print_error(f"Please enter a number between 1 and {len(items)}")
        except ValueError:
            print_error("Invalid input. Enter a number.")

def _default_display(item: Dict) -> str:
    title = item.get('title') or 'Untitled'
    username = item.get('username', '')
    user_part = f" ({username})" if username else ""
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

def display_password_strength(password: str, passgen) -> tuple[int, str]:
    """Display strength bar and diagnostics. Returns (score, label)."""
    score, label, diagnostics = passgen.calculate_strength(password)
    bars  = "█" * (score // 10)
    empty = "░" * (10 - score // 10)
    color_fn = colors.error if score < 30 else (colors.warning if score < 70 else colors.success)
    print(f"\nPassword Strength: {color_fn(label)} ({score}/100)")
    print(f"[{color_fn(bars)}{empty}]")
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
    """Overwrite-in-place progress bar for long operations."""
    if total == 0:
        return
    percent  = int((current / total) * 100)
    filled   = int((current / total) * 30)
    bar      = "█" * filled + "░" * (30 - filled)
    print(f"\r{label}: [{bar}] {percent}% ({current}/{total})", end="", flush=True)
    if current == total:
        print()
