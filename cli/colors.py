"""
cli/colors.py - ANSI color management with accessibility support.

OWASP A05: Security Misconfiguration — ANSI escape injection prevention.
All text passed through _wrap() has escape sequences stripped before wrapping.
"""
from __future__ import annotations
import os
import sys
from enum import Enum


class ColorMode(Enum):
    AUTO   = "auto"
    ALWAYS = "always"
    NEVER  = "never"


class Colors:
    """Centralized color management with accessibility support."""

    def __init__(self, mode: ColorMode = ColorMode.AUTO):
        self._enabled = self._should_enable_colors(mode)

    @staticmethod
    def _should_enable_colors(mode: ColorMode) -> bool:
        if mode == ColorMode.NEVER:
            return False
        if mode == ColorMode.ALWAYS:
            return True
        is_atty = sys.stdout.isatty()
        if os.name == "nt":
            if os.getenv("WT_SESSION") or os.getenv("TERM_PROGRAM") == "vscode":
                return True
            return is_atty
        return is_atty and os.getenv("TERM") != "dumb"

    def _wrap(self, text: str, code: str) -> str:
        if not self._enabled:
            return text
        # OWASP A03: strip embedded escape sequences before wrapping
        safe = str(text).replace("\033", "")
        return f"\033[{code}m{safe}\033[0m"

    def error(self, text: str)   -> str: return self._wrap(text, "91")
    def success(self, text: str) -> str: return self._wrap(text, "92")
    def warning(self, text: str) -> str: return self._wrap(text, "93")
    def info(self, text: str)    -> str: return self._wrap(text, "94")
    def dim(self, text: str)     -> str: return self._wrap(text, "2")


# Module-level singleton — replaced by SentraCLI.__init__ after arg parsing
colors = Colors()   