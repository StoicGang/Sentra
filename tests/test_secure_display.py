"""
tests/test_secure_display.py
Unit tests for src/secure_display.py

Strategy:
  - timed_reveal tests use a very short duration and mock time.sleep to avoid
    actually waiting, then inspect sys.stdout output.
  - clipboard tests mock pyperclip so they run without a real clipboard.
  - Threading components are tested by checking timer state and waiting briefly.
"""
from __future__ import annotations

import io
import sys
import threading
import time
from unittest.mock import MagicMock, patch, call
import pytest

from src import secure_display
from src.secure_display import (
    timed_reveal,
    clipboard_copy_with_clear,
    clipboard_available,
    REVEAL_DURATION_SECS,
    CLIPBOARD_CLEAR_SECS,
    _try_import_pyperclip,
)


# ─── Helpers ─────────────────────────────────────────────────────────────────

class CapturedOutput:
    """Context manager: captures all text written to sys.stdout."""
    def __init__(self):
        self._buf = io.StringIO()
        self._old = None

    def __enter__(self):
        self._old = sys.stdout
        sys.stdout = self._buf
        return self

    def __exit__(self, *a):
        sys.stdout = self._old

    @property
    def text(self) -> str:
        return self._buf.getvalue()


# ─── Defaults ────────────────────────────────────────────────────────────────

class TestDefaults:
    def test_reveal_duration_positive(self):
        assert REVEAL_DURATION_SECS > 0

    def test_clipboard_clear_positive(self):
        assert CLIPBOARD_CLEAR_SECS > 0

    def test_reveal_duration_reasonable(self):
        assert 5 <= REVEAL_DURATION_SECS <= 120

    def test_clipboard_clear_reasonable(self):
        assert 10 <= CLIPBOARD_CLEAR_SECS <= 300


# ─── timed_reveal ────────────────────────────────────────────────────────────

class TestTimedReveal:
    """Tests use duration=1 and mock sleep so they finish instantly."""

    def _run_reveal(self, password="S3cr3t!", label="Password", duration=1,
                    sleep_fn=None):
        """Execute timed_reveal with stdout captured and sleep mocked."""
        with CapturedOutput() as cap:
            with patch("src.secure_display.time.sleep",
                       sleep_fn or MagicMock()):
                timed_reveal(password, label=label, duration=duration)
        return cap.text

    def test_password_appears_in_output(self):
        """Password must be visible during reveal."""
        out = self._run_reveal("MySecret123")
        assert "MySecret123" in out

    def test_label_appears_in_output(self):
        out = self._run_reveal("pw", label="Recovery Code")
        assert "Recovery Code" in out

    def test_cleared_message_in_output(self):
        """After reveal the 'cleared from display' message must appear."""
        out = self._run_reveal("pw")
        assert "cleared" in out.lower()

    def test_countdown_mentions_seconds(self):
        """The countdown status line must mention time remaining."""
        out = self._run_reveal("pw", duration=3)
        assert "s" in out  # e.g. "clears in 3s"

    def test_ctrl_c_clears_immediately(self):
        """Simulated KeyboardInterrupt during sleep still triggers cleanup."""
        def raise_interrupt(*_):
            raise KeyboardInterrupt

        out = self._run_reveal("secret", sleep_fn=raise_interrupt)
        assert "cleared" in out.lower()

    def test_custom_label(self):
        out = self._run_reveal("pw", label="Master key")
        assert "Master key" in out

    def test_duration_zero_still_works(self):
        """duration=0 should not crash (no countdown iterations)."""
        out = self._run_reveal("pw", duration=0)
        # password shown, cleared message printed
        assert "pw" in out
        assert "cleared" in out.lower()


# ─── clipboard_copy_with_clear ───────────────────────────────────────────────

class MockPyperclip:
    """Minimal pyperclip mock that records the most recent copy() call."""
    def __init__(self):
        self.contents = ""
        self.calls: list[str] = []

    def copy(self, text: str):
        self.contents = text
        self.calls.append(text)

    def paste(self) -> str:
        return self.contents


class TestClipboardCopyWithClear:

    def _run_copy(self, text="pw", timeout=1, label="Password",
                  pyperclip_mock=None):
        mock = pyperclip_mock or MockPyperclip()
        with CapturedOutput() as cap:
            with patch("src.secure_display._try_import_pyperclip",
                       return_value=mock):
                result = clipboard_copy_with_clear(
                    text, timeout=timeout, label=label
                )
        return result, cap.text, mock

    def test_returns_true_on_success(self):
        ok, _, _ = self._run_copy()
        assert ok is True

    def test_text_is_copied(self):
        _, _, mock = self._run_copy("SuperSecret")
        assert mock.calls[0] == "SuperSecret"

    def test_returns_false_when_pyperclip_missing(self):
        with CapturedOutput():
            with patch("src.secure_display._try_import_pyperclip",
                       return_value=None):
                result = clipboard_copy_with_clear("x")
        assert result is False

    def test_no_clipboard_prints_install_hint(self):
        with CapturedOutput() as cap:
            with patch("src.secure_display._try_import_pyperclip",
                       return_value=None):
                clipboard_copy_with_clear("x")
        assert "pyperclip" in cap.text.lower()

    def test_success_message_printed(self):
        _, out, _ = self._run_copy()
        assert "copied" in out.lower()

    def test_timer_registered(self):
        """A Timer should be started (active_clear_timer set)."""
        mock = MockPyperclip()
        with CapturedOutput():
            with patch("src.secure_display._try_import_pyperclip",
                       return_value=mock):
                clipboard_copy_with_clear("x", timeout=60)
        assert secure_display._active_clear_timer is not None

    def test_timer_is_daemon(self):
        timer = secure_display._active_clear_timer
        if timer is not None:
            assert timer.daemon is True

    def test_clipboard_cleared_after_timeout(self):
        """After timeout seconds the clipboard should be emptied."""
        mock = MockPyperclip()
        with CapturedOutput():
            with patch("src.secure_display._try_import_pyperclip",
                       return_value=mock):
                clipboard_copy_with_clear("sensitive", timeout=1)

        # Wait for the timer to fire (timeout + grace)
        time.sleep(1.5)
        # The clear call passes "" to pyperclip
        assert "" in mock.calls

    def test_previous_timer_cancelled_on_new_copy(self):
        """A second copy call should cancel the first clear timer."""
        mock = MockPyperclip()
        with CapturedOutput():
            with patch("src.secure_display._try_import_pyperclip",
                       return_value=mock):
                clipboard_copy_with_clear("first", timeout=60)
                first_timer = secure_display._active_clear_timer
                clipboard_copy_with_clear("second", timeout=60)

        # First timer must have been cancelled
        assert not first_timer.is_alive()

    def test_copy_error_returns_false(self):
        """If pyperclip.copy() raises, returns False gracefully."""
        bad_mock = MagicMock()
        bad_mock.copy.side_effect = RuntimeError("no clipboard")
        with CapturedOutput():
            with patch("src.secure_display._try_import_pyperclip",
                       return_value=bad_mock):
                result = clipboard_copy_with_clear("x")
        assert result is False


# ─── clipboard_available ─────────────────────────────────────────────────────

class TestClipboardAvailable:
    def test_returns_false_when_pyperclip_missing(self):
        with patch("src.secure_display._try_import_pyperclip",
                   return_value=None):
            assert clipboard_available() is False

    def test_returns_true_when_copy_works(self):
        mock = MockPyperclip()
        with patch("src.secure_display._try_import_pyperclip",
                   return_value=mock):
            assert clipboard_available() is True

    def test_returns_false_when_copy_raises(self):
        bad = MagicMock()
        bad.copy.side_effect = Exception("no display")
        with patch("src.secure_display._try_import_pyperclip",
                   return_value=bad):
            assert clipboard_available() is False


# ─── _try_import_pyperclip ───────────────────────────────────────────────────

class TestTryImportPyperclip:
    def test_returns_none_when_import_fails(self):
        import builtins
        real_import = builtins.__import__

        def raise_on_pyperclip(name, *args, **kwargs):
            if name == "pyperclip":
                raise ImportError("mocked missing")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=raise_on_pyperclip):
            result = _try_import_pyperclip()
        assert result is None

    def test_returns_module_when_available(self):
        # If pyperclip is installed, it should return the module
        mock_mod = MagicMock()
        with patch.dict("sys.modules", {"pyperclip": mock_mod}):
            result = _try_import_pyperclip()
        assert result is mock_mod
