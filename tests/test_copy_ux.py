"""
tests/test_copy_ux.py
Unit tests for Enhanced Copy UX in SentraCLI.
"""
from __future__ import annotations
from unittest.mock import MagicMock, patch
import pytest
from sentra_cli import SentraCLI
from src.secure_display import CLIPBOARD_CLEAR_SECS

class TestCopyUX:
    @pytest.fixture
    def cli(self):
        with patch('sentra_cli.VaultController') as mock_vault:
            cli = SentraCLI()
            cli.session_active = True
            cli.vault.is_unlocked = True
            return cli

    def test_cmd_get_populates_last_password_state(self, cli):
        """test that cmd_get stores password in state for later copying."""
        mock_entry = {
            'id': '1',
            'title': 'TestEntry',
            'password': 'secret_password',
            'password_strength': 80
        }
        cli.vault.search_entries.return_value = [mock_entry]
        
        with patch('sentra_cli.choose_from_list', return_value='1'):
            with patch('sentra_cli.confirm_action', return_value=True):
                cli.vault.get_password.return_value = mock_entry
                
                # Mock args for get
                args = MagicMock()
                args.title = 'TestEntry'
                args.show = False
                args.copy = False
                
                cli.cmd_get(args)
                
                assert cli._last_password_secret == 'secret_password'
                assert cli._last_password_title == 'TestEntry'

    def test_cmd_copy_calls_clipboard_with_state(self, cli):
        """test that cmd_copy uses stored state to trigger clipboard copy."""
        cli._last_password_secret = 'saved_secret'
        cli._last_password_title = 'SavedTitle'
        cli.vault.get_config.return_value = None # Use default

        with patch('src.secure_display.clipboard_copy_with_clear') as mock_copy:
            cli.cmd_copy()
            mock_copy.assert_called_once_with(
                'saved_secret',
                timeout=CLIPBOARD_CLEAR_SECS,
                label="Password for 'SavedTitle'"
            )

    def test_cmd_copy_uses_custom_timeout(self, cli):
        """test that cmd_copy respects the clipboard_timeout setting."""
        cli._last_password_secret = 'secret'
        cli._last_password_title = 'Title'
        cli.vault.get_config.return_value = "45"

        with patch('src.secure_display.clipboard_copy_with_clear') as mock_copy:
            cli.cmd_copy()
            mock_copy.assert_called_once_with(
                'secret',
                timeout=45,
                label="Password for 'Title'"
            )

    def test_cmd_copy_fails_if_no_state(self, cli):
        """test that cmd_copy warns if no entry has been viewed."""
        cli._last_password_secret = None
        with patch('sentra_cli.print_error') as mock_error:
            cli.cmd_copy()
            mock_error.assert_called_with("No entry has been viewed yet. Run 'get' first.")

    def test_cmd_config_updates_timeout(self, cli):
        """test that cmd_config --clipboard-timeout sets the vault config."""
        args = MagicMock()
        args.clipboard_timeout = 60
        
        cli.cmd_config(args)
        cli.vault.set_config.assert_called_once_with("clipboard_timeout", 60)
