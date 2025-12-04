import pytest
from unittest.mock import MagicMock, patch, call
import sys
import argparse
from sentra_cli import SentraCLI, PROG

# -----------------------------------------------------------------------------
# FIXTURES
# -----------------------------------------------------------------------------

@pytest.fixture
def mock_vault():
    """Mocks the VaultController to prevent actual DB/Crypto usage"""
    with patch('sentra_cli.VaultController') as MockVC:
        # The instance returned when VaultController() is called
        mock_instance = MockVC.return_value
        
        # Default state: Unlocked
        mock_instance.is_unlocked = False
        
        # Default responses
        mock_instance.list_entries.return_value = []
        mock_instance.search_entries.return_value = []
        
        yield mock_instance

@pytest.fixture
def cli(mock_vault):
    """Returns a CLI instance with a mocked vault"""
    # Suppress print output during initialization
    with patch('builtins.print'):
        app = SentraCLI()
        app.vault = mock_vault # Inject the mock explicitly
        return app

# -----------------------------------------------------------------------------
# TEST CLASSES
# -----------------------------------------------------------------------------

class TestCLIAuthentication:
    """Tests for login and unlock flows"""

    def test_ensure_unlocked_already_active(self, cli):
        cli.session_active = True
        cli.vault.is_unlocked = True
        assert cli.ensure_unlocked() is True

    @patch('getpass.getpass')
    def test_ensure_unlocked_success(self, mock_getpass, cli):
        # Setup
        cli.session_active = False
        mock_getpass.return_value = "correct_password"
        
        # Action
        result = cli.ensure_unlocked()
        
        # Verify
        assert result is True
        assert cli.session_active is True
        cli.vault.unlock_vault.assert_called_with("correct_password")

    @patch('getpass.getpass')
    def test_ensure_unlocked_failure(self, mock_getpass, cli):
        # Setup: Mock unlock to raise error
        from src.vault_controller import VaultError
        cli.vault.unlock_vault.side_effect = VaultError("Invalid password")
        mock_getpass.return_value = "wrong"
        
        # Action
        # We expect it to retry 3 times then fail
        result = cli.ensure_unlocked()
        
        # Verify
        assert result is False
        assert cli.session_active is False
        assert cli.vault.unlock_vault.call_count == 3


class TestCLICommands:
    """Tests for specific commands (Add, List, Get, etc.)"""

    def setup_method(self):
        # Helper to create dummy args
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--title")
        self.parser.add_argument("--username")
        self.parser.add_argument("--password")
        self.parser.add_argument("--url")
        self.parser.add_argument("--notes")
        self.parser.add_argument("--tags")
        self.parser.add_argument("--category")
        self.parser.add_argument("--gen", action="store_true")
        self.parser.add_argument("--length", type=int)

    @patch('builtins.input')
    def test_cmd_add_interactive(self, mock_input, cli):
        """Test 'add' command requesting inputs interactively"""
        # Bypass auth
        cli.session_active = True
        cli.vault.is_unlocked = True
        
        # Mock inputs: Title, Username, Password Choice (Generate)
        mock_input.side_effect = ["My Bank", "user_abc", "g"]
        
        # Create empty args object
        args = self.parser.parse_args([])
        
        # Action
        cli.cmd_add(args)
        
        # Verify Vault Call
        # We don't check the exact random password, just that it was called
        call_args = cli.vault.add_password.call_args[1]
        assert call_args['title'] == "My Bank"
        assert call_args['username'] == "user_abc"
        assert len(call_args['password']) == 16 # Default gen length

    def test_cmd_add_arguments(self, cli):
        """Test 'add' command with command line arguments"""
        cli.session_active = True
        cli.vault.is_unlocked = True
        
        args = self.parser.parse_args([
            "--title", "GitHub", 
            "--username", "dev", 
            "--password", "secret"
        ])
        
        cli.cmd_add(args)
        
        cli.vault.add_password.assert_called_with(
            title="GitHub",
            url=None,
            username="dev",
            password="secret",
            notes=None,
            tags=None,
            category="General"
        )

    def test_cmd_list(self, cli, capsys):
        """Test listing entries"""
        cli.session_active = True
        cli.vault.is_unlocked = True
        
        # Mock data
        cli.vault.list_entries.return_value = [
            {"id": "uuid-1", "title": "Amazon", "username": "user1"},
            {"id": "uuid-2", "title": "Google", "username": None}
        ]
        
        cli.cmd_list(None)
        
        # Capture stdout
        captured = capsys.readouterr()
        assert "Amazon" in captured.out
        assert "Google" in captured.out
        assert "uuid-1" in captured.out

    @patch('builtins.input')
    def test_cmd_get_flow(self, mock_input, cli):
        """Test search -> select -> get details flow"""
        cli.session_active = True
        cli.vault.is_unlocked = True
        
        # 1. Mock Search Results
        mock_matches = [{"id": "target-uuid", "title": "Target Entry", "username": "u"}]
        cli.vault.search_entries.return_value = mock_matches
        
        # 2. Mock Get Result
        cli.vault.get_password.return_value = {
            "title": "Target Entry", "username": "u", "password": "p", 
            "notes": "n", "tags": "t", "category": "c", "url": "url", "password_strength": 90
        }
        
        # 3. Mock User Inputs: 
        #   - "query" (for search)
        #   - "1" (select first result)
        mock_input.side_effect = ["search term", "1"]
        
        args = self.parser.parse_args([])
        cli.cmd_get(args)
        
        # Verify
        cli.vault.search_entries.assert_called_with("search term")
        cli.vault.get_password.assert_called_with("target-uuid")

    @patch('builtins.input')
    def test_cmd_delete_flow(self, mock_input, cli):
        """Test delete flow with confirmation"""
        cli.session_active = True
        cli.vault.is_unlocked = True
        
        # Mock Search
        cli.vault.search_entries.return_value = [{"id": "del-uuid", "title": "To Delete"}]
        
        # Mock Inputs: Search query, Selection, Confirmation
        mock_input.side_effect = ["query", "DELETE"]
        
        args = self.parser.parse_args([])
        cli.cmd_delete(args)
        
        cli.vault.delete_entry.assert_called_with("del-uuid")

    def test_cmd_genpass(self, cli, capsys):
        """Test tool: generate password"""
        args = self.parser.parse_args(["--length", "20"])
        cli.cmd_genpass(args)
        
        captured = capsys.readouterr()
        assert "Password:" in captured.out
        # Simple check to ensure we got output
        assert len(captured.out.strip().split()[-1]) == 20

    def test_cmd_lock(self, cli):
        cli.session_active = True
        cli.vault.lock_vault.return_value = True
        
        cli.cmd_lock(None)
        
        assert cli.session_active is False
        cli.vault.lock_vault.assert_called_once()