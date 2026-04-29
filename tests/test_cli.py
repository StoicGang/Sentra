import pytest
from unittest.mock import MagicMock, patch, call, mock_open
import sys
import argparse
import os
from sentra_cli import SentraCLI, PROG

# -----------------------------------------------------------------------------
# FIXTURES
# -----------------------------------------------------------------------------

@pytest.fixture
def mock_vault():
    """Mocks the VaultController."""
    with patch('sentra_cli.VaultController') as MockVC:
        instance = MockVC.return_value
        instance.is_unlocked = False
        instance.vault_exists.return_value = True
        
        # Default return values for common methods to avoid NoneType errors
        instance.list_entries.return_value = []
        instance.search_entries.return_value = []
        instance.get_password.return_value = {}
        instance.view_audit_log.return_value = []
        instance.update_entry.return_value = True # Ensure updates succeed
        
        yield instance

@pytest.fixture
def mock_passgen():
    with patch('sentra_cli.PasswordGenerator') as MockPG:
        instance = MockPG.return_value
        instance.generate_password.return_value = ("mock_password", "")
        instance.calculate_strength.return_value = (100, "Strong", {})
        yield instance

@pytest.fixture
def mock_totp():
    with patch('sentra_cli.TOTPGenerator') as MockTG:
        instance = MockTG.return_value
        instance.generate_totp.return_value = "123456"
        instance.get_time_remaining.return_value = 30
        yield instance

@pytest.fixture
def cli(mock_vault, mock_passgen, mock_totp):
    """Returns a CLI instance with mocked dependencies"""
    with patch('builtins.print'):  # Suppress init prints
        # Use simple color mode for tests
        app = SentraCLI(color_mode=None) 
        return app

# -----------------------------------------------------------------------------
# AUTHENTICATION TESTS
# -----------------------------------------------------------------------------

class TestAuthentication:
    
    def test_ensure_unlocked_already_active(self, cli):
        cli.session_active = True
        cli.vault.is_unlocked = True
        assert cli.ensure_unlocked() is True

    @patch('getpass.getpass')
    def test_unlock_existing_success(self, mock_getpass, cli):
        cli.vault.vault_exists.return_value = True
        mock_getpass.return_value = "valid_long_password"
        
        assert cli.ensure_unlocked() is True
        cli.vault.unlock_vault.assert_called_with("valid_long_password")
        assert cli.session_active is True

    @patch('getpass.getpass')
    @patch('builtins.input', return_value='y') # Confirm weak password if needed
    def test_first_time_setup_success(self, mock_input, mock_getpass, cli):
        cli.vault.vault_exists.return_value = False
        # FIX: Passwords must be >= 12 chars to pass validation loop
        valid_pw = "correct_horse_battery_staple"
        mock_getpass.side_effect = [valid_pw, valid_pw]
        
        assert cli.ensure_unlocked() is True
        cli.vault.unlock_vault.assert_called_with(valid_pw)
        assert cli.session_active is True

    @patch('getpass.getpass')
    def test_first_time_setup_mismatch(self, mock_getpass, cli):
        cli.vault.vault_exists.return_value = False
        # FIX: Passwords must be >= 12 chars
        pw1 = "correct_horse_battery_staple_1"
        pw2 = "correct_horse_battery_staple_2"
        pw3 = "correct_horse_battery_staple_3"
        
        # Mismatch then match
        mock_getpass.side_effect = [pw1, pw2, pw3, pw3]
        
        assert cli.ensure_unlocked() is True
        assert cli.vault.unlock_vault.call_count == 1 # Only called once on success

# -----------------------------------------------------------------------------
# COMMAND TESTS
# -----------------------------------------------------------------------------

class TestCommands:
    
    @pytest.fixture(autouse=True)
    def setup_cli_state(self, cli):
        # Auto-unlock for command tests
        cli.session_active = True
        cli.vault.is_unlocked = True
        
        # Helper to parse args
        self.parser = cli.build_parser()

    # --- ADD ---
    
    def test_cmd_add_args(self, cli):
        # FIX: Add --batch to prevent prompts for optional fields
        args = self.parser.parse_args([
            "add", "--title", "Test", "--username", "u", "--password", "p", "--batch"
        ])
        cli.cmd_add(args)
        cli.vault.add_password.assert_called_with(
            title="Test", username="u", password="p", 
            url=None, notes=None, tags=None, category="General", favorite=False
        )

    @patch('builtins.input')
    def test_cmd_add_interactive(self, mock_input, cli):
        # FIX: Added 'notes' input at end
        # Inputs: Title, URL, Username, Password Choice (Enter), Notes
        mock_input.side_effect = ["MyBank", "http://bank.com", "user", "e", "my notes"] 
        with patch('getpass.getpass', return_value="secure123"):
            args = self.parser.parse_args(["add"])
            cli.cmd_add(args)
            
        cli.vault.add_password.assert_called()
        call_kwargs = cli.vault.add_password.call_args[1]
        assert call_kwargs['title'] == "MyBank"
        assert call_kwargs['password'] == "secure123"
        assert call_kwargs['notes'] == "my notes"

    # --- LIST ---

    def test_cmd_list_basic(self, cli, capsys):
        cli.vault.list_entries.return_value = [
            {"id": "1", "title": "Netflix", "category": "Fun"},
            {"id": "2", "title": "Work", "category": "Work"}
        ]
        args = self.parser.parse_args(["list"])
        cli.cmd_list(args)
        
        out = capsys.readouterr().out
        assert "Netflix" in out
        assert "Work" in out

    @patch('builtins.input', return_value='n') # Stop pagination
    def test_cmd_list_pagination(self, mock_input, cli):
        # Return enough entries to trigger pagination
        cli.vault.list_entries.return_value = [{"id": str(i), "title": f"Entry{i}"} for i in range(25)]
        
        args = self.parser.parse_args(["list"])
        cli.cmd_list(args)
        
        # Should have called list_entries at least once
        cli.vault.list_entries.assert_called()

    # --- GET ---

    @patch('builtins.input')
    def test_cmd_get_interactive(self, mock_input, cli):
        # FIX: Single search result triggers confirmation prompt ('y'), not selection ('1')
        mock_input.side_effect = ["Netflix", "y"]
        
        cli.vault.search_entries.return_value = [{"id": "uuid1", "title": "Netflix"}]
        cli.vault.get_password.return_value = {"title": "Netflix", "password": "pass", "password_strength": 80}
        
        args = self.parser.parse_args(["get"])
        cli.cmd_get(args)
        
        cli.vault.search_entries.assert_called_with("Netflix")
        cli.vault.get_password.assert_called_with("uuid1")

    # --- UPDATE ---

    @patch('builtins.input') 
    def test_cmd_update_interactive(self, mock_input, cli):
        # FIX: Provide inputs for ALL prompt fields to prevent StopIteration.
        # Sequence: 
        # 1. Search ("Spotify")
        # 2. Confirm ("y")
        # 3. New Title ("" to keep)
        # 4. New URL ("" to keep)
        # 5. New Username ("new_user")
        # 6. New Password ("" to keep)
        # 7. New Notes ("" to keep)
        mock_input.side_effect = ["Spotify", "y", "", "", "new_user", "", ""]
        
        cli.vault.search_entries.return_value = [{"id": "uuid2", "title": "Spotify"}]
        cli.vault.get_password.return_value = {"title": "Spotify", "username": "old"}
        
        args = self.parser.parse_args(["update"])
        cli.cmd_update(args)
        
        # Verify call only contains the changed field
        cli.vault.update_entry.assert_called_with("uuid2", username="new_user")

    # --- DELETE ---

    @patch('builtins.input')
    def test_cmd_delete(self, mock_input, cli):
        # FIX: 'y' to confirm single result selection
        # Sequence: Query(Adobe), ConfirmSelection(y), ConfirmDelete(yes)
        mock_input.side_effect = ["Adobe", "y", "yes"]
        
        cli.vault.search_entries.return_value = [{"id": "uuid3", "title": "Adobe"}]
        cli.vault.get_password.return_value = {"title": "Adobe"}
        
        args = self.parser.parse_args(["delete"])
        cli.cmd_delete(args)
        
        cli.vault.delete_entry.assert_called_with("uuid3")

    # --- RECOVER ---

    @patch('builtins.input')
    def test_cmd_recover(self, mock_input, cli):
        # FIX: 'y' to confirm single result selection
        mock_input.side_effect = ["y"]
        
        # list_entries with trash=True
        cli.vault.list_entries.return_value = [{"id": "del_uuid", "title": "Deleted Item", "is_deleted": 1}]
        cli.vault.restore_entry.return_value = True
        
        args = self.parser.parse_args(["recover"])
        cli.cmd_recover(args)
        
        cli.vault.restore_entry.assert_called_with("del_uuid")

    # --- SEARCH ---

    def test_cmd_search(self, cli):
        args = self.parser.parse_args(["search", "bank"])
        cli.vault.search_entries.return_value = [{"title": "Bank of America"}]
        
        cli.cmd_search(args)
        cli.vault.search_entries.assert_called_with("bank", include_deleted=False)

    # --- TOOLS ---

    def test_cmd_genpass(self, cli, capsys):
        args = self.parser.parse_args(["genpass", "-l", "20"])
        cli.cmd_genpass(args)
        
        cli.passgen.generate_password.assert_called_with(length=20)
        out = capsys.readouterr().out
        assert "Generated Password" in out

    def test_cmd_totp(self, cli):
        args = self.parser.parse_args(["totp", "-s", "JBSWY3DP"])
        cli.cmd_totp(args)
        cli.totp.generate_totp.assert_called_with("JBSWY3DP")

    # --- BACKUP / IMPORT ---

    def test_cmd_backup(self, cli):
        args = self.parser.parse_args(["backup"])
        mock_mgr = MagicMock()
        cli.vault.create_backup_manager.return_value = mock_mgr
        
        # Patch chmod to avoid OS errors in tests
        with patch('os.chmod'):
            cli.cmd_backup(args)
        
        cli.vault.create_backup_manager.assert_called_once()
        mock_mgr.create_backup.assert_called()

    @patch('builtins.input', return_value="backup.enc")
    @patch('sentra_cli.confirm_action', return_value=True)
    @patch('os.path.exists', return_value=True)
    def test_cmd_import(self, mock_exists, mock_confirm, mock_input, cli):
        args = self.parser.parse_args(["import", "-i", "backup.enc"])
        mock_mgr = MagicMock()
        cli.vault.create_backup_manager.return_value = mock_mgr
        
        cli.cmd_import(args)
        
        mock_mgr.restore_backup.assert_called_with("backup.enc")

    # --- SECURITY / AUDIT ---

    def test_cmd_audit(self, cli):
        cli.vault.view_audit_log.return_value = [{"action_type": "LOGIN", "timestamp": "2023-01-01"}]
        args = self.parser.parse_args(["audit"])
        cli.cmd_audit(args)
        cli.vault.view_audit_log.assert_called()

    def test_cmd_security(self, cli):
        # Needs list entries and then get_password for details
        cli.vault.list_entries.return_value = [{"id": "u1"}]
        cli.vault.get_password.return_value = {"password_strength": 10, "password_age_days": 100}
        
        args = self.parser.parse_args(["security"])
        cli.cmd_security(args)
        
        # Verify it fetched details
        cli.vault.get_password.assert_called_with("u1")

    # --- EXPORT ---

    @patch('sentra_cli.confirm_action', return_value=True)
    def test_cmd_export_csv(self, mock_confirm, cli):
        args = self.parser.parse_args(["export", "-o", "out.csv"])
        cli.vault.list_entries.return_value = [{"id": "u1"}]
        cli.vault.get_password.return_value = {"title": "T", "password": "P"}
        
        # Mock file opening
        with patch('builtins.open', mock_open()) as m:
            cli.cmd_export(args)
            
        # Verify writing happened
        m.assert_called_with("out.csv", 'w', newline='', encoding='utf-8')
        handle = m()
        # Header + 1 row
        assert handle.write.call_count >= 1

    # --- LOCK ---
    
    def test_cmd_lock(self, cli):
        args = self.parser.parse_args(["lock"])
        cli.cmd_lock(args)
        cli.vault.lock_vault.assert_called()
        assert cli.session_active is False