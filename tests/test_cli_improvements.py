import pytest
from unittest.mock import MagicMock, patch
import os
from sentra_cli import SentraCLI

@pytest.fixture
def cli():
    with patch('sentra_cli.VaultController'), \
         patch('builtins.print'):
        # Use real Colors with NEVER mode for tests
        app = SentraCLI(color_mode='never')
        app.system_vault = MagicMock()
        app.system_session_active = True
        return app

def test_switch_to_vault_flexible_matching(cli):
    # Setup registered vaults
    cli.system_vault.get_registered_vaults.return_value = [
        {'nickname': 'personal', 'path': 'data/personal.db'},
        {'nickname': 'Work.db', 'path': 'data/work.db'}
    ]
    
    # Mock os.path.exists to always return True for these paths
    with patch('os.path.exists', return_value=True), \
         patch.object(cli, '_unlock_existing_vault', return_value=True):
        
        # 1. Exact match
        assert cli._switch_to_vault('personal') is True
        
        # 2. Case-insensitive
        assert cli._switch_to_vault('PERSONAL') is True
        
        # 3. With .db when nickname doesn't have it
        assert cli._switch_to_vault('personal.db') is True
        
        # 4. Without .db when nickname has it
        assert cli._switch_to_vault('Work') is True
        
        # 5. Case-insensitive + with .db
        assert cli._switch_to_vault('WORK.db') is True

def test_switch_to_vault_not_found(cli):
    cli.system_vault.get_registered_vaults.return_value = [
        {'nickname': 'personal', 'path': 'data/personal.db'}
    ]
    
    with patch('os.path.exists', return_value=True):
        assert cli._switch_to_vault('nonexistent') is False

def test_vaults_list_with_missing_files(cli, capsys):
    cli.system_vault.get_registered_vaults.return_value = [
        {'nickname': 'valid', 'path': 'data/valid.db'},
        {'nickname': 'missing', 'path': 'data/missing.db'}
    ]
    
    with patch('os.path.exists') as mock_exists:
        mock_exists.side_effect = lambda p: 'valid.db' in p
        cli.cmd_vaults_list()
        
    out = capsys.readouterr().out
    assert "valid" in out
    assert "missing" in out
    assert "[MISSING]" in out

def test_cmd_list_sorting_with_missing_titles(cli, capsys):
    # Entries where some have None as title
    cli.system_vault.get_registered_vaults.return_value = [{'nickname': 'p', 'path': 'd'}]
    cli.active_vault = MagicMock()
    cli.active_vault.is_unlocked = True
    cli.session_active = True
    
    cli.vault.list_entries.return_value = [
        {'id': '1', 'title': 'Zebra', 'modified_at': '2021-01-01'},
        {'id': '2', 'title': None, 'modified_at': '2021-01-02'},
        {'id': '3', 'title': 'Apple', 'modified_at': '2021-01-03'}
    ]
    
    # Mocking argparse Namespace for list command
    args = MagicMock()
    args.trash = False
    args.category = None
    args.favorite = False
    args.sort = 'title' # This triggers the problematic sort
    
    # Mocking input to avoid waiting for next page
    with patch('builtins.input', return_value='n'):
        cli.cmd_list(args)
    
    out = capsys.readouterr().out
    assert "Apple" in out
    assert "Zebra" in out
    assert "Untitled" in out # _default_display converts None to Untitled

def test_vaults_list_with_orphans(cli, capsys):
    cli.system_vault.get_registered_vaults.return_value = [
        {'nickname': 'registered', 'path': 'data/registered.db'}
    ]
    # Mock data folder listing
    with patch('os.path.exists', return_value=True), \
         patch('os.listdir', return_value=['registered.db', 'orphan.db', 'not_a_db.txt', 'manager.db']):
        # manager_path is data/manager.db
        cli.manager_path = 'data/manager.db'
        cli.cmd_vaults_list()
        
    out = capsys.readouterr().out
    assert "personal" not in out # registries are mocked
    assert "registered" in out
    assert "Unregistered Vaults" in out
    assert "orphan.db" in out

def test_vaults_remove_with_delete(cli):
    cli.system_vault.get_registered_vaults.return_value = [
        {'nickname': 'gone', 'path': 'data/gone.db'}
    ]
    
    args = MagicMock()
    args.subcmd = 'remove'
    args.name = 'gone'
    args.delete = True
    
    with patch('sentra_cli.confirm_action', return_value=True), \
         patch('os.path.exists', return_value=True), \
         patch('os.remove') as mock_remove:
        cli.cmd_vaults(args)
        
    cli.system_vault.unregister_vault.assert_called_with('gone')
    mock_remove.assert_called_once()
    # Check that it tried to remove the correct path
    assert 'gone.db' in mock_remove.call_args[0][0]
