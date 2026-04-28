import pytest
import sqlite3
import os
from src.database_manager import DatabaseManager
from src.vault_controller import VaultController
from src.crypto_engine import generate_salt

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_vault.db")

@pytest.fixture
def vault(db_path):
    # VaultController initializes its own DatabaseManager
    v = VaultController(db_path)
    # Unlock vault
    passphrase = "test_password"
    v.initialize_vault(passphrase)
    v.unlock_vault(passphrase)
    return v

def test_audit_log_leakage_reproduction(vault):
    """
    Reproduce the security issue where decrypted titles are logged in plaintext.
    """
    title = "SENSITIVE_SITE_TITLE"
    entry_id = vault.add_password(title=title, password="secret_password")
    
    # 1. Test get_password leakage
    vault.get_password(entry_id)
    
    # 2. Test copy_secret leakage
    vault.copy_secret(entry_id)
    
    # Check audit logs for the sensitive title
    logs = vault.db.get_audit_logs(limit=10)
    
    leak_found = False
    for log in logs:
        details = str(log.get("details", ""))
        if title in details:
            leak_found = True
            print(f"LEAK DETECTED in log action {log.get('event_type')}: {details}")
    
    # This assertion should FAIL if the leak is present
    assert not leak_found, f"Plaintext metadata '{title}' found in audit logs!"
