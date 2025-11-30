import os
import pytest
import gc # Added for Windows file lock handling
from src.vault_controller import VaultController, VaultLockedError, VaultError, VaultAlreadyUnlockedError

# --- FIX START: Use a fixture for reliable setup and teardown ---
@pytest.fixture
def vault():
    """Fixture to provide a clean vault controller for each test"""
    db_path = "data/test_vault.db"
    
    # Setup: Ensure no leftover DB exists
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except PermissionError:
            pass # Handle edge case where file is stuck

    controller = VaultController(db_path)
    
    yield controller # Pass controller to the test
    
    # Teardown: Clean up resources
    try:
        # Close DB connection explicitly
        if controller.db.connection:
            controller.db.close()
            
        # Ensure memory is unlocked (if controller was used)
        if controller.is_unlocked:
            try:
                controller.lock_vault()
            except:
                pass 

    except Exception:
        pass
    
    # Force garbage collection to release SQLite file locks on Windows
    del controller
    gc.collect()

    # Clean up file
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except PermissionError:
            pass
# --- FIX END ---

def test_vault_unlock_and_lock(vault): # Pass fixture
    # Initial unlock should succeed (new vault)
    password = "StrongPassword123!"
    assert vault.unlock_vault(password) is True
    assert vault.is_unlocked is True

    # Unlocking again should raise error
    with pytest.raises(VaultAlreadyUnlockedError):
        vault.unlock_vault(password)

    # Lock the vault
    assert vault.lock_vault() is True
    assert vault.is_unlocked is False

    # Locking already locked vault returns True silently
    assert vault.lock_vault() is True


def test_add_password_locked_fails(vault): # Pass fixture
    with pytest.raises(VaultLockedError):
        vault.add_password(title="Example")


def test_get_password_locked_fails(vault): # Pass fixture
    with pytest.raises(VaultLockedError):
        vault.get_password("nonexistent-id")


def test_add_and_get_password_success(vault): # Pass fixture
    vault.unlock_vault("StrongPassword123!")

    # Add entry
    entry_id = vault.add_password(
        title="My Email",
        url="https://mail.example.com",
        username="user@example.com",
        password="P@ssw0rd!",
        notes="My email password",
        tags="email,personal",
        category="Email"
    )
    assert entry_id

    # Retrieve entry
    entry = vault.get_password(entry_id)
    assert entry is not None
    assert entry["title"] == "My Email"
    assert entry["url"] == "https://mail.example.com"
    assert entry["username"] == "user@example.com"
    assert entry["password"] == "P@ssw0rd!"
    assert entry["notes"] == "My email password"
    assert entry["tags"] == "email,personal"
    assert entry["category"] == "Email"


def test_add_password_invalid_title(vault): # Pass fixture
    vault.unlock_vault("StrongPassword123!")

    with pytest.raises(VaultError):
        vault.add_password(title="")

def test_data_is_destroyed_after_lock(vault):
    vault.unlock_vault("StrongPassword123!")
    
    # 1. Keep a strong reference to the mutable bytearray object
    # This ensures Python doesn't delete the memory when vault.lock_vault() runs
    sensitive_data_ref = vault.master_key_secure
    
    # Sanity check: Ensure it actually has data before we start
    assert any(b != 0 for b in sensitive_data_ref), "Key should not be zero initially"
    
    # 2. Lock the vault
    # This triggers secure_mem.zeroize(self.master_key_secure)
    vault.lock_vault()
    
    # 3. Verify the reference is zeroed
    # Since bytearray is mutable, the change happens in-place.
    # If this passes, it proves the memory was securely wiped.
    assert all(b == 0 for b in sensitive_data_ref), "Security Breach: Key was not zeroized in memory!"