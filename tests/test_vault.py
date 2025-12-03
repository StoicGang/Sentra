import os
import pytest
import gc 
from src.vault_controller import VaultController, VaultLockedError, VaultError, VaultAlreadyUnlockedError

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

def test_search_entries(vault):
    # Ensure vault is unlocked before searching
    vault.unlock_vault("StrongPassword123!")

    # Setup: Add sample entries
    e1_id = vault.add_password(
        title="Example Entry",
        url="https://example.com",
        username="user1",
        password="pass1",
        tags="email,personal",
        category="Email"
    )
    e2_id = vault.add_password(
        title="Old Entry",
        url="https://old.com",
        username="user2",
        password="pass2",
        tags="work,archive",
        category="Work"
    )
    
    # Soft delete second entry
    vault.db.mark_entry_deleted(e2_id)

    # 1. Search existing keyword
    results = vault.search_entries("example")
    assert isinstance(results, list)
    assert any("example" in entry["title"].lower() for entry in results)

    # 2. Search with include_deleted=False
    results_no_deleted = vault.search_entries("old", include_deleted=False)
    # Updated key: isdeleted -> is_deleted
    assert all(entry.get("is_deleted", 0) == 0 for entry in results_no_deleted)

    # 3. Search with include_deleted=True
    results_with_deleted = vault.search_entries("old", include_deleted=True)
    # Updated key: isdeleted -> is_deleted
    assert any(entry.get("is_deleted", 0) == 1 for entry in results_with_deleted)

    # 4. Check vault locked behavior
    vault.lock_vault()
    try:
        vault.search_entries("test")
        assert False, "Search should fail when vault is locked."
    except VaultLockedError:
        pass

def test_auto_password_strength(vault):
    """Test that adding a password automatically calculates strength"""
    vault.unlock_vault("StrongPassword123!")

    # 1. Add a WEAK password
    weak_id = vault.add_password(
        title="Weak Entry",
        password="123"
    )
    
    # 2. Add a STRONG password
    strong_id = vault.add_password(
        title="Strong Entry",
        password="Correct-Horse-Battery-Staple-99!"
    )

    # 3. Verify scores
    weak_entry = vault.get_password(weak_id)
    strong_entry = vault.get_password(strong_id)

    # Note: Exact score depends on your alg, but weak should be low, strong high
    assert weak_entry['password_strength'] < 50, "Weak password should have low score"
    assert strong_entry['password_strength'] > 50, "Strong password should have high score"

def test_favorites_handling(vault):
    """Test toggling favorite status via controller"""
    vault.unlock_vault("StrongPassword123!")

    # Add as favorite
    entry_id = vault.add_password(
        title="My Favorite",
        password="pass",
        favorite=True
    )

    entry = vault.get_password(entry_id)
    assert entry['favorite'] is True

def test_audit_log_access(vault):
    """Test accessing audit logs via controller"""
    vault.unlock_vault("StrongPassword123!")

    # Create activity
    vault.add_password(title="Log Entry 1")
    vault.add_password(title="Log Entry 2")

    # Fetch logs
    logs = vault.view_audit_log()
    
    assert isinstance(logs, list)
    assert len(logs) >= 2
    assert logs[0]['action_type'] == 'CREATE'


if __name__ == "__main__":
    test_add_and_get_password_success()
    test_add_password_invalid_title()
    test_add_password_locked_fails()
    test_search_entries()
    test_data_is_destroyed_after_lock()
    test_vault_unlock_and_lock()
    test_auto_password_strength() 
    test_favorites_handling()     
    test_audit_log_access()
    print("\n all test cases passed")