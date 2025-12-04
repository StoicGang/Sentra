import os
import pytest
import gc 
from src.vault_controller import VaultController, VaultLockedError, VaultError, VaultAlreadyUnlockedError

# -----------------------------------------------------------------------------
# FIXTURES
# -----------------------------------------------------------------------------

@pytest.fixture
def vault():
    """Fixture to provide a clean vault controller for each test method"""
    db_path = "data/test_vault_class.db"
    
    # Setup: Ensure no leftover DB exists
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except PermissionError:
            pass 

    controller = VaultController(db_path)
    
    yield controller
    
    # Teardown: Clean up resources
    try:
        if controller.db.connection:
            controller.db.close()
            
        if controller.is_unlocked:
            try:
                controller.lock_vault()
            except:
                pass 
    except Exception:
        pass
    
    # Force garbage collection to release SQLite file locks
    del controller
    gc.collect()

    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except PermissionError:
            pass


# -----------------------------------------------------------------------------
# TEST CLASSES
# -----------------------------------------------------------------------------

class TestVaultAuthentication:
    """Tests related to locking, unlocking, and state management"""

    def test_unlock_and_lock_lifecycle(self, vault):
        # Initial state
        assert vault.is_unlocked is False

        # Unlock
        password = "StrongPassword123!"
        assert vault.unlock_vault(password) is True
        assert vault.is_unlocked is True

        # Unlocking again should fail
        with pytest.raises(VaultAlreadyUnlockedError):
            vault.unlock_vault(password)

        # Lock
        assert vault.lock_vault() is True
        assert vault.is_unlocked is False

    def test_idempotent_lock(self, vault):
        """Locking an already locked vault should be silent success"""
        assert vault.lock_vault() is True


class TestEntryBasicOperations:
    """Tests for basic Add/Get operations and validations"""

    def test_add_and_get_password_success(self, vault):
        vault.unlock_vault("Pass123!")

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

        entry = vault.get_password(entry_id)
        assert entry["title"] == "My Email"
        assert entry["password"] == "P@ssw0rd!"
        assert entry["category"] == "Email"

    def test_operation_while_locked_fails(self, vault):
        """Verify operations raise VaultLockedError when locked"""
        with pytest.raises(VaultLockedError):
            vault.add_password(title="Example")

        with pytest.raises(VaultLockedError):
            vault.get_password("nonexistent-id")

    def test_add_password_invalid_input(self, vault):
        vault.unlock_vault("Pass123!")
        with pytest.raises(VaultError):
            vault.add_password(title="")  # Empty title not allowed


class TestEntryFeatures:
    """Tests for specific entry features like Strength, Favorites, etc."""

    def test_auto_password_strength_calculation(self, vault):
        vault.unlock_vault("Pass123!")

        # Weak
        weak_id = vault.add_password(title="Weak", password="123")
        # Strong
        strong_id = vault.add_password(title="Strong", password="Correct-Horse-Battery-Staple-99!")

        weak_entry = vault.get_password(weak_id)
        strong_entry = vault.get_password(strong_id)

        assert weak_entry['password_strength'] < 50
        assert strong_entry['password_strength'] > 50

    def test_favorites_handling(self, vault):
        vault.unlock_vault("Pass123!")
        eid = vault.add_password(title="Fav", password="pass", favorite=True)
        assert vault.get_password(eid)['favorite'] is True


class TestVaultLifecycle:
    """Tests for the full lifecycle: List, Update, Delete, Restore, Search"""

    def test_crud_delegation_flow(self, vault):
        vault.unlock_vault("Pass123!")

        # 1. ADD
        eid = vault.add_password(title="Lifecycle Test", password="Init")
        
        # 2. LIST
        entries = vault.list_entries()
        assert len(entries) == 1
        assert entries[0]['title'] == "Lifecycle Test"

        # 3. UPDATE
        vault.update_entry(eid, title="Updated Title", password="New")
        updated = vault.get_password(eid)
        assert updated['title'] == "Updated Title"
        assert updated['password'] == "New"

        # 4. DELETE
        vault.delete_entry(eid)
        assert len(vault.list_entries()) == 0

        # 5. RESTORE
        vault.restore_entry(eid)
        assert len(vault.list_entries()) == 1
        assert vault.get_password(eid)['title'] == "Updated Title"

    def test_search_integration(self, vault):
        vault.unlock_vault("Pass123!")
        
        vault.add_password(title="GitHub", tags="dev")
        vault.add_password(title="GitLab", tags="dev")
        trash_id = vault.add_password(title="Old Yahoo", tags="email")
        
        vault.delete_entry(trash_id)

        # Active Search
        results = vault.search_entries("Git")
        assert len(results) == 2

        # Deleted Search
        results_deleted = vault.search_entries("Yahoo", include_deleted=True)
        assert len(results_deleted) == 1
        assert results_deleted[0]['id'] == trash_id


class TestVaultSecurity:
    """Tests for critical security requirements"""

    def test_memory_zeroization(self, vault):
        """Ensure keys are wiped from RAM after lock"""
        vault.unlock_vault("Pass123!")
        
        # Capture reference to the mutable buffer
        key_ref = vault.master_key_secure
        assert any(b != 0 for b in key_ref)
        
        vault.lock_vault()
        
        # Verify in-place zeroization
        assert all(b == 0 for b in key_ref)

    def test_audit_log_generation(self, vault):
        vault.unlock_vault("Pass123!")
        vault.add_password(title="Audit Check")
        
        logs = vault.view_audit_log()
        assert len(logs) > 0
        assert logs[0]['action_type'] == 'CREATE'
