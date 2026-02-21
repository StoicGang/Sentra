"""
tests/test_self_destruct.py
Verification of the Self-Destruct feature (manual and automatic).
"""
import os
import pytest
import shutil
from src.vault_controller import VaultController, VaultDestroyedError, VaultError
from src.database_manager import DatabaseManager

# --- Fixtures ---

@pytest.fixture
def temp_vault(tmp_path):
    """Create a temporary vault with a known master password."""
    db_path = str(tmp_path / "test_vault.db")
    controller = VaultController(db_path=db_path)
    
    # Explicitly initialize schema to ensure all tables exist before any checks
    controller.db.initialize_database()
    controller._schema_initialized = True
    
    controller.unlock_vault("MasterPass123!", create_if_missing=True)
    controller.lock_vault()
    return controller, db_path

# --- Tests ---

class TestSelfDestruct:

    def test_manual_self_destruct_deletes_file(self, temp_vault):
        """Verifying manual self_destruct() physically removes the DB file."""
        controller, db_path = temp_vault
        assert os.path.exists(db_path)

        with pytest.raises(VaultDestroyedError):
            controller.self_destruct()

        assert not os.path.exists(db_path)

    def test_config_persistence(self, temp_vault):
        """Verifying set_config / get_config via the metadata table."""
        controller, _ = temp_vault
        controller.unlock_vault("MasterPass123!")
        
        # Set a config value
        success = controller.set_config("test_key", "test_value")
        assert success is True
        
        # Read it back
        val = controller.get_config("test_key")
        assert val == "test_value"
        
        controller.lock_vault()

    def test_auto_self_destruct_trigger(self, temp_vault):
        """Verifying that N failed logins trigger self-destruct if threshold is set."""
        import time
        controller, db_path = temp_vault
        
        # 1. Enable auto-self-destruct with threshold=3
        controller.unlock_vault("MasterPass123!")
        controller.set_config("auto_self_destruct_threshold", 3)
        controller.lock_vault()
        
        # 2. Fail login 2 times
        # Must sleep to bypass soft lockout delay between attempts
        for _ in range(2):
            with pytest.raises(VaultError) as exc:
                controller.unlock_vault("WRONG")
            assert "Invalid password" in str(exc.value)
            time.sleep(1.1) 
        
        assert os.path.exists(db_path)
        
        # 3. Fail 3rd time (reaches threshold)
        with pytest.raises(VaultDestroyedError):
            controller.unlock_vault("WRONG")
            
        assert not os.path.exists(db_path)

    def test_auto_self_destruct_with_crypto_failure(self, temp_vault):
        """Verifying trigger also works during cryptographic failures (e.g. metadata exists but key is wrong)."""
        controller, db_path = temp_vault
        
        # 1. Enable threshold=1
        controller.unlock_vault("MasterPass123!")
        controller.set_config("auto_self_destruct_threshold", 1)
        controller.lock_vault()
        
        # 2. Trigger a VaultError (invalid password)
        # Note: In our current implementation, even the first fail should trigger it if threshold=1
        with pytest.raises(VaultDestroyedError):
            controller.unlock_vault("WRONG")
            
        assert not os.path.exists(db_path)

    def test_self_destruct_clears_memory(self, temp_vault):
        """Verifying self-destruct locks the vault (clearing keys) before deleting."""
        controller, _ = temp_vault
        controller.unlock_vault("MasterPass123!")
        assert controller.is_unlocked is True
        
        with pytest.raises(VaultDestroyedError):
            controller.self_destruct()
            
        assert controller.is_unlocked is False
        assert controller.master_key_secure is None
        assert controller.vault_key_secure is None
