import sys
import os
import time

# Adjust path to import from 'src'
sys.path.append(os.getcwd())

from src.vault_controller import VaultController, VaultDestroyedError

def test_self_destruct():
    print("Running Self-Destruct Backend Tests...")
    db_path = "tests/sd_test.db"
    backup_path = "tests/sd_backup.enc"
    
    if os.path.exists(db_path):
        os.remove(db_path)
    if os.path.exists(backup_path):
        os.remove(backup_path)

    vc = VaultController(db_path=db_path)
    password = "test-password-123"
    
    # 1. Setup Vault
    print("Setting up test vault...")
    vc.unlock_vault(password, create_if_missing=True)
    assert vc.is_unlocked
    
    # 2. Mock a backup in history
    print("creating mock backup record...")
    with open(backup_path, "w") as f:
        f.write("mock backup content")
    
    vc.db.connect().execute(
        "INSERT INTO backup_history (operation_type, filename, status) VALUES (?, ?, ?)",
        ("CREATED_BACKUP", backup_path, "Success")
    )
    vc.db.connect().commit()
    
    # 3. Enable Auto-Destruct
    print("Enabling auto-destruct (threshold=2)...")
    vc.db.update_metadata("auto_self_destruct_enabled", "true")
    vc.db.update_metadata("auto_self_destruct_threshold", "2")
    
    # 4. Simulate failed logins
    print("Simulating first failed login...")
    try:
        vc.lock_vault()
        vc.unlock_vault("wrong-password")
    except Exception:
        pass
    
    assert os.path.exists(db_path), "Vault should still exist after 1 failure"
    assert os.path.exists(backup_path), "Backup should still exist after 1 failure"
    
    print("Waiting for soft lockout delay (1s)...")
    time.sleep(1.2)

    print("Simulating second failed login (triggering auto-destruct)...")
    try:
        vc.unlock_vault("wrong-password")
    except VaultDestroyedError as e:
        print(f"  Caught expected error: {e}")
    except Exception as e:
        print(f"  Unexpected error: {type(e).__name__}: {e}")

    # 5. Verify annihilation
    print("Verifying annihilation...")
    assert not os.path.exists(db_path), "Vault DB file was NOT deleted!"
    assert not os.path.exists(backup_path), "Backup file was NOT deleted!"
    print("  Success: Vault and backups annihilated.")

    print("\nALL SELF-DESTRUCT BACKEND TESTS PASSED!")

if __name__ == "__main__":
    try:
        test_self_destruct()
    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
