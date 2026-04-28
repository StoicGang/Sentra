import sys
import os
from datetime import datetime

# Adjust path to import from 'src'
sys.path.append(os.getcwd())

from src.vault_controller import VaultController
from src.database_manager import DatabaseManager

def test_recovery_backend():
    print("Running Recovery Rebuild Backend Tests...")
    db_path = "tests/recovery_test.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    vc = VaultController(db_path=db_path)
    password = "test-password-123"
    
    # 1. Setup Vault
    print("Setting up test vault...")
    vc.unlock_vault(password, create_if_missing=True)
    assert vc.is_unlocked
    print("  Success: Vault unlocked.")

    # 2. Test Password Verification
    print("Testing password verification...")
    assert vc.verify_password(password) == True, "Correct password failed"
    assert vc.verify_password("wrong-password") == False, "Wrong password succeeded"
    print("  Success: Password verification works.")

    # 3. Test Recovery Passphrase Setup
    print("Testing Recovery Passphrase setup...")
    vc.setup_recovery_passphrase("my secret recovery phrase")
    status = vc.get_recovery_status()
    assert status['enabled'] == True
    assert status['type'] == 'passphrase'
    print("  Success: Passphrase configured.")

    # 4. Test Recovery Codes Generation
    print("Testing Recovery Codes generation...")
    codes = vc.setup_recovery_codes(count=5)
    assert len(codes) == 5
    status = vc.get_recovery_status()
    assert status['type'] == 'both'
    assert status['codes_remaining'] == 5
    print("  Success: Codes generated and status updated.")

    # 5. Test Recovery Reset
    print("Testing Recovery Reset...")
    vc.reset_recovery()
    status = vc.get_recovery_status()
    assert status['enabled'] == False
    assert status['type'] is None
    print("  Success: Recovery reset.")

    # 6. Verify Audit Logs
    print("Verifying Audit Logs...")
    logs = vc.db.get_audit_logs()
    event_types = [l['event_type'] for l in logs]
    print(f"  Found events: {event_types}")
    
    assert 'RECOVERY_PASSPHRASE_UPDATE' in event_types
    assert 'RECOVERY_CODES_GENERATE' in event_types
    assert 'RECOVERY_RESET' in event_types
    print("  Success: All recovery audit logs found.")

    vc.close()
    # os.remove(db_path) # Cleanup might fail on Windows if locked
    print("\nALL RECOVERY BACKEND TESTS PASSED!")

if __name__ == "__main__":
    try:
        test_recovery_backend()
    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
