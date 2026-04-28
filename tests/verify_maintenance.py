import os
import sys
import tempfile
sys.path.append(os.getcwd())
from src.vault_controller import VaultController
from src.database_manager import DatabaseManager

def run_tests():
    print("Running Maintenance Rebuild Tests (Standalone)...")
    
    db_path = os.path.join(tempfile.gettempdir(), f"test_maint_{os.getpid()}.db")
    if os.path.exists(db_path): os.remove(db_path)
    
    db = DatabaseManager(db_path)
    db.initialize_database()
    vc = VaultController(db_path)
    vc.unlock_vault("pass", create_if_missing=True)
    
    try:
        # 1. Testing Backup History
        print("Testing Backup History...")
        backup_path = "test_man_backup.enc"
        vc.create_backup(backup_path)
        hist = vc.db.get_backup_history()
        assert len(hist) > 0, "History should not be empty"
        assert hist[0]['operation_type'] == 'CREATED_BACKUP', "Wrong operation type"
        print(f"  Success: {hist[0]}")
        
        # 2. Testing CSV Export
        print("Testing CSV Export...")
        export_path = "test_man_export.csv"
        vc.add_password("T1", "u1", "p1", "h1")
        vc.export_csv(export_path)
        hist = vc.db.get_backup_history()
        assert any(h['operation_type'] == 'EXPORTED_CSV' for h in hist), "Export should be logged"
        print("  Success: Export logged.")
        
        # 3. Testing CSV Import
        print("Testing CSV Import...")
        s, f = vc.import_csv(export_path)
        assert s == 1, f"Expected 1 success, got {s}"
        hist = vc.db.get_backup_history()
        assert any(h['operation_type'] == 'IMPORTED_CSV' for h in hist), "Import should be logged"
        print(f"  Success: Imported {s} entries.")
        
        # 4. Testing Audit Logs
        print("Testing Audit Logs...")
        logs = vc.db.get_audit_logs()
        assert any(l['event_type'] == 'CREATE_BACKUP' for l in logs), "Audit log for backup missing"
        assert any(l['event_type'] == 'EXPORT_CSV' for l in logs), "Audit log for export missing"
        print("  Success: Audit logs found.")
        
        print("\nALL BACKEND TESTS PASSED!")
    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        # if os.path.exists(db_path): os.remove(db_path)
        if os.path.exists("test_man_backup.enc"): os.remove("test_man_backup.enc")
        if os.path.exists("test_man_export.csv"): os.remove("test_man_export.csv")

if __name__ == "__main__":
    run_tests()
