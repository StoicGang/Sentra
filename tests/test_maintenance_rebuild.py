import os
import pytest
from src.vault_controller import VaultController
from src.database_manager import DatabaseManager

@pytest.fixture
def vault():
    db_path = "data/test_maintenance.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    
    # Initialize DB with schema
    db = DatabaseManager(db_path)
    db.initialize_database()
    
    vc = VaultController(db_path)
    vc.create_vault("test_maintenance.db", "strong_password")
    vc.unlock_vault("strong_password", "test_maintenance.db")
    
    yield vc
    
    if os.path.exists(db_path):
        os.remove(db_path)
    if os.path.exists("test_backup.enc"):
        os.remove("test_backup.enc")
    if os.path.exists("test_export.csv"):
        os.remove("test_export.csv")

def test_backup_history_logging(vault):
    # 1. Create Backup
    backup_path = "test_backup.enc"
    vault.create_backup(backup_path)
    
    history = vault.db.get_backup_history()
    assert len(history) >= 1
    assert history[0]['operation_type'] == 'CREATED_BACKUP'
    assert history[0]['status'] == 'Success'
    assert history[0]['filename'] == os.path.basename(backup_path)
    assert history[0]['file_size'] > 0

def test_csv_export_and_import(vault):
    # 1. Add some entries
    vault.add_password("Test1", "user1", "pass1", "https://test1.com")
    vault.add_password("Test2", "user2", "pass2", "https://test2.com")
    
    # 2. Export
    export_path = "test_export.csv"
    vault.export_csv(export_path)
    
    history = vault.db.get_backup_history()
    assert any(h['operation_type'] == 'EXPORTED_CSV' for h in history)
    
    # 3. Import back
    success, failed = vault.import_csv(export_path)
    assert success == 2
    assert failed == 0
    
    history = vault.db.get_backup_history()
    assert any(h['operation_type'] == 'IMPORTED_CSV' for h in history)

def test_audit_logging(vault):
    vault.create_backup("test_backup.enc")
    
    # We need to find Audit logs
    logs = vault.db.get_audit_logs(limit=10)
    assert any(l['action_type'] == 'CREATE_BACKUP' for l in logs)

if __name__ == "__main__":
    # Simple manual runner
    print("Running Maintenance Rebuild Tests...")
    import tempfile
    
    db_path = os.path.join(tempfile.gettempdir(), "test_maint.db")
    if os.path.exists(db_path): os.remove(db_path)
    
    db = DatabaseManager(db_path)
    db.initialize_database()
    vc = VaultController(db_path)
    vc.create_vault("test_maint.db", "pass")
    vc.unlock_vault("pass", "test_maint.db")
    
    try:
        print("Testing Backup History...")
        backup_path = "test_man_backup.enc"
        vc.create_backup(backup_path)
        hist = vc.db.get_backup_history()
        assert len(hist) > 0
        print(f"  Success: {hist[0]}")
        
        print("Testing CSV Export...")
        export_path = "test_man_export.csv"
        vc.add_password("T1", "u1", "p1", "h1")
        vc.export_csv(export_path)
        hist = vc.db.get_backup_history()
        assert any(h['operation_type'] == 'EXPORTED_CSV' for h in hist)
        print("  Success: Export logged.")
        
        print("Testing CSV Import...")
        s, f = vc.import_csv(export_path)
        assert s == 1
        print(f"  Success: Imported {s} entries.")
        
        print("Testing Audit Logs...")
        logs = vc.db.get_audit_logs()
        assert any(l['action_type'] == 'CREATE_BACKUP' for l in logs)
        print("  Success: Audit logs found.")
        
        print("\nALL BACKEND TESTS PASSED!")
    finally:
        if os.path.exists(db_path): os.remove(db_path)
        if os.path.exists("test_man_backup.enc"): os.remove("test_man_backup.enc")
        if os.path.exists("test_man_export.csv"): os.remove("test_man_export.csv")
