"""
Tests for Sentra Sync Transaction Manager
"""
import pytest
from src.database_manager import DatabaseManager
from src.sync.sync_journal import SyncJournal, SyncOpType
from src.sync.tombstone_manager import TombstoneManager
from src.sync.sync_transaction_manager import SyncTransactionManager, SyncTransactionError

@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test_transaction.db")
    db = DatabaseManager(db_path=db_path)
    conn = db.connect()
    with open("data/schema.sql", "r") as f:
        conn.executescript(f.read())
    with open("src/storage/migrations/004_trusted_devices.sql", "r") as f:
        conn.executescript(f.read())
    # Add peer to trusted_devices for FK
    conn.execute("INSERT INTO trusted_devices (device_id, public_key) VALUES (?, ?)", ("peer1", b"pubkey"))
    conn.commit()
    return db

@pytest.fixture
def manager(db):
    journal = SyncJournal(db)
    tombstones = TombstoneManager(db)
    return SyncTransactionManager(db, journal, tombstones)

def test_atomic_apply_insert(manager):
    ops = [
        {
            "op_type": "INSERT",
            "entry_id": "e1",
            "hlc": "1000:0:p1",
            "origin_device_id": "p1",
            "payload": {
                "title": "Secret", 
                "password_encrypted": b"123", 
                "password_nonce": b"n", 
                "password_tag": b"t", 
                "kdf_salt": b"s", 
                "created_at": "now", 
                "modified_at": "now"
            }
        }
    ]
    
    manager.apply_sync_batch("peer1", ops)
    
    conn = manager.db.connect()
    row = conn.execute("SELECT title, password_encrypted FROM entries WHERE id = 'e1'").fetchone()
    assert row['title'] == "Secret"
    assert row['password_encrypted'] == b"123"

def test_conflict_resolution_lww(manager):
    # Setup local entry
    conn = manager.db.connect()
    conn.execute("""
        INSERT INTO entries (id, hlc, origin_device_id, title, password_encrypted, password_nonce, password_tag, kdf_salt, created_at, modified_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, ('e1', '2000:0:local', 'local', 'Local Old', b'p', b'n', b't', b's', 'now', 'now'))
    conn.commit()
    
    # Remote update with SMALLER HLC
    ops = [{
        "op_type": "UPDATE",
        "entry_id": "e1",
        "hlc": "1000:0:peer1",
        "origin_device_id": "peer1",
        "payload": {"title": "Remote Stale"}
    }]
    manager.apply_sync_batch("peer1", ops)
    assert conn.execute("SELECT title FROM entries WHERE id = 'e1'").fetchone()['title'] == "Local Old"
    
    # Remote update with HIGHER HLC
    ops = [{
        "op_type": "UPDATE",
        "entry_id": "e1",
        "hlc": "3000:0:peer1",
        "origin_device_id": "peer1",
        "payload": {"title": "Remote Newer"}
    }]
    manager.apply_sync_batch("peer1", ops)
    assert conn.execute("SELECT title FROM entries WHERE id = 'e1'").fetchone()['title'] == "Remote Newer"

def test_tombstone_block_resurrection(manager):
    # 1. Local Delete
    manager.apply_sync_batch("peer1", [{
        "op_type": "DELETE",
        "entry_id": "e1",
        "hlc": "2000:0:p1",
        "origin_device_id": "p1"
    }])
    
    assert manager.tombstones.is_deleted("e1") is True
    
    # 2. Incoming stale update for deleted entry
    ops = [{
        "op_type": "UPDATE",
        "entry_id": "e1",
        "hlc": "1000:0:p2",
        "origin_device_id": "p2",
        "payload": {
            "title": "Resurrected?",
            "password_encrypted": b"123", 
            "password_nonce": b"n", 
            "password_tag": b"t", 
            "kdf_salt": b"s", 
            "created_at": "now", 
            "modified_at": "now"
        }
    }]
    manager.apply_sync_batch("peer1", ops)
    
    # Should still be deleted
    conn = manager.db.connect()
    assert conn.execute("SELECT COUNT(*) as cnt FROM entries WHERE id = 'e1'").fetchone()['cnt'] == 0

def test_rollback_on_failure(manager):
    # Mocking a failure inside apply_sync_batch is best done via malformed payload or DB error
    # We'll use a payload that violates a constraint if possible, or just a bad type
    ops = [
        {
            "op_type": "INSERT", 
            "entry_id": "e1", 
            "hlc": "1000:0:p1", 
            "origin_device_id": "p1", 
            "payload": {
                "title": "valid",
                "password_encrypted": b"123", 
                "password_nonce": b"n", 
                "password_tag": b"t", 
                "kdf_salt": b"s", 
                "created_at": "now", 
                "modified_at": "now"
            }
        },
        {"op_type": "INVALID", "entry_id": "e2", "hlc": "1001:0:p1", "origin_device_id": "p1"} 
    ]
    
    with pytest.raises(SyncTransactionError):
        manager.apply_sync_batch("peer1", ops)
        
    # Verify first op was rolled back
    conn = manager.db.connect()
    assert conn.execute("SELECT COUNT(*) as cnt FROM entries WHERE id = 'e1'").fetchone()['cnt'] == 0
    
    # Verify journal state
    row = conn.execute("SELECT status FROM sync_journal ORDER BY id DESC LIMIT 1").fetchone()
    assert row['status'] == "ROLLED_BACK"

def test_idempotency(manager):
    op = {
        "op_type": "INSERT",
        "entry_id": "e1",
        "hlc": "1000:0:p1",
        "origin_device_id": "p1",
        "payload": {
            "title": "First",
            "password_encrypted": b"123", 
            "password_nonce": b"n", 
            "password_tag": b"t", 
            "kdf_salt": b"s", 
            "created_at": "now", 
            "modified_at": "now"
        }
    }
    
    manager.apply_sync_batch("peer1", [op])
    manager.apply_sync_batch("peer1", [op]) # Re-apply same op
    
    conn = manager.db.connect()
    rows = conn.execute("SELECT title FROM entries WHERE id = 'e1'").fetchall()
    assert len(rows) == 1
    assert rows[0]['title'] == "First"
