"""
Tests for Crash Recovery
Simulates process crashes mid-transaction and verifies recovery.
"""
import pytest
import sqlite3
from src.database_manager import DatabaseManager
from src.sync.sync_journal import SyncJournal, SyncOpType
from src.sync.tombstone_manager import TombstoneManager
from src.sync.sync_transaction_manager import SyncTransactionManager
from src.sync.recovery_manager import RecoveryManager, RecoveryError

@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test_recovery.db")
    db = DatabaseManager(db_path=db_path)
    conn = db.connect()
    with open("data/schema.sql", "r") as f:
        conn.executescript(f.read())
    with open("src/storage/migrations/004_trusted_devices.sql", "r") as f:
        conn.executescript(f.read())
    conn.execute("INSERT INTO trusted_devices (device_id, public_key) VALUES (?, ?)", ("peer1", b"pk"))
    conn.commit()
    return db

@pytest.fixture
def recovery_env(db):
    journal = SyncJournal(db)
    tombstones = TombstoneManager(db)
    tm = SyncTransactionManager(db, journal, tombstones)
    recovery = RecoveryManager(db, journal, tm)
    return db, journal, tm, recovery

def test_recover_interrupted_batch(recovery_env):
    db, journal, tm, recovery = recovery_env
    
    # 1. Manually create a PENDING batch
    batch_id = journal.create_batch("peer1")
    
    # Append an operation
    payload = {
        "title": "RecoverMe",
        "password_encrypted": b"123", 
        "password_nonce": b"n", 
        "password_tag": b"t", 
        "kdf_salt": b"s", 
        "created_at": "now", 
        "modified_at": "now"
    }
    journal.append_operation(batch_id, SyncOpType.INSERT, "e1", "100:0:p1", "p1", payload)
    
    # Verify it is pending
    assert len(journal.get_pending_batches()) == 1
    
    # 2. Recover
    recovery.recover_interrupted_batches()
    
    # 3. Batch should now be COMMITTED as the replay logic worked.
    conn = db.connect()
    row = conn.execute("SELECT status FROM sync_journal WHERE id = ?", (batch_id,)).fetchone()
    assert row['status'] == "COMMITTED"

def test_recovery_integrity_mismatch(recovery_env):
    db, journal, tm, recovery = recovery_env
    
    batch_id = journal.create_batch("peer1")
    journal.append_operation(batch_id, SyncOpType.INSERT, "e1", "100:0:p1", "p1", {"title": "Valid"})
    
    # Manually tamper with integrity hash in DB
    conn = db.connect()
    conn.execute("UPDATE sync_operations SET payload_hash = 'badhash' WHERE batch_id = ?", (batch_id,))
    conn.commit()
    
    # Recovery should fail
    with pytest.raises(RecoveryError, match="Integrity check failed"):
        recovery.recover_interrupted_batches()
