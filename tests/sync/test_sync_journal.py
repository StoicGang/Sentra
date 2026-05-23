"""
Tests for Sentra Sync Journal
"""
import pytest
from src.database_manager import DatabaseManager
from src.sync.sync_journal import SyncJournal, SyncOpType, BatchStatus

@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test_journal.db")
    db = DatabaseManager(db_path=db_path)
    # Use schema and migration 004
    conn = db.connect()
    with open("data/schema.sql", "r") as f:
        conn.executescript(f.read())
    with open("src/storage/migrations/004_trusted_devices.sql", "r") as f:
        conn.executescript(f.read())
    return db

@pytest.fixture
def journal(db):
    # Add peer for FK
    db.connect().execute("INSERT INTO trusted_devices (device_id, public_key) VALUES (?, ?)", ('peer1', b'pk'))
    db.connect().commit()
    return SyncJournal(db)

def test_batch_lifecycle(journal):
    batch_id = journal.create_batch("peer1")
    assert batch_id > 0
    
    journal.append_operation(batch_id, SyncOpType.INSERT, "entry1", "100:0:peer1", "peer1", {"data": "foo"})
    
    pending = journal.get_pending_batches()
    assert len(pending) == 1
    assert pending[0]['id'] == batch_id
    
    journal.commit_batch(batch_id)
    assert len(journal.get_pending_batches()) == 0

def test_batch_rollback(journal):
    batch_id = journal.create_batch("peer1")
    journal.rollback_batch(batch_id)
    
    conn = journal.db.connect()
    row = conn.execute("SELECT status FROM sync_journal WHERE id = ?", (batch_id,)).fetchone()
    assert row['status'] == BatchStatus.ROLLED_BACK.value

def test_get_batch_operations(journal):
    batch_id = journal.create_batch("peer1")
    journal.append_operation(batch_id, SyncOpType.UPDATE, "e1", "100:0", "p1")
    journal.append_operation(batch_id, SyncOpType.UPDATE, "e2", "101:0", "p1")
    
    ops = journal.get_batch_operations(batch_id)
    assert len(ops) == 2
    assert ops[0]['entry_id'] == "e1"
    assert ops[1]['entry_id'] == "e2"

def test_purge_old_batches(journal):
    batch_id = journal.create_batch("peer1")
    journal.commit_batch(batch_id)
    
    # 1. Test that it DOES NOT purge recently created batch (with 30 day threshold)
    journal.purge_old_batches(days=30)
    conn = journal.db.connect()
    assert conn.execute("SELECT COUNT(*) as cnt FROM sync_journal").fetchone()['cnt'] == 1
    
    # 2. Test that it DOES purge if we use a "negative" days to shift boundary into the future
    # SQLite: datetime('now', '- -1 days') == datetime('now', '+1 days')
    journal.purge_old_batches(days=-1)
    assert conn.execute("SELECT COUNT(*) as cnt FROM sync_journal").fetchone()['cnt'] == 0
