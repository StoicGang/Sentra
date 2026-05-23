"""
Tests for Sentra Tombstone Manager
"""
import pytest
import time
from src.database_manager import DatabaseManager
from src.sync.tombstone_manager import TombstoneManager

@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test_tombstones.db")
    db = DatabaseManager(db_path=db_path)
    conn = db.connect()
    with open("data/schema.sql", "r") as f:
        conn.executescript(f.read())
    with open("src/storage/migrations/004_trusted_devices.sql", "r") as f:
        conn.executescript(f.read())
    return db

@pytest.fixture
def tm(db):
    return TombstoneManager(db)

def test_create_and_check_tombstone(tm):
    entry_id = "e1"
    hlc = "1000:0:p1"
    tm.create_tombstone(entry_id, hlc, "p1")
    
    assert tm.is_deleted(entry_id) is True
    assert tm.is_deleted("unknown") is False
    
    t = tm.get_tombstone(entry_id)
    assert t['deleted_hlc'] == hlc

def test_resurrection_prevention(tm):
    entry_id = "e1"
    delete_hlc = "2000:0:p1"
    tm.create_tombstone(entry_id, delete_hlc, "p1")
    
    # Stale update (before delete)
    assert tm.should_apply_update(entry_id, "1000:0:p2") is False
    
    # Same time update
    assert tm.should_apply_update(entry_id, delete_hlc) is False
    
    # Newer update (after delete) - Resurrection allowed if HLC is higher? 
    # Actually, in some systems tombstone always wins until purged. 
    # In ours, hlc > deleted_hlc allows update.
    assert tm.should_apply_update(entry_id, "3000:0:p2") is True

def test_tombstone_update_monotonic(tm):
    entry_id = "e1"
    tm.create_tombstone(entry_id, "1000:0:p1", "p1")
    # Receive an older tombstone for same ID
    tm.create_tombstone(entry_id, "500:0:p2", "p2")
    
    assert tm.get_tombstone(entry_id)['deleted_hlc'] == "1000:0:p1"
    
    # Receive a newer tombstone
    tm.create_tombstone(entry_id, "2000:0:p2", "p2")
    assert tm.get_tombstone(entry_id)['deleted_hlc'] == "2000:0:p2"

def test_purge_tombstones(tm):
    # Set tombstone to long ago
    tm.create_tombstone("old", "100:0:p1", "p1")
    tm.create_tombstone("new", f"{int(time.time())}:0:p1", "p1")
    
    tm.purge_expired_tombstones(days=30)
    
    assert tm.is_deleted("old") is False
    assert tm.is_deleted("new") is True
