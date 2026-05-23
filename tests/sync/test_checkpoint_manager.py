"""
Tests for Sentra Checkpoint Manager
"""
import pytest
from src.database_manager import DatabaseManager
from src.sync.checkpoint_manager import CheckpointManager, CheckpointError
from src.sync.hlc import HybridLogicalClock
from src.storage.device_repository import DeviceRepository # To add trusted device

@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test_checkpoint.db")
    db = DatabaseManager(db_path=db_path)
    conn = db.connect()
    with open("data/schema.sql", "r") as f:
        conn.executescript(f.read())
    with open("src/storage/migrations/004_trusted_devices.sql", "r") as f:
        conn.executescript(f.read())
    return db

@pytest.fixture
def repo(db):
    return DeviceRepository(db)

@pytest.fixture
def cm(db, repo):
    repo.add_device("peer1", b"pubkey1", "Peer 1")
    repo.add_device("peer2", b"pubkey2", "Peer 2")
    return CheckpointManager(db)

def test_update_and_get_checkpoint(cm):
    peer_id = "peer1"
    hlc1 = "1000:0:peer1"
    
    assert cm.update_checkpoint(peer_id, hlc1) is True
    assert cm.get_peer_checkpoint(peer_id) == hlc1
    
    hlc2 = "1000:1:peer1"
    assert cm.update_checkpoint(peer_id, hlc2) is True
    assert cm.get_peer_checkpoint(peer_id) == hlc2

def test_update_checkpoint_monotonicity(cm):
    peer_id = "peer1"
    hlc1 = "1000:0:peer1"
    hlc2 = "1000:1:peer1"
    
    cm.update_checkpoint(peer_id, hlc2)
    # Attempt to update with an older HLC, should be ignored
    cm.update_checkpoint(peer_id, hlc1)
    assert cm.get_peer_checkpoint(peer_id) == hlc2

def test_rollback_checkpoint_valid(cm):
    peer_id = "peer2"
    hlc_current = "2000:0:peer2"
    hlc_target = "1000:0:peer2"
    
    cm.update_checkpoint(peer_id, hlc_current)
    assert cm.rollback_checkpoint(peer_id, hlc_target) is True
    assert cm.get_peer_checkpoint(peer_id) == hlc_target

def test_rollback_checkpoint_to_newer_hlc_fails(cm):
    peer_id = "peer2"
    hlc_current = "1000:0:peer2"
    hlc_target = "2000:0:peer2"
    
    cm.update_checkpoint(peer_id, hlc_current)
    with pytest.raises(CheckpointError, match="Cannot rollback checkpoint to a newer HLC"):
        cm.rollback_checkpoint(peer_id, hlc_target)
    assert cm.get_peer_checkpoint(peer_id) == hlc_current # Should not have changed

def test_verify_checkpoint_integrity(cm):
    peer_id = "peer1"
    hlc = "1000:0:peer1"
    cm.update_checkpoint(peer_id, hlc)
    
    assert cm.verify_checkpoint_integrity(peer_id, hlc) is True
    assert cm.verify_checkpoint_integrity(peer_id, "2000:0:peer1") is False
    
    # Test initial state
    assert cm.get_peer_checkpoint("new_peer") is None
    assert cm.verify_checkpoint_integrity("new_peer", None) is True
