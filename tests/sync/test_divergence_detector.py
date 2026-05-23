"""
Tests for Sentra Divergence Detector
"""
import pytest
from unittest.mock import MagicMock, patch

from src.database_manager import DatabaseManager
from src.sync.hlc import HybridLogicalClock
from src.sync.checkpoint_manager import CheckpointManager
from src.sync.divergence_detector import DivergenceDetector, DivergenceError
from src.storage.device_repository import DeviceRepository


@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test_divergence.db")
    db = DatabaseManager(db_path=db_path)
    conn = db.connect()
    with open("data/schema.sql", "r") as f:
        conn.executescript(f.read())
    with open("src/storage/migrations/004_trusted_devices.sql", "r") as f:
        conn.executescript(f.read())
    return db

@pytest.fixture
def hlc():
    return HybridLogicalClock("local_node")

@pytest.fixture
def cm(db, repo): # repo is from test_checkpoint_manager fixture.
    return CheckpointManager(db)

@pytest.fixture
def repo(db):
    r = DeviceRepository(db)
    r.add_device("peer1", b"pubkey1", "Peer 1")
    return r

@pytest.fixture
def detector(db, cm, repo, hlc):
    return DivergenceDetector(db, cm, repo, hlc)

# Helper to add entries to the mock DB
def add_entry(db, entry_id, hlc_str, origin_device_id, title="Test"):
    conn = db.connect()
    conn.execute("""
        INSERT INTO entries (id, hlc, origin_device_id, title, password_encrypted, password_nonce, password_tag, kdf_salt, created_at, modified_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (entry_id, hlc_str, origin_device_id, title, b'p', b'n', b't', b's', 'now', 'now'))
    conn.commit()


def test_compute_local_manifest_empty(detector):
    manifest = detector.compute_local_manifest()
    assert manifest["last_hlc"] == ""
    assert manifest["entry_count"] == 0
    assert manifest["entries_hash"] == ""

def test_compute_local_manifest_with_entries(detector, db):
    add_entry(db, "e1", "1000:0:local", "local")
    add_entry(db, "e2", "1000:1:local", "local")
    
    manifest = detector.compute_local_manifest()
    assert manifest["entry_count"] == 2
    assert HybridLogicalClock.compare(manifest["last_hlc"], "1000:1:local") == 0
    assert manifest["entries_hash"] != ""

def test_compare_peer_state_in_sync(detector, db):
    add_entry(db, "e1", "1000:0:local", "local")
    local_manifest = detector.compute_local_manifest()
    
    # Remote is identical
    remote_manifest = local_manifest
    status = detector.compare_peer_state("peer1", remote_manifest)
    assert status == "IN_SYNC"

def test_compare_peer_state_remote_ahead(detector, db):
    add_entry(db, "e1", "1000:0:local", "local")
    
    remote_manifest = detector.compute_local_manifest() # Base for remote
    remote_manifest["last_hlc"] = "2000:0:peer1"
    remote_manifest["entry_count"] = 2 # Simulate extra entry
    remote_manifest["entries_hash"] = "different_hash"
    
    status = detector.compare_peer_state("peer1", remote_manifest)
    assert status == "REMOTE_AHEAD"

def test_compare_peer_state_local_ahead(detector, db):
    add_entry(db, "e1", "2000:0:local", "local") # Local is ahead
    
    remote_manifest = detector.compute_local_manifest("1000:0:local") # Simulate older remote manifest
    remote_manifest["last_hlc"] = "1000:0:peer1"
    remote_manifest["entry_count"] = 1
    remote_manifest["entries_hash"] = "different_hash_for_older_state"

    status = detector.compare_peer_state("peer1", remote_manifest)
    assert status == "LOCAL_AHEAD"

def test_compare_peer_state_diverged(detector, db):
    # Both have made changes at the same effective HLC, but different content
    add_entry(db, "e1", "1000:0:local", "local", "LocalTitle")
    
    remote_manifest = detector.compute_local_manifest() # Same HLC as local
    remote_manifest["entries_hash"] = "hash_for_different_content" # but different content
    
    status = detector.compare_peer_state("peer1", remote_manifest)
    assert status == "DIVERGED"

def test_protocol_version_mismatch(detector):
    local_manifest = detector.compute_local_manifest()
    remote_manifest = local_manifest.copy()
    remote_manifest["protocol_version"] = "99.0"
    
    with pytest.raises(DivergenceError, match="Incompatible protocol versions"):
        detector.compare_peer_state("peer1", remote_manifest)

def test_verify_manifest_integrity(detector):
    manifest = {"last_hlc": "1000:0:p1", "entries_hash": "some_hash"}
    assert detector.verify_manifest(manifest) is True
    
    invalid_manifest = {"last_hlc": "1000:0:p1"} # Missing hash
    assert detector.verify_manifest(invalid_manifest) is False
