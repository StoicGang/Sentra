"""
Tests for Sentra Device Repository
"""
import pytest
from src.database_manager import DatabaseManager
from src.storage.device_repository import DeviceRepository
from src.sync.hlc import HybridLogicalClock

@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test_sentra.db")
    db = DatabaseManager(db_path=db_path)
    
    # Initialize with core schema and our migration
    conn = db.connect()
    with open("data/schema.sql", "r") as f:
        conn.executescript(f.read())
    with open("src/storage/migrations/004_trusted_devices.sql", "r") as f:
        conn.executescript(f.read())
    
    return db

@pytest.fixture
def repo(db):
    return DeviceRepository(db)

def test_add_and_get_device(repo):
    device_id = "device1"
    public_key = b"pubkey1"
    nickname = "My Phone"
    
    assert repo.add_device(device_id, public_key, nickname) is True
    
    device = repo.get_trusted_device(device_id)
    assert device is not None
    assert device["device_id"] == device_id
    assert device["public_key"] == public_key
    assert device["nickname"] == nickname
    assert device["trust_level"] == 1

def test_revoke_device(repo):
    device_id = "device1"
    repo.add_device(device_id, b"key", "nickname")
    
    assert repo.revoke_device(device_id) is True
    
    device = repo.get_trusted_device(device_id)
    assert device["trust_level"] == 0
    
    # List should not include revoked by default
    devices = repo.list_trusted_devices()
    assert len(devices) == 0
    
    # List with revoked
    all_devices = repo.list_trusted_devices(include_revoked=True)
    assert len(all_devices) == 1

def test_update_last_seen(repo):
    device_id = "device1"
    repo.add_device(device_id, b"key", "nickname")
    
    hlc = "1234567890:0001:device1"
    assert repo.update_last_seen(device_id, last_hlc=hlc) is True
    
    device = repo.get_trusted_device(device_id)
    assert device["last_synced_hlc"] == hlc
    assert device["last_seen_at"] is not None

def test_local_identity_roundtrip(repo):
    device_id = "local_device"
    public_key = b"pubkey"
    private_key_enc = b"encrypted_privkey"
    nonce = b"nonce"
    tag = b"tag"
    
    assert repo.store_local_identity(device_id, public_key, private_key_enc, nonce, tag) is True
    
    identity = repo.get_local_identity()
    assert identity is not None
    assert identity["device_id"] == device_id
    assert identity["public_key"] == public_key
    assert identity["private_key_encrypted"] == private_key_enc
    assert identity["nonce"] == nonce
    assert identity["tag"] == tag

def test_add_device_on_conflict_update(repo):
    device_id = "device1"
    repo.add_device(device_id, b"key1", "name1")
    
    # Update same device
    assert repo.add_device(device_id, b"key2", "name2") is True
    
    device = repo.get_trusted_device(device_id)
    assert device["public_key"] == b"key2"
    assert device["nickname"] == "name2"
