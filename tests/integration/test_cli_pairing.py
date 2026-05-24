"""
Integration tests for P2P pairing flow.
"""
import pytest
import json
import sqlite3
from src.database_manager import DatabaseManager
from src.storage.device_repository import DeviceRepository
from src.crypto.identity import IdentityManager

@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test_pairing.db")
    db = DatabaseManager(db_path=db_path)
    conn = db.connect()
    # Initialize schema
    with open("data/schema.sql", "r") as f:
        conn.executescript(f.read())
    # Create migrations table and apply trusted devices
    conn.execute("CREATE TABLE IF NOT EXISTS migrations (id TEXT PRIMARY KEY)")
    with open("src/storage/migrations/004_trusted_devices.sql", "r") as f:
        conn.executescript(f.read())
    return db

@pytest.fixture
def repo(db):
    return DeviceRepository(db)

def test_pairing_flow_persistence(db, repo):
    # Simulate Generator (Device A) identity
    id_mgr = IdentityManager(db)
    id_mgr.ensure_identity()
    
    # 1. Generate payload
    device_id = "peer-b"
    public_key = b"\x01" * 32
    pairing_payload = json.dumps({
        "device_id": device_id,
        "public_key": public_key.hex()
    })
    
    # 2. Confirm (mimicking sync confirm)
    data = json.loads(pairing_payload)
    repo.add_device(data['device_id'], bytes.fromhex(data['public_key']), nickname="Peer B")
    
    # 3. Verify
    device = repo.get_trusted_device(device_id)
    assert device is not None
    assert device['trust_level'] == 1
    assert device['public_key'] == public_key

def test_revoked_device_listing(db, repo):
    repo.add_device("peer-b", b"\x01" * 32, nickname="Peer B")
    repo.revoke_device("peer-b")
    
    devices = repo.list_trusted_devices(include_revoked=True)
    assert devices[0]['trust_level'] == 0
    
    devices_trusted = repo.list_trusted_devices(include_revoked=False)
    assert len(devices_trusted) == 0

def test_device_removal(db, repo):
    repo.add_device("peer-b", b"\x01" * 32, nickname="Peer B")
    assert len(repo.list_trusted_devices()) == 1
    
    success = repo.remove_device("peer-b")
    assert success is True
    assert len(repo.list_trusted_devices(include_revoked=True)) == 0
