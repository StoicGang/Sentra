"""
Integration tests for P2P pairing flow.
"""
import pytest
import json
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
    with open("src/storage/migrations/004_trusted_devices.sql", "r") as f:
        conn.executescript(f.read())
    return db

@pytest.fixture
def repo(db):
    return DeviceRepository(db)

def test_pairing_flow(db, repo):
    # Simulate Generator (Device A) identity
    id_mgr = IdentityManager(db)
    id_mgr.ensure_identity()
    
    # 1. Generate payload (mimicking 'sync pair' command)
    device_id = "peer-b"
    public_key = b"\x01" * 32
    pairing_payload = json.dumps({
        "device_id": device_id,
        "public_key": public_key.hex()
    })
    
    # 2. Confirm (mimicking 'sync confirm')
    data = json.loads(pairing_payload)
    repo.add_device(data['device_id'], bytes.fromhex(data['public_key']), nickname="Peer B")
    
    # 3. Verify
    device = repo.get_trusted_device(device_id)
    assert device is not None
    assert device['trust_level'] == 1
    assert device['public_key'] == public_key
