"""
Tests for Sentra Delta Synchronization Engine
Verifies delta generation, reconciliation, and resumable sync logic.
"""
import pytest
from src.database_manager import DatabaseManager
from src.sync.hlc import HybridLogicalClock
from src.sync.sync_journal import SyncJournal
from src.sync.tombstone_manager import TombstoneManager
from src.sync.sync_transaction_manager import SyncTransactionManager
from src.sync.checkpoint_manager import CheckpointManager
from src.sync.divergence_detector import DivergenceDetector
from src.sync.delta_engine import DeltaEngine
from src.storage.device_repository import DeviceRepository

@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test_delta.db")
    db = DatabaseManager(db_path=db_path)
    conn = db.connect()
    with open("data/schema.sql", "r") as f:
        conn.executescript(f.read())
    with open("src/storage/migrations/004_trusted_devices.sql", "r") as f:
        conn.executescript(f.read())
    # Add peers
    conn.execute("INSERT INTO trusted_devices (device_id, public_key) VALUES (?, ?)", ("peer1", b"pubkey1"))
    conn.commit()
    return db

@pytest.fixture
def engine(db):
    hlc = HybridLogicalClock("local")
    journal = SyncJournal(db)
    tombstones = TombstoneManager(db)
    tm = SyncTransactionManager(db, journal, tombstones)
    cm = CheckpointManager(db)
    repo = DeviceRepository(db)
    dd = DivergenceDetector(db, cm, repo, hlc)
    return DeltaEngine(db, hlc, journal, tombstones, tm, cm, dd)

def test_generate_and_apply_delta(engine, db):
    # 1. Add local entry
    conn = db.connect()
    conn.execute("""
        INSERT INTO entries (id, hlc, origin_device_id, title, password_encrypted, password_nonce, password_tag, kdf_salt, created_at, modified_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, ('e1', '1000:0:local', 'local', 'Local', b'p', b'n', b't', b's', 'now', 'now'))
    conn.commit()
    
    # 2. Generate delta
    delta = engine.generate_delta("peer1", since_hlc="0:0:local")
    assert len(delta['operations']) == 1
    assert delta['operations'][0]['entry_id'] == 'e1'
    
    # 3. Apply to a peer (or simulated peer)
    # Clear DB to simulate fresh peer
    conn.execute("DELETE FROM entries")
    conn.commit()
    
    engine.apply_remote_delta("peer1", delta)
    
    row = conn.execute("SELECT title FROM entries WHERE id = 'e1'").fetchone()
    assert row['title'] == 'Local'

def test_resumable_sync(engine, db):
    # Add multiple entries
    conn = db.connect()
    conn.execute("INSERT INTO entries (id, hlc, origin_device_id, title, password_encrypted, password_nonce, password_tag, kdf_salt, created_at, modified_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", ('e1', '1000:0:local', 'local', 'T1', b'p', b'n', b't', b's', 'now', 'now'))
    conn.execute("INSERT INTO entries (id, hlc, origin_device_id, title, password_encrypted, password_nonce, password_tag, kdf_salt, created_at, modified_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", ('e2', '1000:1:local', 'local', 'T2', b'p', b'n', b't', b's', 'now', 'now'))
    conn.commit()
    
    # Sync first half
    delta = engine.generate_delta("peer1", since_hlc="0:0:local", limit=1)
    assert len(delta['operations']) == 1
    assert delta['has_more'] is True
    
    # Sync second half
    next_hlc = delta['max_hlc_in_batch']
    delta2 = engine.generate_delta("peer1", since_hlc=next_hlc, limit=1)
    assert len(delta2['operations']) == 1
    assert delta2['operations'][0]['entry_id'] == 'e2'

def test_tombstone_propagation(engine, db):
    # Delete entry
    conn = db.connect()
    conn.execute("INSERT INTO entries (id, hlc, origin_device_id, title, password_encrypted, password_nonce, password_tag, kdf_salt, created_at, modified_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", ('e1', '1000:0:local', 'local', 'T1', b'p', b'n', b't', b's', 'now', 'now'))
    conn.commit()
    
    # Tombstone it
    conn.execute("DELETE FROM entries WHERE id = 'e1'")
    conn.execute("INSERT INTO tombstones (entry_id, deleted_hlc, origin_device_id) VALUES ('e1', '2000:0:local', 'local')")
    conn.commit()
    
    delta = engine.generate_delta("peer1", since_hlc="0:0:local")
    assert any(op['op_type'] == 'TOMBSTONE_CREATE' for op in delta['operations'])
