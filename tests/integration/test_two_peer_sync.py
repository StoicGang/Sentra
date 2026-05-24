"""
Integration Test: Two-Peer Sync
Verifies full end-to-end synchronization between two independent Sentra nodes.
"""
import pytest
import sqlite3
import time
import threading
from src.database_manager import DatabaseManager
from src.sync.delta_engine import DeltaEngine
from src.storage.device_repository import DeviceRepository
from src.crypto.identity import IdentityManager
from cli.daemon.network_daemon import NetworkDaemon
from cli.commands.sync_commands import sync_now

def setup_db(db_path):
    db = DatabaseManager(db_path=db_path)
    conn = db.connect()
    # Read and execute schema
    with open("data/schema.sql", "r") as f:
        conn.executescript(f.read())
    with open("src/storage/migrations/004_trusted_devices.sql", "r") as f:
        conn.executescript(f.read())
    return db

def test_full_peer_sync(tmp_path):
    # 1. Setup two separate DB managers (simulating two peers)
    db_path1 = str(tmp_path / "peer1.db")
    db_path2 = str(tmp_path / "peer2.db")
    
    db1 = setup_db(db_path1)
    db2 = setup_db(db_path2)
    
    # 2. Generate identities for both
    id1 = IdentityManager(db1).ensure_identity()
    id2 = IdentityManager(db2).ensure_identity()
    
    # Verify identities are stable (ensure_identity returns same on consecutive calls)
    id1_again = IdentityManager(db1).ensure_identity()
    assert id1['device_id'] == id1_again['device_id']
    
    # 3. Cross-pair them (trust each other)
    repo1 = DeviceRepository(db1)
    repo2 = DeviceRepository(db2)
    
    repo1.add_device(id2['device_id'], id2['public_key'], nickname="Peer2")
    repo2.add_device(id1['device_id'], id1['public_key'], nickname="Peer1")
    
    # 4. Add entries on Peer 1 and Peer 2
    conn1 = db1.connect()
    conn1.execute("""
        INSERT INTO entries (id, hlc, origin_device_id, title, password_encrypted, password_nonce, password_tag, kdf_salt, created_at, modified_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, ('e1', '1000:0000:local', 'local', 'EntryFromPeer1', b'p1', b'n1', b't1', b's1', 'now', 'now'))
    conn1.commit()
    
    conn2 = db2.connect()
    conn2.execute("""
        INSERT INTO entries (id, hlc, origin_device_id, title, password_encrypted, password_nonce, password_tag, kdf_salt, created_at, modified_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, ('e2', '1001:0000:local', 'local', 'EntryFromPeer2', b'p2', b'n2', b't2', b's2', 'now', 'now'))
    conn2.commit()
    
    # 5. Start Daemon for Peer 2 on port 15559
    port = 15559
    daemon = NetworkDaemon(host='127.0.0.1', port=port, db_manager=db2)
    daemon_thread = threading.Thread(target=daemon.run, daemon=True)
    daemon_thread.start()
    
    # Wait for daemon to bind
    time.sleep(0.5)
    
    # 6. Trigger sync from Peer 1 connecting to Peer 2's daemon
    sync_now(host='127.0.0.1', port=port, db_manager=db1)
        
    # Wait for synchronization to complete
    time.sleep(1.0)
    
    daemon.stop()
    daemon_thread.join(timeout=2.0)
    
    # 7. Verify EntryFromPeer2 is synced to Peer 1's database
    row1 = conn1.execute("SELECT title FROM entries WHERE id = 'e2'").fetchone()
    assert row1 is not None
    assert row1['title'] == 'EntryFromPeer2'
    
    # 8. Verify EntryFromPeer1 is synced to Peer 2's database
    row2 = conn2.execute("SELECT title FROM entries WHERE id = 'e1'").fetchone()
    assert row2 is not None
    assert row2['title'] == 'EntryFromPeer1'
