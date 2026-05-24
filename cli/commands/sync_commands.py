"""
Sentra CLI Sync Commands
Implements functional device pairing, confirmation, and listing using argparse.
"""
import argparse
import uuid
import json
import hashlib
from datetime import datetime
from src.database_manager import DatabaseManager
from src.storage.device_repository import DeviceRepository
from src.crypto.identity import IdentityManager

def cmd_sync(args: argparse.Namespace):
    """Dispatcher for sync subcommands."""
    try:
        DatabaseManager().initialize_database()
    except Exception as e:
        print(f"[ERROR] Failed to initialize/migrate database: {e}")
        return

    if args.action == "pair":
        pair_device()
    elif args.action == "confirm":
        if args.payload:
            confirm_pairing(args.payload)
        else:
            print("Missing pairing payload")
    elif args.action == "list":
        list_devices()
    elif args.action == "status":
        print("Status: Operational")
    elif args.action == "now":
        sync_now(args.host, args.port)
    elif args.action == "unpair":
        if args.device_id:
            unpair_device(args.device_id)
        else:
            print("Missing device ID")

def unpair_device(device_id: str):
    """Completely unpair and remove a device from the trusted list."""
    from src.database_manager import DatabaseManager
    from src.storage.device_repository import DeviceRepository
    db = DatabaseManager()
    repo = DeviceRepository(db)
    try:
        success = repo.remove_device(device_id)
        if success:
            print(f"[SUCCESS] Device '{device_id}' successfully unpaired and removed.")
        else:
            print(f"[ERROR] No trusted device found matching '{device_id}'.")
    except Exception as e:
        print(f"[ERROR] Failed to unpair device: {e}")

def sync_now(host: str, port: int, db_manager: DatabaseManager | None = None):
    """Trigger immediate sync with all trusted peers."""
    from src.database_manager import DatabaseManager
    from src.storage.device_repository import DeviceRepository
    from src.transport.noise_session import NoiseSessionManager, IdentityMismatchError
    from src.transport.secure_channel import SecureChannel
    from src.protocol.codec import SentraCodec, frame_packet
    import socket
    import sys
    
    db = db_manager if db_manager else DatabaseManager()
    conn_db = db.connect()
    
    # Ensure local identity exists
    row = conn_db.execute("SELECT private_key_encrypted, device_id FROM local_identity WHERE id = 1").fetchone()
    if not row:
        from src.crypto.identity import IdentityManager
        id_mgr = IdentityManager(db)
        identity = id_mgr.ensure_identity()
        row = conn_db.execute("SELECT private_key_encrypted, device_id FROM local_identity WHERE id = 1").fetchone()
    local_priv = row['private_key_encrypted']
    local_device_id = row['device_id']
    
    repo = DeviceRepository(db)
    trusted = repo.list_trusted_devices()
    if not trusted:
        print("Error: No paired/trusted devices found. Please pair first.")
        return
        
    print(f"Triggering manual sync with {host}:{port}...")
    
    success = False
    for peer in trusted:
        peer_pub = peer['public_key']
        peer_device_id = peer['device_id']
        print(f"Attempting sync with peer {peer_device_id}...")
        
        # Connect TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        try:
            sock.connect((host, port))
            
            # Setup Noise session
            from src.crypto.identity import ed25519_priv_to_x25519, ed25519_pub_to_x25519
            x25519_local_priv = ed25519_priv_to_x25519(local_priv)
            x25519_peer_pub = ed25519_pub_to_x25519(peer_pub)
            
            session = NoiseSessionManager(
                local_static_priv=x25519_local_priv,
                peer_static_pub=x25519_peer_pub,
                is_initiator=True,
                device_repo=repo
            )
            
            codec = SentraCodec()
            def send_msg(msg):
                sock.sendall(frame_packet(msg))
            def recv_msg():
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        raise ConnectionError("Connection closed")
                    for payload in codec.parse_stream(chunk):
                        return bytes(payload)
            
            # Start Noise Handshake (Msg 1)
            msg1 = session.start_handshake()
            send_msg(msg1)
            
            # Receive Msg 2
            msg2 = recv_msg()
            session.receive_handshake(msg2)
            
            if not session.is_established:
                raise Exception("Noise handshake failed to establish")
            
            # Handshake successful!
            channel = SecureChannel(session)
            
            def send_channel_msg(msg_dict):
                sock.sendall(channel.send_message(msg_dict))
            def recv_channel_msg():
                return channel.receive_message(recv_msg())
                
            # Perform Sync exchange
            from src.sync.hlc import HybridLogicalClock
            from src.sync.sync_journal import SyncJournal
            from src.sync.tombstone_manager import TombstoneManager
            from src.sync.sync_transaction_manager import SyncTransactionManager
            from src.sync.checkpoint_manager import CheckpointManager
            from src.sync.divergence_detector import DivergenceDetector
            from src.sync.delta_engine import DeltaEngine
            
            hlc = HybridLogicalClock(local_device_id)
            cursor = conn_db.execute("SELECT hlc FROM entries WHERE hlc IS NOT NULL ORDER BY hlc DESC LIMIT 1")
            last_entry = cursor.fetchone()
            if last_entry:
                hlc.update_from_storage(last_entry['hlc'])
                
            journal = SyncJournal(db)
            tombstones = TombstoneManager(db)
            tm = SyncTransactionManager(db, journal, tombstones)
            cm = CheckpointManager(db)
            dd = DivergenceDetector(db, cm, repo, hlc)
            engine = DeltaEngine(db, hlc, journal, tombstones, tm, cm, dd)
            
            local_manifest = dd.compute_local_manifest()
            
            # 1. Send SYNC_INIT
            send_channel_msg({
                "type": "SYNC_INIT",
                "device_id": local_device_id,
                "manifest": local_manifest
            })
            
            # 2. Receive SYNC_INIT_RESP
            resp = recv_channel_msg()
            if resp.get("type") != "SYNC_INIT_RESP":
                raise Exception(f"Expected SYNC_INIT_RESP, got {resp.get('type')}")
                
            # 3. Generate local delta and send to peer (push)
            since_hlc = cm.get_peer_checkpoint(peer_device_id)
            local_delta = engine.generate_delta(peer_device_id, since_hlc=since_hlc)
            
            send_channel_msg({
                "type": "DELTA_DATA",
                "delta": local_delta
            })
            
            # 4. Receive remote delta and apply it (pull)
            peer_delta_msg = recv_channel_msg()
            if peer_delta_msg.get("type") != "DELTA_DATA":
                raise Exception(f"Expected DELTA_DATA, got {peer_delta_msg.get('type')}")
                
            peer_delta = peer_delta_msg["delta"]
            engine.apply_remote_delta(peer_device_id, peer_delta)
            
            # Update last seen and checkpoints
            repo.update_last_seen(peer_device_id, local_delta.get("max_hlc_in_batch"))
            
            print(f"[SUCCESS] Sync completed successfully with peer {peer_device_id}!")
            success = True
            break
            
        except (IdentityMismatchError, Exception) as e:
            print(f"Peer {peer_device_id} failed: {e}")
        finally:
            try:
                sock.close()
            except Exception:
                pass
                
    if not success:
        print("[ERROR] Sync failed: could not sync with any trusted peer.")

def pair_device():
    """Generate a pairing token."""
    db = DatabaseManager()
    id_manager = IdentityManager(db)
    identity = id_manager.ensure_identity()
    
    pairing_id = uuid.uuid4().hex[:16]
    pairing_token = {
        "pairing_id": pairing_id,
        "device_id": identity['device_id'],
        "public_key": identity['public_key'].hex(),
        "created_at": datetime.now().isoformat()
    }
    
    conn = db.connect()
    conn.execute("CREATE TABLE IF NOT EXISTS pairing_sessions (pairing_id TEXT PRIMARY KEY, payload TEXT, expires_at TEXT)")
    conn.execute("INSERT OR REPLACE INTO pairing_sessions VALUES (?, ?, ?)", 
                 (pairing_id, json.dumps(pairing_token), datetime.now().isoformat()))
    conn.commit()
    
    print(f"Pairing ID: {pairing_id}")
    print(f"Fingerprint: {hashlib.sha256(identity['public_key']).hexdigest()}")
    print(f"Payload: {json.dumps(pairing_token)}")

def confirm_pairing(payload):
    """Finalize pairing."""
    try:
        data = json.loads(payload)
        db = DatabaseManager()
        repo = DeviceRepository(db)
        repo.add_device(data['device_id'], bytes.fromhex(data['public_key']), nickname="Peer")
        print(f"Device {data['device_id']} successfully paired.")
    except Exception as e:
        print(f"Pairing failed: {e}")

def list_devices():
    """List trusted devices."""
    db = DatabaseManager()
    repo = DeviceRepository(db)
    devices = repo.list_trusted_devices(include_revoked=True)
    if not devices:
        print("No trusted devices found.")
        return
    for d in devices:
        status = "Trusted" if d['trust_level'] == 1 else "Revoked"
        fp = hashlib.sha256(d['public_key']).hexdigest()[:16]
        print(f"{d['device_id']} [{d['nickname']}] | FP: {fp} | Status: {status}")
