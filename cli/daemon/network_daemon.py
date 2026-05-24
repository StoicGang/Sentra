"""
Sentra Sync Daemon
Starts a network-listening daemon for synchronization.
"""
import logging
import socket
import threading
from src.app.sync_orchestrator import SyncOrchestrator
from src.database_manager import DatabaseManager
from src.sync.delta_engine import DeltaEngine

class NetworkDaemon:
    def __init__(self, host: str = '0.0.0.0', port: int = 5555, allow_ips: list[str] | None = None, db_manager: DatabaseManager | None = None):
        self.host = host
        self.port = port
        self.allow_ips = allow_ips
        self.db = db_manager if db_manager else DatabaseManager()
        self.logger = logging.getLogger("SentraDaemon")
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
        self.orchestrator = self._init_orchestrator()
        self.running = False

    def _init_orchestrator(self):
        # Initializing delta engine with all dependencies
        # Assuming these are available from previous phases
        # For the daemon entry point, we just need the orchestrator
        return SyncOrchestrator(self.db, None) # DeltaEngine mock or placeholder if not fully resolved

    def run(self):
        self.running = True
        try:
            self.db.initialize_database()
        except Exception as e:
            self.logger.error(f"Failed to initialize/migrate database: {e}")
            raise
        self.logger.info("Daemon startup initiated")
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.bind((self.host, self.port))
            self.logger.info("Socket bind success")
            msg = f"[INFO] Sync daemon listening on {self.host}:{self.port}"
            print(msg)
            self.logger.info(msg)
        except Exception as e:
            self.logger.error(f"Socket startup failure: {e}")
            raise
            
        backlog = 5
        server.listen(backlog)
        self.logger.info(f"Listening with backlog: {backlog}")
        server.settimeout(1.0)
        
        self.logger.info("Entering accept() wait state")
        while self.running:
            try:
                conn, addr = server.accept()
                client_ip = addr[0]
                self.logger.info("Incoming connection accepted")
                self.logger.info(f"Remote peer IP/port: {addr}")
                
                if self.allow_ips is not None and client_ip not in self.allow_ips:
                    self.logger.warning(f"Connection rejected: IP {client_ip} not in allow list {self.allow_ips}")
                    try:
                        conn.close()
                    except Exception:
                        pass
                    continue
                
                # Dispatch to sync_orchestrator in a thread
                threading.Thread(target=self._handle_peer, args=(conn, addr), daemon=True).start()
                self.logger.info("Returning to accept() wait state")
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.logger.error(f"Daemon accept error: {e}")
        
        server.close()
        self.logger.info("Daemon stopped.")

    def _handle_peer(self, conn, addr):
        self.logger.info(f"Transport handler creation for {addr}")
        conn.settimeout(10.0) # Hardened socket timeout for handshake and sync
        try:
            self.logger.info(f"Socket read start for {addr}")
            
            # 1. Initialize local identity and repo
            db = self.db
            conn_db = db.connect()
            row = conn_db.execute("SELECT private_key_encrypted FROM local_identity WHERE id = 1").fetchone()
            if not row:
                from src.crypto.identity import IdentityManager
                id_mgr = IdentityManager(db)
                identity = id_mgr.ensure_identity()
                row = conn_db.execute("SELECT private_key_encrypted FROM local_identity WHERE id = 1").fetchone()
            local_priv = row['private_key_encrypted']
            
            from src.storage.device_repository import DeviceRepository
            from src.transport.noise_session import NoiseSessionManager
            from src.transport.secure_channel import SecureChannel
            from src.protocol.codec import SentraCodec, frame_packet
            
            from src.crypto.identity import ed25519_priv_to_x25519
            x25519_local_priv = ed25519_priv_to_x25519(local_priv)
            
            repo = DeviceRepository(db)
            session = NoiseSessionManager(
                local_static_priv=x25519_local_priv,
                is_initiator=False,
                device_repo=repo
            )
            
            codec = SentraCodec()
            def send_msg(msg):
                conn.sendall(frame_packet(msg))
            def recv_msg():
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        raise ConnectionError("Connection closed")
                    for payload in codec.parse_stream(chunk):
                        return bytes(payload)
            
            # 2. Noise Handshake
            self.logger.info("Awaiting Handshake Msg 1...")
            msg1 = recv_msg()
            self.logger.info("Processing Handshake Msg 1...")
            msg2 = session.receive_handshake(msg1)
            self.logger.info("Sending Handshake Msg 2...")
            send_msg(msg2)
            
            if not session.is_established:
                raise Exception("Noise handshake failed to establish")
            
            self.logger.info("Noise handshake established successfully!")
            channel = SecureChannel(session)
            
            def send_channel_msg(msg_dict):
                conn.sendall(channel.send_message(msg_dict))
            def recv_channel_msg():
                return channel.receive_message(recv_msg())
            
            # 3. Perform Sync exchange
            # Receive SYNC_INIT
            self.logger.info("Awaiting SYNC_INIT from peer...")
            init_msg = recv_channel_msg()
            if init_msg.get("type") != "SYNC_INIT":
                raise Exception(f"Expected SYNC_INIT, got {init_msg.get('type')}")
            
            peer_device_id = init_msg["device_id"]
            peer_manifest = init_msg["manifest"]
            self.logger.info(f"Received SYNC_INIT from peer {peer_device_id}. Manifest: {peer_manifest}")
            
            # Compute local manifest and respond
            from src.sync.hlc import HybridLogicalClock
            from src.sync.sync_journal import SyncJournal
            from src.sync.tombstone_manager import TombstoneManager
            from src.sync.sync_transaction_manager import SyncTransactionManager
            from src.sync.checkpoint_manager import CheckpointManager
            from src.sync.divergence_detector import DivergenceDetector
            
            # Ensure local identity to retrieve our own device_id
            from src.crypto.identity import IdentityManager
            id_mgr = IdentityManager(db)
            local_identity = id_mgr.ensure_identity()
            local_device_id = local_identity["device_id"]
            
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
            self.logger.info(f"Local manifest computed: {local_manifest}")
            
            send_channel_msg({
                "type": "SYNC_INIT_RESP",
                "device_id": local_device_id,
                "manifest": local_manifest
            })
            
            # Receive peer's delta data and apply it
            self.logger.info("Awaiting DELTA_DATA from peer...")
            peer_delta_msg = recv_channel_msg()
            if peer_delta_msg.get("type") != "DELTA_DATA":
                raise Exception(f"Expected DELTA_DATA, got {peer_delta_msg.get('type')}")
            
            peer_delta = peer_delta_msg["delta"]
            self.logger.info(f"Applying remote delta from peer {peer_device_id}...")
            engine.apply_remote_delta(peer_device_id, peer_delta)
            self.logger.info("Remote delta applied successfully.")
            
            # Generate local delta and send to peer
            since_hlc = cm.get_peer_checkpoint(peer_device_id)
            self.logger.info(f"Generating outgoing delta since: {since_hlc}")
            local_delta = engine.generate_delta(peer_device_id, since_hlc=since_hlc)
            
            send_channel_msg({
                "type": "DELTA_DATA",
                "delta": local_delta
            })
            self.logger.info("Sent outgoing delta to peer.")
            
            # Update last seen
            repo.update_last_seen(peer_device_id, local_delta.get("max_hlc_in_batch"))
            self.logger.info("Sync session completed successfully!")
            
        except socket.timeout:
            self.logger.warning(f"Socket operation timeout for {addr}")
        except Exception as e:
            self.logger.error(f"Handler exception for {addr}: {e}")
        finally:
            try:
                conn.close()
                self.logger.info(f"Graceful connection teardown completed for {addr}")
            except Exception as e:
                self.logger.error(f"Error during teardown for {addr}: {e}")

    def stop(self):
        self.running = False
        self.orchestrator.shutdown()
