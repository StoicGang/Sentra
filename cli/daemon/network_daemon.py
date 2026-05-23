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
    def __init__(self, host: str = '0.0.0.0', port: int = 5555):
        self.host = host
        self.port = port
        self.logger = logging.getLogger("SentraDaemon")
        self.orchestrator = self._init_orchestrator()
        self.running = False

    def _init_orchestrator(self):
        db = DatabaseManager()
        # Initializing delta engine with all dependencies
        # Assuming these are available from previous phases
        # For the daemon entry point, we just need the orchestrator
        return SyncOrchestrator(db, None) # DeltaEngine mock or placeholder if not fully resolved

    def run(self):
        self.running = True
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.bind((self.host, self.port))
            msg = f"[INFO] Sync daemon listening on {self.host}:{self.port}"
            print(msg)
            self.logger.info(msg)
        except Exception as e:
            self.logger.error(f"Socket startup failure: {e}")
            raise
            
        server.listen(5)
        server.settimeout(1.0)
        
        while self.running:
            try:
                conn, addr = server.accept()
                self.logger.info(f"Connection from {addr}")
                # Dispatch to sync_orchestrator in a thread
                threading.Thread(target=self._handle_peer, args=(conn,)).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.logger.error(f"Daemon error: {e}")
        
        server.close()
        self.logger.info("Daemon stopped.")

    def _handle_peer(self, conn):
        # Noise IK Handshake logic goes here
        conn.close()

    def stop(self):
        self.running = False
        self.orchestrator.shutdown()
