"""
Sentra Sync Orchestrator
Coordinates the high-level lifecycle of P2P synchronization.
Enforces fail-closed semantics and ensures safe resource management.
"""
import threading
from typing import Optional, Dict
from src.database_manager import DatabaseManager
from src.transport.noise_session import NoiseSessionManager
from src.transport.secure_channel import SecureChannel
from src.sync.delta_engine import DeltaEngine

class SyncOrchestrator:
    """
    Coordinates the synchronization lifecycle.
    Owns the transport session and ensures deterministic state transitions.
    """

    def __init__(self, db: DatabaseManager, delta_engine: DeltaEngine):
        self.db = db
        self.delta_engine = delta_engine
        self._active_sessions: Dict[str, SecureChannel] = {}
        self._lock = threading.Lock()
        self.is_shutting_down = False

    def start_session(self, peer_id: str, session: SecureChannel):
        """Register a new active sync session."""
        with self._lock:
            if self.is_shutting_down:
                session.close()
                return
            self._active_sessions[peer_id] = session

    def perform_sync(self, peer_id: str):
        """
        Orchestrates a synchronization pull/push flow.
        Fail-closed: Any exception results in session teardown.
        """
        try:
            channel = self._active_sessions.get(peer_id)
            if not channel:
                return

            # 1. Reconcile State
            status = self.delta_engine.reconcile_peer_state(peer_id)
            if status == "IN_SYNC":
                return

            # 2. Sync loop (Pull example)
            # In production, this would be a loop fetching delta batches
            remote_delta = channel.receive_message(channel.session.decrypt(b'')) # Mock call
            self.delta_engine.apply_remote_delta(peer_id, remote_delta)
            
        except Exception as e:
            self.teardown_session(peer_id)
            raise e

    def teardown_session(self, peer_id: str):
        """Gracefully close and cleanup a session."""
        with self._lock:
            channel = self._active_sessions.pop(peer_id, None)
            if channel:
                channel.close()

    def shutdown(self):
        """Graceful shutdown of all sessions."""
        self.is_shutting_down = True
        with self._lock:
            for channel in self._active_sessions.values():
                channel.close()
            self._active_sessions.clear()
