"""
Sentra Delta Synchronization Engine
Generates and applies HLC-based delta operations for peer-to-peer sync.
Ensures deterministic ordering, replay-safety, and integrity.
"""
import hashlib
from typing import List, Dict, Any, Optional

from src.database_manager import DatabaseManager
from src.sync.hlc import HybridLogicalClock
from src.sync.sync_journal import SyncJournal, SyncOpType
from src.sync.tombstone_manager import TombstoneManager
from src.sync.sync_transaction_manager import SyncTransactionManager
from src.sync.checkpoint_manager import CheckpointManager
from src.sync.divergence_detector import DivergenceDetector

class DeltaSyncError(Exception):
    """Base exception for delta synchronization errors."""
    pass

class DeltaEngine:
    """
    Orchestrates the delta synchronization process between two peers.
    """

    def __init__(self, db_manager: DatabaseManager, hlc: HybridLogicalClock, 
                 journal: SyncJournal, tombstones: TombstoneManager, 
                 transaction_manager: SyncTransactionManager,
                 checkpoint_manager: CheckpointManager,
                 divergence_detector: DivergenceDetector):
        self.db = db_manager
        self.hlc = hlc
        self.journal = journal
        self.tombstones = tombstones
        self.transaction_manager = transaction_manager
        self.checkpoint_manager = checkpoint_manager
        self.divergence_detector = divergence_detector

    def generate_delta(self, peer_id: str, since_hlc: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
        """
        Generates a delta batch of operations to send to a peer.
        Includes new/updated entries and tombstones since the last synced HLC.
        """
        since_hlc = since_hlc if since_hlc else "0:0:local"
        conn = self.db.connect()
        operations = []
        max_hlc_in_delta = since_hlc # Initialize with the starting HLC

        # 1. Fetch new/updated entries
        entry_query = "SELECT id, hlc, origin_device_id, title, password_encrypted, password_nonce, password_tag, kdf_salt, created_at, modified_at FROM entries WHERE hlc > ? ORDER BY hlc, id LIMIT ?"
        entry_cursor = conn.execute(entry_query, (since_hlc, limit))
        
        def to_hex(val):
            return val.hex() if isinstance(val, bytes) else val

        for row in entry_cursor.fetchall():
            op_payload = {
                "title": row['title'],
                "password_encrypted": to_hex(row['password_encrypted']),
                "password_nonce": to_hex(row['password_nonce']),
                "password_tag": to_hex(row['password_tag']),
                "kdf_salt": to_hex(row['kdf_salt']),
                "created_at": row['created_at'],
                "modified_at": row['modified_at']
                # Add other encrypted/metadata fields here
            }
            operations.append({
                "op_type": SyncOpType.UPDATE.value, # Update for existing, Insert for new
                "entry_id": row['id'],
                "hlc": row['hlc'],
                "origin_device_id": row['origin_device_id'],
                "payload": op_payload
            })
            if HybridLogicalClock.compare(row['hlc'], max_hlc_in_delta) > 0:
                max_hlc_in_delta = row['hlc']
        
        # 2. Fetch new tombstones
        tombstone_query = "SELECT entry_id, deleted_hlc, origin_device_id FROM tombstones WHERE deleted_hlc > ? ORDER BY deleted_hlc, entry_id LIMIT ?"
        tombstone_cursor = conn.execute(tombstone_query, (since_hlc, limit - len(operations)))

        for row in tombstone_cursor.fetchall():
            operations.append({
                "op_type": SyncOpType.TOMBSTONE_CREATE.value,
                "entry_id": row['entry_id'],
                "hlc": row['deleted_hlc'],
                "origin_device_id": row['origin_device_id']
            })
            if HybridLogicalClock.compare(row['deleted_hlc'], max_hlc_in_delta) > 0:
                max_hlc_in_delta = row['deleted_hlc']
        
        # Sort operations deterministically for consistent manifest/hash generation
        operations.sort(key=lambda op: (op['hlc'], op['entry_id']))

        return {
            "operations": operations,
            "max_hlc_in_batch": max_hlc_in_delta,
            "has_more": len(operations) == limit
        }

    def apply_remote_delta(self, peer_id: str, remote_delta: Dict[str, Any]):
        """
        Applies a delta batch received from a peer to the local database.
        """
        operations = remote_delta.get("operations", [])
        if not operations:
            return # Nothing to apply

        # 1. Verify integrity/order of remote_delta (e.g. from manifest if we had one here)
        # For now, rely on HLC in transaction manager

        # Convert hex strings back to bytes for database
        byte_keys = {
            "password_encrypted", "password_nonce", "password_tag", "kdf_salt",
            "title_encrypted", "title_nonce", "title_tag",
            "url_encrypted", "url_nonce", "url_tag",
            "username_encrypted", "username_nonce", "username_tag",
            "totp_secret_encrypted", "totp_secret_nonce", "totp_secret_tag", "totp_secret"
        }
        for op in operations:
            payload = op.get("payload")
            if payload:
                for k in byte_keys:
                    if k in payload and isinstance(payload[k], str):
                        try:
                            payload[k] = bytes.fromhex(payload[k])
                        except ValueError:
                            pass

        # 2. Apply batch atomically
        self.transaction_manager.apply_sync_batch(peer_id, operations)

        # 3. Update local checkpoint for this peer
        max_hlc_in_batch = remote_delta.get("max_hlc_in_batch")
        if max_hlc_in_batch:
            self.checkpoint_manager.update_checkpoint(peer_id, max_hlc_in_batch)

    def reconcile_peer_state(self, peer_id: str) -> str:
        """
        Reconciles the local state with a peer's state.
        This involves exchanging manifests, detecting divergence, and initiating delta sync.
        
        Returns:
            "IN_SYNC", "SYNC_STARTED", "DIVERGED_NEEDS_RESOLUTION"
        """
        # 1. Get remote manifest (This would come from a network message)
        # For now, mock a remote manifest for testing
        remote_manifest = self.divergence_detector.compute_local_manifest() # Simplified: assume peer is self
        
        # 2. Compare states
        status = self.divergence_detector.compare_peer_state(peer_id, remote_manifest)
        
        if status == "IN_SYNC":
            return "IN_SYNC"
        elif status == "DIVERGED":
            return "DIVERGED_NEEDS_RESOLUTION"
        elif status in ["LOCAL_AHEAD", "REMOTE_AHEAD"]:
            # Initiate delta transfer
            # For MVP, assume remote_manifest is always up-to-date for pulling
            # or local_manifest is always up-to-date for pushing
            
            # This is where the push/pull decision logic would go.
            # For MVP, let's assume we always try to pull if remote is ahead, or push if local is ahead.
            
            # For example: If REMOTE_AHEAD, start pulling deltas
            # If LOCAL_AHEAD, start pushing deltas
            return "SYNC_STARTED"
        else:
            raise DeltaSyncError(f"Unknown divergence status: {status}")

    def compute_sync_checkpoint(self, peer_id: str) -> Optional[str]:
        """Convenience method to get current checkpoint for a peer."""
        return self.checkpoint_manager.get_peer_checkpoint(peer_id)

    def detect_divergence(self, peer_id: str, remote_manifest: Dict[str, Any]) -> str:
        """Wrapper for divergence_detector.compare_peer_state."""
        return self.divergence_detector.compare_peer_state(peer_id, remote_manifest)
