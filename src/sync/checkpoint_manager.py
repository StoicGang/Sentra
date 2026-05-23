"""
Sentra Checkpoint Manager
Tracks the synchronization state for each peer, enabling resumable syncs and divergence detection.
"""
from typing import Dict, Any, Optional
from datetime import datetime
from src.database_manager import DatabaseManager, DatabaseError
from src.sync.hlc import HybridLogicalClock

class CheckpointError(Exception):
    """Base exception for checkpoint manager errors."""
    pass

class CheckpointManager:
    """
    Manages per-peer synchronization checkpoints.
    
    A checkpoint for a peer stores the last HLC value successfully synced with that peer.
    This is used to request deltas (changes since that HLC) and to detect divergence.
    """

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def update_checkpoint(self, peer_id: str, last_synced_hlc: str) -> bool:
        """
        Update the checkpoint for a given peer.
        This operation is monotonic: a checkpoint can only advance forward in HLC time.
        """
        try:
            conn = self.db.connect()
            
            # Fetch current checkpoint
            cursor = conn.execute("SELECT last_synced_hlc FROM trusted_devices WHERE device_id = ?", (peer_id,))
            row = cursor.fetchone()
            
            if row and row['last_synced_hlc']:
                existing_hlc = row['last_synced_hlc']
                if HybridLogicalClock.compare(last_synced_hlc, existing_hlc) <= 0:
                    # Incoming HLC is older or same, do not update (idempotency)
                    return True
            
            # Update last_synced_hlc in trusted_devices table
            conn.execute("""
                UPDATE trusted_devices SET last_synced_hlc = ?, last_seen_at = ?
                WHERE device_id = ?
            """, (last_synced_hlc, datetime.now().isoformat(), peer_id))
            conn.commit()
            return True
        except Exception as e:
            raise DatabaseError(f"Failed to update checkpoint for peer {peer_id}: {e}")

    def get_peer_checkpoint(self, peer_id: str) -> Optional[str]:
        """Retrieve the last synced HLC for a given peer."""
        try:
            conn = self.db.connect()
            cursor = conn.execute("SELECT last_synced_hlc FROM trusted_devices WHERE device_id = ?", (peer_id,))
            row = cursor.fetchone()
            return row['last_synced_hlc'] if row else None
        except Exception as e:
            raise DatabaseError(f"Failed to retrieve checkpoint for peer {peer_id}: {e}")

    def rollback_checkpoint(self, peer_id: str, target_hlc: str) -> bool:
        """
        Rollback a peer's checkpoint to an earlier (or same) HLC.
        This is a dangerous operation and should only be used for recovery from detected divergence.
        It must be explicitly allowed (e.g., in a conflict resolution UI).
        """
        try:
            conn = self.db.connect()
            
            # Fetch current checkpoint
            cursor = conn.execute("SELECT last_synced_hlc FROM trusted_devices WHERE device_id = ?", (peer_id,))
            row = cursor.fetchone()
            
            if not row or not row['last_synced_hlc']:
                # No existing checkpoint or target_hlc is for initial state
                conn.execute("""
                    UPDATE trusted_devices SET last_synced_hlc = ?, last_seen_at = ?
                    WHERE device_id = ?
                """, (target_hlc, datetime.now().isoformat(), peer_id))
            else:
                existing_hlc = row['last_synced_hlc']
                # Only allow rollback to an earlier or same HLC
                if HybridLogicalClock.compare(target_hlc, existing_hlc) > 0:
                    raise CheckpointError(f"Cannot rollback checkpoint to a newer HLC ({target_hlc} > {existing_hlc})")
                
                conn.execute("""
                    UPDATE trusted_devices SET last_synced_hlc = ?, last_seen_at = ?
                    WHERE device_id = ?
                """, (target_hlc, datetime.now().isoformat(), peer_id))
            conn.commit()
            return True
        except CheckpointError: # Catch our specific error and re-raise directly
            raise
        except Exception as e: # Wrap other database errors
            raise DatabaseError(f"Failed to rollback checkpoint for peer {peer_id}: {e}")

    def verify_checkpoint_integrity(self, peer_id: str, expected_hlc: str) -> bool:
        """
        Verify that a peer's checkpoint matches an expected HLC.
        Used to detect if a checkpoint has been tampered with or rolled back by an attacker.
        """
        actual_hlc = self.get_peer_checkpoint(peer_id)
        if actual_hlc is None and expected_hlc is None:
            return True # Both are initial state
        return actual_hlc == expected_hlc
