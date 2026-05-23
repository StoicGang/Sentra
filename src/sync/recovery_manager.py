"""
Sentra Recovery Manager
Orchestrates deterministic recovery of interrupted synchronization batches.
Ensures crash-resilience and idempotency via sync journal replay.
"""
import hashlib
import json
from typing import List, Dict, Any
from src.database_manager import DatabaseManager, DatabaseError
from src.sync.sync_journal import SyncJournal, SyncOpType, BatchStatus
from src.sync.sync_transaction_manager import SyncTransactionManager

class RecoveryError(Exception):
    """Base exception for recovery operations."""
    pass

class RecoveryManager:
    """
    Handles the replay of incomplete sync batches.
    Ensures that replayed operations are idempotent and consistent with local state.
    """

    def __init__(self, db: DatabaseManager, journal: SyncJournal, tx_manager: SyncTransactionManager):
        self.db = db
        self.journal = journal
        self.tx_manager = tx_manager

    def recover_interrupted_batches(self):
        """
        Recover all PENDING batches.
        Fail-closed strategy: If a batch cannot be deterministically replayed/verified,
        mark as FAILED for manual audit.
        """
        pending = self.journal.get_pending_batches()
        for batch in pending:
            self._replay_batch(batch['id'])

    def _replay_batch(self, batch_id: int):
        """Replay operations for a single batch."""
        try:
            ops = self.journal.get_batch_operations(batch_id)
            
            # Use BEGIN IMMEDIATE to ensure atomic replay
            conn = self.db.connect()
            with conn:
                conn.execute("BEGIN IMMEDIATE")
                
                for op in ops:
                    # Idempotency check: hash/integrity check before application
                    # Verify integrity using op metadata
                    if not self._verify_integrity(op):
                        raise RecoveryError(f"Integrity check failed for op {op['id']}")
                    
                    # Replay the operation using TransactionManager logic
                    if op.get('payload_blob'):
                         op['payload'] = json.loads(op['payload_blob'])
                    else:
                         op['payload'] = {}
                    self.tx_manager._apply_operation(batch_id, op)
                
                self.journal.commit_batch(batch_id)
                
        except Exception as e:
            # If replay fails, we must NOT leave the system in an inconsistent state.
            # Rollback logic is handled by the SQL transaction context.
            self.journal.rollback_batch(batch_id)
            # Log for operator intervention
            raise RecoveryError(f"Recovery failed for batch {batch_id}: {e}")

    def _verify_integrity(self, op: Dict[str, Any]) -> bool:
        """Verify the integrity of a replayed operation."""
        # Recalculate hash and compare with stored hash
        payload_blob = op.get('payload_blob', "")
        computed_hash = hashlib.sha256(payload_blob.encode()).hexdigest()
        return computed_hash == op['payload_hash']
