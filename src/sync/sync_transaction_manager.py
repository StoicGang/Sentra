"""
Sentra Sync Transaction Manager
Orchestrates atomic application of sync batches with conflict detection and idempotency.
Enforces fail-closed semantics to preserve database consistency.
"""
import hashlib
from typing import List, Dict, Any, Optional
from src.database_manager import DatabaseManager, DatabaseError
from src.sync.hlc import HybridLogicalClock
from src.sync.sync_journal import SyncJournal, SyncOpType
from src.sync.tombstone_manager import TombstoneManager

class SyncTransactionError(Exception):
    """Base exception for sync transaction errors."""
    pass

class SyncTransactionManager:
    """
    Handles the application of remote sync batches to the local database.
    
    Responsibilities:
    - Atomic application of batches.
    - Idempotency (re-applying same operation has no effect).
    - Conflict detection using HLC.
    - Tombstone integration to prevent resurrection.
    """

    def __init__(self, db_manager: DatabaseManager, journal: SyncJournal, tombstones: TombstoneManager):
        self.db = db_manager
        self.journal = journal
        self.tombstones = tombstones

    def apply_sync_batch(self, peer_id: str, operations: List[Dict[str, Any]]):
        """
        Apply a list of sync operations atomically.
        Each operation dict should contain: op_type, entry_id, hlc, origin_device_id, payload.
        """
        batch_id = self.journal.create_batch(peer_id)
        
        # Use BEGIN IMMEDIATE to lock the DB for the entire sync operation
        # This prevents UI edits from conflicting with sync writes.
        try:
            conn = self.db.connect()
            with conn: # Standard sqlite3 transaction wrapper
                conn.execute("BEGIN IMMEDIATE")
                
                for op in operations:
                    self._apply_operation(batch_id, op)
                
                self.journal.commit_batch(batch_id)
                
        except Exception as e:
            self.journal.rollback_batch(batch_id)
            raise SyncTransactionError(f"Failed to apply sync batch: {e}")

    def _apply_operation(self, batch_id: int, op: Dict[str, Any]):
        """Apply a single operation within a batch."""
        op_type = SyncOpType(op['op_type'])
        entry_id = op['entry_id']
        incoming_hlc = op['hlc']
        origin_id = op['origin_device_id']
        payload = op.get('payload')

        # 1. Journal the attempt
        self.journal.append_operation(batch_id, op_type, entry_id, incoming_hlc, origin_id, payload)

        # 2. Check Tombstones (Resurrection Prevention)
        if not self.tombstones.should_apply_update(entry_id, incoming_hlc):
            return # Stale update after deletion, skip

        # 3. Handle specific operation types
        if op_type == SyncOpType.INSERT or op_type == SyncOpType.UPDATE:
            self._handle_upsert(entry_id, incoming_hlc, origin_id, payload)
        elif op_type == SyncOpType.DELETE:
            self._handle_delete(entry_id, incoming_hlc, origin_id)
        elif op_type == SyncOpType.TOMBSTONE_CREATE:
            self.tombstones.create_tombstone(entry_id, incoming_hlc, origin_id)

    def _handle_upsert(self, entry_id: str, incoming_hlc: str, origin_id: str, payload: Dict):
        """Handle incoming INSERT/UPDATE with conflict resolution."""
        conn = self.db.connect()
        
        # 1. Check local state
        cursor = conn.execute("SELECT hlc FROM entries WHERE id = ?", (entry_id,))
        row = cursor.fetchone()
        
        if row:
            local_hlc = row['hlc']
            # Conflict Resolution: HLC comparison
            # 1 if hlc1 > hlc2, 0 if hlc1 == hlc2, -1 if hlc1 < hlc2
            comparison = HybridLogicalClock.compare(incoming_hlc, local_hlc)
            
            if comparison <= 0:
                # Local is ahead or same, skip incoming (Idempotency + LWW)
                return
            
            # Incoming is ahead, perform update
            self._execute_update(entry_id, incoming_hlc, origin_id, payload)
        else:
            # Entry doesn't exist, perform insert
            self._execute_insert(entry_id, incoming_hlc, origin_id, payload)

    def _handle_delete(self, entry_id: str, hlc: str, origin_id: str):
        """Handle incoming DELETE (Create local tombstone and remove entry)."""
        conn = self.db.connect()
        
        # 1. Create tombstone (handles concurrency internally)
        self.tombstones.create_tombstone(entry_id, hlc, origin_id)
        
        # 2. Remove the actual entry if it exists
        conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))

    def _execute_insert(self, entry_id: str, hlc: str, origin_id: str, payload: Dict):
        """Direct DB insert."""
        conn = self.db.connect()
        # Payload expected to be the encrypted fields and metadata
        # We need to map payload keys to DB columns.
        # This implementation assumes the caller provided a sanitized payload.
        columns = ['id', 'hlc', 'origin_device_id']
        values = [entry_id, hlc, origin_id]
        
        for k, v in payload.items():
            columns.append(k)
            values.append(v)
            
        placeholders = ', '.join(['?'] * len(columns))
        query = f"INSERT INTO entries ({', '.join(columns)}) VALUES ({placeholders})"
        conn.execute(query, tuple(values))

    def _execute_update(self, entry_id: str, hlc: str, origin_id: str, payload: Dict):
        """Direct DB update."""
        conn = self.db.connect()
        
        set_clauses = ["hlc = ?", "origin_device_id = ?"]
        values = [hlc, origin_id]
        
        for k, v in payload.items():
            set_clauses.append(f"{k} = ?")
            values.append(v)
            
        values.append(entry_id)
        query = f"UPDATE entries SET {', '.join(set_clauses)} WHERE id = ?"
        conn.execute(query, tuple(values))

    def recover_interrupted_batches(self):
        """
        Scan the journal for PENDING batches and attempt to finalize or rollback.
        In this MVP, we simple mark them as FAILED for manual review/audit,
        as we don't have enough metadata for full auto-replay yet.
        """
        pending = self.journal.get_pending_batches()
        for batch in pending:
            # Logic for recovery would go here. 
            # Since SQLite transactions are atomic, any PENDING batch here
            # means the 'commit_batch' call never ran. 
            # The actual DB changes were rolled back by SQLite automatically.
            # We just need to sync the journal state.
            self.journal.rollback_batch(batch['id'])
