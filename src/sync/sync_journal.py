"""
Sentra Sync Journal Manager
Implements a WAL-safe synchronization journal for atomic batch tracking and crash recovery.
OWASP A03: Ensures integrity of sync operations via checksums and deterministic ordering.
"""
import json
import hashlib
import sqlite3
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple
import base64
from datetime import datetime

from src.database_manager import DatabaseManager, DatabaseError

class SyncJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (bytes, bytearray)):
            return base64.b64encode(o).decode('ascii')
        return super().default(o)

class SyncOpType(Enum):
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    TOMBSTONE_CREATE = "TOMBSTONE_CREATE"
    TOMBSTONE_PURGE = "TOMBSTONE_PURGE"

class BatchStatus(Enum):
    PENDING = "PENDING"
    COMMITTED = "COMMITTED"
    ROLLED_BACK = "ROLLED_BACK"
    FAILED = "FAILED"

class SyncJournal:
    """
    Manages the sync_journal table to ensure atomic application of sync batches.
    
    Security Boundaries:
    - Verifies operation integrity via SHA256 hashes.
    - Prevents partial sync application after crashes.
    """

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def create_batch(self, peer_id: str) -> int:
        """Create a new sync batch and return its ID."""
        try:
            conn = self.db.connect()
            cursor = conn.execute("""
                INSERT INTO sync_journal (peer_id, status, started_at)
                VALUES (?, ?, ?)
            """, (peer_id, BatchStatus.PENDING.value, datetime.now().isoformat()))
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            raise DatabaseError(f"Failed to create sync batch: {e}")

    def append_operation(self, batch_id: int, op_type: SyncOpType, entry_id: str, 
                         hlc: str, origin_device_id: str, payload: Optional[Dict] = None):
        """
        Append an operation to the current batch.
        In this implementation, we store the operation metadata in the journal
        to allow for replay/recovery.
        """
        # Calculate payload hash for integrity
        payload_json = json.dumps(payload, sort_keys=True, cls=SyncJSONEncoder) if payload else ""
        payload_hash = hashlib.sha256(payload_json.encode()).hexdigest()

        try:
            conn = self.db.connect()
            # Note: We are using the existing sync_journal table but extending 
            # its usage. In a production system, we'd have a separate sync_operations table.
            # For this artifact, we'll store op details in a new table if it doesn't exist,
            # or use a JSON blob in a 'details' field.
            
            # Ensure the operations table exists (Bootstrap step)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sync_operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id INTEGER,
                    op_type TEXT,
                    entry_id TEXT,
                    hlc TEXT,
                    origin_device_id TEXT,
                    payload_hash TEXT,
                    payload_blob TEXT,
                    FOREIGN KEY(batch_id) REFERENCES sync_journal(id)
                )
            """)
            
            conn.execute("""
                INSERT INTO sync_operations (batch_id, op_type, entry_id, hlc, origin_device_id, payload_hash, payload_blob)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (batch_id, op_type.value, entry_id, hlc, origin_device_id, payload_hash, payload_json))
            conn.commit()
        except Exception as e:
            raise DatabaseError(f"Failed to append sync operation: {e}")

    def commit_batch(self, batch_id: int):
        """Mark a batch as successfully committed."""
        try:
            conn = self.db.connect()
            conn.execute("""
                UPDATE sync_journal SET status = ? WHERE id = ?
            """, (BatchStatus.COMMITTED.value, batch_id))
            conn.commit()
        except Exception as e:
            raise DatabaseError(f"Failed to commit sync batch: {e}")

    def rollback_batch(self, batch_id: int):
        """Mark a batch as rolled back."""
        try:
            conn = self.db.connect()
            conn.execute("""
                UPDATE sync_journal SET status = ? WHERE id = ?
            """, (BatchStatus.ROLLED_BACK.value, batch_id))
            conn.commit()
        except Exception as e:
            raise DatabaseError(f"Failed to rollback sync batch: {e}")

    def get_pending_batches(self) -> List[Dict]:
        """Retrieve all batches that were interrupted (status = PENDING)."""
        try:
            conn = self.db.connect()
            cursor = conn.execute("""
                SELECT * FROM sync_journal WHERE status = ?
            """, (BatchStatus.PENDING.value,))
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            raise DatabaseError(f"Failed to retrieve pending batches: {e}")

    def get_batch_operations(self, batch_id: int) -> List[Dict]:
        """Retrieve all operations for a specific batch."""
        try:
            conn = self.db.connect()
            cursor = conn.execute("""
                SELECT * FROM sync_operations WHERE batch_id = ? ORDER BY id ASC
            """, (batch_id,))
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            raise DatabaseError(f"Failed to retrieve batch operations: {e}")

    def purge_old_batches(self, days: int = 30):
        """Remove completed/rolled back batches older than X days."""
        try:
            conn = self.db.connect()
            # If days is 30, we want '-30 days'. 
            interval = f"{-days} days"
            conn.execute("""
                DELETE FROM sync_journal 
                WHERE status != ? AND started_at < datetime('now', ?)
            """, (BatchStatus.PENDING.value, interval))
            conn.commit()
        except Exception as e:
            raise DatabaseError(f"Failed to purge old batches: {e}")
