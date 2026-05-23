"""
Sentra Tombstone Manager
Handles the lifecycle of deleted entries to ensure propagation across the peer mesh.
Prevents entry resurrection and handles conflicting delete/update races.
"""
import time
from typing import Dict, Optional, List
from src.database_manager import DatabaseManager, DatabaseError
from src.sync.hlc import HybridLogicalClock

class TombstoneManager:
    """
    Manages the 'tombstones' table.
    
    Responsibilities:
    - Creating tombstones for local deletions.
    - Applying tombstones received from peers.
    - Preventing resurrection of deleted entries.
    - Purging old tombstones after synchronization is confirmed.
    """

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def create_tombstone(self, entry_id: str, hlc: str, origin_device_id: str) -> bool:
        """
        Record a deletion as a tombstone.
        This should be called as part of a transaction that deletes the entry.
        """
        try:
            conn = self.db.connect()
            # We fetch existing to compare in Python or use a sophisticated SQL compare.
            # For robustness, we'll fetch and compare here.
            cursor = conn.execute("SELECT deleted_hlc FROM tombstones WHERE entry_id = ?", (entry_id,))
            row = cursor.fetchone()
            
            if row:
                existing_hlc = row['deleted_hlc']
                if HybridLogicalClock.compare(hlc, existing_hlc) <= 0:
                    return True # Existing tombstone is newer or same
            
            conn.execute("""
                INSERT INTO tombstones (entry_id, deleted_hlc, origin_device_id)
                VALUES (?, ?, ?)
                ON CONFLICT(entry_id) DO UPDATE SET
                    deleted_hlc = excluded.deleted_hlc,
                    origin_device_id = excluded.origin_device_id
            """, (entry_id, hlc, origin_device_id))
            return True
        except Exception as e:
            raise DatabaseError(f"Failed to create tombstone: {e}")

    def is_deleted(self, entry_id: str) -> bool:
        """Check if an entry is already deleted according to local tombstones."""
        try:
            conn = self.db.connect()
            cursor = conn.execute("SELECT 1 FROM tombstones WHERE entry_id = ?", (entry_id,))
            return cursor.fetchone() is not None
        except Exception as e:
            raise DatabaseError(f"Failed to check tombstone status: {e}")

    def get_tombstone(self, entry_id: str) -> Optional[Dict]:
        """Retrieve tombstone details for an entry."""
        try:
            conn = self.db.connect()
            cursor = conn.execute("SELECT * FROM tombstones WHERE entry_id = ?", (entry_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            raise DatabaseError(f"Failed to retrieve tombstone: {e}")

    def should_apply_update(self, entry_id: str, incoming_hlc: str) -> bool:
        """
        Determine if an incoming update should be applied or if it's stale relative 
        to a tombstone. Resurrection prevention logic lives here.
        """
        tombstone = self.get_tombstone(entry_id)
        if not tombstone:
            return True
        
        # If incoming update happened BEFORE or AT THE SAME TIME as the deletion, 
        # we reject it to prevent resurrection.
        # HLC comparison: 1 if hlc1 > hlc2, 0 if hlc1 == hlc2, -1 if hlc1 < hlc2
        comparison = HybridLogicalClock.compare(incoming_hlc, tombstone['deleted_hlc'])
        return comparison > 0

    def list_tombstones(self, since_hlc: Optional[str] = None) -> List[Dict]:
        """List tombstones for synchronization."""
        try:
            conn = self.db.connect()
            if since_hlc:
                cursor = conn.execute("""
                    SELECT * FROM tombstones WHERE deleted_hlc > ?
                """, (since_hlc,))
            else:
                cursor = conn.execute("SELECT * FROM tombstones")
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            raise DatabaseError(f"Failed to list tombstones: {e}")

    def purge_expired_tombstones(self, days: int = 90):
        """
        Physical removal of tombstones older than X days.
        Note: In a true mesh, we only purge once all nodes acknowledge. 
        For MVP, we use a simple TTL.
        """
        try:
            conn = self.db.connect()
            # Since deleted_hlc starts with a timestamp (seconds), we can filter.
            # We need to extract the timestamp part.
            conn.execute("""
                DELETE FROM tombstones 
                WHERE CAST(SUBSTR(deleted_hlc, 1, INSTR(deleted_hlc, ':') - 1) AS INTEGER) < ?
            """, (int(time.time()) - (days * 86400),))
            conn.commit()
        except Exception as e:
            # We need to import time if we use it
            raise DatabaseError(f"Failed to purge tombstones: {e}")
