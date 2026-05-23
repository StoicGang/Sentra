"""
Sentra Device Repository
Handles persistence for trusted devices, identity pinning, and revocation.
"""
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import sqlite3

from src.database_manager import DatabaseManager, DatabaseError

class DeviceRepository:
    """
    Manages the 'trusted_devices' and 'local_identity' tables.
    
    Responsibilities:
        - Registering new trusted devices (Pairing)
        - Revoking device trust
        - Identity pinning (storing/retrieving public keys)
        - Updating sync metadata (last seen, last HLC)
    """

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def add_device(self, device_id: str, public_key: bytes, nickname: str) -> bool:
        """
        Add a new trusted device to the registry.
        Implements identity pinning by storing the public key.
        """
        try:
            conn = self.db.connect()
            conn.execute("""
                INSERT INTO trusted_devices (device_id, public_key, nickname, last_seen_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    public_key = excluded.public_key,
                    nickname = excluded.nickname,
                    trust_level = 1,
                    last_seen_at = excluded.last_seen_at
            """, (device_id, public_key, nickname, datetime.now().isoformat()))
            conn.commit()
            return True
        except Exception as e:
            raise DatabaseError(f"Failed to add trusted device: {e}")

    def revoke_device(self, device_id: str) -> bool:
        """
        Revoke trust for a device.
        Revoked devices are blocked from future sync sessions.
        """
        try:
            conn = self.db.connect()
            cursor = conn.execute("""
                UPDATE trusted_devices 
                SET trust_level = 0 
                WHERE device_id = ?
            """, (device_id,))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            raise DatabaseError(f"Failed to revoke device: {e}")

    def get_trusted_device(self, device_id: str) -> Optional[Dict]:
        """
        Retrieve a trusted device by its ID.
        Used to verify identity pinning during handshake.
        """
        try:
            conn = self.db.connect()
            cursor = conn.execute("""
                SELECT device_id, public_key, nickname, trust_level, last_synced_hlc, last_seen_at
                FROM trusted_devices
                WHERE device_id = ?
            """, (device_id,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
        except Exception as e:
            raise DatabaseError(f"Failed to retrieve device: {e}")

    def list_trusted_devices(self, include_revoked: bool = False) -> List[Dict]:
        """List all registered devices."""
        try:
            conn = self.db.connect()
            query = "SELECT * FROM trusted_devices"
            if not include_revoked:
                query += " WHERE trust_level = 1"
            
            cursor = conn.execute(query)
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            raise DatabaseError(f"Failed to list devices: {e}")

    def update_last_seen(self, device_id: str, last_hlc: Optional[str] = None) -> bool:
        """Update the last seen timestamp and last synced HLC for a device."""
        try:
            conn = self.db.connect()
            if last_hlc:
                conn.execute("""
                    UPDATE trusted_devices 
                    SET last_seen_at = ?, last_synced_hlc = ?
                    WHERE device_id = ?
                """, (datetime.now().isoformat(), last_hlc, device_id))
            else:
                conn.execute("""
                    UPDATE trusted_devices 
                    SET last_seen_at = ?
                    WHERE device_id = ?
                """, (datetime.now().isoformat(), device_id))
            conn.commit()
            return True
        except Exception as e:
            raise DatabaseError(f"Failed to update device status: {e}")

    def store_local_identity(self, device_id: str, public_key: bytes, 
                             private_key_enc: bytes, nonce: bytes, tag: bytes) -> bool:
        """Store this device's own identity keypair."""
        try:
            conn = self.db.connect()
            conn.execute("""
                INSERT INTO local_identity (id, device_id, public_key, private_key_encrypted, nonce, tag)
                VALUES (1, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    device_id = excluded.device_id,
                    public_key = excluded.public_key,
                    private_key_encrypted = excluded.private_key_encrypted,
                    nonce = excluded.nonce,
                    tag = excluded.tag
            """, (device_id, public_key, private_key_enc, nonce, tag))
            conn.commit()
            return True
        except Exception as e:
            raise DatabaseError(f"Failed to store local identity: {e}")

    def get_local_identity(self) -> Optional[Dict]:
        """Retrieve this device's identity."""
        try:
            conn = self.db.connect()
            cursor = conn.execute("SELECT * FROM local_identity WHERE id = 1")
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
        except Exception as e:
            raise DatabaseError(f"Failed to retrieve local identity: {e}")
