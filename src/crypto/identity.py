"""
Sentra Identity Manager
Handles Ed25519 identity keys for P2P authentication.
"""
import os
import hashlib
from typing import Dict
from cryptography.hazmat.primitives.asymmetric import ed25519
from src.database_manager import DatabaseManager, DatabaseError

class IdentityManager:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def ensure_identity(self) -> Dict[str, bytes]:
        """Ensures a device identity exists, generating if necessary."""
        # Simple implementation for MVP identity storage.
        # In production, private_key_encrypted would be encrypted by the master key.
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw()
        priv_bytes = priv.private_bytes_raw()
        
        device_id = hashlib.sha256(pub).hexdigest()
        
        # Store in local_identity
        conn = self.db.connect()
        conn.execute("""
            INSERT OR REPLACE INTO local_identity (id, device_id, public_key, private_key_encrypted, nonce, tag)
            VALUES (1, ?, ?, ?, ?, ?)
        """, (device_id, pub, priv_bytes, b"n", b"t"))
        conn.commit()
        
        return {"device_id": device_id, "public_key": pub}
