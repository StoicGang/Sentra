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
        from src.storage.device_repository import DeviceRepository
        repo = DeviceRepository(self.db)
        existing = repo.get_local_identity()
        if existing:
            return {
                "device_id": existing["device_id"],
                "public_key": existing["public_key"]
            }

        # Simple implementation for MVP identity storage.
        # In production, private_key_encrypted would be encrypted by the master key.
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw()
        priv_bytes = priv.private_bytes_raw()
        
        device_id = hashlib.sha256(pub).hexdigest()
        
        repo.store_local_identity(device_id, pub, priv_bytes, b"n", b"t")
        
        return {"device_id": device_id, "public_key": pub}

def ed25519_pub_to_x25519(ed_pub_bytes: bytes) -> bytes:
    y_bytes = bytearray(ed_pub_bytes)
    y_bytes[31] &= 0x7F
    y = int.from_bytes(y_bytes, 'little')
    
    p = 2**255 - 19
    u = (1 + y) * pow(1 - y, p - 2, p) % p
    return u.to_bytes(32, 'little')

def ed25519_priv_to_x25519(ed_priv_bytes: bytes) -> bytes:
    import hashlib
    h = hashlib.sha512(ed_priv_bytes).digest()
    return h[:32]
