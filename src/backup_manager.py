import os
import datetime
import json
import base64
from typing import Tuple, List, Dict

from src.crypto_engine import (
    encrypt_entry, decrypt_entry, compute_hmac
)
from src.database_manager import DatabaseManager


class BackupManager:
    def __init__(self, db: DatabaseManager, vault_keys: Tuple[bytes, bytes], hierarchy_keys: Dict):
        """
        Args:
            db: DatabaseManager instance for vault operations.
            vault_keys: Tuple of (encryption_key, hmac_key).
            hierarchy_keys: Optional dict of hierarchical keys.
        """
        self.db = db
        self.vault_keys = vault_keys
        self.hierarchy_keys = hierarchy_keys

    def create_backup(self, filename: str, entries: List[str] = None) -> bool:
        """
        Export vault data to an encrypted backup file.
        - Entries list is optional; if empty, back up entire vault.
        - Encrypt each entry and serialize with Base64.
        - Generate HMAC for integrity.
        """
        try:
            # Step 1: Fetch entries
            if not entries:
                data = self.db.get_all_entries()
            else:
                data = [self.db.get_entry(eid, self.vault_keys[0]) for eid in entries]

            # Step 2: Encrypt entries
            encrypted_entries = []
            for entry in data:
                ciphertext, nonce, tag = encrypt_entry(
                    plaintext=json.dumps(entry),
                    key=self.vault_keys[0],
                    associated_data=b"backup-entry"
                )
                encrypted_entries.append({
                    "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
                    "nonce": base64.b64encode(nonce).decode("utf-8"),
                    "tag": base64.b64encode(tag).decode("utf-8"),
                })

            # Step 3: Build backup structure
            backup = {
                "metadata": {
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "version": "1.0"
                },
                "entries": encrypted_entries
            }

            # Step 4: Generate HMAC
            serialized = json.dumps(backup).encode("utf-8")
            hmac_value = compute_hmac(serialized, self.vault_keys[1])
            backup["hmac"] = base64.b64encode(hmac_value).decode("utf-8")

            # Step 5: Write to file
            with open(filename, "w") as f:
                json.dump(backup, f)

            return True
        except Exception as e:
            raise RuntimeError(f"Backup failed: {e}")

    def restore_backup(self, filename: str) -> bool:
        """
        Restore vault data from encrypted backup.
        - Verify HMAC integrity.
        - Decrypt entries.
        - Import into database.
        """
        try:
            # Step 1: Read file
            with open(filename, "r") as f:
                backup = json.load(f)

            hmac_value = base64.b64decode(backup.pop("hmac"))
            serialized = json.dumps(backup).encode("utf-8")

            # Step 2: Verify HMAC
            expected_hmac = compute_hmac(serialized, self.vault_keys[1])
            if hmac_value != expected_hmac:
                raise ValueError("Backup integrity check failed (HMAC mismatch).")

            # Step 3: Decrypt entries
            for enc in backup["entries"]:
                plaintext = decrypt_entry(
                    ciphertext=base64.b64decode(enc["ciphertext"]),
                    nonce=base64.b64decode(enc["nonce"]),
                    auth_tag=base64.b64decode(enc["tag"]),
                    key=self.vault_keys[0],
                    associated_data=b"backup-entry"
                )
                entry = json.loads(plaintext)

                # Step 4: Insert into DB
                self.db.add_entry(**entry)

            return True
        except Exception as e:
            raise RuntimeError(f"Restore failed: {e}")
