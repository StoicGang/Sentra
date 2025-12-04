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
        if not isinstance(self.vault_keys, tuple) or len(self.vault_keys) != 2:
            raise ValueError("Configuration Error: vault_keys must be a tuple: (encryption_key, hmac_key)")

        enc_key, hmac_key = self.vault_keys

        # Validate Encryption Key (ChaCha20-Poly1305 requires 32 bytes)
        if not isinstance(enc_key, bytes) or len(enc_key) != 32:
            raise ValueError(f"Invalid Encryption Key: Expected 32 bytes, got {len(enc_key) if isinstance(enc_key, bytes) else type(enc_key)}.")

        # Validate HMAC Key (Must be bytes, length depends on implementation but must exist)
        if not isinstance(hmac_key, bytes) or len(hmac_key) == 0:
            raise ValueError("Invalid HMAC Key: Must be non-empty bytes.")
        
        try:
            # Step 1: Fetch entries
            if not entries:
                data = self.db.get_all_entries(vault_key=self.vault_keys[0])
            else:
                data = [self.db.get_entry(eid, self.vault_keys[0]) for eid in entries]

            # Step 2: Encrypt entries
            encrypted_entries = []
            for entry in data:
                # DEFENSIVE CHECK: Skip None entries (corrupt/deleted race condition)
                if entry is None:
                    continue

                # Canonical serialization for deterministic plaintext
                entry_json = json.dumps(
                    entry, 
                    sort_keys=True, 
                    separators=(",", ":"), 
                    ensure_ascii=False
                )

                # Use unpacked variable 'enc_key'
                ciphertext, nonce, tag = encrypt_entry(
                    plaintext=entry_json,
                    key=enc_key,
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
            serialized = json.dumps(
                backup, 
                sort_keys=True, 
                separators=(",", ":"), 
                ensure_ascii=False
            ).encode("utf-8")
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
            serialized = json.dumps(
                backup, 
                sort_keys=True, 
                separators=(",", ":"), 
                ensure_ascii=False
            ).encode("utf-8")

            # Step 2: Verify HMAC
            expected_hmac = compute_hmac(serialized, self.vault_keys[1])
            if hmac_value != expected_hmac:
                raise ValueError("Backup integrity check failed (HMAC mismatch).")

            # Step 3: Decrypt entries with partial failure handling
            success_count = 0
            fail_count = 0
            
            print(f"Restoring {len(backup['entries'])} entries...")

            for index, enc in enumerate(backup["entries"]):
                try:
                    # Decryption
                    plaintext = decrypt_entry(
                        ciphertext=base64.b64decode(enc["ciphertext"]),
                        nonce=base64.b64decode(enc["nonce"]),
                        auth_tag=base64.b64decode(enc["tag"]),
                        key=self.vault_keys[0],
                        associated_data=b"backup-entry"
                    )
                    entry = json.loads(plaintext)

                    # Step 4: Insert into DB
                    title = entry.get("title")
                    if not title: 
                        print(f"Warning: Skipping entry #{index} - Missing title.")
                        fail_count += 1
                        continue 

                    original_id = entry.get("id")
                    
                    # Logic: Try ADD, fallback to UPDATE (Upsert)
                    try:
                        self.db.add_entry(
                            vault_key=self.vault_keys[0],
                            entry_id=original_id,
                            title=title,
                            url=entry.get("url"),
                            username=entry.get("username"),
                            password=entry.get("password"),
                            notes=entry.get("notes"),
                            tags=entry.get("tags"),
                            category=entry.get("category", "General"),
                            favorite=entry.get("favorite", False)
                        )
                    except Exception:
                        # If ADD fails (likely duplicate ID), we must UPDATE.
                        # 1. Ensure it's not in the trash (so update_entry can find it)
                        self.db.restore_entry(original_id)
                        
                        # 2. Update the existing record with backup data
                        self.db.update_entry(
                            entry_id=original_id,
                            vault_key=self.vault_keys[0],
                            title=title,
                            url=entry.get("url"),
                            username=entry.get("username"),
                            password=entry.get("password"),
                            notes=entry.get("notes"),
                            tags=entry.get("tags"),
                            category=entry.get("category", "General"),
                            favorite=entry.get("favorite", False)
                        )
                    
                    success_count += 1

                except Exception as e:
                    # Robustness: Log failure but continue with next entry
                    print(f"Error restoring entry #{index}: {e}")
                    fail_count += 1
                    continue

            print(f"Restore Complete: {success_count} succeeded, {fail_count} failed.")
            return True

        except Exception as e:
            # Fatal errors (File IO, HMAC) still raise
            raise RuntimeError(f"Restore failed: {e}")