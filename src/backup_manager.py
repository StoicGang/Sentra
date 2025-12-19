import os
from datetime import datetime, timezone 
import json
import base64
import hmac, hashlib
import uuid
from typing import Tuple, List, Dict

from src.crypto_engine import (
    encrypt_entry, decrypt_entry, derive_hkdf_key, generate_salt
)
from src.database_manager import DatabaseManager


MAX_BACKUP_SIZE = 100 * 1024 * 1024  # e.g. 100 MB
MAX_HEADER_LEN = 10 * 1024

class BackupManager:
    def __init__(self, db: DatabaseManager, vault_keys: Tuple[bytes, bytes], hierarchy_keys: Dict):
        """
        Args:
            db: DatabaseManager instance for vault operations.
            vault_keys: Tuple of (encryption_key, hmac_key).
            hierarchy_keys: Optional dict of hierarchical keys.
        """
        self.db = db

        if not isinstance(vault_keys, tuple) or len(vault_keys) != 2:
            raise ValueError("vault_keys must be a tuple: (encryption_key, hmac_key)")
        
        self.vault_keys = vault_keys
        # Validate hierarchy keys schema early (fail fast)
        if not isinstance(hierarchy_keys, dict):
            raise ValueError("hierarchy_keys must be a dict")

        vault_key = hierarchy_keys.get("vault_key")
        if not isinstance(vault_key, (bytes, bytearray)) or len(vault_key) != 32:
            raise ValueError(
                "hierarchy_keys must contain 'vault_key' as 32-byte bytes"
            )

        self.hierarchy_keys = hierarchy_keys

        enc_key, hmac_key = self.vault_keys
        if hmac.compare_digest(enc_key, hmac_key):
            raise ValueError(
                "CRITICAL SECURITY ERROR: Encryption key and HMAC key must be different. "
                "Check key derivation logic."
            )

    def create_backup(self, filename: str, entries: List[str] = None) -> bool:
        """
        Export vault data to an encrypted backup file.
        - Entries list is optional; if empty, back up entire vault.
        - Encrypt each entry and serialize with Base64.
        - Generate HMAC for integrity.
        """
        if not isinstance(self.vault_keys, tuple) or len(self.vault_keys) != 2:
            raise ValueError("Configuration Error: vault_keys must be a tuple: (encryption_key, hmac_key)")

        # Keys for the BACKUP FILE
        enc_key, hmac_key = self.vault_keys

        # FIX: Retrieve INTERNAL key to decrypt source DB entries
        internal_vault_key = self.hierarchy_keys.get('vault_key')
        if not internal_vault_key:
            raise RuntimeError("Missing 'vault_key' in hierarchy_keys. Cannot access vault data.")

        try:
            # Step 1: Fetch and Decrypt source entries
            # We must use internal_vault_key here, otherwise DB decryption fails.
            if not entries:
                entry_ids = self.db.list_entry_ids()
            else:
                entry_ids = entries

            # Step 2: Re-Encrypt for Backup
            encrypted_entries = []

            for eid in entry_ids:
                entry = self.db.get_entry(eid, internal_vault_key)
                if entry is None:
                    continue

                entry_copy = dict(entry)
                entry_copy["password"] = entry_copy.get("password") or ""
                entry_copy["notes"] = entry_copy.get("notes") or ""

                entry_json = json.dumps(
                    entry_copy,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False
                )

                backup_entry_key = derive_hkdf_key(
                    master_key=enc_key,
                    info=b"backup-entry-" + eid.encode(),
                    salt=b"\x00" * 16
                )

                ciphertext, nonce, tag = encrypt_entry(
                    plaintext=entry_json,
                    key=backup_entry_key,
                    associated_data=b"backup-entry"
                )

                encrypted_entries.append({
                    "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
                    "nonce": base64.b64encode(nonce).decode("utf-8"),
                    "tag": base64.b64encode(tag).decode("utf-8"),
                })

                # Reduce plaintext lifetime
                del entry_json, backup_entry_key, entry_copy

            # Step 3: Construct Binary Segments

            # A. Header
            header_dict = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": 1,
                "entry_count": len(encrypted_entries),
                "backup_id": str(uuid.uuid4())
            }
            header_bytes = json.dumps(header_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
            header_len_bytes = len(header_bytes).to_bytes(4, "big")

            # B. Payload
            payload_dict = {"entries": encrypted_entries}
            payload_bytes = json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")

            # Step 4: Compute HMAC (Header + Payload)
            hmac_computed = hmac.new(
                key=hmac_key,
                msg=header_bytes + payload_bytes,
                digestmod=hashlib.sha256
            ).digest()

            # Step 5: Write Binary File
            with open(filename, "wb") as f:
                f.write(header_len_bytes)
                f.write(header_bytes)
                f.write(payload_bytes)
                f.write(hmac_computed)
                f.flush()
                os.fsync(f.fileno())

            return True

        except Exception as e:
            raise RuntimeError(f"Backup failed: {e}")

        finally:
            if self.vault_keys:
                k1, k2 = self.vault_keys
                if isinstance(k1, bytearray):
                    for i in range(len(k1)): k1[i] = 0
                if isinstance(k2, bytearray):
                    for i in range(len(k2)): k2[i] = 0
            try:
                del enc_key
                del hmac_key
            except UnboundLocalError:
                pass

    def restore_backup(self, filename: str) -> bool:
        """
        Restore vault with Timing Protection, Header Validation, and Two-Phase Commit.
        """
        enc_key, hmac_key = self.vault_keys

        # 1. Size Check
        try:
            if os.path.getsize(filename) > MAX_BACKUP_SIZE:
                raise ValueError("Backup file exceeds maximum allowed size.")
        except OSError as e:
            raise RuntimeError(f"Could not access backup file: {e}")

        try:
            with open(filename, "rb") as f:
                raw = f.read()

            if len(raw) < 4 + 2 + 32:
                raise ValueError("Backup file is truncated.")

            header_len = int.from_bytes(raw[:4], "big")
            header_end = 4 + header_len

            # FIX CRITICAL-07: Unified Error Path (Timing Protection)
            try:
                header_bytes = raw[4:header_end]
                payload_bytes = raw[header_end:-32]
                hmac_stored = raw[-32:]

                # A. Verify HMAC
                hmac_computed = hmac.new(
                    key=hmac_key,
                    msg=header_bytes + payload_bytes,
                    digestmod=hashlib.sha256
                ).digest()

                if not hmac.compare_digest(hmac_stored, hmac_computed):
                    raise ValueError("Integrity failure")

                    # B. Parse JSON
                header = json.loads(header_bytes.decode("utf-8"))
                backup_data = json.loads(payload_bytes.decode("utf-8"))

                # C. Validate Header Metadata (FIXED)
                # Ensure version is supported
                if header.get("version", 1) != 1:
                    raise ValueError("Unsupported backup version.")

                # Ensure payload matches declared count
                declared_count = header.get("entry_count")
                actual_entries = backup_data.get("entries", [])
                if declared_count is not None and declared_count != len(actual_entries):
                    raise ValueError("Entry count mismatch between header and payload.")

            except Exception:
                # SECURITY: Do not reveal if it was HMAC, JSON, or Header mismatch
                raise RuntimeError("Restore failed: Backup invalid, corrupt, or wrong key.")

            # FIX CRITICAL-06: Phase 1 - Decrypt/Validate into Memory
            validated_entries = []
            entries_list = backup_data.get("entries", [])
            internal_vault_key = self.hierarchy_keys.get('vault_key')
            now_iso = datetime.now(timezone.utc).isoformat()

            for item in entries_list:
                try:
                    c_b64 = item.get("ciphertext")
                    n_b64 = item.get("nonce")
                    t_b64 = item.get("tag")

                    if not c_b64 or not n_b64 or not t_b64:
                        continue

                    plaintext = decrypt_entry(
                        ciphertext=base64.b64decode(c_b64),
                        nonce=base64.b64decode(n_b64),
                        auth_tag=base64.b64decode(t_b64),
                        key=enc_key,
                        associated_data=b"backup-entry"
                    )
                    entry_data = json.loads(plaintext)

                    # Prepare for DB (Re-encryption)
                    entry_id = entry_data.get("id") or str(uuid.uuid4())
                    entry_salt = generate_salt(16)

                    internal_entry_key = derive_hkdf_key(
                        master_key=internal_vault_key,
                        info=b"entry-key-" + entry_id.encode("utf-8"),
                        salt=entry_salt
                    )

                    pw_plain = json.dumps({"password": entry_data.get("password", "")})
                    notes_plain = json.dumps({"notes": entry_data.get("notes", "")})

                    pw_c, pw_n, pw_t = encrypt_entry(pw_plain, internal_entry_key)
                    nt_c, nt_n, nt_t = encrypt_entry(notes_plain, internal_entry_key)

                    validated_entries.append((
                        entry_id, entry_data.get("title"), entry_data.get("url"),
                        entry_data.get("username"), pw_c, pw_n, pw_t, nt_c, nt_n, nt_t,
                        entry_data.get("tags"), entry_data.get("category", "General"),
                        now_iso, now_iso,
                        1 if entry_data.get("favorite") else 0,
                        int(entry_data.get("password_strength", 0)),
                        0, None, entry_salt
                    ))

                except Exception as e:
                    raise RuntimeError(f"Corrupt entry in backup: {e}")

            # FIX CRITICAL-06: Phase 2 - Atomic Write
            conn = self.db.connect()
            conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = conn.cursor()
                cursor.executemany("""
                    INSERT OR REPLACE INTO entries (
                        id, title, url, username,
                        password_encrypted, password_nonce, password_tag,
                        notes_encrypted, notes_nonce, notes_tag,
                        tags, category, created_at, modified_at,
                        favorite, password_strength,
                        is_deleted, deleted_at, kdf_salt
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, validated_entries)

                conn.commit()
                return True
            except Exception as e:
                conn.rollback()
                raise RuntimeError(f"Database write failed: {e}")

        except Exception as e:
            raise RuntimeError(f"Restore failed: {e}")