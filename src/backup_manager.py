import os
from datetime import datetime, timezone 
import json
import base64
import hmac, hashlib
import uuid
from typing import Tuple, List, Dict

from src.crypto_engine import (
    encrypt_entry, decrypt_entry, compute_hmac, derive_hkdf_key, generate_salt
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

        enc_key, hmac_key = self.vault_keys
        if enc_key == hmac_key:
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
                data = self.db.get_all_entries(vault_key=internal_vault_key)
            else:
                data = [self.db.get_entry(eid, internal_vault_key) for eid in entries]

            # Step 2: Re-Encrypt for Backup
            encrypted_entries = []
            for entry in data:
                if entry is None: continue

                # Canonical serialization
                entry_json = json.dumps(
                    entry, 
                    sort_keys=True, 
                    separators=(",", ":"), 
                    ensure_ascii=False
                )

                # Encrypt using BACKUP key (enc_key)
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

            # Step 3: Construct Binary Segments
            
            # A. Header
            header_dict = {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
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

    def restore_backup(self, filename: str) -> bool:
        """
        Restore vault data from Secure Binary Envelope.
        Envelope format expected:
        [4-byte BE header_len][header_bytes][payload_bytes][32-byte HMAC]
        HMAC is HMAC-SHA256 computed over (header_bytes || payload_bytes).
        """

        # enc_key/hmac_key were provided when BackupManager was created
        enc_key, hmac_key = self.vault_keys

        try:
            # 1) Read raw file
            with open(filename, "rb") as f:
                raw = f.read()

            # Minimal size: 4 bytes header_len + at least '{}' + 32 bytes HMAC
            if len(raw) < 4 + 2 + 32:
                raise ValueError("Backup file is too short/corrupted.")

            # 2) Parse envelope boundaries safely
            header_len = int.from_bytes(raw[:4], "big")
            if header_len <= 0 or header_len > 10 * 1024:  # 10 kiB max header
                raise ValueError("Invalid header length in backup.")

            header_start = 4
            header_end = 4 + header_len

            if header_end + 32 > len(raw):
                raise ValueError("Backup file truncated or malformed.")

            header_bytes = raw[header_start:header_end]
            payload_bytes = raw[header_end:-32]
            hmac_stored = raw[-32:]

            # 3) Verify HMAC (authenticate-then-parse)
            hmac_computed = hmac.new(key=hmac_key, msg=header_bytes + payload_bytes, digestmod=hashlib.sha256).digest()
            if not hmac.compare_digest(hmac_stored, hmac_computed):
                raise ValueError("Backup integrity check FAILED (HMAC mismatch). File may be corrupted or tampered.")

            # 4) Parse header JSON (now that it's authenticated)
            try:
                header = json.loads(header_bytes.decode("utf-8"))
            except Exception as e:
                raise ValueError(f"Failed to parse backup header JSON: {e}")

            # Optional header sanity checks
            version = header.get("version", 1)
            if version != 1:
                # decide policy: either support older versions or require exact match
                raise ValueError(f"Unsupported backup version: {version}")

            declared_count = header.get("entry_count")
            # We will compare with actual entries after parsing payload

            # 5) Parse payload JSON (authenticated)
            try:
                backup_data = json.loads(payload_bytes.decode("utf-8"))
            except Exception as e:
                raise ValueError(f"Failed to parse backup payload JSON: {e}")

            entries_list = backup_data.get("entries", [])
            if declared_count is not None and declared_count != len(entries_list):
                raise ValueError("Backup header entry_count mismatch with payload.")

            # 6) Start DB transaction (IMMEDIATE to lock DB for restore)
            conn = self.db.connect()
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")

            try:
                # 7) Obtain internal vault key for re-encryption
                internal_vault_key = self.hierarchy_keys.get('vault_key')
                if not internal_vault_key:
                    raise RuntimeError("Missing 'vault_key' in hierarchy_keys. Cannot re-encrypt for storage.")

                # Ensure internal_vault_key is bytes
                if isinstance(internal_vault_key, str):
                    internal_vault_key = bytes.fromhex(internal_vault_key)

                # Process each entry
                now_iso = datetime.now(timezone.utc).isoformat()
                for item in entries_list:
                    # Each item should already contain base64 ciphertext/nonce/tag for the entry-level enc_key
                    try:
                        c_b64 = item.get("ciphertext")
                        n_b64 = item.get("nonce")
                        t_b64 = item.get("tag")

                        if not c_b64 or not n_b64 or not t_b64:
                            raise ValueError("Malformed entry in backup (missing ciphertext/nonce/tag).")

                        ciphertext = base64.b64decode(c_b64)
                        nonce = base64.b64decode(n_b64)
                        auth_tag = base64.b64decode(t_b64)

                        # Decrypt entry using backup file encryption key (enc_key)
                        plaintext = decrypt_entry(
                            ciphertext=ciphertext,
                            nonce=nonce,
                            auth_tag=auth_tag,
                            key=enc_key,
                            associated_data=b"backup-entry"
                        )
                        entry_data = json.loads(plaintext)

                        # Required fields & defaults
                        entry_id = entry_data.get("id") or str(uuid.uuid4())
                        title = entry_data.get("title")
                        if not title:
                            # skip entries with no title
                            continue

                        url = entry_data.get("url")
                        username = entry_data.get("username")
                        tags = entry_data.get("tags")
                        category = entry_data.get("category", "General")
                        favorite_flag = 1 if entry_data.get("favorite") else 0
                        password_strength = int(entry_data.get("password_strength", 0))
                        password_age_days = int(entry_data.get("password_age_days", 0))

                        # Derive per-entry key for *internal* vault storage
                        entry_salt = generate_salt(16)  # bytes
                        internal_entry_key = derive_hkdf_key(
                            master_key=internal_vault_key,
                            info=entry_id.encode('utf-8'),
                            salt=entry_salt
                        )

                        # Re-encrypt password and notes under internal_entry_key
                        pw_plain = json.dumps({"password": entry_data.get("password", "")})
                        notes_plain = json.dumps({"notes": entry_data.get("notes", "")})

                        pw_c, pw_n, pw_t = encrypt_entry(plaintext=pw_plain, key=internal_entry_key)
                        nt_c, nt_n, nt_t = encrypt_entry(plaintext=notes_plain, key=internal_entry_key)

                        # Insert (or replace) into entries table
                        cursor.execute("""
                            INSERT OR REPLACE INTO entries (
                                id, title, url, username,
                                password_encrypted, password_nonce, password_tag,
                                notes_encrypted, notes_nonce, notes_tag,
                                tags, category, created_at, modified_at,
                                favorite, password_strength, password_age_days,
                                is_deleted, deleted_at, kdf_salt
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            entry_id,
                            title,
                            url,
                            username,
                            pw_c, pw_n, pw_t,
                            nt_c, nt_n, nt_t,
                            tags, category, now_iso, now_iso,
                            favorite_flag, password_strength, password_age_days,
                            0, None, entry_salt
                        ))

                    except Exception as e:
                        # Fail the whole restore if any entry cannot be processed
                        raise RuntimeError(f"Failed to process backup entry '{item.get('id') or '<unknown>'}': {e}")

                # 8) Commit once all entries processed
                conn.commit()

                # Optional: zero sensitive copies
                try:
                    if isinstance(internal_vault_key, bytearray):
                        for i in range(len(internal_vault_key)):
                            internal_vault_key[i] = 0
                except Exception:
                    pass

                return True

            except Exception as e:
                conn.rollback()
                raise RuntimeError(f"Restore failed during DB write: {e}")

        except Exception as e:
            # Wrap errors consistently for caller
            raise RuntimeError(f"Restore failed: {e}")