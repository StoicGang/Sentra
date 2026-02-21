import os
from datetime import datetime, timezone
import json
import base64
import hmac, hashlib
import uuid
from typing import Tuple, List, Dict

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from src.crypto_engine import (
    encrypt_entry, decrypt_entry, derive_hkdf_key, generate_salt, generate_nonce
)
from src.database_manager import DatabaseManager


MAX_BACKUP_SIZE = 100 * 1024 * 1024  # 100 MB
MAX_HEADER_LEN = 10 * 1024

# ---------------------------------------------------------------------------
# Backup format versions
# ---------------------------------------------------------------------------
# v1 (legacy): header_len | header_JSON | payload_JSON | HMAC(32)
#   - Each entry is individually encrypted inside the JSON payload.
#   - The outer payload JSON is written in plaintext.
#
# v2 (current): header_len | header_JSON | enc_payload_len | enc_payload | HMAC(32)
#   - A file-level ChaCha20-Poly1305 key is derived from enc_key via HKDF.
#   - The entire entries-JSON payload is encrypted before writing.
#   - The HMAC covers: header_len || header || enc_payload_len || enc_payload.
#   - KDF salt (16 B) and file nonce (12 B) are stored in the header JSON.
# ---------------------------------------------------------------------------

BACKUP_VERSION = 2
_FILE_ENC_INFO = b"backup-file-enc-v2"


class BackupManager:
    def __init__(self, db: DatabaseManager, vault_keys: Tuple[bytes, bytes], hierarchy_keys: Dict):
        """
        Args:
            db: DatabaseManager instance for vault operations.
            vault_keys: Tuple of (encryption_key, hmac_key).
            hierarchy_keys: Dict containing at least {'vault_key': bytes(32)}.
        """
        self.db = db

        if not isinstance(vault_keys, tuple) or len(vault_keys) != 2:
            raise ValueError("vault_keys must be a tuple: (encryption_key, hmac_key)")

        self.vault_keys = vault_keys

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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _derive_file_enc_key(self, salt: bytes) -> bytes:
        """Derive the file-level encryption key from the master enc_key."""
        enc_key, _ = self.vault_keys
        return derive_hkdf_key(
            master_key=enc_key,
            info=_FILE_ENC_INFO,
            salt=salt,
            length=32,
        )

    def _encrypt_payload(self, payload_bytes: bytes, file_enc_key: bytes, nonce: bytes) -> bytes:
        """
        Encrypt the payload bytes with ChaCha20-Poly1305.
        Returns ciphertext+tag (tag appended by the library).
        """
        cipher = ChaCha20Poly1305(file_enc_key)
        return cipher.encrypt(nonce, payload_bytes, b"backup-payload-v2")

    def _decrypt_payload(self, encrypted: bytes, file_enc_key: bytes, nonce: bytes) -> bytes:
        """Decrypt the outer payload (ChaCha20-Poly1305). Returns plaintext bytes."""
        cipher = ChaCha20Poly1305(file_enc_key)
        return cipher.decrypt(nonce, encrypted, b"backup-payload-v2")

    # ------------------------------------------------------------------
    # create_backup
    # ------------------------------------------------------------------

    def create_backup(self, filename: str, entries: List[str] = None) -> bool:
        """
        Export vault data to an encrypted backup file (format v2).

        - Entries list is optional; if empty/None, backs up the entire vault.
        - Each entry is individually encrypted inside the payload JSON.
        - The entire payload JSON is then encrypted with a per-backup derived key.
        - An HMAC covers the full binary structure for integrity.
        """
        if not isinstance(self.vault_keys, tuple) or len(self.vault_keys) != 2:
            raise ValueError("Configuration Error: vault_keys must be a tuple: (encryption_key, hmac_key)")

        enc_key, hmac_key = self.vault_keys

        # Key used to decrypt source DB entries
        internal_vault_key = self.hierarchy_keys.get("vault_key")
        if not internal_vault_key:
            raise RuntimeError("Missing 'vault_key' in hierarchy_keys. Cannot access vault data.")

        try:
            # --------------------------------------------------------
            # Step 1: Fetch and decrypt source entries
            # --------------------------------------------------------
            if not entries:
                all_entries = self.db.get_all_entries(vault_key=internal_vault_key)
            else:
                all_entries = []
                for eid in entries:
                    entry = self.db.get_entry(eid, internal_vault_key)
                    if entry is not None:
                        all_entries.append(entry)

            # --------------------------------------------------------
            # Step 2: Re-encrypt each entry for the backup file
            # --------------------------------------------------------
            encrypted_entries = []

            for entry in all_entries:
                eid = entry.get("id") or str(uuid.uuid4())
                entry_copy = dict(entry)
                entry_copy["password"] = entry_copy.get("password") or ""
                entry_copy["notes"] = entry_copy.get("notes") or ""

                entry_json = json.dumps(
                    entry_copy,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )

                backup_entry_key = derive_hkdf_key(
                    master_key=enc_key,
                    info=b"backup-entry-" + eid.encode(),
                    salt=b"\x00" * 16,
                )

                ciphertext, nonce_e, tag = encrypt_entry(
                    plaintext=entry_json,
                    key=backup_entry_key,
                    associated_data=b"backup-entry",
                )

                encrypted_entries.append({
                    "entry_id": eid,
                    "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
                    "nonce": base64.b64encode(nonce_e).decode("utf-8"),
                    "tag": base64.b64encode(tag).decode("utf-8"),
                })

                del entry_json, backup_entry_key, entry_copy

            # --------------------------------------------------------
            # Step 3: Serialize payload and encrypt it (v2)
            # --------------------------------------------------------
            payload_dict = {"entries": encrypted_entries}
            payload_bytes = json.dumps(
                payload_dict, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")

            # Derive a fresh per-backup file encryption key
            kdf_salt = generate_salt(16)
            file_enc_key = self._derive_file_enc_key(kdf_salt)
            file_nonce = generate_nonce(12)

            encrypted_payload = self._encrypt_payload(payload_bytes, file_enc_key, file_nonce)
            del payload_bytes, file_enc_key

            # --------------------------------------------------------
            # Step 4: Build header (plaintext – contains kdf_salt & nonce)
            # --------------------------------------------------------
            header_dict = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": BACKUP_VERSION,
                "entry_count": len(encrypted_entries),
                "backup_id": str(uuid.uuid4()),
                "kdf_salt": base64.b64encode(kdf_salt).decode("utf-8"),
                "file_nonce": base64.b64encode(file_nonce).decode("utf-8"),
            }
            header_bytes = json.dumps(
                header_dict, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
            header_len_bytes = len(header_bytes).to_bytes(4, "big")

            enc_payload_len_bytes = len(encrypted_payload).to_bytes(4, "big")

            # --------------------------------------------------------
            # Step 5: Compute HMAC over the full binary structure
            # --------------------------------------------------------
            hmac_body = (
                header_len_bytes
                + header_bytes
                + enc_payload_len_bytes
                + encrypted_payload
            )
            hmac_computed = hmac.new(
                key=hmac_key,
                msg=hmac_body,
                digestmod=hashlib.sha256,
            ).digest()

            # --------------------------------------------------------
            # Step 6: Write binary file atomically
            # --------------------------------------------------------
            with open(filename, "wb") as f:
                f.write(header_len_bytes)
                f.write(header_bytes)
                f.write(enc_payload_len_bytes)
                f.write(encrypted_payload)
                f.write(hmac_computed)
                f.flush()
                os.fsync(f.fileno())

            return True

        except Exception as e:
            raise RuntimeError(f"Backup failed: {e}")

        finally:
            # Zero out key references if they are mutable
            if self.vault_keys:
                k1, k2 = self.vault_keys
                if isinstance(k1, bytearray):
                    for i in range(len(k1)):
                        k1[i] = 0
                if isinstance(k2, bytearray):
                    for i in range(len(k2)):
                        k2[i] = 0
            try:
                del enc_key
                del hmac_key
            except UnboundLocalError:
                pass

    # ------------------------------------------------------------------
    # restore_backup
    # ------------------------------------------------------------------

    def restore_backup(self, filename: str) -> bool:
        """
        Restore vault from a v1 or v2 backup file.

        Security features:
        - Size limit check.
        - HMAC verification before any payload parsing.
        - Version-gated decryption (v1 legacy / v2 encrypted payload).
        - Two-phase commit: validate all entries in memory, then write atomically.
        """
        enc_key, hmac_key = self.vault_keys

        # ----------------------------------------------------------
        # 1. Size check
        # ----------------------------------------------------------
        try:
            if os.path.getsize(filename) > MAX_BACKUP_SIZE:
                raise ValueError("Backup file exceeds maximum allowed size.")
        except OSError as e:
            raise RuntimeError(f"Could not access backup file: {e}")

        try:
            with open(filename, "rb") as f:
                raw = f.read()
        except OSError as e:
            raise RuntimeError(f"Could not read backup file: {e}")

        # Minimum: 4 (hdr_len) + 2 (hdr) + 4 (payload sentinel) + 32 (HMAC)
        if len(raw) < 4 + 2 + 32:
            raise RuntimeError("Backup file is too short.")

        # ----------------------------------------------------------
        # 2. Parse header length and validate it
        # ----------------------------------------------------------
        header_len = int.from_bytes(raw[:4], "big")
        if header_len == 0 or header_len > MAX_HEADER_LEN:
            raise RuntimeError(f"Invalid header length: {header_len}")

        header_end = 4 + header_len
        if header_end > len(raw) - 32:
            raise RuntimeError("Backup file is truncated (header overflows).")

        header_bytes = raw[4:header_end]

        # Parse header early to detect version
        try:
            header = json.loads(header_bytes.decode("utf-8"))
        except Exception:
            raise RuntimeError("Restore failed: Backup invalid, corrupt, or wrong key.")

        version = header.get("version", 1)
        if version not in (1, 2):
            raise RuntimeError(f"Unsupported backup version: {version}")

        # ----------------------------------------------------------
        # 3. Split body and HMAC; verify integrity
        # ----------------------------------------------------------
        # In v1: body = header_len | header | payload_JSON
        #         file = body | HMAC(32)
        # In v2: body = header_len | header | enc_payload_len | enc_payload
        #         file = body | HMAC(32)
        hmac_stored = raw[-32:]
        body_bytes = raw[:-32]  # everything except the trailing HMAC

        hmac_computed = hmac.new(
            key=hmac_key,
            msg=body_bytes,
            digestmod=hashlib.sha256,
        ).digest()

        if not hmac.compare_digest(hmac_stored, hmac_computed):
            raise RuntimeError("Restore failed: HMAC mismatch — backup tampered or wrong key.")

        # ----------------------------------------------------------
        # 4. Decode payload per version
        # ----------------------------------------------------------
        try:
            if version == 1:
                # Legacy: plaintext JSON payload follows the header directly
                payload_bytes = raw[header_end:-32]
                backup_data = json.loads(payload_bytes.decode("utf-8"))

            else:  # version == 2
                # Encrypted payload: [4 bytes enc_len][enc_payload]
                if header_end + 4 > len(raw) - 32:
                    raise ValueError("Truncated v2 payload length field.")

                enc_payload_len = int.from_bytes(raw[header_end:header_end + 4], "big")
                enc_start = header_end + 4
                enc_end = enc_start + enc_payload_len

                if enc_end > len(raw) - 32:
                    raise ValueError("Truncated v2 encrypted payload.")

                encrypted_payload = raw[enc_start:enc_end]

                # Recover the file-level encryption key from header params
                kdf_salt_b64 = header.get("kdf_salt")
                file_nonce_b64 = header.get("file_nonce")
                if not kdf_salt_b64 or not file_nonce_b64:
                    raise ValueError("v2 backup missing kdf_salt or file_nonce in header.")

                kdf_salt = base64.b64decode(kdf_salt_b64)
                file_nonce = base64.b64decode(file_nonce_b64)

                file_enc_key = self._derive_file_enc_key(kdf_salt)
                payload_bytes = self._decrypt_payload(encrypted_payload, file_enc_key, file_nonce)
                del file_enc_key

                backup_data = json.loads(payload_bytes.decode("utf-8"))

        except Exception:
            # Do not reveal whether it was a decryption, JSON, or version error
            raise RuntimeError("Restore failed: Backup invalid, corrupt, or wrong key.")

        # ----------------------------------------------------------
        # 5. Validate header metadata
        # ----------------------------------------------------------
        declared_count = header.get("entry_count")
        actual_entries = backup_data.get("entries", [])
        if declared_count is not None and declared_count != len(actual_entries):
            raise RuntimeError("Restore failed: entry_count mismatch between header and payload.")

        # ----------------------------------------------------------
        # 6. Phase 1 — Decrypt & validate each entry into memory
        # ----------------------------------------------------------
        validated_entries = []
        internal_vault_key = self.hierarchy_keys.get("vault_key")
        now_iso = datetime.now(timezone.utc).isoformat()

        for item in actual_entries:
            try:
                c_b64 = item.get("ciphertext")
                n_b64 = item.get("nonce")
                t_b64 = item.get("tag")

                if not c_b64 or not n_b64 or not t_b64:
                    continue

                # The entry_id is stored in plaintext so we can derive the
                # same per-entry HKDF key that was used during create_backup.
                stored_entry_id = item.get("entry_id")
                if not stored_entry_id:
                    continue

                backup_restore_key = derive_hkdf_key(
                    master_key=enc_key,
                    info=b"backup-entry-" + stored_entry_id.encode(),
                    salt=b"\x00" * 16,
                )

                plaintext = decrypt_entry(
                    ciphertext=base64.b64decode(c_b64),
                    nonce=base64.b64decode(n_b64),
                    auth_tag=base64.b64decode(t_b64),
                    key=backup_restore_key,
                    associated_data=b"backup-entry",
                )
                entry_data = json.loads(plaintext)

                entry_id = entry_data.get("id") or str(uuid.uuid4())
                entry_salt = generate_salt(16)

                internal_entry_key = derive_hkdf_key(
                    master_key=internal_vault_key,
                    info=b"entry-key-" + entry_id.encode("utf-8"),
                    salt=entry_salt,
                )

                pw_plain = json.dumps({"password": entry_data.get("password", "")})
                notes_plain = json.dumps({"notes": entry_data.get("notes", "")})

                pw_c, pw_n, pw_t = encrypt_entry(pw_plain, internal_entry_key,
                                                  associated_data=b"password")
                nt_c, nt_n, nt_t = encrypt_entry(notes_plain, internal_entry_key,
                                                  associated_data=b"notes")

                validated_entries.append((
                    entry_id, entry_data.get("title"), entry_data.get("url"),
                    entry_data.get("username"), pw_c, pw_n, pw_t, nt_c, nt_n, nt_t,
                    entry_data.get("tags"), entry_data.get("category", "General"),
                    now_iso, now_iso,
                    1 if entry_data.get("favorite") else 0,
                    int(entry_data.get("password_strength", 0)),
                    0, None, entry_salt,
                ))

            except Exception as e:
                raise RuntimeError(f"Restore failed: Corrupt entry — {e}")

        # ----------------------------------------------------------
        # 7. Phase 2 — Atomic write to DB
        # ----------------------------------------------------------
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

        # Outer exception handler
        # (RuntimeError from the inner try already propagates; this is for unexpected errors)