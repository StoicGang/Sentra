"""
SENTRA Database Manager
Handles SQLit operations with encrypted entry storage and hierarchical key management
"""

import sqlite3
import os
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import warnings
import re
import json
import uuid
from src.config import DB_PATH, SCHEMA_PATH
from src.crypto_engine import encrypt_entry, decrypt_entry, derive_master_key, generate_salt, generate_nonce, compute_auth_hash, compute_hmac, derive_hkdf_key

# ============ Validation Constants ============
MAX_TITLE_LEN = 256
MAX_URL_LEN = 2048      # Standard browser limit
MAX_USERNAME_LEN = 256
MAX_TAGS_LEN = 512
MAX_NOTES_LEN = 32768   # 32KB limit for notes (enough for RSA keys)
MAX_CATEGORY_LEN = 64

class DatabaseError(Exception):
    """Base Exception for database operations"""
    pass

class VaultNotInitializedError(DatabaseError):
    """Raised when trying to use uninitialized vault"""
    pass

class EntryNotFoundError(DatabaseError):
    """Raised when entry doesn't exist"""

class DatabaseManager:
    """
    Manges SQLite database for SENTRA vault

    Reponsibilities:
        - Database initialization and schema creation
        - Vault metadata CRUD operations
        - Entry CRUD operations with encrypted storage
        - Transaction management
        - Connection pooling

    Security:
        - All sensitive data (passwords, notes) encrypted before storage
        - Uses hierarchical key (master -> vault -> entry)
        - Supports soft delete (trash system) for recovery
    """

    def __init__(self, db_path: str = DB_PATH):
        """
        Initialize database manager
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.connection: Optional[sqlite3.Connection] = None
        # Ensure data directory exists
        directory = os.path.dirname(self.db_path)
        try:
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
            # Attempt a write test to ensure permissions
            test_path = os.path.join(directory, ".sentra_write_test")
            with open(test_path, "w") as f:
                f.write("ok")
            os.remove(test_path)
        except Exception as e:
            raise RuntimeError(f"Database directory is not writable: {directory}") from e
    
    def connect(self) -> sqlite3.Connection:
        """ 
        Create or return existing databse connection
        
        Returns:
            SQLite connection object with Row factory    
        """
        if self.connection is None:
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA foreign_keys = ON")

            # Try WAL mode directly on the main connection
            res = self.connection.execute("PRAGMA journal_mode=WAL;").fetchone()
            actual_mode = res[0] if res else None

            if actual_mode != "wal":
                print("Warning: WAL mode unsupported, using DELETE journal mode.")
                self.connection.execute("PRAGMA journal_mode=DELETE;")

        return self.connection

    def close(self):
        """
        close the database connection
        """
        # TODO: Implement connection closing
        # HINTS:
        # 1. Check if self.connection exists
        # 2. If yes, commit any pending transactions: self.connection.commit()
        # 3. Close connection: self.connection.close()
        # 4. Set self.connection = None
        
        if self.connection:
            try:
                self.connection.commit()
            finally:
                self.connection.close()
                self.connection = None

    def __enter__(self):
        """Context manager entry - auto-connect"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - auto-close"""
        self.close()

    def _derive_entry_key(self, vault_key: bytes, entry_id:str, entry_salt: bytes) -> bytes:
            """ 
            Derive entry specific encryption key from vault key
            
            Args: 
                - vault_key: 32-bytes vault key
                - entry_id: Entry UUID string

            Returns:
                32-byte entry-specific key
            """
            # Encrypt the entry_key
            return derive_hkdf_key(
                master_key=vault_key,
                info=entry_id.encode(),
                salt=entry_salt,
                length=32
            )
    
    def _validate_entry_data(
        self, 
        title: Optional[str] = None, 
        url: Optional[str] = None, 
        username: Optional[str] = None, 
        notes: Optional[str] = None,
        tags: Optional[str] = None,
        category: Optional[str] = None
    ):
        """Helper to enforce strict length limits on entry data."""
        if title is not None:
            if not title or len(title) > MAX_TITLE_LEN:
                raise ValueError(f"Title must be 1-{MAX_TITLE_LEN} characters.")
        
        if url and len(url) > MAX_URL_LEN:
            raise ValueError(f"URL exceeds max length of {MAX_URL_LEN}.")
            
        if username and len(username) > MAX_USERNAME_LEN:
            raise ValueError(f"Username exceeds max length of {MAX_USERNAME_LEN}.")
            
        if tags and len(tags) > MAX_TAGS_LEN:
            raise ValueError(f"Tags exceed max length of {MAX_TAGS_LEN}.")
            
        if category and len(category) > MAX_CATEGORY_LEN:
            raise ValueError(f"Category exceeds max length of {MAX_CATEGORY_LEN}.")
            
        if notes and len(notes) > MAX_NOTES_LEN:
            raise ValueError(f"Notes exceed max length of {MAX_NOTES_LEN} characters.")

    def get_all_entries(self, vault_key: bytes) -> List[Dict]:
        """
        Retrieve and decrypt ALL entries (used for backups).
        """
        try:
            conn = self.connect()
            # Get all active IDs
            cursor = conn.execute("SELECT id FROM entries WHERE is_deleted = 0")
            rows = cursor.fetchall()
            
            all_entries = []
            for row in rows:
                # Reuse get_entry to handle key derivation and decryption safely
                entry = self.get_entry(row["id"], vault_key)
                if entry:
                    all_entries.append(entry)
            
            return all_entries
        except Exception as e:
            raise DatabaseError(f"Failed to retrieve all entries: {e}")

    def initialize_database(self) -> bool:
        """
        Initialize database shema from schema.sql file

        Returns:
            True if initialization successful
            False if already initialized

        Raises:
            DatabaseError: If schema file not found or SQL execution fails

        Error Handling:
            - FileNotFoundError: schema.sql not found
            - sqlite3.Error: SQL execution failed
        """
        try:
            conn = self.connect()

            # Always load the full schema atomically
            with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
                schema_sql = f.read()

            conn.execute("BEGIN IMMEDIATE;")
            conn.executescript(schema_sql)   # Schema already includes lockout_attempts
            conn.commit()
            return True

        except Exception as e:
            conn.rollback()
            raise DatabaseError(f"Critical: Database initialization failed: {e}") from e
    
    def save_vault_metadata(
            self,
            salt: bytes,
            auth_hash: bytes, 
            vault_key_encrypted: bytes, 
            vault_key_nonce: bytes, 
            vault_key_tag:bytes,
            kdf_config: Optional[Dict] = None
    ) -> bool:
        """
        Save vault initialization metadata to database

        Args:
            salt: 16-byte Argon2id salt
            auth_hash: 32-byte PBKDF2-HMAC-SHA256 password verification hash
            vault_key_encrypted: Encrypted vault key (32 bytes)
            vault_key_nonce: 12-byte ChaCha20 nonce
            vault_key_tag: 16-byte Poly1305 authentication tag
        
        Returns:
            True if save successful
            False if vault already initialized
        
        Raises:
            DatabaseError: If database operation fails
        """
        conn = self.connect()

        try:
            # FIX: Prepare the insert directly. 
            # If ID=1 exists, this will raise IntegrityError (handled below).
            
            kdf_json = json.dumps(kdf_config) if kdf_config else None
            
            conn.execute("BEGIN IMMEDIATE")
            
            conn.execute("""
                INSERT INTO vault_metadata (
                    id, salt, auth_hash, 
                    vault_key_encrypted, vault_key_nonce, vault_key_tag,
                    kdf_config,
                    created_at, version,
                    unlock_count, last_unlocked_at
                ) VALUES (
                    1, ?, ?, ?, ?, ?, ?, 
                    datetime('now'),    -- Use SQLite timestamp
                    '2.0', 
                    0, NULL
                )
            """, (
                salt, auth_hash,
                vault_key_encrypted, vault_key_nonce, vault_key_tag,
                kdf_json
            ))
            
            conn.commit()
            return True

        except sqlite3.IntegrityError as e:
            raise DatabaseError(f"Vault metadata already exists or schema violation: {e}") from e
        except Exception as e:
            conn.rollback() 
            raise DatabaseError(f"Failed to save vault metadata: {e}") from e
    
    def delete_vault_metadata(self) -> None:
        """
        Emergency rollback: delete vault metadata if initialization verification fails.
        """
        try:
            conn = self.connect()
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM vault_metadata WHERE id = 1")
            conn.commit()
        except Exception as e:
            # If rollback fails, we are in a bad state, but must try
            conn.rollback()
            raise DatabaseError(f"Critical failure: unable to rollback vault metadata: {e}") from e
        
    def load_vault_metadata(self) -> Optional[Dict]:
        """
        Load vault metadata from database

        Returns:
            Dictionary with vault configuration:
            {
                'salt': bytes,
                'auth_hash': bytes,
                'vault_key_encrypted': bytes,
                'vault_key_nonce': bytes,
                'vault_key_tag': bytes,
                'created_at': str,
                'last_unlocked_at': str,
                'unlock_count': int,
                'version': str
            }
            None if vault not initialized
        Raises:
            DatabaseError: If database operation fails
        """
        # TODO: Implement vault metadata load
        # HINTS:
        # 1. SELECT * FROM vault_metadata WHERE id = 1
        # 2. If no row found, return None
        # 3. Convert row to dictionary
        # 4. Return dictionary with all fields
        # 
        # Note: sqlite3.Row objects can be accessed like dicts
        conn = self.connect()

        cursor = conn.execute("SELECT * FROM vault_metadata WHERE id = 1")
        row = cursor.fetchone()

        if not row:
            return None
        
        # convert row to dictionary
        return dict(row)

    def update_unlock_timestamp(self) -> bool:
        """
        Update last unlock timestamp and increment unlock counter

        Returns:
            True if update successful
            False if vault not initialized

        Raises:
            DatabaseError: If database operation fails
        """
        conn = self.connect()
        timestamp = datetime.now().isoformat()

        cursor = conn.execute("""
            UPDATE vault_metadata
            SET last_unlocked_at = ?, unlock_count = unlock_count + 1
            WHERE id = 1
        """, (timestamp,))

        conn.commit()

        if cursor.rowcount == 0:
            raise DatabaseError("Vault metadata missing during unlock timestamp update")

        return cursor.rowcount > 0 # True if row was updated
    
    def add_entry(
            self, 
            vault_key: bytes, 
            title: str, 
            url: Optional[str] = None,
            username: Optional[str] = None, 
            password: Optional[str] = None, 
            notes: Optional[str] = None, 
            tags: Optional[str] = None, 
            category: str = "General",
            favorite: bool = False,
            password_strength: int = 0,
            entry_id: Optional[str] = None
    ) -> str:
        """ 
        Add new encrypted entry to vault
        
        Args:
            - vault_key: Vault encryption key 
            - title: Entry title (plaintext, searchable)
            - url: Optional[str] = Website URL (plaintext, searchable)
            - username: Optional[str] = Username/email (plaintext, searchable)
            - password: Optional[str] = Password (will be encrypted)
            - notes: Optional[str] = Additional notes (will be encrypted)
            - tags: Optional[str] = Comma-separated tags (plaintext, searchable)
            - category: str = Entry category

        Returns
            - Entry UUID
        
        Raises:
            DatabaseError: If database operation fails
        """
        try:
            # Validate inputs
            if not title or not isinstance(title, str):
                raise ValueError("Entry title must be a non-empty string")
            
            self._validate_entry_data(
                title=title, url=url, username=username, 
                notes=notes, tags=tags, category=category
            )

            if not isinstance(vault_key, bytes) or len(vault_key) != 32:
                raise ValueError("Vault key must be 32 bytes")
            
            # Generate the UUID
            if entry_id is None:
                entry_id = str(uuid.uuid4())
            
            entry_salt = generate_salt(16)

            # Derive the entry key
            entry_key = self._derive_entry_key(vault_key, entry_id, entry_salt)
            
            # 1. Encrypt Password
            pw_payload = {"password": password or ""}
            pw_cipher, pw_nonce, pw_tag = encrypt_entry(json.dumps(pw_payload), entry_key)
            
            # 2. Encrypt Notes
            notes_payload = {"notes": notes or ""}
            notes_cipher, notes_nonce, notes_tag = encrypt_entry(json.dumps(notes_payload), entry_key)
            
            # Insert into entries
            conn = self.connect()
            conn.execute("""
                INSERT INTO entries (
                    id, title, url, username,
                    password_encrypted, password_nonce, password_tag,
                    notes_encrypted, notes_nonce, notes_tag,
                    kdf_salt,
                    tags, category, created_at, modified_at,
                    favorite, password_strength
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), ?, ?)
            """, (
                entry_id, title, url, username,
                pw_cipher, pw_nonce, pw_tag,          
                notes_cipher, notes_nonce, notes_tag, 
                entry_salt,
                tags, category, 
                1 if favorite else 0,   
                password_strength
            ))
            conn.commit()
            return entry_id
            
        except ValueError as e:
            raise DatabaseError(f"Invalid entry data: {str(e)}")
        except sqlite3.IntegrityError as e:
            raise DatabaseError(f"Entry already exists or constraint violation: {str(e)}")
        except sqlite3.OperationalError as e:
            raise DatabaseError(f"Database operation failed: {str(e)}")
        except Exception as e:
            raise DatabaseError(f"Unexpected error during entry creation: {str(e)}")
    
    def get_entry(self, entry_id: str, vault_key: bytes) -> Optional[Dict]:
        """ 
        Retrive and decrypt entry by ID
        
        Args:
            - entry_id: Entry UUID
            - vault_key: Vault encryption key
            
        Returns:
            Dictionary with decrypted entry data:
            {
                'id': str,
                'title': str,
                'url': str,
                'username': str,
                'password': str,  # Decrypted
                'notes': str,     # Decrypted
                'tags': str,
                'category': str,
                'created_at': str,
                'modified_at': str,
                'last_accessed_at': str
            }
            None if entry not found or is deleted
            
        Raises:
            - DatabaseError: If decryption fails
        """
        try:
            # Validate inputs
            if not entry_id or not isinstance(entry_id, str):
                raise ValueError("Entry ID must be a non-empty string")
            
            if not isinstance(vault_key, bytes) or len(vault_key) != 32:
                raise ValueError("Vault key must be 32 bytes")
            
            conn = self.connect()
            
            cursor = conn.execute(
                "SELECT * FROM entries WHERE id = ? AND is_deleted = 0", 
                (entry_id,)
            )
            
            row = cursor.fetchone()
            
            if row is None:
                return None  # Entry not found is not an error
            
            try:
                entry_salt = row["kdf_salt"]
            except IndexError:
                # Handle legacy schema gracefully if needed, or fail safe
                raise DatabaseError("Database integrity error: Missing salt for entry.")

            entry_key = self._derive_entry_key(vault_key, entry_id, entry_salt)
            
            # Decrypt password field
            try:
                password_data = decrypt_entry(
                    row["password_encrypted"],
                    row["password_nonce"],
                    row["password_tag"],
                    entry_key
                )
                password_dict = json.loads(password_data)
                password = password_dict.get("password")
            except Exception as e:
                raise DatabaseError(f"CRITICAL: Password decryption failed for {entry_id}. Data may be tampered or corrupt.")
                
            # Decrypt notes field
            try:
                notes_data = decrypt_entry(
                    row["notes_encrypted"],
                    row["notes_nonce"],
                    row["notes_tag"],
                    entry_key
                )
                notes_dict = json.loads(notes_data)
                notes = notes_dict.get("notes")
            except Exception as e:
                notes = None
                raise DatabaseError(f"CRITICAL: Notes decryption failed for {entry_id}.")
            
            try:
                modified_date = datetime.strptime(row["modified_at"], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                modified_date = datetime.fromisoformat(row["modified_at"])

            # 🔑 NORMALIZE TIMEZONE (THIS IS THE FIX)
            if modified_date.tzinfo is None:
                modified_date = modified_date.replace(tzinfo=timezone.utc)

            age_days = (datetime.now(timezone.utc) - modified_date).days

            # Return combined dict
            entry = {
                "id": row["id"],
                "title": row["title"],
                "url": row["url"],
                "username": row["username"],
                "tags": row["tags"],
                "category": row["category"],
                "favorite": bool(row["favorite"]),          # <--- Return as bool
                "password_strength": row["password_strength"], # <--- Return score
                "password_age_days": age_days,
                "created_at": row["created_at"],
                "modified_at": row["modified_at"],
                "last_accessed_at": row["last_accessed_at"],
                "password": password,
                "notes": notes,
            }
            
            return entry
            
        except ValueError as e:
            raise DatabaseError(f"Invalid input: {str(e)}")
        except sqlite3.OperationalError as e:
            raise DatabaseError(f"Database query failed: {str(e)}")
        except Exception as e:
            raise DatabaseError(f"Unexpected error retrieving entry: {str(e)}")

    def update_entry(
            self,
            entry_id: str, 
            vault_key: bytes, 
            title: Optional[str] = None,
            url: Optional[str] = None, 
            username: Optional[str] = None,
            password: Optional[str] = None,
            notes: Optional[str] = None, 
            tags: Optional[str] = None, 
            category: Optional[str] = None,
            favorite: Optional[bool] = None,       
            password_strength: Optional[int] = None
    )->bool:
        """ 
        Update existing entry (only provided fields)

        Args:
            - entry_id: Entry UUID
            - vault_key: Vault encryption key
            - **kwargs: Fields to update (None = no change)

        Returns:
            - True if updated successfully
            - False if entry not found

        Raises:
            DatabaseError: If database operation fails
        """
        try:
            # Validate inputs
            if not entry_id or not isinstance(entry_id, str):
                raise ValueError("Entry ID must be a non-empty string")
            
            self._validate_entry_data(
                title=title, url=url, username=username, 
                notes=notes, tags=tags, category=category
            )
            
            if not isinstance(vault_key, bytes) or len(vault_key) != 32:
                raise ValueError("Vault key must be 32 bytes")
            
            conn = self.connect()
            
            # Check if entry exists
            cursor = conn.execute(
                "SELECT id, kdf_salt FROM entries WHERE id = ? AND is_deleted = 0",
                (entry_id,)
            )

            row = cursor.fetchone()
            
            if row is None:
                return (False, 0)  # Entry not found
            
            current_salt = row['kdf_salt']
            
            fields = []
            values = []
            
            # Build update query dynamically
            if title is not None:
                fields.append("title = ?")
                values.append(title)
            
            if url is not None:
                fields.append("url = ?")
                values.append(url)
            
            if username is not None:
                fields.append("username = ?")
                values.append(username)
            
            if tags is not None:
                fields.append("tags = ?")
                values.append(tags)
            
            if category is not None:
                fields.append("category = ?")
                values.append(category)
            
            if favorite is not None:
                fields.append("favorite = ?")
                values.append(1 if favorite else 0)

            if password_strength is not None:
                if not isinstance(password_strength, int) or not (0 <= password_strength <= 100):
                    raise ValueError("password_strength must be integer between 0 and 100")
                fields.append("password_strength = ?")
                values.append(password_strength)

            
            # If password or notes changed, re-encrypt
            if password is not None or notes is not None:
                entry_key = self._derive_entry_key(vault_key, entry_id, current_salt)
                
                if password is not None:
                    payload = {"password": password}
                    payload_json = json.dumps(payload)
                    ciphertext, nonce, tag = encrypt_entry(payload_json, entry_key)
                    fields.extend(["password_encrypted = ?", "password_nonce = ?", "password_tag = ?"])
                    values.extend([ciphertext, nonce, tag])
                
                if notes is not None:
                    payload = {"notes": notes}
                    payload_json = json.dumps(payload)
                    ciphertext, nonce, tag = encrypt_entry(payload_json, entry_key)
                    fields.extend(["notes_encrypted = ?", "notes_nonce = ?", "notes_tag = ?"])
                    values.extend([ciphertext, nonce, tag])
            
            # If no fields to update, return False (indicates nothing happened)
            if not fields:
                return (False, 0)
            
            # Always update modified_at
            fields.append("modified_at = datetime('now')")
            
            # Build SQL correctly
            set_clause = ", ".join(fields)
            sql = f"UPDATE entries SET {set_clause} WHERE id = ?"
            values.append(entry_id)

            # Ensure we hold a write lock to avoid race conditions
            conn.execute("BEGIN IMMEDIATE;")
            cur = conn.execute(sql, tuple(values))
            rows = cur.rowcount if hasattr(cur, "rowcount") else conn.total_changes
            conn.commit()
            return (True, rows)
            
        except ValueError as e:
            raise DatabaseError(f"Invalid input: {str(e)}")
        except sqlite3.IntegrityError as e:
            conn.rollback()
            raise DatabaseError(f"Update violates constraints: {str(e)}")
        except sqlite3.OperationalError as e:
            conn.rollback()
            raise DatabaseError(f"Database operation failed: {str(e)}")
        except Exception as e:
            conn.rollback()
            raise DatabaseError(f"Unexpected error updating entry: {str(e)}") from e

    def delete_entry(self, entry_id: str) -> bool:
        """
        Soft delete entry (move to trash)
        
        Args:
            entry_id: Entry UUID
        
        Returns:
            True if deleted successfully
            False if entry not found
        
        Raises:
            DatabaseError: If database operation fails
        """
        try:
            # Validate input
            if not entry_id or not isinstance(entry_id, str):
                raise ValueError("Entry ID must be a non-empty string")
            
            conn = self.connect()

            # Begin write transaction
            conn.execute("BEGIN IMMEDIATE;")

            cursor = conn.execute(
                "UPDATE entries "
                "SET is_deleted = 1, deleted_at = datetime('now') "
                "WHERE id = ? AND is_deleted = 0",
                (entry_id,)
            )
            
            if cursor.rowcount > 0:
                conn.commit()
                return True
            else:
                conn.rollback()
                return False  # Entry not found or already deleted
                
        except ValueError as e:
            raise DatabaseError(f"Invalid input: {str(e)}")
        except sqlite3.OperationalError as e:
            conn.rollback()
            raise DatabaseError(f"Database operation failed: {str(e)}")
        except Exception as e:
            conn.rollback()
            raise DatabaseError(f"Unexpected error deleting entry: {str(e)}")

    def list_entries(
            self, 
            include_deleted: bool = False, 
            limit: int = 100, 
            offset: int = 0
    ) -> List[Dict]:
        """ 
        List all entries (metadata only, no decryption)
        
        Args:
            - include_deleted: Include soft-deleted entries in trash
        
        Returns:
            - List of entry metadata dictionaries (passwords NOT decrypted)
        """
        try:
            conn = self.connect()
            
            if limit > 1000:
                raise ValueError("Limit exceeds maximum allowed (1000)")
            if limit < 1:
                limit = 1
            if offset < 0:
                offset = 0

            if include_deleted:
                sql = """
                    SELECT id, title, url, username, tags, category, created_at, modified_at, is_deleted, deleted_at
                    FROM entries
                    ORDER BY modified_at DESC
                    LIMIT ? OFFSET ?
                """
            else:
                sql = """
                    SELECT id, title, url, username, tags, category, created_at, modified_at
                    FROM entries
                    WHERE is_deleted = 0
                    ORDER BY modified_at DESC
                    LIMIT ? OFFSET ?
                """
            
            # Pass limit/offset safely as parameters
            cursor = conn.execute(sql, (limit, offset))
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.OperationalError as e:
            raise DatabaseError(f"Database query failed: {str(e)}")
        except Exception as e:
            raise DatabaseError(f"Unexpected error listing entries: {str(e)}")
    
    def restore_entry(self, entry_id: str) -> bool:
        """
        Restore soft-deleted entry from trash
        Trigger 'entries_au' automatically handles FTS re-indexing and Audit Log.

        Args:
            - entry_id: Entry UUID
        
        Returns:
            - True if restored successfully
            - False if entry not found in trash
        """ 
        try:
            # Validate input
            if not entry_id or not isinstance(entry_id, str):
                raise ValueError("Entry ID must be a non-empty string")
            
            conn = self.connect()
            
            conn.execute("BEGIN IMMEDIATE;")

            cursor = conn.execute(
                """
                UPDATE entries
                SET 
                    is_deleted = 0,
                    deleted_at = NULL,
                    modified_at = datetime('now')   -- keep schema timestamp consistency
                WHERE id = ? AND is_deleted = 1
                """,
                (entry_id,)
            )
            
            if cursor.rowcount > 0:
                conn.commit()
                return True
            else:
                conn.rollback()
                return False  # Entry not found in trash
                
        except ValueError as e:
            raise DatabaseError(f"Invalid input: {str(e)}")
        except sqlite3.OperationalError as e:
            conn.rollback()
            raise DatabaseError(f"Database operation failed: {str(e)}")
        except Exception as e:
            conn.rollback()
            raise DatabaseError(f"Unexpected error restoring entry: {str(e)}")

    def get_metadata(self, key: str) -> Optional[str]:
        """
        Retrieve metadata value or None if not found.
        Used by AdaptiveLockout.
        """
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT value FROM metadata WHERE key = ?",
                (key,)
            ).fetchone()
            if row is None:
                return None
            return json.loads(row["value"])
        except Exception as e:
            raise DatabaseError(f"Failed to read metadata[{key}]: {e}") from e

    def update_metadata(self, key: str, value: str) -> bool:
        """
        Upsert metadata key/value into metadata table.
        """
        conn = self.connect()
        try:
            json_value = json.dumps(value)
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute(
                """
                INSERT INTO metadata (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, json_value)
            )
            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            raise DatabaseError(f"Failed to update metadata[{key}]: {e}") from e
        
    def get_audit_logs(self, limit: int = 50) -> List[Dict]:
        """
        Retrieve recent security audit logs.
        Ordered by time (newest first) and ID (to handle same-second events).
        """
        conn = self.connect()
        cursor = conn.execute("""
            SELECT a.id, a.entry_id, e.title, a.action_type, a.timestamp
            FROM audit_log a
            LEFT JOIN entries e ON a.entry_id = e.id
            ORDER BY a.timestamp DESC, a.id DESC  -- <--- FIXED: Added secondary sort
            LIMIT ?
        """, (limit,))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_old_entries(self, days_threshold: int = 90) -> List[Dict]:
        """
        Identify passwords older than X days for security auditing.
        
        Best Practice: 
        Uses SQL date math on 'modified_at' to be 100% accurate,
        bypassing the stale 'password_age_days' column.
        """
        try:
            conn = self.connect()
            
            # SQL Logic: Find entries where 'modified_at' is older than threshold
            # This is fast, accurate, and read-only.
            cursor = conn.execute("""
                SELECT id, title, username, modified_at, password_strength
                FROM entries 
                WHERE modified_at < datetime('now', ?)
                AND is_deleted = 0
                ORDER BY modified_at ASC
            """, (f"-{days_threshold} days",))

            
            results = []
            for row in cursor.fetchall():
                # Calculate exact age for display purposes
                try:
                    mod_date = datetime.strptime(row["modified_at"], "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    mod_date = datetime.fromisoformat(row["modified_at"])

                age = (datetime.now(timezone.utc) - mod_date).days
                
                results.append({
                    "id": row["id"],
                    "title": row["title"],
                    "username": row["username"],
                    "age_days": age,  # Real-time calculation
                    "strength": row["password_strength"]
                })
            return results
            
        except Exception as e:
            raise DatabaseError(f"Failed to fetch old entries: {e}")
        
    def search_entries(
        self,
        query: str,
        include_deleted: bool = False,
        limit: int = 50, 
        offset: int =0
    ) -> List[Dict]:
        """
        Search entries by title/URL/tags
        
        Args:
            query: Search query
            include_deleted: Include soft-deleted entries
        
        Returns:
            List of matching entries (metadata only, not decrypted)
        
        Raises:
            VaultLockedError: If vault locked
            VaultError: If search fails

        Security:
        - Ensures vault unlocked before access.
        - Uses parameterized queries to prevent SQL injection.
        - Returns non-sensitive metadata only.
        
        """
        try:
            if limit > 1000:
                raise ValueError("Limit exceeds maximum allowed (1000)")
            if limit < 1:
                limit = 1
            if offset < 0:
                offset = 0

            conn = self.connect()
            query = query.strip()
            if not query: return []

            # 1. VALIDATION
            safe_token_pattern = re.compile(r'^[A-Za-z0-9._-]{1,30}$')
            terms = query.split()
            
            # 2. DECISION: Prefer FTS, fallback to LIKE for symbols
            use_fts = True
            
            # If requesting trash, we MUST use LIKE (trash not in FTS)
            if include_deleted:
                use_fts = False
            else:
                # If query has symbols, FTS tokenizers might choke/strip them.
                # Fallback to LIKE to ensure we find "C++" or "user@email".
                for term in terms:
                    if not term.isascii():
                        use_fts = False
                        break
                    if not safe_token_pattern.match(term):
                        use_fts = False
                        break

            # 3. EXECUTION
            if use_fts:
                # --- FAST PATH (FTS) ---
                fts_query = " ".join([f'"{t}"*' for t in terms])
                
                # FTS query structure is rigid, so we hardcode the filter
                sql = """
                    SELECT e.id, e.title, e.url, e.username, e.tags, e.category, 
                           e.created_at, e.modified_at, e.is_deleted, e.password_strength
                    FROM entries e
                    JOIN entries_fts f ON e.rowid = f.rowid
                    WHERE entries_fts MATCH ? AND e.is_deleted = 0
                    ORDER BY bm25(entries_fts) ASC
                    LIMIT ? OFFSET ?
                """
                params = [fts_query, limit, offset]
                
            else:
                # --- ROBUST PATH (LIKE) ---
                safe_query = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                wildcard = f"%{safe_query}%"
                
                # Construct WHERE clauses as a list to prevent logic errors
                where_clauses = [
                    r"(title LIKE ? ESCAPE '\\' OR url LIKE ? ESCAPE '\\' OR "
                    r"username LIKE ? ESCAPE '\\' OR tags LIKE ? ESCAPE '\\')"
                ]
                
                # Explicitly add deletion filter if needed
                if not include_deleted:
                    where_clauses.append("is_deleted = 0")
                
                # Join clauses safely
                where_sql = " AND ".join(where_clauses)
                
                sql = f"""
                    SELECT id, title, url, username, tags, category, 
                           created_at, modified_at, is_deleted, password_strength
                    FROM entries
                    WHERE {where_sql}
                    ORDER BY modified_at DESC
                    LIMIT ? OFFSET ?
                """
                
                params = [wildcard, wildcard, wildcard, wildcard, limit, offset]

            cursor = conn.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]
        
        except Exception as e:
            raise DatabaseError(f"Failed to search entries: {e}")
        
    def record_lockout_failure(self) -> None:
        """
        Record a failed attempt and prune history older than 1 hour.
        """
        try:
            conn = self.connect()
            import time
            now = int(time.time())

            conn.execute("BEGIN IMMEDIATE;")
            
            # 1. Insert new failure
            conn.execute(
                "INSERT INTO lockout_attempts (attempt_ts) VALUES (?)",
                (now,)
            )
            # 2. Prune old entries to prevent table bloat (keep last 1 hour)
            conn.execute(
            "DELETE FROM lockout_attempts WHERE attempt_ts < ?",
                (now - 3600,)
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise DatabaseError(f"Failed to record lockout failure: {e}") from e

    def get_lockout_history(self, since_timestamp: int = 0) -> List[int]:
        """
        Retrieve lockout timestamps, optionally filtering by a cutoff time.
        """
        try:
            conn = self.connect()
            cursor = conn.execute(
                "SELECT attempt_ts FROM lockout_attempts WHERE attempt_ts >= ? ORDER BY attempt_ts ASC",
                (since_timestamp,)
            )
            return [row["attempt_ts"] for row in cursor.fetchall()]
        except Exception as e:
            raise DatabaseError(f"Failed to retrieve lockout history: {e}") from e
        
    def clear_lockout_history(self) -> None:
        """
        Reset lockout history (e.g., after successful login or delay expiration).
        """
        try:
            conn = self.connect()
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute("DELETE FROM lockout_attempts")
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise DatabaseError(f"Failed to clear lockout history: {e}") from e