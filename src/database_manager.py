"""
SENTRA Database Manager
Handles SQLit operations with encrypted entry storage and hierarchical key management
"""

import sqlite3
import os
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple, Any
import threading
import re
import json
import uuid
from src.config import DB_PATH, SCHEMA_PATH
from src.crypto_engine import encrypt_entry, decrypt_entry, generate_salt, derive_hkdf_key

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

    Responsibilities:
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
        self._conn_lock = threading.Lock()
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
        Create or return existing database connection
        
        Returns:
            SQLite connection object with Row factory    
        """
        with self._conn_lock:
            if self.connection is not None:
                return self.connection
            if self.connection is None:
                self.connection = sqlite3.connect(self.db_path)
                self.connection.row_factory = sqlite3.Row
                self.connection.execute("PRAGMA foreign_keys = ON")

                # Try WAL mode directly on the main connection
                res = self.connection.execute("PRAGMA journal_mode=WAL;").fetchone()
                actual_mode = res[0].lower() if res else None

                if actual_mode != "wal":
                    # Fallback to DELETE
                    res = self.connection.execute("PRAGMA journal_mode=DELETE;").fetchone()
                    fallback_mode = res[0].lower() if res else None

                    if fallback_mode != "delete":
                        raise RuntimeError(
                            f"SQLite journaling misconfigured: WAL unsupported and DELETE fallback failed (mode={fallback_mode})"
                        )

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

    @staticmethod
    def _derive_entry_key(vault_key: bytes, entry_id:str, entry_salt: bytes) -> bytes:
            # Encrypt the entry_key
            return derive_hkdf_key(
                master_key=vault_key,
                info=entry_id.encode(),
                salt=entry_salt,
                length=32
            )

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

    @staticmethod
    def _validate_entry_data(
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
        conn = None
        try:
            conn = self.connect()

            # Always load the full schema atomically
            with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
                schema_sql = f.read()

            conn.execute("BEGIN IMMEDIATE;")
            conn.executescript(schema_sql) 
            
            # --- Migration Section: Robust Audit Log Upgrade ---
            try:
                # Check for existing structure
                cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'")
                if cursor.fetchone():
                    cursor = conn.execute("PRAGMA table_info(audit_log)")
                    columns = {row[1]: row for row in cursor.fetchall()}
                    
                    needs_table_recreation = False
                    if 'details' not in columns:
                        needs_table_recreation = True
                    elif columns['entry_id'][3] == 1: # entry_id is NOT NULL
                        needs_table_recreation = True
                    elif 'actor' not in columns: # Check for Phase 27 fields
                        needs_table_recreation = True
                    
                    if needs_table_recreation:
                        # Rename old, create new
                        conn.execute("ALTER TABLE audit_log RENAME TO audit_log_old")
                        conn.execute("""
                            CREATE TABLE audit_log (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                entry_id TEXT,                          
                                action_type TEXT NOT NULL,
                                actor TEXT DEFAULT 'system',
                                source TEXT DEFAULT 'Internal',
                                severity TEXT DEFAULT 'Info',
                                ip_address TEXT DEFAULT '127.0.0.1',
                                details TEXT,                           
                                timestamp TEXT DEFAULT (datetime('now'))
                            )
                        """)
                        
                        # Migration logic: map old columns and provide defaults for new ones
                        old_cols = columns.keys()
                        mapping = ["id", "entry_id", "action_type", "timestamp"]
                        if 'details' in old_cols: mapping.append("details")
                        
                        source_cols = ", ".join(mapping)
                        target_cols = ", ".join(mapping)
                        
                        conn.execute(f"""
                            INSERT INTO audit_log ({target_cols})
                            SELECT {source_cols} FROM audit_log_old
                        """)
                        conn.execute("DROP TABLE audit_log_old")
                        
                        # --- CRITICAL: Recreate triggers ---
                        # When we renamed audit_log to audit_log_old, SQLite automatically 
                        # updated existing triggers to point to audit_log_old. 
                        # We must drop and recreate them to point back to the new audit_log.
                        conn.execute("DROP TRIGGER IF EXISTS entries_ai")
                        conn.execute("DROP TRIGGER IF EXISTS entries_au")
                        conn.execute("DROP TRIGGER IF EXISTS entries_ad")
                        
                        # Note: These will be recreated by the schema_sql executescript above 
                        # ONLY IF they don't exist. Since we just dropped them, we should 
                        # re-run the schema or just explicitly define them here. 
                        # To be safe, we re-run the trigger part of the schema.
                        conn.executescript(schema_sql)
            except Exception as e:
                # Log but maybe don't crash everything if migration fails? 
                # Actually, better to raise so user knows why audit logging is broken.
                raise DatabaseError(f"Audit log migration failed: {e}")

            # --- Migration Section: Metadata Encryption (v2.1) ---
            try:
                cursor = conn.execute("PRAGMA table_info(entries)")
                columns = {row[1] for row in cursor.fetchall()}
                
                if 'title_encrypted' not in columns:
                    conn.execute("ALTER TABLE entries ADD COLUMN title_encrypted BLOB")
                    conn.execute("ALTER TABLE entries ADD COLUMN title_nonce BLOB")
                    conn.execute("ALTER TABLE entries ADD COLUMN title_tag BLOB")
                    conn.execute("ALTER TABLE entries ADD COLUMN url_encrypted BLOB")
                    conn.execute("ALTER TABLE entries ADD COLUMN url_nonce BLOB")
                    conn.execute("ALTER TABLE entries ADD COLUMN url_tag BLOB")
                    conn.execute("ALTER TABLE entries ADD COLUMN username_encrypted BLOB")
                    conn.execute("ALTER TABLE entries ADD COLUMN username_nonce BLOB")
                    conn.execute("ALTER TABLE entries ADD COLUMN username_tag BLOB")
            except Exception as e:
                raise DatabaseError(f"Metadata schema upgrade failed: {e}")

            # --- Migration Section: Maintenance History (v2.2) ---
            try:
                cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='backup_history'")
                if not cursor.fetchone():
                    # Table will be created by schema_sql, but we can explicitly run it if needed
                    # but since executescript(schema_sql) was called at line 218, it might already be there.
                    # However, PRAGMA journal_mode = WAL etc. at start of schema might cause issues if run twice.
                    # The executescript at 218 handled it for NEW users. Existing users need this check.
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS backup_history (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp TEXT DEFAULT (datetime('now')),
                            operation_type TEXT NOT NULL,
                            filename TEXT,
                            file_size INTEGER,
                            status TEXT DEFAULT 'Success',
                            details TEXT
                        )
                    """)
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_backup_history_timestamp ON backup_history(timestamp DESC)")
            except Exception as e:
                raise DatabaseError(f"Backup history schema upgrade failed: {e}")
            
            # --- Migration Section: Rich Vault Metadata (v2.3) ---
            try:
                cursor = conn.execute("PRAGMA table_info(vault_metadata)")
                columns = {row[1] for row in cursor.fetchall()}
                
                if 'display_name' not in columns:
                    conn.execute("ALTER TABLE vault_metadata ADD COLUMN display_name TEXT")
                if 'description' not in columns:
                    conn.execute("ALTER TABLE vault_metadata ADD COLUMN description TEXT")
                if 'username' not in columns:
                    conn.execute("ALTER TABLE vault_metadata ADD COLUMN username TEXT DEFAULT 'admin'")
                if 'account_status' not in columns:
                    conn.execute("ALTER TABLE vault_metadata ADD COLUMN account_status TEXT DEFAULT 'Active'")
                if 'preferences' not in columns:
                    conn.execute("ALTER TABLE vault_metadata ADD COLUMN preferences TEXT DEFAULT '{}'")
                if 'auto_lock_duration' not in columns:
                    conn.execute("ALTER TABLE vault_metadata ADD COLUMN auto_lock_duration INTEGER DEFAULT 900")
            except Exception as e:
                raise DatabaseError(f"Vault metadata schema upgrade failed: {e}")
            
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
            kdf_config: Optional[Dict] = None,
            display_name: Optional[str] = None,
            description: Optional[str] = None
    ) -> bool:
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
                    kdf_config, display_name, description,
                    username, account_status, preferences, auto_lock_duration,
                    created_at, version,
                    unlock_count, last_unlocked_at
                ) VALUES (
                    1, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Active', '{}', 900,
                    datetime('now'),    -- Use SQLite timestamp
                    '2.3', 
                    0, NULL
                )
            """, (
                salt, auth_hash,
                vault_key_encrypted, vault_key_nonce, vault_key_tag,
                kdf_json, display_name, description,
                "admin" # Default username
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
        conn = None
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
        conn = self.connect()

        cursor = conn.execute("SELECT * FROM vault_metadata WHERE id = 1")
        row = cursor.fetchone()

        if not row:
            return None
        
        # convert row to dictionary
        return dict(row)

    def update_unlock_timestamp(self) -> bool:
        conn = self.connect()
        timestamp = datetime.now().isoformat()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute("""
                UPDATE vault_metadata
                SET last_unlocked_at = ?, unlock_count = unlock_count + 1
                WHERE id = 1
            """, (timestamp,))
            conn.commit()
            return True
        except Exception as e:
            if conn: conn.rollback()
            raise DatabaseError(f"Failed to update unlock timestamp: {e}")

    def get_session_history(self, limit: int = 10) -> List[Dict]:
        """
        Reconstruct session history from audit logs.
        """
        conn = self.connect()
        cursor = conn.execute("""
            SELECT id, action_type, timestamp, ip_address, details
            FROM audit_log
            WHERE action_type IN ('UNLOCK', 'LOCK', 'failed_unlock')
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def update_metadata_field(self, field: str, value: Any) -> bool:
        """
        Update a specific field in the vault_metadata table.
        """
        allowed_fields = ['display_name', 'description', 'username', 'account_status', 'preferences', 'auto_lock_duration']
        if field not in allowed_fields:
            raise DatabaseError(f"Field {field} is not allowed for update")
        
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute(f"UPDATE vault_metadata SET {field} = ? WHERE id = 1", (value,))
            conn.commit()
            return True
        except Exception as e:
            if conn: conn.rollback()
            raise DatabaseError(f"Failed to update {field}: {e}")
    
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
            
            # 1. Encrypt Metadata
            title_cipher, title_nonce, title_tag = encrypt_entry(
                title, entry_key, associated_data=entry_id.encode("utf-8")
            )
            
            url_cipher, url_nonce, url_tag = None, None, None
            if url:
                url_cipher, url_nonce, url_tag = encrypt_entry(
                    url, entry_key, associated_data=entry_id.encode("utf-8")
                )
                
            username_cipher, username_nonce, username_tag = None, None, None
            if username:
                username_cipher, username_nonce, username_tag = encrypt_entry(
                    username, entry_key, associated_data=entry_id.encode("utf-8")
                )

            # 2. Encrypt Password
            pw_payload = {"password": password or ""}
            pw_cipher, pw_nonce, pw_tag = encrypt_entry(
                json.dumps(pw_payload),
                entry_key,
                associated_data=entry_id.encode("utf-8")
            )
            
            # 3. Encrypt Notes
            notes_payload = {"notes": notes or ""}
            notes_cipher, notes_nonce, notes_tag = encrypt_entry(
                json.dumps(notes_payload),
                entry_key,
                associated_data=entry_id.encode("utf-8")
            )
            
            # Insert into entries
            conn = self.connect()
            conn.execute("""
                INSERT INTO entries (
                    id, title, url, username,
                    title_encrypted, title_nonce, title_tag,
                    url_encrypted, url_nonce, url_tag,
                    username_encrypted, username_nonce, username_tag,
                    password_encrypted, password_nonce, password_tag,
                    notes_encrypted, notes_nonce, notes_tag,
                    kdf_salt,
                    tags, category, created_at, modified_at,
                    favorite, password_strength
                ) VALUES (?, NULL, NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), ?, ?)
            """, (
                entry_id, 
                title_cipher, title_nonce, title_tag,
                url_cipher, url_nonce, url_tag,
                username_cipher, username_nonce, username_tag,
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
    
    def get_entry(self, entry_id: str, vault_key: bytes, include_deleted: bool = False) -> Optional[Dict]:
        try:
            # Validate inputs
            if not entry_id or not isinstance(entry_id, str):
                raise ValueError("Entry ID must be a non-empty string")
            
            if not isinstance(vault_key, bytes) or len(vault_key) != 32:
                raise ValueError("Vault key must be 32 bytes")
            
            conn = self.connect()

            if include_deleted:
                sql = "SELECT * FROM entries WHERE id = ?"
            else:
                sql = "SELECT * FROM entries WHERE id = ? AND is_deleted = 0"

            cursor = conn.execute(sql, (entry_id,))
            
            row = cursor.fetchone()
            
            if row is None:
                return None  # Entry not found is not an error
            
            try:
                entry_salt = row["kdf_salt"]
            except IndexError:
                # Handle legacy schema gracefully if needed, or fail-safe
                raise DatabaseError("Database integrity error: Missing salt for entry.")

            entry_key = self._derive_entry_key(vault_key, entry_id, entry_salt)
            return self._decrypt_row(row, entry_key)
            
        except ValueError as e:
            raise DatabaseError(f"Invalid input: {str(e)}")
        except sqlite3.OperationalError as e:
            raise DatabaseError(f"Database query failed: {str(e)}")
        except Exception as e:
            raise DatabaseError(f"Failed to retrieve entry: {e}")

    def get_all_active_entries(self, vault_key: bytes) -> List[Dict]:
        """
        Retrieves and decrypts all non-deleted entries.
        """
        if not isinstance(vault_key, bytes) or len(vault_key) != 32:
            raise ValueError("Vault key must be 32 bytes")

        try:
            conn = self.connect()
            cursor = conn.execute("SELECT * FROM entries WHERE is_deleted = 0")
            rows = cursor.fetchall()
            
            results = []
            for row in rows:
                try:
                    entry_id = row["id"]
                    entry_salt = row["kdf_salt"]
                    entry_key = self._derive_entry_key(vault_key, entry_id, entry_salt)
                    entry = self._decrypt_row(row, entry_key)
                    results.append(entry)
                except Exception:
                    # Skip corrupt entries during bulk scan
                    continue
            return results
        except Exception as e:
            raise DatabaseError(f"Failed to retrieve all active entries: {e}")

    def _decrypt_row(self, row: sqlite3.Row, entry_key: bytes) -> Dict:
        """Helper to decrypt all fields in a row."""
        entry_id = row["id"]
        
        # Decrypt Metadata
        title = row["title"]
        url = row["url"]
        username = row["username"]
        
        if row["title_encrypted"]:
            try:
                title = decrypt_entry(
                    row["title_encrypted"], row["title_nonce"], row["title_tag"],
                    entry_key, associated_data=entry_id.encode("utf-8")
                )
            except Exception:
                raise DatabaseError(f"CRITICAL: Title decryption failed for {entry_id}.")
        
        if row["url_encrypted"]:
            try:
                url = decrypt_entry(
                    row["url_encrypted"], row["url_nonce"], row["url_tag"],
                    entry_key, associated_data=entry_id.encode("utf-8")
                )
            except Exception:
                raise DatabaseError(f"CRITICAL: URL decryption failed for {entry_id}.")

        if row["username_encrypted"]:
            try:
                username = decrypt_entry(
                    row["username_encrypted"], row["username_nonce"], row["username_tag"],
                    entry_key, associated_data=entry_id.encode("utf-8")
                )
            except Exception:
                raise DatabaseError(f"CRITICAL: Username decryption failed for {entry_id}.")

        # Decrypt password field
        password = ""
        if row["password_encrypted"]:
            try:
                password_data = decrypt_entry(
                    row["password_encrypted"],
                    row["password_nonce"],
                    row["password_tag"],
                    entry_key,
                    associated_data=entry_id.encode("utf-8")
                )
                password_dict = json.loads(password_data)
                password = password_dict.get("password", "")
            except Exception:
                raise DatabaseError(f"CRITICAL: Password decryption failed for {entry_id}.")
                
        # Decrypt notes field
        notes = ""
        if row["notes_encrypted"]:
            try:
                notes_data = decrypt_entry(
                    row["notes_encrypted"],
                    row["notes_nonce"],
                    row["notes_tag"],
                    entry_key,
                    associated_data=entry_id.encode("utf-8")
                )
                notes_dict = json.loads(notes_data)
                notes = notes_dict.get("notes", "")
            except Exception:
                raise DatabaseError(f"CRITICAL: Notes decryption failed for {entry_id}.")
        
        try:
            modified_date = datetime.strptime(row["modified_at"], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            modified_date = datetime.fromisoformat(row["modified_at"])

        if modified_date.tzinfo is None:
            modified_date = modified_date.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - modified_date).days

        return {
            "id": row["id"],
            "title": title,
            "url": url,
            "username": username,
            "tags": row["tags"],
            "category": row["category"],
            "favorite": bool(row["favorite"]),
            "password_strength": row["password_strength"],
            "password_age_days": age_days,
            "created_at": row["created_at"],
            "modified_at": row["modified_at"],
            "last_accessed_at": row["last_accessed_at"],
            "password": password,
            "notes": notes,
            "is_deleted": bool(row["is_deleted"])
        }

    def update_entry(self, entry_id: str, vault_key: bytes, **kwargs) -> Tuple[bool, int]:
        conn = None
        try:
            if not entry_id: raise ValueError("Invalid ID")
            conn = self.connect()
            conn.execute("BEGIN IMMEDIATE;")

            cursor = conn.execute(
                "SELECT id, kdf_salt FROM entries WHERE id = ? AND is_deleted = 0",
                (entry_id,)
            )
            row = cursor.fetchone()
            if not row:
                conn.rollback()
                return False, 0

            fields, values = [], []
            # Handle standard fields (title, url, etc.)
            for key in ['title', 'url', 'username', 'tags', 'category', 'favorite']:
                if key in kwargs and kwargs[key] is not None:
                    fields.append(f"{key} = ?")
                    values.append(kwargs[key] if key != 'favorite' else (1 if kwargs[key] else 0))

            # Handle sensitive fields (re-encryption required)
            if any(k in kwargs for k in ['password', 'notes']):
                entry_key = self._derive_entry_key(vault_key, entry_id, row['kdf_salt'])

                if 'password' in kwargs:
                    pw_json = json.dumps({"password": kwargs['password'] or ""})
                    ct, nonce, tag = encrypt_entry(
                        pw_json,
                        entry_key,
                        associated_data=entry_id.encode("utf-8")
                    )
                    fields.extend(["password_encrypted = ?", "password_nonce = ?", "password_tag = ?"])
                    values.extend([ct, nonce, tag])

                # Handle metadata re-encryption
                for meta in ['title', 'url', 'username']:
                    if meta in kwargs:
                        val = kwargs[meta]
                        if val is not None:
                            ct, nonce, tag = encrypt_entry(
                                val, entry_key, associated_data=entry_id.encode("utf-8")
                            )
                            fields.extend([f"{meta}_encrypted = ?", f"{meta}_nonce = ?", f"{meta}_tag = ?"])
                            values.extend([ct, nonce, tag])
                        else:
                            fields.extend([f"{meta}_encrypted = NULL", f"{meta}_nonce = NULL", f"{meta}_tag = NULL"])
                        
                        # Nullify plaintext version
                        fields.append(f"{meta} = NULL")

                if 'notes' in kwargs:
                    nt_json = json.dumps({"notes": kwargs['notes'] or ""})
                    ct, nonce, tag = encrypt_entry(
                        nt_json,
                        entry_key,
                        associated_data=entry_id.encode("utf-8")
                    )
                    fields.extend(["notes_encrypted = ?", "notes_nonce = ?", "notes_tag = ?"])
                    values.extend([ct, nonce, tag])

            if not fields:
                conn.rollback()
                return False, 0

            fields.append("modified_at = datetime('now')")
            sql = f"UPDATE entries SET {', '.join(fields)} WHERE id = ?"
            values.append(entry_id)

            cur = conn.execute(sql, tuple(values))
            count = cur.rowcount
            conn.commit()
            return True, count
        except Exception as e:
            if conn: conn.rollback()
            raise DatabaseError(f"Update failed: {e}")

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
        conn = None
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
            if conn: conn.rollback()
            raise DatabaseError(f"Unexpected error deleting entry: {str(e)}")

    def list_entries(
            self,
            include_deleted: bool = False,
            only_deleted: bool = False,
            category=None,
            favorite=None,
            limit: int = 100,
            last_timestamp: str = None,
            last_id: str = None
    ) -> List[Dict]:
        try:
            conn = self.connect()
            if limit > 1000: limit = 1000

            conditions = []
            params = []

            if only_deleted:
                conditions.append("is_deleted = 1")
            elif not include_deleted:
                conditions.append("is_deleted = 0")
            if category is not None:
                conditions.append("category = ?")
                params.append(category)
            if favorite is not None:
                conditions.append("favorite = ?")
                params.append(1 if favorite else 0)

            if last_timestamp and last_id:
                conditions.append("(modified_at < ? OR (modified_at = ? AND id < ?))")
                params.extend([last_timestamp, last_timestamp, last_id])

            where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
            sql = f"""
                SELECT id, title, url, username, tags, category, password_strength,
                    created_at, modified_at, is_deleted
                FROM entries
                {where_clause}
                ORDER BY modified_at DESC, id DESC
                LIMIT ?
            """
            params.append(limit)

            cursor = conn.execute(sql, tuple(params))
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            raise DatabaseError(f"Unexpected error listing entries: {e}")
    
    def restore_entry(self, entry_id: str) -> bool:
        conn = None
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
            if conn: conn.rollback()
            raise DatabaseError(f"Database operation failed: {str(e)}")
        except Exception as e:
            if conn: conn.rollback()
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
        
    def add_audit_log(
        self, 
        action_type: str, 
        entry_id: Optional[str] = None, 
        details: Optional[str] = None,
        actor: str = 'system',
        source: str = 'Internal',
        severity: str = 'Info',
        ip_address: str = '127.0.0.1'
    ) -> None:
        """
        Record an event in the security audit log.
        """
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO audit_log 
                (entry_id, action_type, actor, source, severity, ip_address, details) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (entry_id, action_type, actor, source, severity, ip_address, details)
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise DatabaseError(f"Failed to add audit log: {e}")

    def get_audit_logs(self, limit: int = 50) -> List[Dict]:
        """
        Retrieve recent security audit logs.
        """
        conn = self.connect()
        cursor = conn.execute("""
            SELECT 
                a.id, 
                a.entry_id, 
                e.title as entry_title, 
                a.action_type as event_type,
                a.actor,
                a.source,
                a.severity,
                a.ip_address,
                a.details,
                a.timestamp
            FROM audit_log a
            LEFT JOIN entries e ON a.entry_id = e.id
            ORDER BY a.timestamp DESC, a.id DESC
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
            vault_key: bytes,
            query: str,
            include_deleted: bool = False,
            limit: int = 50,
            offset: int = 0
    ) -> List[Dict]:
        try:
            if limit > 1000: limit = 1000
            if limit < 1: limit = 1
            if offset < 0: offset = 0

            conn = self.connect()
            query = query.strip()
            if not query: return []

            safe_token_pattern = re.compile(r'^[A-Za-z0-9._-]{1,30}$')
            terms = query.split()
            use_fts = not include_deleted

            for term in terms:
                if not term.isascii() or not safe_token_pattern.match(term):
                    use_fts = False
                    break

            if use_fts:
                fts_query = " ".join([f'"{t}"*' for t in terms])
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
                safe_query = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                wildcard = f"%{safe_query}%"
                # FIX: Use static SQL with a conditional filter for 'is_deleted'
                sql = """
                    SELECT id, title, url, username, tags, category, 
                           created_at, modified_at, is_deleted, password_strength
                    FROM entries
                    WHERE (title LIKE ? ESCAPE '\\' OR url LIKE ? ESCAPE '\\' OR 
                           username LIKE ? ESCAPE '\\' OR tags LIKE ? ESCAPE '\\')
                      AND (is_deleted = 0 OR ? = 1)
                    ORDER BY modified_at DESC
                    LIMIT ? OFFSET ?
                """
                params = [wildcard, wildcard, wildcard, wildcard, 1 if include_deleted else 0, limit, offset]

            cursor = conn.execute(sql, params)
            results = [dict(row) for row in cursor.fetchall()]
            
            # Option A: Decrypt-on-search
            final_results = []
            
            # For decrypt-on-search for title/url/username:
            # We fetch all active entries (if not already matched by tags) and perform substring match.
            sql_all = "SELECT * FROM entries WHERE (is_deleted = 0 OR ? = 1)"
            all_rows = conn.execute(sql_all, (1 if include_deleted else 0,)).fetchall()
            
            query_lower = query.lower()
            
            for row in all_rows:
                entry_id = row["id"]
                entry_salt = row["kdf_salt"]
                entry_key = self._derive_entry_key(vault_key, entry_id, entry_salt)
                
                # Decrypt title
                title = row["title"]
                if row["title_encrypted"]:
                    try:
                        title = decrypt_entry(row["title_encrypted"], row["title_nonce"], row["title_tag"], entry_key, associated_data=entry_id.encode())
                    except Exception: title = "[Decryption Failed]"
                
                # Decrypt URL
                url = row["url"]
                if row["url_encrypted"]:
                    try:
                        url = decrypt_entry(row["url_encrypted"], row["url_nonce"], row["url_tag"], entry_key, associated_data=entry_id.encode())
                    except Exception: url = ""
                
                # Decrypt Username
                username = row["username"]
                if row["username_encrypted"]:
                    try:
                        username = decrypt_entry(row["username_encrypted"], row["username_nonce"], row["username_tag"], entry_key, associated_data=entry_id.encode())
                    except Exception: username = ""
                
                tags = row["tags"] or ""
                
                # Perform substring match
                if (query_lower in title.lower() or 
                    (url and query_lower in url.lower()) or 
                    (username and query_lower in username.lower()) or
                    (tags and query_lower in tags.lower())):
                    
                    try:
                        modified_date = datetime.strptime(row["modified_at"], "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        modified_date = datetime.fromisoformat(row["modified_at"])
                    if modified_date.tzinfo is None:
                        modified_date = modified_date.replace(tzinfo=timezone.utc)
                    age_days = (datetime.now(timezone.utc) - modified_date).days

                    final_results.append({
                        "id": row["id"],
                        "title": title,
                        "url": url,
                        "username": username,
                        "tags": tags,
                        "category": row["category"],
                        "favorite": bool(row["favorite"]),
                        "password_strength": row["password_strength"],
                        "created_at": row["created_at"],
                        "modified_at": row["modified_at"],
                        "age_days": age_days
                    })
            
            # Sort by modified_at DESC
            final_results.sort(key=lambda x: x["modified_at"], reverse=True)
            
            # Apply pagination
            return final_results[offset : offset + limit]
        except Exception as e:
            raise DatabaseError(f"Failed to search entries: {e}")

    def migrate_entries_metadata(self, vault_key: bytes) -> int:
        """
        Migrate plaintext 'title', 'url', 'username' to encrypted storage.
        """
        conn = self.connect()
        cursor = conn.execute("SELECT * FROM entries WHERE title IS NOT NULL OR url IS NOT NULL OR username IS NOT NULL")
        rows = cursor.fetchall()
        
        migrated_count = 0
        for row in rows:
            entry_id = row["id"]
            entry_salt = row["kdf_salt"]
            entry_key = self._derive_entry_key(vault_key, entry_id, entry_salt)
            
            updates = []
            vals = []
            
            # Encrypt Title
            if row["title"] and not row["title_encrypted"]:
                ct, nonce, tag = encrypt_entry(row["title"], entry_key, associated_data=entry_id.encode())
                updates.extend(["title_encrypted = ?", "title_nonce = ?", "title_tag = ?", "title = NULL"])
                vals.extend([ct, nonce, tag])
            
            # Encrypt URL
            if row["url"] and not row["url_encrypted"]:
                ct, nonce, tag = encrypt_entry(row["url"], entry_key, associated_data=entry_id.encode())
                updates.extend(["url_encrypted = ?", "url_nonce = ?", "url_tag = ?", "url = NULL"])
                vals.extend([ct, nonce, tag])
            
            # Encrypt Username
            if row["username"] and not row["username_encrypted"]:
                ct, nonce, tag = encrypt_entry(row["username"], entry_key, associated_data=entry_id.encode())
                updates.extend(["username_encrypted = ?", "username_nonce = ?", "username_tag = ?", "username = NULL"])
                vals.extend([ct, nonce, tag])
            
            if updates:
                sql = f"UPDATE entries SET {', '.join(updates)} WHERE id = ?"
                vals.append(entry_id)
                conn.execute(sql, tuple(vals))
                migrated_count += 1
        
        if migrated_count > 0:
            conn.commit()
            self.add_audit_log(action_type="MIGRATE_METADATA", details=f"Migrated {migrated_count} entries to encrypted metadata (v2.1)")
            
        return migrated_count

    def list_entry_ids(self) -> List[str]:
        """
        Retrieve all active entry IDs (for backup purposes).
        """
        try:
            conn = self.connect()
            # Select all non-deleted IDs
            cursor = conn.execute("SELECT id FROM entries WHERE is_deleted = 0")
            return [row["id"] for row in cursor.fetchall()]
        except Exception as e:
            raise DatabaseError(f"Failed to list entry IDs: {e}")

    def record_lockout_failure(self, retention_seconds: int = 3600, trim_limit: int = 100) -> None:
        """
        Record a failed attempt and prune history older than 1 hour.
        """
        conn = None
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
            cutoff = now - retention_seconds
            conn.execute(
            "DELETE FROM lockout_attempts WHERE attempt_ts < ?",
                (cutoff,)
            )
            conn.execute(
                f"""
                            DELETE FROM lockout_attempts 
                            WHERE id NOT IN (
                                SELECT id FROM lockout_attempts 
                                ORDER BY attempt_ts DESC 
                                LIMIT ?
                            )
                            """,
                (trim_limit,)
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
        conn = None
        try:
            conn = self.connect()
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute("DELETE FROM lockout_attempts")
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise DatabaseError(f"Failed to clear lockout history: {e}") from e
    
    def record_totp_attempt(self, secret_id: str, ts: int) -> None:
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO totp_attempts (secret_id, attempt_ts) VALUES (?, ?)",
                (secret_id, ts)
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def count_recent_totp_attempts(self, secret_id: str, since_ts: int) -> int:
        conn = self.connect()
        cursor = conn.execute(
            """
            SELECT COUNT(*) 
            FROM totp_attempts
            WHERE secret_id = ? AND attempt_ts >= ?
            """,
            (secret_id, since_ts)
        )
        return int(cursor.fetchone()[0])
    
    def clear_totp_attempts(self, secret_id: str) -> None:
        conn = self.connect()
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "DELETE FROM totp_attempts WHERE secret_id = ?",
            (secret_id,)
        )
        conn.commit()

    def hard_delete_entry(self, entry_id: str) -> bool:
        """
        Permanently remove an entry from the database.
        WARNING: This cannot be undone.
        """
        conn = None
        try:
            conn = self.connect()
            conn.execute("BEGIN IMMEDIATE;")

            # This triggers the 'entries_ad' trigger in schema.sql
            # which automatically cleans up FTS index and adds an audit log.
            cursor = conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))

            if cursor.rowcount > 0:
                conn.commit()
                return True
            else:
                conn.rollback()
                return False  # Entry not found

        except Exception as e:
            if conn: conn.rollback()
            raise DatabaseError(f"Hard delete failed: {e}")
    def empty_trash(self) -> int:
        """
        Permanently remove ALL entries marked as deleted.
        Returns the number of entries removed.
        """
        conn = None
        try:
            conn = self.connect()
            conn.execute("BEGIN IMMEDIATE")
            
            cursor = conn.execute("DELETE FROM entries WHERE is_deleted = 1")
            count = cursor.rowcount
            
            conn.commit()
            return count
        except Exception as e:
            if conn: conn.rollback()
            raise DatabaseError(f"Empty trash failed: {e}")

    def add_backup_history_entry(self, operation_type: str, filename: Optional[str] = None, 
                                 file_size: Optional[int] = None, status: str = "Success", 
                                 details: Optional[str] = None) -> None:
        """
        Record a maintenance operation in the backup history.
        """
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("""
                INSERT INTO backup_history (operation_type, filename, file_size, status, details)
                VALUES (?, ?, ?, ?, ?)
            """, (operation_type, filename, file_size, status, details))
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise DatabaseError(f"Failed to add backup history entry: {e}")

    def get_backup_history(self, limit: int = 50) -> List[Dict]:
        """
        Retrieve recent maintenance operation history.
        """
        conn = self.connect()
        cursor = conn.execute("""
            SELECT id, timestamp, operation_type, filename, file_size, status, details
            FROM backup_history
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def get_metadata(self, key: str) -> Optional[Any]:
        """
        Retrieve a value from the metadata table.
        """
        conn = self.connect()
        cursor = conn.execute("SELECT value FROM metadata WHERE key = ?", (key,))
        row = cursor.fetchone()
        if row:
            try:
                return json.loads(row["value"])
            except Exception:
                return row["value"]
        return None

    def update_metadata(self, key: str, value: Any) -> bool:
        """
        Upsert a key/value pair into the metadata table.
        """
        conn = None
        try:
            conn = self.connect()
            conn.execute("BEGIN IMMEDIATE;")
            
            # Serialize if not a string
            if not isinstance(value, str):
                val_str = json.dumps(value)
            else:
                # Try to see if it's already valid JSON
                try:
                    json.loads(value)
                    val_str = value
                except Exception:
                    val_str = json.dumps(value)

            conn.execute("""
                INSERT INTO metadata (key, value, updated_at)
                VALUES (?, ?, datetime('now'))
                ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            """, (key, val_str))
            
            conn.commit()
            return True
        except Exception as e:
            if conn: conn.rollback()
            raise DatabaseError(f"Failed to update metadata: {e}")
