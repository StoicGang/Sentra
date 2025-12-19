"""
SENTRA Database Manager
Handles SQLit operations with encrypted entry storage and hierarchical key management
"""

import sqlite3
import os
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
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
            pw_cipher, pw_nonce, pw_tag = encrypt_entry(
                json.dumps(pw_payload),
                entry_key,
                associated_data=entry_id.encode("utf-8")
            )
            
            # 2. Encrypt Notes
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
            
            # Decrypt password field
            try:
                password_data = decrypt_entry(
                    row["password_encrypted"],
                    row["password_nonce"],
                    row["password_tag"],
                    entry_key,
                    associated_data=entry_id.encode("utf-8")
                )
                password_dict = json.loads(password_data)
                password = password_dict.get("password")
            except Exception:
                raise DatabaseError(f"CRITICAL: Password decryption failed for {entry_id}. Data may be tampered or corrupt.")
                
            # Decrypt notes field
            try:
                notes_data = decrypt_entry(
                    row["notes_encrypted"],
                    row["notes_nonce"],
                    row["notes_tag"],
                    entry_key,
                    associated_data=entry_id.encode("utf-8")
                )
                notes_dict = json.loads(notes_data)
                notes = notes_dict.get("notes")
            except Exception:
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
                "is_deleted": bool(row["is_deleted"])
            }
            
            return entry
            
        except ValueError as e:
            raise DatabaseError(f"Invalid input: {str(e)}")
        except sqlite3.OperationalError as e:
            raise DatabaseError(f"Database query failed: {str(e)}")
        except Exception as e:
            raise DatabaseError(f"Unexpected error retrieving entry: {str(e)}")

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
            category=None,
            favorite=None,
            limit: int = 100,
            last_timestamp: str = None,  # Keyset: last seen modified_at
            last_id: str = None  # Keyset: tie-breaker id
    ) -> List[Dict]:
        try:
            conn = self.connect()
            if limit > 1000: limit = 1000

            conditions = []
            params = []

            if not include_deleted:
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
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            raise DatabaseError(f"Failed to search entries: {e}")

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