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
import json
import uuid
from src.config import DB_PATH, SCHEMA_PATH
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from src.crypto_engine import encrypt_entry, decrypt_entry, derive_master_key, generate_salt, generate_nonce, compute_auth_hash, compute_hmac

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
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    def connect(self) -> sqlite3.Connection:
        """ 
        Create or return existing databse connection
        
        Returns:
            SQLite connection object with Row factory    
        """
        if self.connection is None:
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory  = sqlite3.Row  # Dict-like rows
            self.connection.execute("PRAGMA foreign_keys = ON")
            self.connection.execute("PRAGMA journal_mode = WAL") # Better concurency
        
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
        conn = self.connect()

        # check if already initialized
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='vault_metadata'"
        )
        if cursor.fetchone():
            return False  # Already initialized
        
        # Read schema file
        try:
            with open(SCHEMA_PATH, 'r') as f:
                schema_sql = f.read()

            # Execute schema
            conn.executescript(schema_sql)
            conn.commit()
            return True
        except IOError as e:
            raise DatabaseError(f"Failed to read schema file: {e}")
        except sqlite3.Error as e:
            raise DatabaseError(f"SQL execution failed: {e}")
    
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

        # check if already initialized
        cursor = conn.execute("SELECT id FROM vault_metadata WHERE id = 1")
        if cursor.fetchone():
            return False # already initialized
        
        # Insert vault metadata
        created_at = datetime.now().isoformat()
        kdf_json = json.dumps(kdf_config) if kdf_config else None

        # FIXED: Explicitly mapping all columns to avoid parameter count mismatch
        conn.execute("""
            INSERT INTO vault_metadata (
                id, salt, auth_hash, 
                vault_key_encrypted, vault_key_nonce, vault_key_tag,
                kdf_config,
                created_at, version,
                unlock_count, last_unlocked_at
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, '2.0', 0, NULL)
        """, (salt, auth_hash, vault_key_encrypted, vault_key_nonce,
              vault_key_tag, kdf_json, created_at))
        
        conn.commit()
        return True
        
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
        # TODO: Implement unlock timestamp update
        # HINTS:
        # 1. Get current timestamp: datetime.now().isoformat()
        # 2. UPDATE vault_metadata SET 
        #     last_unlocked_at = ?, 
        #     unlock_count = unlock_count + 1
        # WHERE id = 1
        # 3. Check if rowcount > 0 (row was updated)
        # 4. Commit transaction
        # 5. Return True if updated, False otherwise
        conn = self.connect()
        timestamp = datetime.now().isoformat()

        cursor = conn.execute("""
            UPDATE vault_metadata
            SET last_unlocked_at = ?, unlock_count = unlock_count + 1
            WHERE id = 1
        """, (timestamp,))

        conn.commit()

        return cursor.rowcount > 0 # True if row was updated
    
    def _derive_entry_key(self, vault_key: bytes, entry_id:str) -> bytes:
        """ 
        Derive entry specific encryption key from vault key
        
        Args: 
            - vault_key: 32-bytes vault key
            - entry_id: Entry UUID string

        Returns:
            32-byte entry-specific key
        """
        # Encrypt the entry_key
        entry_key  = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=entry_id.encode()
        ).derive(vault_key)

        return entry_key

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
            
            if not isinstance(vault_key, bytes) or len(vault_key) != 32:
                raise ValueError("Vault key must be 32 bytes")
            
            # Generate the UUID
            if entry_id is None:
                entry_id = str(uuid.uuid4())
            
            # Derive the entry key
            entry_key = self._derive_entry_key(vault_key, entry_id)
            
            # 1. Encrypt Password
            pw_payload = {"password": password or ""}
            pw_cipher, pw_nonce, pw_tag = encrypt_entry(json.dumps(pw_payload), entry_key)
            
            # 2. Encrypt Notes
            notes_payload = {"notes": notes or ""}
            notes_cipher, notes_nonce, notes_tag = encrypt_entry(json.dumps(notes_payload), entry_key)
            
            # Timestamp
            now = datetime.now(timezone.utc).isoformat()
            
            # Insert into entries
            conn = self.connect()
            conn.execute("""
                INSERT INTO entries (
                    id, title, url, username,
                    password_encrypted, password_nonce, password_tag,
                    notes_encrypted, notes_nonce, notes_tag,
                    tags, category, created_at, modified_at,
                    favorite, password_strength, password_age_days
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """, (
                entry_id, title, url, username,
                pw_cipher, pw_nonce, pw_tag,          
                notes_cipher, notes_nonce, notes_tag, 
                tags, category, now, now,
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
        Retriev and decrypt entry by ID
        
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
            
            # Derive entry-specific key
            entry_key = self._derive_entry_key(vault_key, entry_id)
            
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
                warnings.warn(f"Failed to decrypt password for entry {entry_id}: {str(e)}")
                password = None
            
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
                warnings.warn(f"Failed to decrypt notes for entry {entry_id}: {str(e)}")
                notes = None
            
            # Update last accessed timestamp
            now = datetime.now(timezone.utc).isoformat()
            try:
                conn.execute(
                    "UPDATE entries SET last_accessed_at = ? WHERE id = ?",
                    (now, entry_id)
                )
                conn.commit()
            except sqlite3.OperationalError as e:
                warnings.warn(f"Failed to update last_accessed_at: {str(e)}")
            
            modified_date = datetime.fromisoformat(row["modified_at"])
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
                "last_accessed_at": now,
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
            
            if not isinstance(vault_key, bytes) or len(vault_key) != 32:
                raise ValueError("Vault key must be 32 bytes")
            
            conn = self.connect()
            
            # Check if entry exists
            cursor = conn.execute(
                "SELECT id FROM entries WHERE id = ? AND is_deleted = 0",
                (entry_id,)
            )
            
            if cursor.fetchone() is None:
                return False  # Entry not found
            
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
                fields.append("password_strength = ?")
                values.append(password_strength)
            
            # If password or notes changed, re-encrypt
            if password is not None or notes is not None:
                entry_key = self._derive_entry_key(vault_key, entry_id)
                
                if password is not None:
                    payload = {"password": password}
                    payload_json = json.dumps(payload)
                    ciphertext, nonce, tag = encrypt_entry(payload_json, entry_key)
                    fields.extend(["password_encrypted = ?", "password_nonce = ?", "password_tag = ?"])
                    values.extend([ciphertext, nonce, tag])
                    fields.append("password_age_days = 0")
                
                if notes is not None:
                    payload = {"notes": notes}
                    payload_json = json.dumps(payload)
                    ciphertext, nonce, tag = encrypt_entry(payload_json, entry_key)
                    fields.extend(["notes_encrypted = ?", "notes_nonce = ?", "notes_tag = ?"])
                    values.extend([ciphertext, nonce, tag])
            
            # If no fields to update, return True (nothing to do)
            if not fields:
                return True
            
            # Always update modified_at
            now = datetime.now(timezone.utc).isoformat()
            fields.append("modified_at = ?")
            values.append(now)
            
            # Build SQL correctly
            set_clause = ", ".join(fields)
            sql = f"UPDATE entries SET {set_clause} WHERE id = ?"
            values.append(entry_id)

            # Execute
            conn.execute(sql, tuple(values))
            conn.commit()
            
            return True
            
        except ValueError as e:
            raise DatabaseError(f"Invalid input: {str(e)}")
        except sqlite3.IntegrityError as e:
            raise DatabaseError(f"Update violates constraints: {str(e)}")
        except sqlite3.OperationalError as e:
            raise DatabaseError(f"Database operation failed: {str(e)}")
        except Exception as e:
            raise DatabaseError(f"Unexpected error updating entry: {str(e)}")

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
            
            deleted_at = datetime.now(timezone.utc).isoformat()
            
            cursor = conn.execute(
                "UPDATE entries SET is_deleted = 1, deleted_at = ? WHERE id = ? AND is_deleted = 0",
                (deleted_at, entry_id)
            )
            
            if cursor.rowcount > 0:
                conn.commit()
                return True
            else:
                return False  # Entry not found or already deleted
                
        except ValueError as e:
            raise DatabaseError(f"Invalid input: {str(e)}")
        except sqlite3.OperationalError as e:
            raise DatabaseError(f"Database operation failed: {str(e)}")
        except Exception as e:
            raise DatabaseError(f"Unexpected error deleting entry: {str(e)}")

    def list_entries(self, include_deleted: bool = False) -> List[Dict]:
        """ 
        List all entries (metadata only, no decryption)
        
        Args:
            - include_deleted: Include soft-deleted entries in trash
        
        Returns:
            - List of entry metadata dictionaries (passwords NOT decrypted)
        """
        # TODO: Implement entry listing
        # HINTS:
        # 1. SELECT id, title, url, username, tags, category, created_at, modified_at
        # FROM entries
        # WHERE is_deleted = 0 (or 1 if include_deleted)
        # 2. Convert rows to list of dicts
        # 3. Return list (may be empty)
        
        try:
            conn = self.connect()
            
            if include_deleted:
                cursor = conn.execute("""
                    SELECT id, title, url, username, tags, category, created_at, modified_at, is_deleted, deleted_at
                    FROM entries
                """)
            else:
                cursor = conn.execute("""
                    SELECT id, title, url, username, tags, category, created_at, modified_at
                    FROM entries
                    WHERE is_deleted = 0
                """)
            
            rows = cursor.fetchall()
            
            # Convert rows to list of dicts
            entries = [dict(row) for row in rows]
            
            return entries
            
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
            
            now = datetime.now(timezone.utc).isoformat()
            
            cursor = conn.execute(
                "UPDATE entries SET is_deleted = 0, deleted_at = NULL WHERE id = ? AND is_deleted = 1",
                (entry_id,)
            )
            
            if cursor.rowcount > 0:
                conn.commit()
                return True
            else:
                return False  # Entry not found in trash
                
        except ValueError as e:
            raise DatabaseError(f"Invalid input: {str(e)}")
        except sqlite3.OperationalError as e:
            raise DatabaseError(f"Database operation failed: {str(e)}")
        except Exception as e:
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
            return row["value"] if row else None
        except Exception:
            return None

    def update_metadata(self, key: str, value: str) -> bool:
        """
        Upsert metadata key/value into metadata table.
        """
        conn = self.connect()
        try:
            conn.execute(
                """
                INSERT INTO metadata (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value)
            )
            conn.commit()
            return True
        except Exception:
            return False
        
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
            cursor = conn.execute(f"""
                SELECT id, title, username, modified_at, password_strength
                FROM entries 
                WHERE modified_at < datetime('now', '-{int(days_threshold)} days')
                AND is_deleted = 0
                ORDER BY modified_at ASC
            """)
            
            results = []
            for row in cursor.fetchall():
                # Calculate exact age for display purposes
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
        include_deleted: bool = False
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
            conn = self.connect()
            search_query = f"{query.strip()}"
            
            if include_deleted:
                # STRATEGY 2: Recovery Mode (Bypass FTS) -> Uses LIKE
                safe = search_query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                wildcard = f"%{safe}%"
                # Since schema triggers remove deleted items from the FTS index,
                # we must scan the 'entries' table directly to find them.
                sql = """
                    SELECT id, title, url, username, tags, category, 
                        created_at, modified_at, is_deleted
                    FROM entries
                    WHERE (
                        title LIKE ? ESCAPE '\\' OR 
                        url LIKE ? ESCAPE '\\' OR 
                        username LIKE ? ESCAPE '\\' OR 
                        tags LIKE ? ESCAPE '\\'
                    )
                """
                # Add wildcards for substring matching
                params = [wildcard, wildcard, wildcard, wildcard]
                
            else:
                # STRATEGY 1: Secure Speed Mode (FTS Index)
                # Robust FTS: Split terms to allow "foo bar" to match "foo...bar" or "bar...foo"
                # rather than enforcing an exact phrase match of "foo bar".
                
                terms = search_query.split()
                
                if not terms:
                    return []

                # 1. Sanitize: Escape double quotes inside terms (standard SQL escaping)
                # 2. Tokenize: Wrap each term in quotes and append * for prefix matching
                #    Input:  foo "bar
                #    Output: "foo"* """bar"*
                safe_terms = [f'"{t.replace("\"", "\"\"")}"*' for t in terms]
                
                # 3. Join: Space implies implicit AND in FTS5
                fts_query = " ".join(safe_terms)
                
                sql = """
                    SELECT e.id, e.title, e.url, e.username, e.tags, e.category, 
                        e.created_at, e.modified_at, e.is_deleted
                    FROM entries e
                    JOIN entries_fts ON e.rowid = entries_fts.rowid      
                    WHERE entries_fts MATCH ?
                """
                params = [fts_query]

            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()

            results = [dict(row) for row in rows]
            return results
        
        except Exception as e:
            raise DatabaseError(f"Failed to search entries: {e}")