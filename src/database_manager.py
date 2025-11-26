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

    def __init__(self, db_path: str = "data/vault.db"):
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
        # TODO: Implement database connection
        # HINTS:
        # 1. Check if self.connection exists and is open
        # 2. If not, create new connection: sqlite3.connect(self.db_path)
        # 3. Set row_factory to sqlite3.Row for dict-like access:
        #   connection.row_factory = sqlite3.Row
        # 4. Enable foreign keys: connection.execute("PRAGMA foreign_keys = ON")
        # 5. Enable write-ahead logging for concurrency:
        #   connection.execute("PRAGMA journal_mode = WAL")
        # 6. Return connection
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
        # TODO: Implement database initialization
        # HINTS:
        # 1. Check if database already initialized:
        #    - Query: SELECT name FROM sqlite_master WHERE type='table' AND name='vault_metadata'
        #    - If exists, return False (already initialized)
        # 2. Read schema.sql file from data/schema.sql
        # 3. Execute schema SQL: connection.executescript(schema_sql)
        # 4. Commit transaction: connection.commit()
        # 5. Return True

        conn = self.connect()

        # check if already initialized
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='vault_metadata'"
        )
        if cursor.fetchone():
            return False  # Already initialized
        
        # Read schema file
        schema_path = "data/schema.sql"
        if not os.path.exists(schema_path):
            raise DatabaseError(f"Schema file not found: {schema_path}")
        
        with open(schema_path, 'r') as f:
            schema_sql = f.read()

        # Execute schema
        conn.executescript(schema_sql)
        conn.commit()

        return True
    
    def save_vault_metadata(
            self,
            salt: bytes,
            auth_hash: bytes, 
            vault_key_encrypted: bytes, 
            vault_key_nonce: bytes, 
            vault_key_tag:bytes
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
        # TODO: Implement vault metadata save
        # HINTS:
        # 1. Check if vault already initialized (id=1 exists in vault_metadata)
        # 2. If exists, return False
        # 3. Get current timestamp: datetime.now().isoformat()
        # 4. INSERT INTO vault_metadata with all fields
        # 5. Commit transaction
        # 6. Return True
        # 
        # SQL Example:
        #     INSERT INTO vault_metadata (
        #         id, salt, auth_hash, 
        #         vault_key_encrypted, vault_key_nonce, vault_key_tag,
        #         created_at, version
        #     ) VALUES (1, ?, ?, ?, ?, ?, ?, '1.0')

        conn = self.connect()

        # check if already initialized
        cursor = conn.execute("SELECT id FROM vault_metadata WHERE id = 1")
        if cursor.fetchone():
            return False # already initialized
        
        # Insert vault metadata
        created_at = datetime.now().isoformat()

        conn.execute("""
            INSERT INTO vault_metadata (
                id, salt, auth_hash, vault_key_encrypted, vault_key_nonce, vault_key_tag,
                created_at, version
            ) VALUES (1,?,?,?,?,?,?, '1.0')
        """, (salt, auth_hash, vault_key_encrypted, vault_key_nonce,
              vault_key_tag, created_at))
        
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
            category: str = "General"
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
        # TODO: Implement entry creation with encryption
        # HINTS:
        # 1. Generate UUID for entry: entry_id = str(uuid.uuid4())
        # 2. Derive entry-specific key from vault_key using HKDF:
        # from cryptography.hazmat.primitives import hashes
        # from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        # entry_key = HKDF(
        #     algorithm=hashes.SHA256(),
        #     length=32,
        #     salt=None,
        #     info=entry_id.encode()
        # ).derive(vault_key)
        # 3. Import crypto functions:
        # from crypto_engine import encrypt_entry, generate_nonce
        # 4. Prepare data dict: {"password": password, "notes": notes}
        # 5. Encrypt data: ciphertext, nonce, tag = encrypt_entry(data, entry_key)
        # 6. Get current timestamp: datetime.now().isoformat()
        # 7. INSERT INTO entries with encrypted password and notes
        # 8. Commit and return entry_id
        # 
        # SQL Example:
        #     INSERT INTO entries (
        #         id, title, url, username,
        #         password_encrypted, password_nonce, password_tag,
        #         notes_encrypted, notes_nonce, notes_tag,
        #         tags, category, created_at, modified_at
        #     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        try:
            # Validate inputs
            if not title or not isinstance(title, str):
                raise ValueError("Entry title must be a non-empty string")
            
            if not isinstance(vault_key, bytes) or len(vault_key) != 32:
                raise ValueError("Vault key must be 32 bytes")
            
            # Generate the UUID
            entry_id = str(uuid.uuid4())
            
            # Derive the entry key
            entry_key = self._derive_entry_key(vault_key, entry_id)
            
            # Prepare the data
            payload = {
                "password": password or "",
                "notes": notes or ""
            }

            payload_json = json.dumps(payload)
            
            # Encrypt the data
            ciphertext, nonce, tag = encrypt_entry(payload_json, entry_key)
            
            # Timestamp
            now = datetime.now(timezone.utc).isoformat()
            
            # Insert into entries
            conn = self.connect()
            conn.execute("""
                INSERT INTO entries (
                    id, title, url, username,
                    password_encrypted, password_nonce, password_tag,
                    notes_encrypted, notes_nonce, notes_tag,
                    tags, category, created_at, modified_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry_id,
                title, url, username,
                ciphertext, nonce, tag,
                ciphertext, nonce, tag,
                tags, category, now, now
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
         
        # TODO: Implement entry retrieval with decryption
        # HINTS:
        # 1. Query: SELECT * FROM entries WHERE id = ? AND is_deleted = 0
        # 2. If no row found, return None
        # 3. Derive entry_key using same HKDF as add_entry()
        # 4. Import: from crypto_engine import decrypt_entry
        # 5. Decrypt password field:
        #    decrypted_data = decrypt_entry(
        #        row['password_encrypted'],
        #        row['password_nonce'],
        #        row['password_tag'],
        #        entry_key
        #    )
        # 6. Update last_accessed_at timestamp
        # 7. Return combined dict (metadata + decrypted fields)

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
            
            # Return combined dict
            entry = {
                "id": row["id"],
                "title": row["title"],
                "url": row["url"],
                "username": row["username"],
                "tags": row["tags"],
                "category": row["category"],
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
            category: Optional[str] = None
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
        # TODO: Implement entry update
        # HINTS:
        # 1. Check if entry exists: SELECT id FROM entries WHERE id = ? AND is_deleted = 0
        # 2. If not found, return False
        # 3. Build UPDATE query dynamically for non-None fields
        # 4. If password or notes changed, re-encrypt with same entry_key
        # 5. Always update modified_at timestamp
        # 6. Commit and return True
        # 
        # SQL Example:
        #     UPDATE entries 
        #     SET title = ?, url = ?, password_encrypted = ?, modified_at = ?
        #     WHERE id = ?

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
            
            # If password or notes changed, re-encrypt
            if password is not None or notes is not None:
                entry_key = self._derive_entry_key(vault_key, entry_id)
                
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
        # TODO: Implement soft delete
        # HINTS:
        # 1. UPDATE entries SET is_deleted = 1, deleted_at = ? WHERE id = ?
        # 2. Check cursor.rowcount > 0 to verify row was updated
        # 3. Commit and return result
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
        
        Args:
            - entry_id: Entry UUID
        
        Returns:
            - True if restored successfully
            - False if entry not found in trash
        """
        # TODO: Implement entry restoration
        # HINTS:
        # 1. UPDATE entries SET is_deleted = 0, deleted_at = NULL WHERE id = ? AND is_deleted = 1
        # 2. Check cursor.rowcount > 0
        # 3. Commit and return result
        
        try:
            # Validate input
            if not entry_id or not isinstance(entry_id, str):
                raise ValueError("Entry ID must be a non-empty string")
            
            conn = self.connect()
            
            now = datetime.now(timezone.utc).isoformat()
            
            cursor = conn.execute(
                "UPDATE entries SET is_deleted = 0, deleted_at = NULL, modified_at = ? WHERE id = ? AND is_deleted = 1",
                (now, entry_id)
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