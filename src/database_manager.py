"""
SENTRA Database Manager
Handles SQLit operations with encrypted entry storage and hierarchical key management
"""

import sqlite3
import os
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import uuid

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