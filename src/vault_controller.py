""" 
SENTRA vault Controller
Managers vault unlock/lock lifecycle and entry operations with hierarchical key management
"""

from typing import Optional, List, Dict
from datetime import datetime, timezone
import warnings
import json
import base64
from src.crypto_engine import (
    derive_master_key,
    compute_auth_hash, 
    generate_salt, 
    generate_nonce,
    encrypt_entry,
    decrypt_entry,
    generate_key
)
from src.database_manager import DatabaseError, DatabaseManager
from src.secure_memory import SecureMemory

class VaultError(Exception):
    """Base exception for vault operations"""
    pass

class VaultLockedError(VaultError):
    """Raised when trying to access vault while locked"""
    pass

class VaultAlreadyUnlockedError(ValueError):
    """Raised when trying to unlock already unlocked vault"""
    pass

class VaultController:
    """
    Main vault controller managing secure password storage
    
    State Machine:
        - LOCKED: Only unlock_vault() allowed
        - UNLOCKED: All operations allowed
        - After lock(): Return to LOCKED state
    
    Security:
        - Master key: Stored in SecureMemory while unlocked
        - Vault key: Stored in SecurMemory while unlocked
        - Entry keys: Derived on-demand, never persisted
        - Fail-fast: All operations check is_unlocked flag
    """

    def __init__(self, db_path: str = "data/vault.db"):
        """ 
        Initialize vault controller 
        
        Args:
            - db_path : path SQLite database
        """
        self.db = DatabaseManager(db_path)
        self.secure_mem = SecureMemory()

        # State flags
        self.is_unlocked = False

        # Secure memory references
        self.master_key_secure: Optional[bytearray] = None
        self.vault_key_secure: Optional[bytearray] = None

        # Metadata
        self.unlock_timestamp: Optional[str] = None
    
    def _check_unlocked(self) -> None:
        """
        Check if vault is unlocked, raise if locked
        
        Raises:
            VaultLockedError: If vault is locked
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault is locked. Call unlock_vault() first.")
        

    def unlock_vault(self, password: str) -> bool:
        """ 
        Unlock vault and derive hierarchical keys
        
        Args:
            password: User's master password
        
        Returns: 
            True if unlcok successful
            
        Raises:
            VaultError: If vault already unlocked or auth fails
            DatabaseError: If database operation fails
        """

        # TODO: Implement vault unlock with hierarchical key derivation
        # HINTS:
        # 1. Check if already unlocked: raise VaultAlreadyUnlockedError
        # 2. Initialize database: db.initialize_database() (ignore if already exists)
        # 3. Load vault metadata: db.load_vault_metadata()
        # 4. If no metadata, this is first unlock (new vault):
        #    - Generate salt and auth_hash
        #    - Derive master key from password
        #    - Generate vault key
        #    - Encrypt vault key with master key
        #    - Save metadata to database
        # 5. If metadata exists (existing vault):
        #    - Generate salt from metadata
        #    - Derive master key from password
        #    - Verify password: compute_auth_hash(master_key) == metadata['auth_hash']
        #    - Decrypt vault key: decrypt_entry(metadata['vault_key_encrypted'], ...)
        # 6. Store keys in SecureMemory:
        #    - Convert to bytearray for SecureMemory
        #    - Lock memory to prevent swap
        # 7. Set state: is_unlocked = True, unlock_timestamp = now
        # 8. Update database: db.update_unlock_timestamp()
        # 9. Return True

        if self.is_unlocked:
            raise VaultAlreadyUnlockedError("Vault is already unlocked. Call lock_vault() first.")
        
        if not password or not isinstance(password, str):
            raise VaultError("Password must be a non-empty string")
        
        # Initialize the database
        try:
            self.db.initialize_database()
        except Exception as e:
            # Check if it's just an "already initialized" message (which is ok)
            error_msg = str(e).lower()
            if 'already' not in error_msg and 'exists' not in error_msg and 'initialized' not in error_msg:
                raise VaultError(f"Failed to initialize database: {e}")

        # Load metadata
        metadata = self.db.load_vault_metadata()

        # KDF parameters (used for both new and existing vaults)
        kdf_params = {
            "algorithm": "argon2id", 
            "time_cost": 3, 
            "memory_cost": 64 * 1024,  # KB
            "parallelism": 1, 
            "salt_len": 16, 
            "hash_len": 32
        }

        # If no metadata is present (new vault)
        if metadata is None:
            salt = generate_salt(kdf_params["salt_len"])  # Generate the salt

            # Derive master key from password + salt
            master_key = derive_master_key(
                password=password, 
                salt=salt, 
                time_cost=kdf_params["time_cost"],  
                memory_cost=kdf_params["memory_cost"],
                parallelism=kdf_params["parallelism"],
                hash_len=kdf_params["hash_len"],
            )

            # Vault key used to derive per-entry keys
            vault_key = generate_key(32)
            vault_key_json = json.dumps({"vault_key": vault_key.hex()})

            # Auth hash binds master key to fixed context for password verification
            master_key_b64 = base64.b64encode(master_key).decode('utf-8')
            auth_hash = compute_auth_hash(master_key_b64, salt)

            # AEAD encrypt vault key under master key; store nonce + ciphertext + tag
            ciphertext, nonce, tag = encrypt_entry(
                plaintext=vault_key_json, 
                key=master_key,
                associated_data=b"vault-key-v1"
            )
            
            # metadata to save
            saved = self.db.save_vault_metadata(
                salt=salt,
                auth_hash=auth_hash,
                vault_key_encrypted=ciphertext,
                vault_key_nonce=nonce,
                vault_key_tag=tag
            )

            if not saved:
                raise VaultError("Vault metadata already exists, cannot initialize new vault.")

        else:
            # Existing vault - use stored parameters or defaults
            stored_kdf = metadata.get("kdf", {})
            if stored_kdf:
                kdf_params = stored_kdf
            
            salt = metadata["salt"]

            master_key = derive_master_key(
                password=password,
                salt=salt, 
                time_cost=kdf_params["time_cost"],
                memory_cost=kdf_params["memory_cost"],
                parallelism=kdf_params["parallelism"],
                hash_len=kdf_params["hash_len"]
            )

            # verify password
            master_key_b64 = base64.b64encode(master_key).decode('utf-8')
            if compute_auth_hash(master_key_b64, salt=metadata["salt"]) != metadata["auth_hash"]:
                raise VaultError("Invalid password")
            
            # Decrypt vault key 
            try:
                vault_key_json = decrypt_entry(
                    ciphertext=metadata["vault_key_encrypted"],
                    nonce=metadata["vault_key_nonce"],
                    auth_tag=metadata["vault_key_tag"],  
                    key=master_key,
                    associated_data=b"vault-key-v1"  
                )
                vault_key_dict = json.loads(vault_key_json)
                vault_key = bytes.fromhex(vault_key_dict["vault_key"])
            except Exception as e:
                raise VaultError(f"Failed to decrypt vault key: {e}")
            
        # Store keys in secure memory
        try:
            self.master_key_secure = bytearray(master_key)
            self.vault_key_secure = bytearray(vault_key)
            # Check if locking succeeded
            if not self.secure_mem.lock_memory(self.master_key_secure):
                warnings.warn("Master key could not be locked in RAM (swapping possible)", RuntimeWarning)
                
            if not self.secure_mem.lock_memory(self.vault_key_secure):
                warnings.warn("Vault key could not be locked in RAM (swapping possible)", RuntimeWarning)
        except Exception as e:
            # Clean up on failure
            if self.master_key_secure:
                try:
                    self.secure_mem.zeroize(self.master_key_secure)
                except:
                    pass
            if self.vault_key_secure:
                try:
                    self.secure_mem.zeroize(self.vault_key_secure)
                except:
                    pass
            raise VaultError(f"Secure memory lock failed: {e}")
        
        self.is_unlocked = True
        self.unlock_timestamp = datetime.now(timezone.utc).isoformat()

        # Update last unlock timestamp in DB 
        try:
            self.db.update_unlock_timestamp()
        except Exception as e:
            warnings.warn(f"Failed to update unlock timestamp: {e}", RuntimeWarning)

        return True
    
    def lock_vault(self) -> bool:
        """
        Lock vault and securely zero all sensitive data
        
        Returns:
            True if lock successful
        """
        # TODO: Implement vault lock with secure cleanup
        # HINTS:
        # 1. If not unlocked, just return True (already locked)
        # 2. Zeroize master key: secure_mem.zeroize(master_key_secure)
        # 3. Zeroize vault key: secure_mem.zeroize(vault_key_secure)
        # 4. Set to None: master_key_secure = None, vault_key_secure = None
        # 5. Set state: is_unlocked = False
        # 6. Close database connection: db.close()
        # 7. Return True
        if not self.is_unlocked:
            # Already locked, nothing to do
            return True
        
        try:
            if self.master_key_secure:
                self.secure_mem.zeroize(self.master_key_secure)
                self.secure_mem.unlock_memory(self.master_key_secure)
                self.master_key_secure = None

            if self.vault_key_secure:
                self.secure_mem.zeroize(self.vault_key_secure)
                self.secure_mem.unlock_memory(self.vault_key_secure)
                self.vault_key_secure = None
        
            self.is_unlocked = False

            # Close database connection cleanly 
            self.db.close()

            return True
        except Exception as e:
            raise VaultError(f"Failed to lock vault securely: {e}")
    
    def add_password(
        self,
        title: str,
        url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        notes: Optional[str] = None,
        tags: Optional[str] = None,
        category: str = "General"
    ) -> str:
        """
        Add new password entry to vault
        
        Args:
            title: Entry title
            url: Website URL
            username: Username/email
            password: Password
            notes: Notes
            tags: Comma-separated tags
            category: Entry category
        
        Returns:
            Entry ID (UUID)
        
        Raises:
            VaultLockedError: If vault locked
            VaultError: If add fails
        """
        # TODO: Implement add_password with unlock check
        self._check_unlocked()  # Raise if locked

        try:
            # Validate required fields
            if not title or not isinstance(title, str):
                raise ValueError("Entry title must be a non-empty string")

            vault_key = bytes(self.vault_key_secure)

            # add entry
            entry_id = self.db.add_entry(
                vault_key=vault_key, 
                title=title,
                url=url, 
                username=username,
                password=password, 
                notes=notes,
                tags=tags,
                category=category
            )        
            return entry_id
        
        except Exception as e:
            raise VaultError(f"Failed to add password entry: {e}")
    
    def get_password(self, entry_id: str) -> Optional[Dict]:
        """
        Retrieve password entry from vault
        
        Args:
            entry_id: Entry UUID
        
        Returns:
            Decrypted entry dictionary or None
        
        Raises:
            VaultLockedError: If vault locked
            VaultError: If retrieval fails
        """
        # TODO: Implement get_password with unlock check
        self._check_unlocked() 

        try:
            vault_key = bytes(self.vault_key_secure)
            entry = self.db.get_entry(entry_id, vault_key)

            return entry
        except Exception as e:
            raise VaultError(f"Failed to retrieve password entry: {e}")
        
    
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
        
        """
        # TODO: Implement search_entries with unlock check

        self._check_unlocked() 

        try:
            conn = self.db.connect()
            # FTS5 match query search 
            # use parameterized MATCH query to prevent injection
            search_query = f"{query.strip()}"

            sql = """
                SELECT e.id, e.title, url, e.username, e.tags, e.category, e.created_at, e.modified_at
                FROM entries e
                JOIN entries_fts fts ON e.rowid = fts.rowid
                WHERE fts MATCH ?
            """

            params = [search_query] 
            if not include_deleted:
                sql += " AND e.isdeleted = 0"

            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()

            results = [dict(row) for row in rows]
            return results
        
        except Exception as e:
            raise VaultError(f"Failed to search entries: {e}")