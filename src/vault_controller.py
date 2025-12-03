""" 
SENTRA vault Controller
Managers vault unlock/lock lifecycle and entry operations with hierarchical key management
"""

from typing import Optional, List, Dict
from datetime import datetime, timezone
import warnings
import json
from src.adaptive_lockout import AdaptiveLockout
import base64
from src.crypto_engine import (
    derive_master_key,
    compute_auth_hash, 
    generate_salt,
    encrypt_entry,
    decrypt_entry,
    generate_key,
    verify_auth_hash
)
from src.password_generator import PasswordGenerator
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

    def __init__(self, db_path: str = "data/vault.db",config: Optional[Dict] = None):
        """ 
        Initialize vault controller 
        
        Args:
            - db_path : path SQLite database
        """
        self.db = DatabaseManager(db_path)
        self.secure_mem = SecureMemory()

        # Initialize Password Generator (MISSING IN YOUR CODE)
        self.pw_gen = PasswordGenerator()

        # Adaptive lockout manager
        self.config = config or {}
        self.adaptive_lockout = AdaptiveLockout(self.db, self.config)

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

        if self.is_unlocked:
            raise VaultAlreadyUnlockedError("Vault is already unlocked. Call lock_vault() first.") 
        
        allowed, delay = self.adaptive_lockout.check_and_delay()
        if not allowed:
            raise VaultError(f"Vault is temporarily locked due to failed attempts. Try again in {delay} seconds.")

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

            # ----------------------------------------------------------------
            # DESIGN NOTE (Option B): Master-Key-Based Verification
            # We derive the auth_hash from the master_key, not the password.
            # This verifies the user possesses the correct master key.
            # While non-standard, it is cryptographically consistent for local vaults.
            # ----------------------------------------------------------------

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
                vault_key_tag=tag,
                kdf_config=kdf_params
            )

            if not saved:
                raise VaultError("Vault metadata already exists, cannot initialize new vault.")

        else:
            # Existing vault - use stored parameters or defaults
            if metadata.get("kdf_config"):
                try:
                    kdf_params = json.loads(metadata["kdf_config"])
                except json.JSONDecodeError:
                    warnings.warn("Corrupt KDF config in DB, using defaults.")
            
            salt = metadata["salt"]

            master_key = derive_master_key(
                password=password,
                salt=salt, 
                time_cost=kdf_params["time_cost"],
                memory_cost=kdf_params["memory_cost"],
                parallelism=kdf_params["parallelism"],
                hash_len=kdf_params["hash_len"]
            )

            master_key_b64 = base64.b64encode(master_key).decode('utf-8')

            # verify password
            if not verify_auth_hash(metadata["auth_hash"], master_key_b64, salt):
                self.adaptive_lockout.record_failure()
                del master_key
                raise VaultError("Invalid password")
            
            # On successful unlock:
            self.adaptive_lockout.reset_session()   
            
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

            # Remove raw keys from Python stack immediately 
            del master_key
            del vault_key

            # Check if locking succeeded
            # If we cannot lock RAM, we MUST NOT proceed.
            if not self.secure_mem.lock_memory(self.master_key_secure):
                self.secure_mem.zeroize(self.master_key_secure)
                raise VaultError("CRITICAL: Failed to lock master key in memory. Operation aborted for security.")
                
            if not self.secure_mem.lock_memory(self.vault_key_secure):
                self.secure_mem.zeroize(self.vault_key_secure)
                raise VaultError("CRITICAL: Failed to lock vault key in memory. Operation aborted for security.")
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
            # Re-raise unless it's the specific lock error we just raised
            if "CRITICAL" in str(e):
                raise
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
        favorite: bool = False,
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
        self._check_unlocked()  # Raise if locked

        try:
            # Auto-calculate strength if password is provided
            strength_score = 0
            if password:
                score, label, _ = self.pw_gen.calculate_strength(password)
                strength_score = score

            vault_key = bytes(self.vault_key_secure)

            entry_id = self.db.add_entry(
                vault_key=vault_key, 
                title=title,
                url=url, 
                username=username,
                password=password, 
                notes=notes,
                tags=tags,
                category=category,
                favorite=favorite,             # <--- Pass to DB
                password_strength=strength_score # <--- Pass to DB
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

        Security:
        - Ensures vault unlocked before access.
        - Uses parameterized queries to prevent SQL injection.
        - Returns non-sensitive metadata only.
        
        """

        self._check_unlocked()

        try:
            conn = self.db.connect()
            search_query = f"{query.strip()}"
            
            if include_deleted:
                # STRATEGY 2: Recovery Mode (Bypass FTS)
                # Since schema triggers remove deleted items from the FTS index,
                # we must scan the 'entries' table directly to find them.
                sql = """
                    SELECT id, title, url, username, tags, category, 
                           created_at, modified_at, is_deleted
                    FROM entries
                    WHERE (
                        title LIKE ? OR 
                        url LIKE ? OR 
                        username LIKE ? OR 
                        tags LIKE ?
                    )
                """
                # Add wildcards for substring matching
                wildcard = f"%{search_query}%"
                params = [wildcard, wildcard, wildcard, wildcard]
                
            else:
                # STRATEGY 1: Secure Speed Mode (FTS Index)
                # Only searches what is in the index (Active items only).
                # Note: We wrap the query in double quotes for phrase matching logic
                sql = """
                    SELECT e.id, e.title, e.url, e.username, e.tags, e.category, 
                           e.created_at, e.modified_at, e.is_deleted
                    FROM entries e
                    JOIN entries_fts ON e.rowid = entries_fts.rowid      
                    WHERE entries_fts MATCH ?
                """
                # FTS5 syntax: append * for prefix matching (e.g., "amaz" -> amazon)
                fts_query = f'"{search_query}" *' 
                params = [fts_query]

            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()

            results = [dict(row) for row in rows]
            return results
        
        except Exception as e:
            raise VaultError(f"Failed to search entries: {e}")
    
    def view_audit_log(self) -> List[Dict]:
        """
        View the security audit trail of the vault.
        """
        self._check_unlocked()
        try:
            return self.db.get_audit_logs()
        except Exception as e:
            raise VaultError(f"Failed to retrieve audit log: {e}")