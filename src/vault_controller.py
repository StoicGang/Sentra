""" 
SENTRA vault Controller
Managers vault unlock/lock lifecycle and entry operations with hierarchical key management
"""

from typing import Optional, List, Dict, Tuple
from datetime import datetime, timezone
import warnings
import json
from src.adaptive_lockout import AdaptiveLockout
from src.backup_manager import BackupManager
from src.crypto_engine import (
    derive_master_key,
    compute_auth_hash, 
    generate_salt,
    encrypt_entry,
    decrypt_entry,
    generate_key,
    derive_hkdf_key,
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

        # New: Handles for memory locking
        self.master_key_handle = None
        self.vault_key_handle = None

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

    def vault_exists(self) -> bool:
        """
        Check if the vault has been initialized.

        Ensures DB/tables exist first (idempotent), then returns True if metadata exists.
        Returns False on any recoverable DB error.
        """
        try:
            # Ensure database schema exists (idempotent)
            self.db.initialize_database()

            # load_vault_metadata() should now be safe to call
            return self.db.load_vault_metadata() is not None

        except DatabaseError:
            # Known DB error: treat as "not initialized" for CLI's decision path
            return False
        except Exception as e:
            # Unexpected errors: surface a warning in logs, but treat as not-initialized
            warnings.warn(f"vault_exists() check failed: {e}")
            return False

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
            raise VaultLockedError(f"Vault is temporarily locked due to failed attempts. Try again in {delay} seconds.")

        if not password or not isinstance(password, str):
            raise VaultError("Password must be a non-empty string")
        
        # Initialize the database
        self.db.initialize_database()

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

            # Auth hash binds password to fixed context for password verification
            auth_hash = compute_auth_hash(password, salt)

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

            # 1. Reload from DB
            verify_meta = self.db.load_vault_metadata()
            if not verify_meta:
                self.db.delete_vault_metadata()
                raise VaultError("Critical: Vault metadata saved but could not be reloaded.")
            
            # 2. Verify KDF Config JSON integrity
            try:
                if verify_meta.get("kdf_config"):
                    json.loads(verify_meta["kdf_config"])
            except Exception:
                self.db.delete_vault_metadata()
                raise VaultError("Vault initialization failed: Corrupt KDF config storage.")
            
            # 3. Verify Cryptographic Round-Trip
            # Attempt to decrypt the key we just saved. If this fails, the vault is broken.
            try:
                # We need the exact bytes from the DB to ensure type fidelity
                decrypt_entry(
                    ciphertext=verify_meta["vault_key_encrypted"],
                    nonce=verify_meta["vault_key_nonce"],
                    auth_tag=verify_meta["vault_key_tag"],
                    key=master_key,
                    associated_data=b"vault-key-v1"
                )
            except Exception as e:
                # ROLLBACK: Delete the corrupted metadata so user can try again
                self.db.delete_vault_metadata()
                raise VaultError(f"Vault integrity check failed: Cannot decrypt new vault key. Error: {e}")
            
        else:
            # Existing vault - use stored parameters or defaults
            if metadata.get("kdf_config"):
                try:
                    kdf_params = json.loads(metadata["kdf_config"])
                except json.JSONDecodeError:
                    warnings.warn("Corrupt KDF config in DB, using defaults.")
            
            salt = metadata["salt"]

            # verify password
            if not verify_auth_hash(metadata["auth_hash"], password, salt):
                self.adaptive_lockout.record_failure()
                raise VaultError("Invalid password")
            
            # On successful unlock:
            self.adaptive_lockout.reset_session()   

            # Derive Master Key only after auth succeeds
            master_key = derive_master_key(
                password=password,
                salt=salt, 
                time_cost=kdf_params["time_cost"],
                memory_cost=kdf_params["memory_cost"],
                parallelism=kdf_params["parallelism"],
                hash_len=kdf_params["hash_len"]
            )
            
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

            # Lock Master Key
            self.master_key_handle = self.secure_mem.lock_memory(self.master_key_secure)
            if not self.master_key_handle:
                # Fallback: Manual wipe of Python buffer
                self.master_key_secure[:] = b'\x00' * len(self.master_key_secure)
                raise VaultError("CRITICAL: Failed to acquire lock handle for master key.")
            
            # Apply anti-forensics: Prevent fork inheritance
            self.secure_mem.protect_from_fork(self.master_key_handle)

            # Lock Vault Key
            self.vault_key_handle = self.secure_mem.lock_memory(self.vault_key_secure)
            if not self.vault_key_handle:
                # Explicit Cleanup: Wipe vault buffer
                self.vault_key_secure[:] = b'\x00' * len(self.vault_key_secure)
                
                # Explicit Cleanup: Release master key handle immediately
                self.secure_mem.zeroize(self.master_key_handle)
                self.secure_mem.unlock_memory(self.master_key_handle)
                self.master_key_handle = None
                self.master_key_secure[:] = b'\x00' * len(self.master_key_secure)
                
                raise VaultError("CRITICAL: Failed to acquire lock handle for vault key.")
            
            # Apply anti-forensics
            self.secure_mem.protect_from_fork(self.vault_key_handle)

        except Exception as e:
            # Clean up on failure using handles
            if self.master_key_handle:
                self.secure_mem.zeroize(self.master_key_handle)
                self.secure_mem.unlock_memory(self.master_key_handle)
                self.master_key_handle = None
            
            if self.vault_key_handle:
                self.secure_mem.zeroize(self.vault_key_handle)
                self.secure_mem.unlock_memory(self.vault_key_handle)
                self.vault_key_handle = None
                
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
            # Zeroize and Unlock Master Key
            if self.master_key_handle:
                self.secure_mem.zeroize(self.master_key_handle)
                self.secure_mem.unlock_memory(self.master_key_handle)
                self.master_key_handle = None
            
            # Defensive: Explicitly wipe Python buffer to clear potential copies/references
            if self.master_key_secure:
                self.master_key_secure[:] = b'\x00' * len(self.master_key_secure)
                self.master_key_secure = None

            # Zeroize and Unlock Vault Key
            if self.vault_key_handle:
                self.secure_mem.zeroize(self.vault_key_handle)
                self.secure_mem.unlock_memory(self.vault_key_handle)
                self.vault_key_handle = None
            
            # Defensive: Explicitly wipe Python buffer
            if self.vault_key_secure:
                self.vault_key_secure[:] = b'\x00' * len(self.vault_key_secure)
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

    def search_entries(self, query: str, include_deleted: bool = False) -> List[Dict]:
        """
        Search entries by title/URL/tags.
        Delegates to DatabaseManager.search_entries.
        """
        self._check_unlocked()

        try:
            return self.db.search_entries(query, include_deleted)
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

    def list_entries(
        self, 
        include_deleted: bool = False,
        limit: int = 100, 
        offset: int = 0
    ) -> List[Dict]:
        """
        List all entries (metadata only) with pagination support.
        Delegates to DatabaseManager.list_entries.
        """
        self._check_unlocked()
        try:
            return self.db.list_entries(
                include_deleted=include_deleted,
                limit=limit,
                offset=offset
            )
        except Exception as e:
            raise VaultError(f"Failed to list entries: {e}")

    def update_entry(self, entry_id: str, **kwargs) -> bool:
        """
        Update an existing entry.
        
        Handles:
        - Security check (is_unlocked)
        - Key management (retrieves secure key for DB)
        - Password strength recalculation (if password changes)
        """
        self._check_unlocked()
        try:
            vault_key = bytes(self.vault_key_secure)
            
            # If password is being updated, automatically recalculate strength
            if "password" in kwargs and kwargs["password"]:
                score, _, _ = self.pw_gen.calculate_strength(kwargs["password"])
                kwargs["password_strength"] = score
            
            return self.db.update_entry(entry_id, vault_key, **kwargs)
        except Exception as e:
            raise VaultError(f"Failed to update entry: {e}")

    def delete_entry(self, entry_id: str) -> bool:
        """
        Soft-delete an entry.
        Delegates to DatabaseManager.delete_entry.
        """
        self._check_unlocked()
        try:
            return self.db.delete_entry(entry_id)
        except Exception as e:
            raise VaultError(f"Failed to delete entry: {e}")

    def restore_entry(self, entry_id: str) -> bool:
        """
        Restore a deleted entry from trash.
        Delegates to DatabaseManager.restore_entry.
        """
        self._check_unlocked()
        try:
            if not entry_id or not isinstance(entry_id, str):
                raise VaultError("Invalid entry ID")
            
            # FIX: Direct delegation to DB manager
            return self.db.restore_entry(entry_id)
            
        except Exception as e:
            raise VaultError(f"Failed to restore entry: {e}")
        
    def get_backup_keys(self) -> Tuple[bytes, bytes]:
        """
        Derive separate keys for Backup Encryption and HMAC Integrity.
        
        Returns:
            Tuple(encryption_key, hmac_key)
        
        Security:
            - Uses HKDF to split the main vault_key.
            - Ensures 'enc_key' and 'hmac_key' are mathematically independent.
            - Prevents key reuse vulnerabilities.
        """
        self._check_unlocked()
        
        # Access the raw key from secure memory
        if not self.vault_key_secure:
             raise VaultError("Vault key not available.")
             
        master_material = bytes(self.master_key_secure)
        
        try:
            enc_key = derive_hkdf_key(
                master_key=master_material,
                info=b"sentra-backup-enc-v1"
            )
            hmac_key = derive_hkdf_key(
                master_key=master_material,
                info=b"sentra-backup-mac-v1"
            )
        finally:
            # Zero out the local copy of the master key
            # Check if it's mutable (bytearray) first
            if 'master_material' in locals():
                # Since 'bytes' are immutable, we can't zero them in-place easily.
                # However, if 'master_material' was created via 'bytes(self.master_key_secure)',
                # it is an immutable bytes object.
                # To really zero it, we should have cast to bytearray OR just rely on GC (less secure).
                # Ideally:
                if isinstance(master_material, bytearray):
                     for i in range(len(master_material)):
                         master_material[i] = 0
                del master_material

        return enc_key, hmac_key
    
    def create_backup_manager(self):
        """
        Factory method to create a fully configured BackupManager.
        Injects both the external backup keys AND the internal vault key
        needed for re-encryption during restore.
        """
        self._check_unlocked()
        
        if not self.vault_key_secure:
            raise VaultError("Vault key not available in secure memory.")

        # 1. Get Export/Import Keys (for the file itself)
        vault_keys = self.get_backup_keys()
        
        # 2. Get Internal Key (for the database)
        # We retrieve the raw bytes from secure memory to pass to the manager
        internal_vault_key = bytes(self.vault_key_secure)
        
        # 3. Create Manager with full hierarchy
        return BackupManager(
            db=self.db,
            vault_keys=vault_keys,
            hierarchy_keys={'vault_key': internal_vault_key}
        )