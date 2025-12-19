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
import threading

class VaultError(Exception):
    """Base exception for vault operations"""
    pass

class VaultLockedError(VaultError):
    """Raised when trying to access vault while locked"""
    pass

class CriticalVaultError(VaultError):
    """Raised for unrecoverable secure-memory or crypto failures."""
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
        - Vault key: Stored in SecureMemory while unlocked
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
        self._state_lock = threading.RLock()
        self._schema_initialized = False
    
    def _check_unlocked(self) -> None:
        """
        Check if vault is unlocked, raise if locked
        
        Raises:
            VaultLockedError: If vault is locked
        """
        with self._state_lock:
            if not self.is_unlocked:
                raise VaultLockedError("Vault is locked. Call unlock_vault() first.")

            if self.master_key_secure is None or self.vault_key_secure is None:
                raise CriticalVaultError("Inconsistent State: Unlocked without active key handles.")

    def vault_exists(self) -> bool:
        """
        Check if the vault has been initialized.

        Ensures DB/tables exist first (idempotent), then returns True if metadata exists.
        Returns False on any recoverable DB error.
        """
        try:
            # Ensure schema exists only once per controller, not on every call.
            # initialize_database is idempotent, but redundant calls are wasteful.
            if not hasattr(self, "_schema_initialized"):
                self.db.initialize_database()
                self._schema_initialized = True

            # load_vault_metadata() should now be safe to call
            return self.db.load_vault_metadata() is not None

        except DatabaseError:
            # Known DB error: treat as "not initialized" for CLI's decision path
            return False
        except Exception as e:
            if hasattr(self, "_schema_initialized"):
                del self._schema_initialized
            # Unexpected errors: surface a warning in logs, but treat as not-initialized
            warnings.warn(f"vault_exists() check failed: {e}", RuntimeWarning)
            return False

    def unlock_vault(self, password: str, create_if_missing: bool = False) -> bool:
        with self._state_lock:
            if self.is_unlocked:
                raise VaultAlreadyUnlockedError("Vault is already unlocked. Call lock_vault() first.")
            try:
                # Use the hasattr check as seen in your file, or self._schema_initialized if you defined it
                if not hasattr(self, "_schema_initialized"):
                    self.db.initialize_database()
                    self._schema_initialized = True
            except Exception as e:
                raise VaultError(f"Database initialization failed: {e}")

            allowed, delay = self.adaptive_lockout.check_and_delay()
            if not allowed:
                raise VaultLockedError(f"Vault is temporarily locked due to failed attempts. Try again in {delay} seconds.")

            if not password or not isinstance(password, str):
                raise VaultError("Password must be a non-empty string")
            
            # Initialize the database
            if not hasattr(self, "_schema_initialized"):
                self.db.initialize_database()
                self._schema_initialized = True

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
                if not create_if_missing:
                    raise VaultError(
                        "No vault exists at this path. "
                        "Use explicit vault creation before unlocking."
                    )

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
                    try:
                        self.db.delete_vault_metadata()
                    except Exception:
                        pass
                    raise CriticalVaultError("Vault metadata saved but could not be reloaded.")
                
                # 2. Verify KDF Config JSON integrity
                try:
                    if verify_meta.get("kdf_config"):
                        json.loads(verify_meta["kdf_config"])
                except Exception:
                    try:
                        self.db.delete_vault_metadata()
                    except Exception:
                        pass
                    raise VaultError("Vault initialization failed: Corrupt KDF config storage.")
                
                # 3. Verify Cryptographic Round-Trip
                # Attempt to decrypt the key we just saved. If this fails, the vault is broken.
                try:
                    roundtrip_json = decrypt_entry(
                        ciphertext=verify_meta["vault_key_encrypted"],
                        nonce=verify_meta["vault_key_nonce"],
                        auth_tag=verify_meta["vault_key_tag"],
                        key=master_key,
                        associated_data=b"vault-key-v1",
                    )
                    vault_key_roundtrip = json.loads(roundtrip_json)["vault_key"]
                    if vault_key_roundtrip != vault_key.hex():
                        raise ValueError("Vault key mismatch after round-trip decrypt.")
                except Exception as e:
                    try:
                        self.db.delete_vault_metadata()
                    except Exception:
                        pass
                    raise CriticalVaultError(f"Critical vault integrity failure: {e}")
                
            else:
                # Existing vault - use stored parameters or fall back to defaults
                if metadata.get("kdf_config"):
                    try:
                        loaded = json.loads(metadata["kdf_config"])
                        # Normalize/validate kdf params to expected integer types with safe defaults
                        kdf_params = {
                            "algorithm": loaded.get("algorithm", "argon2id"),
                            "time_cost": int(loaded.get("time_cost", 3)),
                            "memory_cost": int(loaded.get("memory_cost", 64 * 1024)),
                            "parallelism": int(loaded.get("parallelism", 1)),
                            "salt_len": int(loaded.get("salt_len", 16)),
                            "hash_len": int(loaded.get("hash_len", 32)),
                        }
                    except Exception:
                        warnings.warn("Corrupt or invalid KDF config in DB; using defaults.", RuntimeWarning)
                        # keep current kdf_params (defaults from above)
                
                # Ensure salt is present
                try:
                    salt = metadata["salt"]
                except KeyError:
                    raise VaultError("Vault metadata missing salt; cannot verify password.")

                # verify password (auth hash binds password to stored salt)
                try:
                    ok = verify_auth_hash(metadata["auth_hash"], password, salt)
                except Exception as e:
                    # Unexpected error while verifying (DB corrupt or HMAC failure)
                    raise DatabaseError(f"Auth verification failed: {e}") from e

                if not ok:
                    # record failure and surface a clear error
                    self.adaptive_lockout.record_failure()
                    raise VaultError("Invalid password")

                # Derive Master Key only after auth succeeds
                master_key = derive_master_key(
                    password=password,
                    salt=salt,
                    time_cost=kdf_params["time_cost"],
                    memory_cost=kdf_params["memory_cost"],
                    parallelism=kdf_params["parallelism"],
                    hash_len=kdf_params["hash_len"]
                )

                # Decrypt vault key (round-trip)
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
                    self.adaptive_lockout.record_failure()
                    # Do not reset lockout history here — treat as a cryptographic failure
                    raise VaultError("Invalid password or vault corrupted.") from e

            # Store keys in secure memory
            # Secure-memory lock + proper zeroization and lockout reset placement
            try:
                # Convert to mutable buffers that we can zeroize
                master_buf = bytearray(master_key)
                vault_buf = bytearray(vault_key)

                # Remove immutable originals asap (they were bytes)
                try:
                    del master_key
                except NameError:
                    pass
                try:
                    del vault_key
                except NameError:
                    pass

                # Attempt to lock master key into secure memory
                self.master_key_handle = self.secure_mem.lock_memory(master_buf)
                if not self.master_key_handle:
                    # Wipe python-side buffers immediately and error out
                    master_buf[:] = b'\x00' * len(master_buf)
                    vault_buf[:] = b'\x00' * len(vault_buf)
                    raise CriticalVaultError("CRITICAL: Failed to acquire lock handle for master key.")

                # Prevent fork inheritance for the master key
                self.secure_mem.protect_from_fork(self.master_key_handle)

                # Now lock vault key into secure memory
                self.vault_key_handle = self.secure_mem.lock_memory(vault_buf)
                if not self.vault_key_handle:
                    # Wipe python buffers and securely release master key handle
                    vault_buf[:] = b'\x00' * len(vault_buf)

                    # best-effort cleanup of master handle
                    try:
                        self.secure_mem.zeroize(self.master_key_handle)
                        self.secure_mem.unlock_memory(self.master_key_handle)
                    except Exception:
                        pass
                    self.master_key_handle = None

                    # wipe remaining python master buffer and raise
                    master_buf[:] = b'\x00' * len(master_buf)
                    raise CriticalVaultError("CRITICAL: Failed to acquire lock handle for vault key.")

                # Prevent fork inheritance for the vault key
                self.secure_mem.protect_from_fork(self.vault_key_handle)

                # At this point both keys are locked into secure memory.
                # Keep a single, controlled python-side bytearray while unlocked.
                # This buffer is the authoritative in-process copy and will be
                # securely zeroed in lock_vault().
                self.master_key_secure = master_buf
                self.vault_key_secure = vault_buf

                self.is_unlocked = True

                # Best-effort: remove local transient names (we still keep the buffers via attributes)
                try:
                    del master_buf
                    del vault_buf
                except Exception:
                    pass

            except Exception as e:
                # Clean up any handles we successfully obtained
                if self.master_key_handle:
                    try:
                        self.secure_mem.zeroize(self.master_key_handle)
                        self.secure_mem.unlock_memory(self.master_key_handle)
                    except Exception:
                        pass
                    self.master_key_handle = None

                if self.vault_key_handle:
                    try:
                        self.secure_mem.zeroize(self.vault_key_handle)
                        self.secure_mem.unlock_memory(self.vault_key_handle)
                    except Exception:
                        pass
                    self.vault_key_handle = None

                # Propagate CRITICAL errors as-is, others as VaultError
                if isinstance(e, CriticalVaultError):
                    raise

                raise VaultError(f"Secure memory lock failed: {e}") from e

            try:
                # First, reset lockout session now that unlock succeeded fully
                try:
                    self.adaptive_lockout.reset_session()
                except Exception:
                      warnings.warn("Warning: failed to reset adaptive lockout after successful unlock.", RuntimeWarning)

                # Mark unlocked state and timestamp
                self.unlock_timestamp = datetime.now(timezone.utc).isoformat()

                # Persist last_unlocked_at in DB; non-fatal if it fails (we already unlocked)
                try:
                    self.db.update_unlock_timestamp()
                except Exception as e:
                    warnings.warn(f"Failed to update unlock timestamp: {e}", RuntimeWarning)

                return True

            except Exception as e:
                # Defensive cleanup if anything in the finalization fails
                # (zeroize/unlock will be handled by lock_vault or here)
                try:
                    if self.master_key_handle:
                        self.secure_mem.zeroize(self.master_key_handle)
                        self.secure_mem.unlock_memory(self.master_key_handle)
                        self.master_key_handle = None
                except Exception:
                    pass
                try:
                    if self.vault_key_handle:
                        self.secure_mem.zeroize(self.vault_key_handle)
                        self.secure_mem.unlock_memory(self.vault_key_handle)
                        self.vault_key_handle = None
                except Exception:
                    pass
                raise VaultError(f"Failed to finalize vault unlock: {e}") from e

    def lock_vault(self) -> bool:
        """
        Lock vault and securely zero all sensitive data
        
        Returns:
            True if lock successful
        """
        with self._state_lock:
            if not self.is_unlocked:
                return True

            errors = []
            # FIX: Attempt cleanup for ALL handles regardless of intermediate failures
            for handle_attr, secure_attr in [
                ('master_key_handle', 'master_key_secure'),
                ('vault_key_handle', 'vault_key_secure')
            ]:
                handle = getattr(self, handle_attr)
                secure_buf = getattr(self, secure_attr)

                try:
                    if handle:
                        self.secure_mem.zeroize(handle)
                        self.secure_mem.unlock_memory(handle)
                    if secure_buf:
                        secure_buf[:] = b'\x00' * len(secure_buf)
                except Exception as e:
                    errors.append(f"{handle_attr} failure: {e}")
                finally:
                    setattr(self, handle_attr, None)
                    setattr(self, secure_attr, None)

            self.is_unlocked = False
            if errors:
                raise CriticalVaultError(f"Partial lock state! Security warning: {', '.join(errors)}")
            return True
    
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
    
    def get_password(self, entry_id: str, include_deleted: bool = False) -> Optional[Dict]:
        self._check_unlocked() 

        try:
            vault_key = bytes(self.vault_key_secure)
            entry = self.db.get_entry(entry_id, vault_key, include_deleted=include_deleted)
            
            if entry is None:
                return None 
            
            return entry
        except Exception as e:
            raise VaultError(f"Failed to retrieve password entry: {e}") from e

    def search_entries(
            self, 
            query: str, 
            include_deleted: bool = False,
            limit: int = 50, 
            offset: int = 0
    ) -> List[Dict]:
        """
        Search entries by title/URL/tags.
        Delegates to DatabaseManager.search_entries.
        """
        self._check_unlocked()

        try:
            if limit < 1:
                limit = 1
            if limit > 1000:
                raise VaultError("Limit exceeds maximum allowed (1000)")
            if offset < 0:
                offset = 0
            return self.db.search_entries(query, include_deleted, limit, offset)
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
        category: str = None,
        favorite: bool = None,
        last_timestamp : str = None,
        last_id: str = None
    ) -> List[Dict]:
        """
        List all entries (metadata only) with pagination support.
        Delegates to DatabaseManager.list_entries.
        """
        self._check_unlocked()
        try:
            return self.db.list_entries(
                include_deleted=include_deleted,
                category=category,
                favorite=favorite,
                limit=limit,
                last_timestamp=last_timestamp,
                last_id=last_id
            )
        except Exception as e:
            raise VaultError(f"Failed to list entries: {e}")

    def update_entry(self, entry_id: str, **kwargs) -> Tuple[bool, int]:
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

        # Access the raw key from secure memory (we maintain a bytearray while unlocked)
        if not self.master_key_secure or not self.vault_key_secure:
            raise VaultError("Vault keys not available in secure memory.")

        # Make a short-lived copy (bytearray) for HKDF operations, then zero it deterministically.
        master_material = bytearray(self.master_key_secure)
        backup_salt = b"sentra-backup-salt-v1"
        try:
            mk_bytes = bytes(master_material)     # immutable input to HKDF
            enc_key = derive_hkdf_key(master_key=mk_bytes, salt=backup_salt, info=b"sentra-backup-enc-v1")
            hmac_key = derive_hkdf_key(master_key=mk_bytes, salt=backup_salt, info=b"sentra-backup-mac-v1")
        finally:
            # Zero the temporary mutable buffer (mk_bytes is immutable; we zero master_material)
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
    
    def get_old_entries(self, days_threshold: int = 90):
        self._check_unlocked()
        return self.db.get_old_entries(days_threshold)

    def hard_delete_entry(self, entry_id: str) -> bool:
        """
        Permanently delete an entry.
        """
        self._check_unlocked()
        try:
            return self.db.hard_delete_entry(entry_id)
        except Exception as e:
            raise VaultError(f"Failed to hard delete entry: {e}")

    def import_csv(self, file_path: str) -> Tuple[int, int]:
        """
        Import entries from a CSV file.
        Returns: (success_count, failure_count)
        """
        self._check_unlocked()
        import csv

        success_count = 0
        fail_count = 0

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                # Use DictReader to automatically handle headers
                reader = csv.DictReader(f)

                # Normalize headers (strip whitespace)
                if reader.fieldnames:
                    reader.fieldnames = [name.strip() for name in reader.fieldnames]

                for row in reader:
                    try:
                        # Robust column fetching (Case-insensitive fallback)
                        def get_val(keys):
                            for k in keys:
                                if k in row and row[k]:
                                    return row[k]
                            return None

                        title = get_val(['Title', 'title', 'name', 'Name'])
                        if not title:
                            # Skip rows without a title
                            fail_count += 1
                            continue

                        self.add_password(
                            title=title,
                            url=get_val(['URL', 'url', 'Website', 'website']),
                            username=get_val(['Username', 'username', 'User', 'user']),
                            password=get_val(['Password', 'password', 'Pass', 'pass']),
                            notes=get_val(['Notes', 'notes', 'Note', 'note']),
                            tags=get_val(['Tags', 'tags']),
                            category=get_val(['Category', 'category', 'Group']) or "General"
                        )
                        success_count += 1
                    except Exception:
                        fail_count += 1

            return success_count, fail_count

        except Exception as e:
            raise VaultError(f"Failed to read CSV file: {e}")