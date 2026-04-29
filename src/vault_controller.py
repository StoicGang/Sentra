""" 
SENTRA vault Controller
Managers vault unlock/lock lifecycle and entry operations with hierarchical key management
"""

import os

from typing import Optional, List, Dict, Tuple, Any
from datetime import datetime, timezone
import warnings
import json
from src.adaptive_lockout import AdaptiveLockout
from src.backup_manager import BackupManager
from src.recovery_manager import (
    RecoveryManager, RecoveryError, RecoveryNotEnabledError, RecoveryCredentialError
)
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

class AccountLockedError(VaultError):
    """
    Raised when the account is locked due to too many failed login attempts.
    Distinct from VaultLockedError (vault not explicitly unlocked in session)
    so the CLI can display a lockout countdown instead of a generic lock message.
    """
    def __init__(self, message: str, delay_seconds: int = 0, hard_locked: bool = False,
                 next_allowed_at: str = None):
        super().__init__(message)
        self.delay_seconds = delay_seconds
        self.hard_locked = hard_locked
        self.next_allowed_at = next_allowed_at

class CriticalVaultError(VaultError):
    """Raised for unrecoverable secure-memory or crypto failures."""
    pass


class VaultAlreadyUnlockedError(ValueError):
    """Raised when trying to unlock already unlocked vault"""
    pass

class VaultDestroyedError(VaultError):
    """Raised when the vault database has been physically deleted (self-destructed)."""
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

    def close(self):
        """Release database file handles and clear secure memory."""
        self.db.close()
        self.secure_mem.cleanup_all()
        self.is_unlocked = False
    
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
            if not self._schema_initialized:
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

    @staticmethod
    def get_vault_info(db_path: str) -> Dict[str, Any]:
        """
        Retrieve non-sensitive metadata and statistics for a vault file.
        Does NOT require the master password.
        """
        if not os.path.exists(db_path):
            return {"exists": False, "name": os.path.basename(db_path)}
        
        db = DatabaseManager(db_path)
        try:
            meta = db.load_vault_metadata()
            if not meta:
                return {"exists": False, "name": os.path.basename(db_path), "initialized": False}
            
            # Count entries
            conn = db.connect()
            res = conn.execute("SELECT COUNT(*) FROM entries WHERE is_deleted = 0").fetchone()
            item_count = res[0] if res else 0
            
            return {
                "exists": True,
                "name": os.path.basename(db_path),
                "display_name": meta.get("display_name") or os.path.basename(db_path).replace(".db", ""),
                "description": meta.get("description") or "",
                "item_count": item_count,
                "created_at": meta.get("created_at"),
                "last_accessed_at": meta.get("last_unlocked_at"),
                "version": meta.get("version", "2.0")
            }
        except Exception:
            return {"exists": True, "name": os.path.basename(db_path), "corrupt": True}
        finally:
            db.close()

    def delete_vault(self, password: str) -> bool:
        """
        Irreversibly delete this vault after verifying the password.
        """
        # We must be unlocked to verify the password, or we verify it manually
        # If we are already unlocked, we just verify the password again for friction
        metadata = self.db.load_vault_metadata()
        if not metadata:
            raise VaultError("Vault not initialized")
        
        salt = metadata["salt"]
        ok = verify_auth_hash(metadata["auth_hash"], password, salt)
        if not ok:
            self.adaptive_lockout.record_failure()
            raise VaultError("Invalid master password")
        
        # friction passed, annihilate
        self.execute_self_destruct()
        return True

    def change_master_password(self, current_password: str, new_password: str) -> bool:
        """
        Re-encrypt the vault key under a new master password.
        Requires re-authentication for friction.
        """
        with self._state_lock:
            self._check_unlocked()
            
            # 1. Verify current password
            meta = self.db.load_vault_metadata()
            if not meta:
                raise VaultError("Vault metadata not found")

            if not verify_auth_hash(meta["auth_hash"], current_password, meta["salt"]):
                self.adaptive_lockout.record_failure()
                raise VaultError("Invalid current master password")

            # 2. Derive existing master key from current session/password
            # We already have self.master_key_secure, but let's be explicit and re-derive 
            # or just use it. Re-deriving is safer for the "verification" step.
            kdf_loaded = json.loads(meta["kdf_config"])
            old_master_key = derive_master_key(
                password=current_password,
                salt=meta["salt"],
                time_cost=kdf_loaded.get("time_cost", 3),
                memory_cost=kdf_loaded.get("memory_cost", 65536),
                parallelism=kdf_loaded.get("parallelism", 4)
            )

            # 3. Decrypt vault key
            try:
                vault_key_json = decrypt_entry(
                    ciphertext=meta["vault_key_encrypted"],
                    nonce=meta["vault_key_nonce"],
                    auth_tag=meta["vault_key_tag"],
                    key=old_master_key,
                    associated_data=b"vault-key-v1"
                )
            except Exception as e:
                raise CriticalVaultError(f"Failed to decrypt vault key during rotation: {e}")

            # 4. Generate NEW parameters
            new_salt = generate_salt(16)
            new_auth_hash = compute_auth_hash(new_password, new_salt)
            
            # Use current benchmarked params if possible, or keep old ones
            # For simplicity, we keep the old KDF params or use defaults
            new_kdf_params = kdf_loaded 

            new_master_key = derive_master_key(
                password=new_password,
                salt=new_salt,
                time_cost=new_kdf_params.get("time_cost", 3),
                memory_cost=new_kdf_params.get("memory_cost", 65536),
                parallelism=new_kdf_params.get("parallelism", 4)
            )

            # 5. Re-encrypt vault key under new master key
            ciphertext, nonce, tag = encrypt_entry(
                plaintext=vault_key_json,
                key=new_master_key,
                associated_data=b"vault-key-v1"
            )

            # 6. Update database
            conn = self.db.connect()
            try:
                conn.execute("""
                    UPDATE vault_metadata
                    SET salt = ?, auth_hash = ?, 
                        vault_key_encrypted = ?, vault_key_nonce = ?, vault_key_tag = ?,
                        kdf_config = ?, version = '2.3'
                    WHERE id = 1
                """, (
                    new_salt, new_auth_hash,
                    ciphertext, nonce, tag,
                    json.dumps(new_kdf_params)
                ))
                conn.commit()
            except Exception as e:
                conn.rollback()
                raise DatabaseError(f"Failed to update vault metadata during password rotation: {e}")

            # 7. Audit Log
            self.add_audit_log(
                action_type="SECURITY_SENSITIVE_UPDATE",
                severity="Critical",
                details="Master password changed successfully. All other sessions invalidated."
            )

            # 8. Force Lock (requirements: "Invalidate all active sessions, force re-login")
            self.lock_vault()
            return True

    def get_account_info(self) -> Dict[str, Any]:
        """Fetch account-level metadata for Profile settings."""
        meta = self.db.load_vault_metadata()
        if not meta:
            return {}
        
        return {
            "username": meta.get("username", "admin"),
            "account_status": meta.get("account_status", "Active"),
            "created_at": meta.get("created_at"),
            "last_login": meta.get("last_unlocked_at"),
            "display_name": meta.get("display_name"),
            "description": meta.get("description")
        }

    def get_preferences(self) -> Dict[str, Any]:
        """Fetch UI preferences."""
        meta = self.db.load_vault_metadata()
        if not meta:
            return {}
        try:
            return json.loads(meta.get("preferences", "{}"))
        except:
            return {}

    def update_preferences(self, preferences: Dict[str, Any]) -> bool:
        """Update and persist UI preferences."""
        return self.db.update_metadata_field("preferences", json.dumps(preferences))

    def get_session_history(self, limit: int = 10) -> List[Dict]:
        """Fetch historical session events."""
        return self.db.get_session_history(limit)

    def unlock_vault(self, password: str, create_if_missing: bool = False, display_name: str = None, description: str = None) -> bool:
        with self._state_lock:
            if self.is_unlocked:
                raise VaultAlreadyUnlockedError("Vault is already unlocked. Call lock_vault() first.")
            try:
                if not self._schema_initialized:
                    self.db.initialize_database()
                    self._schema_initialized = True
            except Exception as e:
                raise VaultError(f"Database initialization failed: {e}")

            allowed, delay = self.adaptive_lockout.check_and_delay()
            if not allowed:
                status = self.adaptive_lockout.get_status()
                raise AccountLockedError(
                    f"Account locked due to too many failed attempts. "
                    f"Try again in {delay} seconds.",
                    delay_seconds=delay,
                    hard_locked=status.get("hard_locked", False),
                    next_allowed_at=status.get("next_allowed_at"),
                )

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
                    kdf_config=kdf_params,
                    display_name=display_name,
                    description=description
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
                    self.db.add_audit_log(action_type="failed_unlock", details="Invalid master password attempt")

                    # NEW: Auto self-destruct trigger
                    enabled = self.get_config("auto_self_destruct_enabled")
                    threshold = self.get_config("auto_self_destruct_threshold")
                    
                    # Robust check for JSON-parsed booleans or raw strings
                    is_enabled = enabled is True or str(enabled).lower() == "true"
                    
                    if is_enabled and threshold is not None:
                        status = self.adaptive_lockout.get_status()
                        if status["failures"] >= int(threshold):
                            # Atomic annihilation
                            self.execute_self_destruct()

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

                    # NEW: Auto self-destruct trigger (also on crypto failure)
                    threshold = self.get_config("auto_self_destruct_threshold")
                    if threshold is not None:
                        status = self.adaptive_lockout.get_status()
                        if status["failures"] >= int(threshold):
                            self.self_destruct()

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
                self.db.add_audit_log(action_type="UNLOCK", details="Vault unlocked successfully")

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

                # --- Migration: Metadata Encryption (v2.1) ---
                try:
                    self.db.migrate_entries_metadata(bytes(self.vault_key_secure))
                except Exception as e:
                    warnings.warn(f"Metadata migration failed (non-fatal): {e}", RuntimeWarning)

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
            self.db.add_audit_log(action_type="LOCK", details="Vault locked")
            
            if errors:
                raise CriticalVaultError(f"Partial lock state! Security warning: {', '.join(errors)}")
            return True

    def execute_self_destruct(self) -> None:
        """
        Permanently and physically delete the entire vault database and all backups.
        This is IRREVERSIBLE.
        """
        import os
        db_path = self.db.db_path

        # 1. Fetch all backups to delete them too
        backups_to_delete = []
        try:
            # Try to get backup filenames from history
            cursor = self.db.connect().execute("SELECT filename FROM backup_history")
            backups_to_delete = [row['filename'] for row in cursor.fetchall() if row['filename']]
        except Exception:
            pass # DB might be locked or corrupt, proceed with core deletion

        # 2. Add final CRITICAL audit event (to internal log before wipe)
        try:
            self.db.add_audit_log(
                action_type="VAULT_SELF_DESTRUCT_INITIATED",
                severity="Critical",
                details="Manual or automatic self-destruct triggered. Irreversible wipe starting."
            )
        except Exception:
            pass

        # 3. Securely lock vault (clears secure memory)
        self.lock_vault()

        # 4. Close database connection
        try:
            self.db.close()
        except Exception:
            pass

        # 5. Destroy Backups
        for b_file in backups_to_delete:
            if b_file and os.path.exists(b_file):
                try:
                    os.remove(b_file)
                except Exception:
                    pass

        # 6. Physically delete the vault database file
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except Exception as e:
                # If we fail here, the system is in a dangerous partial state
                raise CriticalVaultError(f"Self-destruct failed while deleting database: {e}")

        # 7. Physical termination of session
        raise VaultDestroyedError(
            "CRITICAL: The vault has self-destructed. All data has been annihilated."
        )

    def get_config(self, key: str) -> Optional[Any]:
        """Retrieve a persistent application configuration value."""
        try:
            return self.db.get_metadata(key)
        except Exception:
            return None

    def set_config(self, key: str, value: Any) -> bool:
        """Persist an application configuration value."""
        try:
            return self.db.update_metadata(key, value)
        except Exception:
            return False
    
    def add_password(
        self,
        title: str,
        url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        favorite: bool = False,
        notes: Optional[str] = None,
        tags: Optional[str] = None,
        category: str = "General",
        totp_secret: Optional[str] = None
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
                totp_secret=totp_secret,
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
            
            if entry:
                # Log the view event
                self.add_audit_log(
                    action_type="VIEW_SECRET", 
                    entry_id=entry_id, 
                    details=f"Viewed secret for: {entry.get('title')}"
                )
            
            return entry
        except Exception as e:
            raise VaultError(f"Failed to retrieve password entry: {e}") from e

    def copy_secret(self, entry_id: str) -> str:
        """
        Retrieves a secret and logs a COPY_SECRET audit event.
        """
        self._check_unlocked()
        try:
            vault_key = bytes(self.vault_key_secure)
            entry = self.db.get_entry(entry_id, vault_key)
            if entry:
                # Log the copy event
                self.add_audit_log(
                    action_type="COPY_SECRET", 
                    entry_id=entry_id, 
                    details=f"Copied secret for: {entry.get('title')}"
                )
            return entry.get("password", "")
        except Exception as e:
            raise VaultError(f"Failed to copy secret: {e}")

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
            
            vault_key = bytes(self.vault_key_secure)
            return self.db.search_entries(vault_key, query, include_deleted, limit, offset)
        except Exception as e:
            raise VaultError(f"Failed to search entries: {e}")
    
    def add_audit_log(
        self, 
        action_type: str, 
        entry_id: Optional[str] = None, 
        details: Optional[str] = None,
        severity: str = "Info"
    ) -> None:
        """
        Wrapper to log security events with session context.
        """
        # In a real app, 'actor' and 'ip' would come from the current session/request
        # For now, we use sensible defaults that the UI can then display.
        self.db.add_audit_log(
            action_type=action_type,
            entry_id=entry_id,
            details=details,
            actor="admin",       # Default actor for Web/CLI actions
            source="Web UI",     # Default source
            severity=severity,
            ip_address="127.0.0.1"
        )

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
        only_deleted: bool = False,
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
            vault_key = bytes(self.vault_key_secure)
            rows = self.db.list_entries(
                include_deleted=include_deleted,
                only_deleted=only_deleted,
                category=category,
                favorite=favorite,
                limit=limit,
                last_timestamp=last_timestamp,
                last_id=last_id
            )
            for row in rows:
                if row.get('title_encrypted') and row.get('kdf_salt'):
                    try:
                        entry_key = self.db._derive_entry_key(
                            vault_key, row['id'], row['kdf_salt']
                        )
                        row['title'] = _de(
                            row['title_encrypted'], row['title_nonce'],
                            row['title_tag'], entry_key,
                            associated_data=row['id'].encode('utf-8')
                        )
                    except Exception:
                        pass
            return rows
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

    def create_backup(self, file_path: str) -> bool:
        """
        Create an encrypted backup file.
        Logs to backup_history and audit_log.
        """
        self._check_unlocked()
        import os
        
        try:
            bm = self.create_backup_manager()
            success = bm.create_backup(file_path)
            
            if success:
                file_size = os.path.getsize(file_path)
                self.db.add_backup_history_entry(
                   operation_type="CREATED_BACKUP",
                   filename=os.path.basename(file_path),
                   file_size=file_size,
                   status="Success",
                   details="Encrypted backup file created successfully."
                )
                self.add_audit_log(
                    action_type="CREATE_BACKUP",
                    details=f"Backup created: {os.path.basename(file_path)}",
                    severity="Info"
                )
            return success
        except Exception as e:
            self.db.add_backup_history_entry(
                operation_type="CREATED_BACKUP",
                filename=os.path.basename(file_path),
                status="Failed",
                details=str(e)
            )
            raise VaultError(f"Failed to create backup: {e}")

    def restore_backup(self, file_path: str) -> bool:
        """
        Restore vault from an encrypted backup file.
        Logs to backup_history and audit_log.
        """
        self._check_unlocked()
        import os
        
        try:
            file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
            bm = self.create_backup_manager()
            success = bm.restore_backup(file_path)
            
            if success:
                self.db.add_backup_history_entry(
                   operation_type="IMPORTED_BACKUP",
                   filename=os.path.basename(file_path),
                   file_size=file_size,
                   status="Success",
                   details="Vault restored from encrypted backup successfully."
                )
                self.add_audit_log(
                    action_type="RESTORE_BACKUP",
                    details=f"Vault restored from {os.path.basename(file_path)}",
                    severity="Warning" # Major state change
                )
            return success
        except Exception as e:
            self.db.add_backup_history_entry(
                operation_type="IMPORTED_BACKUP",
                filename=os.path.basename(file_path),
                file_size=file_size,
                status="Failed",
                details=str(e)
            )
            raise VaultError(f"Failed to restore backup: {e}")
    
    def get_old_entries(self, days_threshold: int = 90):
        self._check_unlocked()
        return self.db.get_old_entries(days_threshold)

    def get_security_analysis(self) -> Dict:
        """
        Perform a full security scan of all vault entries.
        Detects weak passwords, reuses, and aging credentials.
        Calculates an overall security score (0-100).
        """
        self._check_unlocked()
        try:
            vault_key = bytes(self.vault_key_secure)
            entries = self.db.get_all_active_entries(vault_key)
            
            analysis = {
                "weak": [],
                "reused": [],
                "aging": [],
                "total_entries": len(entries),
                "total_score": 100,
                "status": "Good"
            }
            
            if not entries:
                return analysis

            password_map = {}
            unique_reused_ids = set()
            
            for entry in entries:
                password = entry.get('password', '')
                strength = entry.get('password_strength', 0)
                age_days = entry.get('password_age_days', 0)
                
                summary = {
                    "id": entry["id"],
                    "title": entry["title"],
                    "url": entry["url"],
                    "username": entry["username"],
                    "modified_at": entry["modified_at"],
                    "password_strength": strength,
                    "age_days": age_days
                }
                
                if strength < 50:
                    analysis['weak'].append(summary)
                    
                if age_days > 90:
                    analysis['aging'].append(summary)
                    
                if password:
                    if password not in password_map:
                        password_map[password] = []
                    password_map[password].append(summary)

            for pwd, matches in password_map.items():
                if len(matches) > 1:
                    analysis['reused'].extend(matches)
                    for m in matches:
                        unique_reused_ids.add(m["id"])

            # --- Score Calculation ---
            # -10 per weak password
            # -15 per reused password (unique entries)
            # -2 per aging credential (capped at 50)
            score = 100
            score -= len(analysis['weak']) * 10
            score -= len(unique_reused_ids) * 15
            
            aging_deduction = min(len(analysis['aging']) * 2, 50)
            score -= aging_deduction
            
            analysis["total_score"] = max(0, score)
            
            # Status mapping
            if analysis["total_score"] >= 80:
                analysis["status"] = "Good"
            elif analysis["total_score"] >= 60:
                analysis["status"] = "Warning"
            else:
                analysis["status"] = "Critical"
            
            return analysis
        except Exception as e:
            raise VaultError(f"Security analysis failed: {e}")

    def hard_delete_entry(self, entry_id: str) -> bool:
        """
        Permanently delete an entry.
        """
        self._check_unlocked()
        try:
            return self.db.hard_delete_entry(entry_id)
        except Exception as e:
            raise VaultError(f"Failed to hard delete entry: {e}")

    def empty_trash(self) -> int:
        """
        Permanently remove all entries from trash.
        """
        self._check_unlocked()
        try:
            count = self.db.empty_trash()
            if count > 0:
                self.db.add_audit_log(
                    action_type="EMPTY_TRASH",
                    details=f"Permanently purged {count} deleted entries."
                )
            return count
        except Exception as e:
            raise VaultError(f"Failed to empty trash: {e}")

    def import_csv(self, file_path: str) -> Tuple[int, int]:
        """
        Import entries from a CSV file.
        Returns: (success_count, failure_count)
        """
        self._check_unlocked()
        import csv
        import os

        success_count = 0
        fail_count = 0
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                reader = csv.DictReader(f)
                if reader.fieldnames:
                    reader.fieldnames = [name.strip() for name in reader.fieldnames]

                for row in reader:
                    try:
                        def get_val(keys):
                            for k in keys:
                                if k in row and row[k]:
                                    return row[k]
                            return None

                        title = get_val(['Title', 'title', 'name', 'Name'])
                        if not title:
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

            # Log to History and Audit
            status = "Success" if fail_count == 0 else "Partial Success"
            details = f"Imported {success_count} entries. {fail_count} failed."
            
            self.db.add_backup_history_entry(
                operation_type="IMPORTED_CSV",
                filename=os.path.basename(file_path),
                file_size=file_size,
                status=status,
                details=details
            )
            
            self.add_audit_log(
                action_type="IMPORT_CSV",
                details=details,
                severity="Info"
            )

            return success_count, fail_count

        except Exception as e:
            self.db.add_backup_history_entry(
                operation_type="IMPORTED_CSV",
                filename=os.path.basename(file_path),
                file_size=file_size,
                status="Failed",
                details=str(e)
            )
            raise VaultError(f"Failed to read CSV file: {e}")

    def export_csv(self, file_path: str) -> int:
        """
        Export vault contents to a plaintext CSV file.
        DANGEROUS: Data is unencrypted.
        """
        self._check_unlocked()
        import csv
        import os

        def sanitize_csv_field(text: str) -> str:
            if not text: return ""
            forbidden_prefixes = ('=', '+', '-', '@', '|', '%')
            stripped = text.lstrip()
            # 1. Neutralize Formulas (Improves on older implementation)
            if stripped.startswith(forbidden_prefixes):
                return "'" + text
            # 2. Neutralize Control Characters
            safe_text = text.replace('\t', '    ').replace('\r', ' ').replace('\n', ' ')
            return safe_text

        try:
            entries = self.db.list_entries(include_deleted=False)
            vault_key = bytes(self.vault_key_secure)
            
            export_count = 0
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'title', 'url', 'username', 'password', 'notes', 'category', 'tags'
                ])
                writer.writeheader()

                for entry_meta in entries:
                    # Get complete entry with decrypted password/notes
                    entry = self.db.get_entry(entry_meta['id'], vault_key)
                    if entry:
                        writer.writerow({
                            'title': sanitize_csv_field(entry.get('title', '')),
                            'url': sanitize_csv_field(entry.get('url', '')),
                            'username': sanitize_csv_field(entry.get('username', '')),
                            'password': sanitize_csv_field(entry.get('password', '')),
                            'notes': sanitize_csv_field(entry.get('notes', '')),
                            'category': sanitize_csv_field(entry.get('category', '')),
                            'tags': sanitize_csv_field(entry.get('tags', ''))
                        })
                        export_count += 1

            file_size = os.path.getsize(file_path)
            
            self.db.add_backup_history_entry(
                operation_type="EXPORTED_CSV",
                filename=os.path.basename(file_path),
                file_size=file_size,
                status="Success",
                details=f"Exported {export_count} entries to plaintext CSV."
            )
            
            self.add_audit_log(
                action_type="EXPORT_CSV",
                details=f"Plaintext export created for {export_count} entries.",
                severity="Warning" # Plaintext export is a security risk
            )
            
            return export_count

        except Exception as e:
            self.db.add_backup_history_entry(
                operation_type="EXPORTED_CSV",
                filename=os.path.basename(file_path),
                status="Failed",
                details=str(e)
            )
            raise VaultError(f"Failed to export CSV: {e}")

    # ================================================================
    # Account Recovery
    # ================================================================

    @property
    def recovery_manager(self) -> RecoveryManager:
        """Lazily instantiated RecoveryManager (uses same DatabaseManager)."""
        if not hasattr(self, "_recovery_manager"):
            self._recovery_manager = RecoveryManager(self.db)
        return self._recovery_manager

    def setup_recovery_passphrase(self, passphrase: str) -> None:
        """
        Encrypt the vault key under an Argon2id-derived passphrase key and
        store it in vault_recovery.  Requires vault to be unlocked.

        Args:
            passphrase: The user's chosen recovery passphrase (non-empty).

        Raises:
            VaultLockedError: Vault is not unlocked.
            ValueError:       Empty passphrase.
            RecoveryError / DatabaseError: On crypto or DB failure.
        """
        self._check_unlocked()
        with self._state_lock:
            vault_key = bytes(self.vault_key_secure)
        if len(vault_key) != 32:
            raise VaultError("Secure vault key is invalid size")
        self.recovery_manager.setup_passphrase(vault_key, passphrase)
        
        self.add_audit_log(
            action_type="RECOVERY_PASSPHRASE_UPDATE",
            details="Recovery passphrase was set or updated.",
            severity="Info"
        )

    def setup_recovery_codes(self, count: int = 8) -> list:
        """
        Generate one-time recovery codes and store them encrypted.
        Requires vault to be unlocked.

        Args:
            count: Number of codes to generate (1-16).

        Returns:
            List of plaintext codes.
        """
        self._check_unlocked()
        with self._state_lock:
            vault_key = bytes(self.vault_key_secure)
        if len(vault_key) != 32:
            raise VaultError("Secure vault key is invalid size")

        codes = self.recovery_manager.setup_codes(vault_key, count)
        
        self.add_audit_log(
            action_type="RECOVERY_CODES_GENERATE",
            details=f"Generated {len(codes)} new recovery codes.",
            severity="Warning" # Higher friction as old codes are invalidated
        )
        return codes

    def recover_vault(self, credential: str, credential_type: str,
                      new_password: str) -> bool:
        """
        Recover access to the vault without the master password.

        Steps:
          1. Verify credential (passphrase or code) and decrypt vault_key.
          2. Derive a new master key from new_password + fresh salt.
          3. Re-encrypt vault_key under the new master key.
          4. Update vault_metadata (salt, auth_hash, encrypted vault key).
          5. Unlock the vault in the current session.

        Args:
            credential:      The recovery passphrase or a one-time code.
            credential_type: 'passphrase' or 'code'.
            new_password:    New master password to set.

        Returns:
            True on success.

        Raises:
            VaultError:              On bad new_password or metadata problems.
            RecoveryNotEnabledError: No matching recovery is configured.
            RecoveryCredentialError: Wrong or used credential.
        """
        if self.is_unlocked:
            raise VaultError("Vault is already unlocked. Lock it before recovering.")
        if not new_password or len(new_password) < 1:
            raise VaultError("New password must be a non-empty string.")

        # Step 1: Recover vault_key using the supplied credential
        if credential_type == "passphrase":
            vault_key = self.recovery_manager.recover_with_passphrase(credential)
        elif credential_type == "code":
            vault_key = self.recovery_manager.recover_with_code(credential)
        else:
            raise VaultError(f"Unknown credential_type: {credential_type!r}.")

        # Step 2–3: Derive new master key and re-encrypt vault_key
        kdf_params = {
            "algorithm": "argon2id",
            "time_cost": 3,
            "memory_cost": 64 * 1024,
            "parallelism": 1,
            "salt_len": 16,
            "hash_len": 32,
        }
        new_salt = generate_salt(kdf_params["salt_len"])
        new_master_key = derive_master_key(
            password=new_password,
            salt=new_salt,
            time_cost=kdf_params["time_cost"],
            memory_cost=kdf_params["memory_cost"],
            parallelism=kdf_params["parallelism"],
            hash_len=kdf_params["hash_len"],
        )
        vault_key_json = json.dumps({"vault_key": vault_key.hex()})
        new_auth_hash = compute_auth_hash(new_password, new_salt)
        ciphertext, nonce, tag = encrypt_entry(
            plaintext=vault_key_json,
            key=new_master_key,
            associated_data=b"vault-key-v1",
        )

        # Step 4: Persist to DB (replaces the old master-password-encrypted vault key)
        try:
            conn = self.db.connect()
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute(
                """
                UPDATE vault_metadata SET
                    salt = ?, auth_hash = ?,
                    vault_key_encrypted = ?, vault_key_nonce = ?, vault_key_tag = ?,
                    kdf_config = ?
                WHERE id = 1
                """,
                (
                    new_salt, new_auth_hash,
                    ciphertext, nonce, tag,
                    json.dumps(kdf_params),
                ),
            )
            conn.commit()
        except Exception as e:
            try:
                conn.rollback()
            except Exception:
                pass
            raise VaultError(f"Failed to update vault metadata during recovery: {e}") from e

        # Step 5: Unlock the session immediately with the recovered vault_key
        # Re-use the secure-memory path by simulating a normal unlock flow
        try:
            master_buf = bytearray(new_master_key)
            vault_buf  = bytearray(vault_key)
            del new_master_key, vault_key

            self.master_key_handle = self.secure_mem.lock_memory(master_buf)
            self.vault_key_handle  = self.secure_mem.lock_memory(vault_buf)

            self.master_key_secure = master_buf
            self.vault_key_secure  = vault_buf
            self.is_unlocked = True
            self.unlock_timestamp = datetime.now(timezone.utc).isoformat()

            try:
                self.db.update_unlock_timestamp()
            except Exception:
                pass

            return True

        except Exception as e:
            raise VaultError(f"Recovery succeeded but session unlock failed: {e}") from e

    def disable_recovery(self) -> None:
        """
        Remove all recovery credentials. Requires vault to be unlocked.
        """
        self._check_unlocked()
        self.recovery_manager.disable_recovery()
        self.add_audit_log(
            action_type="RECOVERY_DISABLE",
            details="Account recovery options were disabled.",
            severity="Warning"
        )

    def reset_recovery(self) -> None:
        """
        Permanently clear all recovery configurations. 
        Requires vault to be unlocked.
        """
        self._check_unlocked()
        self.recovery_manager.disable_recovery() # Re-use deletion logic
        self.add_audit_log(
            action_type="RECOVERY_RESET",
            details="Recovery system was reset to factory defaults.",
            severity="Warning"
        )

    def verify_password(self, password: str) -> bool:
        """
        Verify the provided password matches the master password of correctly unlocked vault.
        Used for re-authentication before sensitive operations.
        """
        self._check_unlocked()
        try:
            conn = self.db.connect()
            row = conn.execute("SELECT salt, auth_hash FROM vault_metadata WHERE id = 1").fetchone()
            if not row:
                return False
            
            return verify_auth_hash(row['auth_hash'], password, row['salt'])
        except Exception:
            return False

    def get_recovery_status(self) -> dict:
        """
        Return the current recovery configuration status.
        Does NOT require the vault to be unlocked.

        Returns:
            {enabled, type, codes_total, codes_remaining}
        """
        return self.recovery_manager.get_status()

    # ======== Multi-Vault Registry (New) ========

    def get_registered_vaults(self) -> List[Dict]:
        """
        Get list of all registered vaults from the system controller.
        Requires vault to be unlocked.
        """
        self._check_unlocked()
        try:
            conn = self.db.connect()
            cursor = conn.execute("SELECT nickname, path, created_at, last_accessed_at FROM vault_registry ORDER BY nickname")
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            raise VaultError(f"Failed to retrieve vault registry: {e}")

    def register_vault(self, nickname: str, path: str) -> bool:
        """
        Register a new or existing vault in the system registry.
        Requires vault to be unlocked.
        """
        import os
        self._check_unlocked()
        try:
            conn = self.db.connect()
            conn.execute(
                "INSERT OR REPLACE INTO vault_registry (nickname, path) VALUES (?, ?)",
                (nickname, os.path.abspath(path))
            )
            conn.commit()
            return True
        except Exception as e:
            raise VaultError(f"Failed to register vault: {e}")

    def unregister_vault(self, nickname: str) -> bool:
        """
        Remove a vault from the system registry.
        Requires vault to be unlocked.
        """
        self._check_unlocked()
        try:
            conn = self.db.connect()
            conn.execute("DELETE FROM vault_registry WHERE nickname = ?", (nickname,))
            conn.commit()
            return True
        except Exception as e:
            raise VaultError(f"Failed to unregister vault: {nickname}: {e}")