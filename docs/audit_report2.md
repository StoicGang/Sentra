# Comprehensive File-by-File Analysis of Password Manager Project

---

## 1. schema.sql (Database Schema)

### Overview
Defines the SQLite database structure with 6 tables supporting encrypted storage, audit logging, and security features.

### Tables and Their Purpose

#### Table 1: vault_metadata
**Purpose**: Singleton configuration table storing vault-level encryption parameters
- **Inputs**: Initial vault setup data
- **Outputs**: Cryptographic parameters for vault operations
- **Fields**:
  - `salt`: 16-byte Argon2id salt for key derivation
  - `auth_hash`: 32-byte password verification hash
  - `vault_key_encrypted/nonce/tag`: Encrypted vault key under master key
  - `kdf_config`: JSON string of KDF parameters
  - Metadata: created_at, last_unlocked_at, unlock_count, version

**Issues**:
1. **Missing constraint validation**: The `kdf_config` JSON validation only checks if it's valid JSON, not if it contains required fields (time_cost, memory_cost, etc.)
   - **Why wrong**: Corrupt or incomplete KDF configs could be saved
   - **Fix**: Add CHECK constraint validating JSON structure: `CHECK (json_extract(kdf_config, '$.time_cost') IS NOT NULL AND ...)`

2. **No backup/recovery metadata**: Schema lacks vault backup history tracking
   - **Why wrong**: Users can't see when last backup was created or verify backup integrity
   - **Fix**: Add columns `last_backup_at TEXT, backup_count INTEGER DEFAULT 0`

#### Table 2: entries
**Purpose**: Core password entry storage with per-entry encryption
- **Inputs**: User password data, metadata
- **Outputs**: Encrypted entries for retrieval
- **Fields**:
  - Identity: id (UUID), title, url, username
  - Encrypted data: password_encrypted/nonce/tag, notes_encrypted/nonce/tag
  - Security: kdf_salt (per-entry), password_strength
  - Organization: tags, category, favorite
  - Timestamps: created_at, modified_at, last_accessed_at
  - Soft delete: is_deleted, deleted_at

**Issues**:
1. **Missing `last_accessed_at` update trigger**: Column exists but never gets updated
   - **Why wrong**: Cannot track when entries were last viewed (useful for security audits)
   - **Fix**: Add trigger:
   ```sql
   CREATE TRIGGER update_last_accessed AFTER UPDATE ON entries
   WHEN old.last_accessed_at = new.last_accessed_at
   BEGIN UPDATE entries SET last_accessed_at = datetime('now') WHERE id = new.id; END;
   ```

2. **No password_age_days automatic calculation**: Column referenced in code but not in schema
   - **Why wrong**: Code calculates age dynamically, but schema has no persistent field
   - **Fix**: Either add computed column or remove from code references (current dynamic calculation is actually better)

3. **Missing breach detection fields**: No way to track if passwords appear in known breach databases
   - **Why wrong**: Users can't be warned about compromised passwords
   - **Fix**: Add `breach_detected INTEGER DEFAULT 0, breach_checked_at TEXT`

#### Table 3: failed_attempts_log
**Purpose**: Historical brute-force protection logging
- **Inputs**: Failed authentication attempts
- **Outputs**: Long-term security audit trail
- **Fields**: id, attempt_timestamp, session_id, reason, ip_address

**Issues**:
1. **Redundant with lockout_attempts table**: Two tables serve overlapping purposes
   - **Why wrong**: `lockout_attempts` handles short-term throttling, `failed_attempts_log` is historical—but naming is confusing
   - **Fix**: Rename to `security_events_log` and expand to include all security events (lockouts, password changes, exports)

2. **Auto-pruning at 30 days is hardcoded**: Some organizations require 90-day retention
   - **Why wrong**: Compliance requirements vary
   - **Fix**: Make retention configurable via metadata table

#### Table 4: metadata
**Purpose**: Key-value store for application configuration
- **Inputs**: Configuration keys and JSON values
- **Outputs**: Runtime configuration data

**Issues**:
1. **No schema versioning**: Can't track metadata structure changes across app versions
   - **Why wrong**: Upgrades might break if metadata format changes
   - **Fix**: Add `schema_version INTEGER` to vault_metadata table

#### Table 5: audit_log
**Purpose**: Forensic tracking of entry lifecycle events
- **Inputs**: Entry modifications
- **Outputs**: Immutable audit trail
- **Fields**: id, entry_id, action_type, timestamp

**Issues**:
1. **Missing user context**: No user_id or session_id tracking
   - **Why wrong**: In future multi-user scenarios, can't tell who did what
   - **Fix**: Add `session_id TEXT` column for future extensibility

2. **No old/new value tracking**: Can't see what changed in UPDATE events
   - **Why wrong**: Forensic investigations require knowing what was modified
   - **Fix**: Add `old_values TEXT, new_values TEXT` columns storing JSON snapshots

#### Table 6: lockout_attempts
**Purpose**: Sliding window tracking for adaptive lockout
- **Inputs**: Failed unlock attempts
- **Outputs**: Timestamps for exponential backoff calculation

**Issues**:
1. **Column name inconsistency**: Code uses `timestamp` but schema has `attempt_ts`
   - **Why wrong**: Runtime error when accessing non-existent column
   - **Fix**: Standardize on `timestamp` to match code usage

### Index Analysis

**Existing Indexes**: Good coverage on frequently queried columns
- `idx_entries_title`, `idx_entries_tags`, `idx_entries_modified`, `idx_entries_deleted`

**Missing Indexes**:
1. **No composite index on (is_deleted, category)**: List operations filter by both
   - **Why wrong**: Sequential scan on large datasets
   - **Fix**: `CREATE INDEX idx_entries_active_category ON entries(is_deleted, category)`

2. **No index on entries.favorite**: Favorites view will be slow
   - **Fix**: `CREATE INDEX idx_entries_favorite ON entries(favorite) WHERE favorite = 1`

### FTS (Full-Text Search) Configuration

**Current Setup**: FTS5 virtual table synced via triggers

**Issues**:
1. **FTS doesn't include notes**: Users can't search note content
   - **Why wrong**: Common use case (searching for "API key", "license", etc.)
   - **Fix**: Add `notes` to FTS5 column list (requires decryption during index—security tradeoff)

2. **Trigger complexity risk**: Three triggers (INSERT, UPDATE, DELETE) must stay synchronized
   - **Why wrong**: If any trigger fails, FTS becomes inconsistent
   - **Fix**: Add `PRAGMA foreign_keys = ON` enforcement and test trigger failure scenarios

### Trigger Analysis

#### entries_ai (After Insert)
- **Purpose**: Populate FTS and audit log on new entries
- **Issue**: No error handling if FTS insert fails
- **Fix**: Wrap in transaction with rollback on FTS failure

#### entries_au (After Update)
- **Purpose**: Sync FTS on content changes and soft deletes
- **Issue**: Complex CASE logic is error-prone
  - **Why wrong**: FTS delete/reinsert happens even when only password changes (FTS irrelevant)
  - **Fix**: Add condition `WHERE old.title != new.title OR old.url != new.url ...`

#### entries_ad (After Delete)
- **Purpose**: Remove from FTS and log hard delete
- **Issue**: Hard deletes are never used in current codebase
  - **Why wrong**: Unreachable code path (soft delete only)
  - **Fix**: Document that hard delete is for admin/purge operations only

### Missing Schema Elements

1. **No settings table**: User preferences (theme, clipboard timeout, etc.) have no storage
2. **No session table**: Can't track multiple unlocked sessions (future mobile sync)
3. **No attachment/file storage**: Many password managers support secure file attachments
4. **No password history table**: Can't track previous passwords for reuse detection
5. **No shared entries table**: No multi-user or family sharing support

---

## 2. crypto_engine.py (Cryptographic Primitives)

### Overview
Provides core cryptographic operations: random generation, key derivation, encryption/decryption, and HMAC.

### Functions and Their Specifications

#### `generate_salt(length: int = 16) -> bytes`
- **Inputs**: Desired salt length in bytes (default 16)
- **Outputs**: Random bytes from OS entropy pool
- **Purpose**: Generate unique salts for Argon2id
- **Issues**: None—implementation is secure

#### `generate_nonce(length: int = 12) -> bytes`
- **Inputs**: Desired nonce length (default 12 for ChaCha20)
- **Outputs**: Random 12-byte nonce
- **Purpose**: Generate unique nonces for AEAD encryption
- **Issues**: 
  1. **No collision detection**: With billions of encryptions, birthday paradox risk exists
     - **Why wrong**: 96-bit nonce has 2^48 collision probability
     - **Fix**: Add counter-based nonce generation with overflow protection

#### `generate_key(length: int = 32) -> bytes`
- **Inputs**: Key length (default 32 bytes)
- **Outputs**: Cryptographically secure random key
- **Purpose**: Generate vault keys, recovery keys
- **Issues**: None—uses `secrets` module correctly

#### `derive_master_key(password, salt, time_cost=3, memory_cost=65536, parallelism=4, hash_len=32) -> bytes`
- **Inputs**:
  - Password string
  - 16-byte salt
  - Argon2id parameters (time, memory, parallelism)
  - Output length
- **Outputs**: 32-byte master key
- **Purpose**: Derive encryption key from password using memory-hard KDF
- **Issues**:
  1. **Memory cost bounds checking is crude**: MIN_MEMORY_KB (8MB) too low for modern security
     - **Why wrong**: 8MB Argon2 is breakable with GPUs
     - **Fix**: Increase MIN_MEMORY_KB to 32768 (32MB) minimum
  
  2. **No runtime benchmarking validation**: Parameters accepted without checking if device can handle them
     - **Why wrong**: High memory_cost on low-memory device causes crashes
     - **Fix**: Add optional validation mode that tests parameters before saving

  3. **Parallelism not validated against CPU cores**: Can set parallelism=64 on 4-core CPU
     - **Why wrong**: Degrades performance without security benefit
     - **Fix**: `if parallelism > os.cpu_count(): warnings.warn(...)`

#### `compute_auth_hash(password, salt, iterations=600000) -> bytes`
- **Inputs**: Password, salt, PBKDF2 iterations
- **Outputs**: 32-byte authentication hash
- **Purpose**: Fast password verification (separate from master key derivation)
- **Issues**:
  1. **Context binding is weak**: Only uses fixed `b"sentra-auth-hash-v1"` prefix
     - **Why wrong**: If prefix leaks or is predictable, weakens hash
     - **Fix**: Include vault_id or device_id in context: `context = b"sentra-auth-v1-" + vault_id.encode()`
  
  2. **No iteration count validation**: Accepts any iteration value
     - **Why wrong**: Could save iterations=1 and make brute-force trivial
     - **Fix**: Add minimum check: `if iterations < 100000: raise ValueError`

#### `benchmark_argon2_params(target_time=2.0, min_memory_kb=32768, max_memory_kb=262144, parallelism=4) -> dict`
- **Inputs**: Target unlock time, memory bounds, thread count
- **Outputs**: Dictionary with optimal parameters
- **Purpose**: Device-specific parameter tuning
- **Issues**:
  1. **Binary search logic can fail on heterogeneous systems**: Assumes linear memory/time relationship
     - **Why wrong**: CPU throttling or memory bandwidth limits cause erratic results
     - **Fix**: Run multiple iterations and take median result
  
  2. **No persistence of benchmark results**: Re-benchmarks every time
     - **Why wrong**: Wastes 30+ seconds on every vault creation
     - **Fix**: Save results to metadata table with device fingerprint
  
  3. **Doesn't account for battery state (mobile)**: High memory usage drains battery
     - **Why wrong**: Mobile devices need lower parameters when on battery
     - **Fix**: Add battery detection and reduce memory_cost by 50% when unplugged

#### `encrypt_entry(plaintext, key, associated_data=None) -> Tuple[bytes, bytes, bytes]`
- **Inputs**: JSON string, 32-byte key, optional AAD
- **Outputs**: (ciphertext, nonce, auth_tag)
- **Purpose**: Authenticated encryption with ChaCha20-Poly1305
- **Issues**:
  1. **No input validation**: Accepts empty plaintext or key
     - **Why wrong**: Encrypting empty string wastes space; wrong key length crashes
     - **Fix**: Add `if not plaintext: raise ValueError` and `if len(key) != 32: raise ValueError`
  
  2. **Associated data not enforced**: AAD should be mandatory for entry encryption
     - **Why wrong**: Without AAD, attacker could swap ciphertexts between entries
     - **Fix**: Make AAD required: `if associated_data is None: raise ValueError("AAD required")`

#### `decrypt_entry(ciphertext, nonce, auth_tag, key, associated_data=None) -> str`
- **Inputs**: Encrypted bytes, nonce, tag, key, optional AAD
- **Outputs**: Decrypted UTF-8 string
- **Purpose**: Authenticated decryption
- **Issues**:
  1. **Generic error messages leak info**: Raises `InvalidTag` with description
     - **Why wrong**: Attacker learns if failure was due to wrong key vs. corrupted data
     - **Fix**: Catch all exceptions and raise generic `DecryptionError("Decryption failed")`
  
  2. **No timing attack protection**: Different error paths have different execution times
     - **Why wrong**: Timing side-channel could distinguish wrong key from wrong tag
     - **Fix**: Use constant-time comparison for all validation checks

#### `compute_hmac(data, key, algorithm='sha256') -> bytes`
- **Inputs**: Data bytes, HMAC key, hash algorithm
- **Outputs**: 32-byte HMAC digest
- **Purpose**: Integrity verification for backups
- **Issues**:
  1. **Bytearray conversion is redundant**: Already handles bytes correctly
     - **Why wrong**: Extra conversion adds complexity
     - **Fix**: Remove bytearray checks—bytes works fine
  
  2. **Algorithm parameter ignored**: Hardcoded to SHA256 regardless of input
     - **Why wrong**: Misleading API (parameter does nothing)
     - **Fix**: Remove algorithm parameter or implement: `digestmod=getattr(hashlib, algorithm)`

#### `verify_auth_hash(stored_hash, password, salt) -> bool`
- **Inputs**: Stored hash bytes, password string, salt bytes
- **Outputs**: Boolean (password valid?)
- **Purpose**: Constant-time password verification
- **Issues**: None—uses `hmac.compare_digest` correctly

#### `derive_hkdf_key(master_key, info, salt, length=32) -> bytes`
- **Inputs**: Source key, context info, salt, output length
- **Outputs**: Derived subkey
- **Purpose**: Split master key into independent subkeys
- **Issues**:
  1. **Salt validation too strict**: Requires non-empty salt but HKDF allows None
     - **Why wrong**: Prevents legitimate use cases where salt isn't needed
     - **Fix**: Allow `salt=None` and let HKDF use zero-byte default
  
  2. **No key length validation**: Could derive 0-byte or 1000-byte keys
     - **Why wrong**: Invalid lengths for cryptographic operations
     - **Fix**: `if not (16 <= length <= 64): raise ValueError`

### Missing Functions

1. **No `rotate_master_key()` function**: Can't change master password without full vault export/import
2. **No `derive_backup_key()` convenience function**: Backup key derivation logic scattered in vault_controller
3. **No `secure_compare()` wrapper**: Every comparison uses `hmac.compare_digest` directly (verbose)
4. **No `zeroize_key()` function**: Key zeroing logic scattered across codebase
5. **No key stretching for weak passwords**: Should add extra rounds when password entropy is low

### Security Concerns

1. **No HSM/TPM support**: Keys stored only in process memory (no hardware protection)
2. **No key derivation caching**: Repeated derivations recalculate full Argon2 (slow for multiple operations)
3. **No pepper support**: All security relies on salt—no server-side secret
4. **No post-quantum algorithms**: ChaCha20 and Argon2 are quantum-vulnerable

---

## 3. secure_memory.py (Memory Protection)

### Overview
Prevents sensitive keys from being swapped to disk and ensures secure erasure using OS-specific APIs.

### Classes and Methods

#### `SecureMemoryHandle`
- **Purpose**: Opaque reference to locked memory region
- **Fields**:
  - `addr`: Memory address (integer)
  - `length`: Region size in bytes
  - `keeper`: ctypes buffer object (keeps memory alive)
  - `locked`: Boolean indicating if OS lock succeeded
- **Issues**:
  1. **No validation that keeper matches addr/length**: Could desynchronize
     - **Why wrong**: Unlocking wrong address causes corruption
     - **Fix**: Add validation in constructor: `assert ctypes.addressof(keeper) == addr`

#### `SecureMemory.__init__()`
- **Inputs**: None
- **Outputs**: Initialized SecureMemory instance
- **Purpose**: Detect OS, load system libraries, register cleanup
- **Issues**:
  1. **Silent fallback on library load failure**: Only warns but continues
     - **Why wrong**: User doesn't know memory protection is disabled
     - **Fix**: Add `strict=True` parameter that raises exception on failure
  
  2. **atexit registration happens in __init__**: Can register multiple times if instantiated multiple times
     - **Why wrong**: cleanup_all() runs multiple times on exit
     - **Fix**: Use singleton pattern or check if already registered

#### `_initialize_platform()`
- **Inputs**: None (uses class state)
- **Outputs**: Sets self.libc or self.kernel32
- **Purpose**: Load mlock/VirtualLock APIs
- **Issues**:
  1. **macOS madvise not configured**: Code loads libc.dylib but doesn't set up madvise
     - **Why wrong**: protect_from_fork() fails silently on macOS
     - **Fix**: Add madvise setup for macOS like Linux has
  
  2. **No FreeBSD/OpenBSD support**: Only Linux/macOS/Windows
     - **Why wrong**: Users on BSD systems get no protection
     - **Fix**: Add BSD libc loading (similar to Linux)

#### `lock_memory(data: bytes) -> SecureMemoryHandle`
- **Inputs**: Bytes/bytearray/memoryview to lock
- **Outputs**: Handle object or None on failure
- **Purpose**: Prevent memory region from being swapped to disk
- **Issues**:
  1. **Always creates ctypes copy for bytes**: Doubles memory usage for immutable data
     - **Why wrong**: 32-byte key becomes 64 bytes in memory
     - **Fix**: Document that bytes objects are always copied (by design for safety)
  
  2. **Returns None on failure**: Caller can't distinguish "unsupported" from "insufficient privileges"
     - **Why wrong**: Error handling is ambiguous
     - **Fix**: Raise `MemoryLockError` with specific reason
  
  3. **No alignment check**: Some OSes require page-aligned addresses
     - **Why wrong**: Lock silently fails on misaligned addresses
     - **Fix**: Add `if addr % PAGE_SIZE != 0: warnings.warn(...)` (only warnings since ctypes handles it)

#### `unlock_memory(handle: SecureMemoryHandle) -> bool`
- **Inputs**: Handle from lock_memory()
- **Outputs**: True if unlocked, False if failed
- **Purpose**: Release OS memory lock
- **Issues**:
  1. **Windows error code handling is incomplete**: Only checks 3 error codes
     - **Why wrong**: Other error codes (e.g., invalid handle) not detected
     - **Fix**: Add comprehensive error code list or log unexpected codes
  
  2. **Handle not removed from tracking if unlock fails**: Memory leak in _handles set
     - **Why wrong**: Repeated failures fill memory with dead handles
     - **Fix**: Always discard handle: `finally: self._handles.discard(handle)`

#### `_address_and_length(data) -> Tuple[int, int, object]`
- **Inputs**: bytes/bytearray/memoryview
- **Outputs**: (address, length, keeper object)
- **Purpose**: Extract memory location from Python object
- **Issues**:
  1. **memoryview contiguity check is good** but no shape validation
     - **Why wrong**: Multi-dimensional arrays could cause issues
     - **Fix**: Add `if len(mv.shape) != 1: raise ValueError("Only 1D arrays supported")`
  
  2. **No check for released memoryviews**: Accessing released view crashes
     - **Why wrong**: Race condition if view released between check and use
     - **Fix**: Wrap in try/except BufferError

#### `zeroize(handle: SecureMemoryHandle) -> bool`
- **Inputs**: Handle to zeroed memory
- **Outputs**: True if zeroed successfully
- **Purpose**: Overwrite memory with zeros (compiler-resistant)
- **Issues**:
  1. **Only verifies first byte**: Doesn't check if entire region zeroed
     - **Why wrong**: Partial zeroing could leave secrets
     - **Fix**: Sample multiple bytes: `for i in [0, length//2, length-1]: assert buffer[i] == 0`
  
  2. **No multiple-pass zeroing**: Some standards require 3-pass overwrite
     - **Why wrong**: Single pass may not clear magnetic residue (theoretical)
     - **Fix**: Add optional `passes=3` parameter for paranoid mode

#### `protect_from_fork(data_or_handle) -> bool`
- **Inputs**: Handle or raw buffer
- **Outputs**: True if protection applied
- **Purpose**: Prevent child processes from inheriting sensitive memory
- **Issues**:
  1. **Warning for bytes is misleading**: Says "protects temporary copy" but copy is intentional
     - **Why wrong**: Confuses users about security model
     - **Fix**: Change warning: "Note: bytes objects are copied—this protects the internal buffer only"
  
  2. **Keeps temporary keeper alive**: Discards keeper variable but ctypes still references it
     - **Why wrong**: Memory leak for each protect_from_fork call
     - **Fix**: Store keeper in handle or class attribute

#### `cleanup_all()`
- **Inputs**: None
- **Outputs**: None (side effect: zeros and unlocks all handles)
- **Purpose**: Emergency cleanup on process exit
- **Issues**:
  1. **Silent failures**: All exceptions swallowed
     - **Why wrong**: Cleanup failures go unnoticed
     - **Fix**: Log exceptions to stderr: `except Exception as e: print(f"Cleanup error: {e}", file=sys.stderr)`
  
  2. **No ordering guarantee**: Handles cleaned in arbitrary order
     - **Why wrong**: If handles have dependencies (nested buffers), could fail
     - **Fix**: Sort handles by creation time (requires timestamp tracking)

### Missing Features

1. **No memory pressure detection**: Should unlock non-critical keys when system low on memory
2. **No core dump prevention**: madvise(MADV_DONTDUMP) not used on Linux
3. **No encrypted swap detection**: Can't warn user if swap encryption disabled
4. **No memory locking limits check**: Doesn't verify ulimit before attempting lock
5. **No cleanup verification**: Can't confirm all keys were actually zeroed

---

## 4. database_manager.py (Data Persistence Layer)

### Overview
Handles SQLite operations with encrypted entry storage and hierarchical key management.

### Methods and Their Specifications

#### `__init__(db_path="data/vault.db")`
- **Inputs**: Database file path
- **Outputs**: Initialized DatabaseManager instance
- **Purpose**: Set up database connection and ensure directory exists
- **Issues**:
  1. **Write test uses predictable name**: `.sentra_write_test` could conflict
     - **Why wrong**: Race condition if multiple instances start simultaneously
     - **Fix**: Use `tempfile.mktemp()` or UUID in filename
  
  2. **Directory permissions not set**: Creates with default umask
     - **Why wrong**: On Unix, might be world-readable
     - **Fix**: `os.makedirs(directory, mode=0o700, exist_ok=True)`

#### `connect() -> sqlite3.Connection`
- **Inputs**: None (uses self.db_path)
- **Outputs**: SQLite connection with Row factory
- **Purpose**: Establish or return existing connection
- **Issues**:
  1. **WAL mode fallback is silent**: User doesn't know they're in slower DELETE mode
     - **Why wrong**: Performance degradation goes unnoticed
     - **Fix**: Emit `logging.warning()` when falling back
  
  2. **No connection timeout**: If database locked, waits forever
     - **Why wrong**: Hangs UI indefinitely
     - **Fix**: `self.connection.execute("PRAGMA busy_timeout = 5000")`  # 5 sec
  
  3. **Foreign keys enabled per-connection**: Should be in schema PRAGMA
     - **Why wrong**: If someone uses different tool, foreign keys disabled
     - **Fix**: Document that this is defense-in-depth (schema already has it)

#### `close()`
- **Inputs**: None
- **Outputs**: None (side effect: commits and closes connection)
- **Purpose**: Clean up database connection
- **Issues**:
  1. **Unconditional commit**: Commits even if there were errors
     - **Why wrong**: Could persist partial corrupted state
     - **Fix**: Add flag tracking if transaction succeeded: `if self._transaction_clean: conn.commit()`

#### `_derive_entry_key(vault_key, entry_id, entry_salt) -> bytes`
- **Inputs**: 32-byte vault key, entry UUID string, entry salt bytes
- **Outputs**: 32-byte entry-specific encryption key
- **Purpose**: Derive unique key for each entry
- **Issues**:
  1. **entry_id encoding is unspecified**: Uses default UTF-8 but doesn't validate
     - **Why wrong**: Non-ASCII entry IDs could cause errors
     - **Fix**: Enforce ASCII-only UUIDs or explicitly handle encoding errors
  
  2. **Salt length not validated**: Accepts any length salt
     - **Why wrong**: Short salts weaken key derivation
     - **Fix**: `if len(entry_salt) < 16: raise ValueError("Salt too short")`

#### `_validate_entry_data(title, url, username, notes, tags, category)`
- **Inputs**: Entry fields to validate
- **Outputs**: None (raises ValueError on validation failure)
- **Purpose**: Enforce field length limits
- **Issues**:
  1. **Inconsistent validation**: Title checks `not title` but others only check length
     - **Why wrong**: Could save entry with `title=""` bypassing the check
     - **Fix**: All required fields should check `not field` first
  
  2. **No URL format validation**: Accepts "foobar" as valid URL
     - **Why wrong**: Search/display expects valid URLs
     - **Fix**: Add regex: `if url and not re.match(r'^https?://', url): warnings.warn(...)`
  
  3. **No SQL injection protection note**: Uses parameterized queries but doesn't document this is why
     - **Why wrong**: Maintainers might not understand security implications
     - **Fix**: Add comment: `# Validated for length only; SQL injection prevented by parameterized queries`

#### `get_all_entries(vault_key) -> List[Dict]`
- **Inputs**: Vault encryption key
- **Outputs**: List of all decrypted entries
- **Purpose**: Bulk export for backups
- **Issues**:
  1. **No pagination**: Loads all entries into memory at once
     - **Why wrong**: 10,000-entry vault could consume gigabytes
     - **Fix**: Add `limit` and `offset` parameters
  
  2. **Fails completely if one entry corrupt**: Loop stops on first decryption error
     - **Why wrong**: Backup fails instead of skipping corrupt entries
     - **Fix**: Wrap inner loop in try/except, log corrupt IDs, continue

#### `initialize_database() -> bool`
- **Inputs**: None (uses schema.sql file)
- **Outputs**: True if initialized, raises on failure
- **Purpose**: Create database schema
- **Issues**:
  1. **No version checking**: Runs schema.sql even if tables already exist
     - **Why wrong**: Could corrupt existing database if schema changed
     - **Fix**: Check `PRAGMA user_version` first and skip if already initialized
  
  2. **BEGIN IMMEDIATE used incorrectly**: Should be `BEGIN EXCLUSIVE` for DDL
     - **Why wrong**: Concurrent readers could see half-initialized schema
     - **Fix**: `conn.execute("BEGIN EXCLUSIVE")`
  
  3. **Schema file path is relative**: Assumes CWD is project root
     - **Why wrong**: Breaks if invoked from different directory
     - **Fix**: Use `os.path.join(os.path.dirname(__file__), '..', 'schema.sql')`

#### `save_vault_metadata(...) -> bool`
- **Inputs**: Salt, auth hash, encrypted vault key, KDF config
- **Outputs**: True if saved, False if already exists
- **Purpose**: Initialize vault on first use
- **Issues**:
  1. **KDF config stored as JSON string**: Requires parsing every unlock
     - **Why wrong**: Performance penalty
     - **Fix**: Store as BLOB and use msgpack for faster serialization
  
  2. **No validation of encrypted vault key**: Could save garbage data
     - **Why wrong**: Vault becomes unusable if bad data saved
     - **Fix**: Attempt decrypt immediately after save to verify: `verify_roundtrip()`
  
  3. **Race condition**: Two processes could both check "not exists", both INSERT
     - **Why wrong**: Second process gets IntegrityError
     - **Fix**: Use `INSERT OR IGNORE` and check `rowcount` to detect race

#### `delete_vault_metadata()`
- **Inputs**: None
- **Outputs**: None (raises on failure)
- **Purpose**: Emergency rollback during init failure
- **Issues**:
  1. **Doesn't reset auto-increment**: ID counter stays at 1 after delete
     - **Why wrong**: No functional issue but could confuse troubleshooting
     - **Fix**: `DELETE FROM sqlite_sequence WHERE name='vault_metadata'`
  
  2. **No audit trail**: Silently deletes vault config
     - **Why wrong**: Can't tell if vault was corrupted or deliberately reset
     - **Fix**: Log warning before delete: `logging.critical("VAULT RESET: Deleting metadata")`

#### `load_vault_metadata() -> Optional[Dict]`
- **Inputs**: None
- **Outputs**: Dictionary of vault config or None
- **Purpose**: Retrieve vault initialization parameters
- **Issues**: None—straightforward implementation

#### `update_unlock_timestamp() -> bool`
- **Inputs**: None (uses current time)
- **Outputs**: True if updated
- **Purpose**: Track vault usage
- **Issues**:
  1. **Uses SQLite `datetime('now')`**: Time zone is UTC but not explicit
     - **Why wrong**: Could be misinterpreted as local time
     - **Fix**: Use Python datetime and store ISO format: `datetime.now(timezone.utc).isoformat()`

#### `add_entry(...) -> str`
- **Inputs**: Vault key, entry fields
- **Outputs**: Entry UUID
- **Purpose**: Create new encrypted entry
- **Issues**:
  1. **password_age_days hardcoded to 0**: Should be NULL for new entries
     - **Why wrong**: Age should be calculated from modified_at, not stored
     - **Fix**: Remove column from INSERT (let it default to NULL or remove column entirely)
  
  2. **No duplicate detection**: Can save identical title/username pairs
     - **Why wrong**: Users accidentally create duplicates
     - **Fix**: Add `UNIQUE(title, username)` constraint or warn on similarity
  
  3. **Entry salt generated here**: Should be in crypto_engine for consistency
     - **Why wrong**: Salt generation logic scattered across codebase
     - **Fix**: Call `crypto_engine.generate_salt()` explicitly

#### `get_entry(entry_id, vault_key) -> Optional[Dict]`
- **Inputs**: Entry UUID, vault key
- **Outputs**: Decrypted entry dictionary or None
- **Purpose**: Retrieve and decrypt single entry
- **Issues**:
  1. **Calcpassword age on every access**: Repeated datetime parsing
     - **Why wrong**: Performance penalty for frequent access
     - **Fix**: Cache age calculation or compute once in list view
  
  2. **Favorite returned as int**: Schema stores 0/1 but returns as bool—inconsistent
     - **Why wrong**: API consumer sees different types
     - **Fix**: Always convert: `favorite=bool(row["favorite"])`
  
  3. **Raises DatabaseError on decryption failure**: Should distinguish authentication failure from corruption
     - **Why wrong**: Can't tell if user has wrong key or entry is corrupt
     - **Fix**: Raise different exceptions: `EntryCorruptError` vs `DecryptionError`

#### `update_entry(entry_id, vault_key, **kwargs) -> Tuple[bool, int]`
- **Inputs**: Entry ID, vault key, fields to update
- **Outputs**: (success boolean, rows affected)
- **Purpose**: Modify existing entry
- **Issues**:
  1. **Returns tuple but code expects bool**: Inconsistent with other methods
     - **Why wrong**: Caller `if update_entry(...)` gets wrong result
     - **Fix**: Return only `bool` and remove rowcount from return value
  
  2. **No last_accessed_at update**: Entry modified but access time not recorded
     - **Why wrong**: Audit log incomplete
     - **Fix**: Always update: `fields.append("last_accessed_at = datetime('now')")`
  
  3. **Password strength validation too late**: Validates after accepting value
     - **Why wrong**: Could reject after partial update
     - **Fix**: Validate all inputs before starting transaction

#### `delete_entry(entry_id) -> bool`
- **Inputs**: Entry UUID
- **Outputs**: True if deleted
- **Purpose**: Soft delete (move to trash)
- **Issues**: None—properly implements soft delete

#### `list_entries(include_deleted=False, limit=100, offset=0) -> List[Dict]`
- **Inputs**: Filter flags, pagination params
- **Outputs**: List of entry metadata (no decryption)
- **Purpose**: Display vault contents
- **Issues**:
  1. **Limit clamped to 1000**: Hardcoded ceiling prevents bulk operations
     - **Why wrong**: Backup of 5000-entry vault requires 5 calls
     - **Fix**: Add `unlimited=True` parameter that bypasses limit
  
  2. **include_deleted changes column list**: Deleted entries show is_deleted field, active don't
     - **Why wrong**: Inconsistent response structure
     - **Fix**: Always include is_deleted, filter in WHERE clause only

#### `restore_entry(entry_id) -> bool`
- **Inputs**: Entry UUID
- **Outputs**: True if restored
- **Purpose**: Undelete from trash
- **Issues**:
  1. **No check for is_deleted=1**: Could "restore" active entry (no-op but confusing)
     - **Why wrong**: API allows impossible operation
     - **Fix**: Add to WHERE: `WHERE id = ? AND is_deleted = 1`

#### `search_entries(query, include_deleted=False, limit=50, offset=0) -> List[Dict]`
- **Inputs**: Search string, filters
- **Outputs**: Matching entries (metadata only)
- **Purpose**: Full-text and LIKE search
- **Issues**:
  1. **FTS vs LIKE decision logic is fragile**: ASCII check fails for empty strings
     - **Why wrong**: Crashes on `query=""`
     - **Fix**: Add early return: `if not query.strip(): return []`
  
  2. **LIKE wildcard wrapping**: Query "C++" becomes "%C++%"—literal plus signs
     - **Why wrong**: Doesn't match entries with C++ in title (SQL interprets literally)
     - **Fix**: Escape wildcards correctly in LIKE: `query.replace('+', r'\+')`
  
  3. **FTS query injection possible**: User input directly inserted into MATCH
     - **Why wrong**: Malicious query could crash FTS: `query = '" OR 1=1--'`
     - **Fix**: Sanitize query: Remove quotes, limit length, use parameterized FTS if available

#### `get_audit_logs(limit=50) -> List[Dict]`
- **Inputs**: Row limit
- **Outputs**: Recent security events
- **Purpose**: Forensic investigation
- **Issues**:
  1. **No filtering by date/action**: Can't search for "all deletes last month"
     - **Why wrong**: Large audit logs become unusable
     - **Fix**: Add optional `action_type` and `since_timestamp` parameters

#### `get_old_entries(days_threshold=90) -> List[Dict]`
- **Inputs**: Age threshold
- **Outputs**: Entries with old passwords
- **Purpose**: Security health check
- **Issues**:
  1. **Uses SQL date math**: Good! But could be slow on large tables
     - **Why wrong**: Full table scan if modified_at not indexed well
     - **Fix**: Ensure index exists: `CREATE INDEX idx_modified_date ON entries(modified_at)`

#### Metadata and Lockout Methods

These are thin wrappers around SQL—minimal issues

### Missing Functionality

1. **No bulk operations**: Can't update/delete multiple entries atomically
2. **No entry templates**: Can't save reusable entry patterns
3. **No entry tags management**: Can't list all tags or rename tags globally
4. **No entry history**: Can't view previous versions of modified entries
5. **No data export**: Should have `export_to_csv()` method here instead of CLI

---

## 5. password_generator.py (Password Creation and Analysis)

### Overview
Generates secure passwords and evaluates password strength with entropy analysis and pattern detection.

### Methods and Their Specifications

#### `__init__(min_length=12, max_length=64, dict_path="data/common_passwords.txt")`
- **Inputs**: Length constraints, dictionary file path
- **Outputs**: Initialized generator with loaded dictionary
- **Purpose**: Set up generator with common password database
- **Issues**:
  1. **Dictionary path is relative**: Breaks if CWD changes
     - **Why wrong**: Import fails in production deployments
     - **Fix**: Use `os.path.join(os.path.dirname(__file__), '..', dict_path)`
  
  2. **Silent failure on missing dictionary**: Only prints warning
     - **Why wrong**: Weak password detection degraded without notice
     - **Fix**: Raise warning but continue (current behavior OK)—could add strict mode
  
  3. **No dictionary hash verification**: Could load tampered dictionary
     - **Why wrong**: Malicious dictionary weakens strength calculations
     - **Fix**: Ship `common_passwords.txt.sha256` and verify on load

#### `_load_dictionary(path)`
- **Inputs**: Dictionary file path
- **Outputs**: None (populates self.common_passwords)
- **Purpose**: Load breach database
- **Issues**:
  1. **Filters passwords < 4 chars**: Misses common PINs like "123" or "000"
     - **Why wrong**: Three-digit patterns are common
     - **Fix**: Lower threshold to 3 or load all
  
  2. **Case-insensitive storage**: All lowercased before adding
     - **Why wrong**: "ADMIN" and "admin" treated identically (good) but loses original for display
     - **Fix**: Current behavior is correct for matching

#### `_generate_strong_password(length) -> Tuple[str, str]`
- **Inputs**: Desired password length
- **Outputs**: (password string, warning message)
- **Purpose**: Generate cryptographically random password
- **Issues**:
  1. **Warning message only for 8-11 chars**: Should warn for 12-15 too (barely meets minimum)
     - **Why wrong**: Users think 12 is "strong enough" but it's still weak
     - **Fix**: Add tiered warnings: <8 error, 8-11 warning, 12-15 info
  
  2. **Shuffle uses SystemRandom**: Good! But not documented why
     - **Why wrong**: Maintainer might change to `random.shuffle()` (insecure)
     - **Fix**: Add comment: `# SECURITY: Must use SystemRandom for crypto-quality shuffle`

#### `generate_password(length=16, used_passwords=None) -> Tuple[str, str]`
- **Inputs**: Length, set of existing passwords (for uniqueness)
- **Outputs**: (password, warning)
- **Purpose**: Generate unique password for vault
- **Issues**:
  1. **Infinite loop if all possibilities exhausted**: With length=8 and 10M used passwords, could hang
     - **Why wrong**: Denial of service vulnerability
     - **Fix**: Add retry counter: `for attempt in range(100): ... else: raise RuntimeError("Could not generate unique password")`
  
  2. **used_passwords not case-normalized**: Could accept "Password1" if "PASSWORD1" exists
     - **Why wrong**: Visual duplicate
     - **Fix**: Normalize check: `if pwd.lower() not in {p.lower() for p in used_passwords}`

#### `_levenshtein_distance(s1, s2) -> int`
- **Inputs**: Two strings
- **Outputs**: Edit distance (integer)
- **Purpose**: Fuzzy matching for similar passwords
- **Issues**:
  1. **No length short-circuit**: Compares "a" vs "Lorem ipsum dolor..." fully
     - **Why wrong**: Wasted computation—clearly different
     - **Fix**: `if abs(len(s1) - len(s2)) > 10: return 999  # clearly different`
  
  2. **Memory intensive for long strings**: O(n*m) space complexity
     - **Why wrong**: Comparing 32KB note fields causes OOM
     - **Fix**: Limit input length: `s1, s2 = s1[:100], s2[:100]`

#### `calculate_strength(password, user_inputs=None) -> Tuple[int, str, Dict]`
- **Inputs**: Password string, optional context (username, email)
- **Outputs**: (score 0-100, label, diagnostic dict)
- **Purpose**: Comprehensive password analysis
- **Issues**:
  1. **Character set size calculation is inaccurate**: Doesn't count actual unique chars
     - **Why wrong**: "AAAA" scored as if it uses full uppercase set
     - **Fix**: Use `len(set(password))` as actual charset size
  
  2. **Entropy calculation ignores patterns**: "aaabbbccc" has high entropy but obvious pattern
     - **Why wrong**: Overestimates strength
     - **Fix**: Apply compression test: `if len(zlib.compress(password.encode())) < len(password): deduct_points`
  
  3. **Deductions are additive**: Sequential + keyboard + date patterns compound quickly
     - **Why wrong**: Password gets -50 penalty when should be -30 (patterns overlap)
     - **Fix**: Use `max(deductions)` instead of sum for overlapping patterns
  
  4. **Year pattern (1900-2099) check is separate**: Should be part of date pattern
     - **Why wrong**: "2023" gets two penalties (year + date)
     - **Fix**: Merge into single date detection
  
  5. **Context matching threshold inconsistent**: Uses Levenshtein distance <= 2 for short words, no length scale
     - **Why wrong**: "alice" and "al1ce" distance=1 is caught, but "christopher" and "chr1st0pher" distance=2 is caught too easily
     - **Fix**: Scale threshold by length: `threshold = max(1, len(word) // 5)`
  
  6. **No consecutive character check**: "Password123123123" with long repeat substring not penalized
     - **Why wrong**: Obvious pattern
     - **Fix**: Add substring repeat detection: `if password[i:i+4] == password[i+4:i+8]: deduct`
  
  7. **Dictionary matches don't check substrings**: "SuperPassword2023" not flagged if dictionary only has "password"
     - **Why wrong**: Common words embedded in longer passwords
     - **Fix**: Check if any dictionary word is substring: `for word in dict: if word in normalized: deduct`
  
  8. **Leet speak substitutions incomplete**: Only maps {@, 0, 3, 1, $, !}—missing common ones
     - **Why wrong**: "P455w0rd" (4=a, 5=s) not detected
     - **Fix**: Add: `{'4': 'a', '5': 's', '7': 't', '8': 'b'}`
  
  9. **No credit for length beyond 16**: Passwords >20 chars don't get bonus points
     - **Why wrong**: Discourages passphrases (4-word passphrases are very strong)
     - **Fix**: Add length bonus: `score += min(20, (length - 16) * 2)  # +2 per char over 16`

### Missing Features

1. **No passphrase generation**: Only character-based passwords, not word-based
2. **No pronounceable password option**: "Xk7!mP2$" is strong but hard to type
3. **No entropy-based thresholds**: Should require 60+ bits entropy minimum
4. **No common substitution suggestions**: Doesn't tell user "Use @ instead of a"
5. **No breach API integration**: Should check haveibeenpwned.com for leaked passwords

---

## 6. totp_generator.py (Two-Factor Authentication)

### Overview
Implements RFC 6238 TOTP algorithm with rate limiting for code generation and verification.

### Methods and Their Specifications

#### `__init__()`
- **Inputs**: None
- **Outputs**: Initialized TOTP generator
- **Purpose**: Set up rate limiting state
- **Issues**:
  1. **Rate limit state stored in memory**: Lost on process restart
     - **Why wrong**: Attacker can restart process to reset limit
     - **Fix**: Store in database: `lockout_attempts` table
  
  2. **Tracking salt is hardcoded**: `b"sentra-totp-tracking"` is fixed
     - **Why wrong**: Same secret used for all installations (not unique per vault)
     - **Fix**: Derive from vault_key: `self._tracking_salt = vault_key[:16]`

#### `_check_rate_limit(secret) -> bool`
- **Inputs**: TOTP secret string
- **Outputs**: True if attempts allowed, False if rate limited
- **Purpose**: Prevent brute-force of TOTP codes
- **Issues**:
  1. **Secret hashing uses HMAC backwards**: `data=secret, key=salt` should be reversed
     - **Why wrong**: Salt should be secret, not the key
     - **Fix**: `compute_hmac(data=self._tracking_salt, key=secret.encode())`
  
  2. **Rate limit is per-secret**: User with 10 TOTP entries can attempt 50 times (5×10)
     - **Why wrong**: Bypasses rate limiting by attacking different entries
     - **Fix**: Track globally per session: `_global_attempts = deque()`
  
  3. **Window pruning is O(n)**: Checks every timestamp on each attempt
     - **Why wrong**: 100 rapid attempts cause quadratic slowdown
     - **Fix**: Use bisect to find cutoff point: `bisect_left(history, cutoff)`

#### `generate_totp(secret, time_step=30) -> str`
- **Inputs**: Base32 secret, time window in seconds
- **Outputs**: 6-digit TOTP code
- **Purpose**: Generate current code
- **Issues**:
  1. **Returns "000000" on error**: Indistinguishable from valid code
     - **Why wrong**: User sees "000000" and thinks it's real
     - **Fix**: Raise exception: `raise TOTPError("Invalid secret format")`
  
  2. **No secret validation**: Accepts non-base32 strings
     - **Why wrong**: Fails silently instead of early error
     - **Fix**: Add validation: `try: base64.b32decode(secret) except: raise ValueError`

#### `get_time_remaining(time_step=30) -> int`
- **Inputs**: Time window size
- **Outputs**: Seconds until code expires
- **Purpose**: Display countdown timer
- **Issues**: None—simple and correct

#### `is_valid_totp(secret, code, window=1) -> bool`
- **Inputs**: Secret, user-provided code, time window tolerance
- **Outputs**: True if valid
- **Purpose**: Verify TOTP code
- **Issues**:
  1. **Rate limit exception not caught**: Caller must handle RateLimitError
     - **Why wrong**: Breaks calling code if not documented
     - **Fix**: Document in docstring or return `(False, "rate_limited")` tuple
  
  2. **Window=1 allows 3 time slots**: Current, previous, next (90 seconds total)
     - **Why wrong**: Too generous—30 seconds should be enough
     - **Fix**: Default to `window=0` for strict checking
  
  3. **Generic exception catch**: Swallows all errors including programming bugs
     - **Why wrong**: Masks bugs (e.g., network issues, library crashes)
     - **Fix**: Catch specific exceptions: `except (binascii.Error, ValueError):`

#### `parse_totp_uri(uri) -> Optional[str]`
- **Inputs**: otpauth:// URI string
- **Outputs**: Extracted secret or None
- **Purpose**: Import from QR codes
- **Issues**:
  1. **No URI validation**: Accepts "otpauth://foo?secret=bar" without checking host
     - **Why wrong**: Could parse malformed URIs
     - **Fix**: Validate host: `if parsed.netloc != 'totp': return None`
  
  2. **Returns first secret in query**: If multiple "secret" params, picks arbitrary one
     - **Why wrong**: Ambiguous behavior
     - **Fix**: Raise error if multiple secrets found

#### `generate_totp_uri(secret, issuer, account) -> str`
- **Inputs**: Secret, service name, account name
- **Outputs**: otpauth:// URI
- **Purpose**: Export for QR codes
- **Issues**:
  1. **No input sanitization**: Issuer="Bad:Issuer" breaks URI parsing
     - **Why wrong**: Colon in issuer creates invalid URI
     - **Fix**: URL-encode issuer and account: `urllib.parse.quote(issuer)`
  
  2. **Returns empty string on error**: Indistinguishable from success
     - **Why wrong**: Caller can't detect failure
     - **Fix**: Raise exception on error

### Missing Features

1. **No HOTP support**: Only time-based, not counter-based (RFC 4226)
2. **No backup codes**: Users can't generate emergency fallback codes
3. **No algorithm selection**: Hardcoded to SHA-1 (should support SHA-256)
4. **No digit length customization**: Always 6 digits (some services use 8)
5. **No URI validation for period/digits**: Doesn't parse custom time_step from URI

---

## 7. adaptive_lockout.py (Brute-Force Protection)

### Overview
Implements sliding-window exponential backoff for failed authentication attempts.

### Methods and Their Specifications

#### `__init__(dbmanager, config)`
- **Inputs**: Database manager instance, configuration dict
- **Outputs**: Initialized lockout manager
- **Purpose**: Set up rate limiting parameters
- **Issues**:
  1. **Config normalization creates new dict**: Doesn't modify original
     - **Why wrong**: Changes not visible to caller (could cause confusion)
     - **Fix**: Document that config is copied: `# Creates defensive copy`
  
  2. **No config persistence**: Parameters only live in memory
     - **Why wrong**: Restart resets to defaults
     - **Fix**: Save config to database: `db.update_metadata('lockout_config', config)`
  
  3. **Validation happens in __init__**: Can't change config without recreating object
     - **Why wrong**: Runtime reconfiguration impossible
     - **Fix**: Add `update_config(new_config)` method

#### `record_failure()`
- **Inputs**: None (implicit: current time)
- **Outputs**: None (side effect: updates database)
- **Purpose**: Log failed authentication attempt
- **Issues**:
  1. **Two-phase pruning is confusing**: DB prunes by time, then class prunes by count
     - **Why wrong**: Pruning logic split across layers
     - **Fix**: Move all pruning to DB layer with LIMIT clause: `DELETE ... ORDER BY timestamp DESC LIMIT -1 OFFSET ?`
  
  2. **No transaction isolation**: Could interleave with other failures
     - **Why wrong**: Race condition causes incorrect count
     - **Fix**: Database already uses `BEGIN IMMEDIATE`—good!
  
  3. **Exception handling swallows errors**: Try/except with `pass` hides issues
     - **Why wrong**: Silent failures hard to debug
     - **Fix**: Log exception: `logging.exception("Failed to prune lockout history")`

#### `check_and_delay() -> Tuple[bool, int]`
- **Inputs**: None (uses current time)
- **Outputs**: (allowed: bool, seconds_remaining: int)
- **Purpose**: Determine if authentication attempt permitted
- **Issues**:
  1. **Exponential calculation uses count-1**: For 1 failure, uses 2^0 = 1 second
     - **Why wrong**: First failure has no penalty
     - **Fix**: Use `count` directly: `delay = min(max_delay, 2 ** count)`
  
  2. **Max exponent cap at 31**: With max_delay=300, this never reached
     - **Why wrong**: Dead code (300 = 2^8.23, never reaches 2^31)
     - **Fix**: Remove max_exp check or lower to realistic value: `max_exp = 10`
  
  3. **No check for timestamp order**: Assumes DB returns ascending order
     - **Why wrong**: If DB returns unsorted, uses wrong "last attempt"
     - **Fix**: Add safety check: `timestamps = sorted(timestamps)` or verify with assertion

#### `reset_session()`
- **Inputs**: None
- **Outputs**: None (side effect: clears database)
- **Purpose**: Clear lockout state after successful auth
- **Issues**:
  1. **Clears all history**: Loses audit trail
     - **Why wrong**: Can't see how many attempts before success
     - **Fix**: Don't delete, just mark as "session_ended": `UPDATE lockout_attempts SET session_end = ...`

#### `get_status_message() -> dict`
- **Inputs**: None
- **Outputs**: Dict with allowed, delay, failures
- **Purpose**: User-friendly lockout status
- **Issues**:
  1. **Returns raw dict**: Not a proper error message
     - **Why wrong**: Method name implies string, returns dict
     - **Fix**: Rename to `get_status()` or return formatted string

### Missing Features

1. **No IP-based tracking**: Can't rate-limit by network location
2. **No progressive challenges**: Should add CAPTCHA after N failures
3. **No notification system**: Owner not alerted to brute-force attempts
4. **No allowlist**: Trusted devices can't bypass lockout
5. **No permanent lockout**: After 1000 attempts, should require admin reset

---

## 8. backup_manager.py (Import/Export Operations)

### Overview
Handles encrypted backup creation and restoration with HMAC integrity verification.

### Methods and Their Specifications

#### `__init__(db, vault_keys, hierarchy_keys)`
- **Inputs**: Database manager, (enc_key, hmac_key) tuple, hierarchy dict
- **Outputs**: Initialized backup manager
- **Purpose**: Set up backup encryption context
- **Issues**:
  1. **Key equality check prevents key reuse**: Ensures enc_key ≠ hmac_key
     - **Why wrong**: Actually GOOD—prevents key reuse vulnerability
     - **Fix**: None—this is correct!
  
  2. **Hierarchy keys validation is rigid**: Requires exact structure
     - **Why wrong**: Future key types (e.g., "recovery_key") rejected
     - **Fix**: Only validate required keys: `if 'vault_key' not in hierarchy_keys: raise`

#### `create_backup(filename, entries=None) -> bool`
- **Inputs**: Output filename, optional entry ID list
- **Outputs**: True on success, raises RuntimeError on failure
- **Purpose**: Export encrypted vault backup
- **Issues**:
  1. **Filename not validated**: Accepts "../../../etc/passwd"
     - **Why wrong**: Path traversal vulnerability
     - **Fix**: Validate filename: `if '/' in filename or '\\' in filename: raise ValueError`
  
  2. **No atomic write**: File written directly (could corrupt on crash)
     - **Why wrong**: Power loss mid-write leaves corrupt backup
     - **Fix**: Write to temp file, then rename: `os.rename(temp, filename)`
  
  3. **Entries list not validated**: Could pass non-existent IDs
     - **Why wrong**: Backup silently skips missing entries
     - **Fix**: Raise error on missing: `if entry is None: raise ValueError(f"Entry {eid} not found")`
  
  4. **JSON canonicalization inconsistent**: Uses `separators=(',', ':')` but code comments say no spaces
     - **Why wrong**: Future change could break HMAC verification
     - **Fix**: Document explicitly: `# CRITICAL: Any change breaks HMAC compatibility`
  
  5. **Header length as 4-byte int**: Limits header to 4GB (should be enough)
     - **Why wrong**: Actually reasonable limit
     - **Fix**: None needed
  
  6. **No compression**: 1000-entry backup could be 10MB+ (mostly JSON whitespace)
     - **Why wrong**: Wastes disk space
     - **Fix**: Add optional gzip compression: `gzip.compress(payload_bytes)`
  
  7. **No encryption of entry metadata**: Title, URL, username visible in backup
     - **Why wrong**: Backup file leaks metadata
     - **Fix**: Currently they ARE encrypted (wrapped in encrypt_entry)—good!

#### `restore_backup(filename) -> bool`
- **Inputs**: Backup filename
- **Outputs**: True on success, raises on failure
- **Purpose**: Import encrypted backup
- **Issues**:
  1. **No duplicate ID handling**: Restoring same backup twice doubles entries
     - **Why wrong**: User confusion
     - **Fix**: Use `INSERT OR REPLACE` or check for existing IDs first
  
  2. **HMAC verification before parsing**: Good security practice!
     - **Why wrong**: None—this is correct design
     - **Fix**: None needed
  
  3. **Reads entire file into memory**: 1GB backup file causes OOM
     - **Why wrong**: Large backups unusable
     - **Fix**: Stream processing: Read header, verify HMAC on chunks
  
  4. **Version checking too strict**: Rejects version != 1
     - **Why wrong**: Can't restore future backups with backward-compatible changes
     - **Fix**: Accept `version >= 1` with optional warnings
  
  5. **Entry count mismatch is fatal**: Rejects if declared count ≠ actual
     - **Why wrong**: Minor corruption prevents entire restore
     - **Fix**: Warn but continue: `if declared != actual: warnings.warn(...)`
  
  6. **Transaction semantics unclear**: Uses `BEGIN IMMEDIATE` but no clear rollback policy
     - **Why wrong**: Partial restore could corrupt vault
     - **Fix**: Wrap entire loop in try/except with explicit rollback
  
  7. **No progress reporting**: 10,000-entry restore appears frozen
     - **Why wrong**: User thinks it crashed
     - **Fix**: Add callback: `progress_callback(current, total)`
  
  8. **Zeroing internal_vault_key is best-effort**: Uses try/except pass
     - **Why wrong**: Silent failure
     - **Fix**: At minimum log failure: `logging.warning("Failed to zero key")`

### Missing Features

1. **No incremental backups**: Always exports entire vault
2. **No backup encryption with separate password**: Uses same master key
3. **No backup compression**: JSON is highly compressible
4. **No backup signing**: Can't verify backup author identity
5. **No restore preview**: Can't see what's in backup before restoring

---

## 9. vault_controller.py (Core Business Logic)

This is the largest and most complex file. I'll focus on critical issues.

### Methods and Their Specifications

#### `__init__(db_path, config)`
- **Inputs**: Database path, configuration dict
- **Outputs**: Initialized controller
- **Purpose**: Orchestrate vault operations
- **Issues**:
  1. **Password generator initialized without config**: Uses hardcoded defaults
     - **Why wrong**: Can't customize generator behavior
     - **Fix**: Pass config to PasswordGenerator: `self.pw_gen = PasswordGenerator(**config.get('passgen', {}))`
  
  2. **Secure memory initialized unconditionally**: No way to disable for testing
     - **Why wrong**: Unit tests can't mock secure memory
     - **Fix**: Add config flag: `if config.get('use_secure_memory', True): self.secure_mem = ...`

#### `unlock_vault(password) -> bool`
- **Inputs**: Master password string
- **Outputs**: True on success, raises on failure
- **Purpose**: Authenticate and derive keys
- **Issues**:
  1. **First-time setup vs existing vault logic intertwined**: 200+ line method
     - **Why wrong**: Hard to maintain, test, and reason about
     - **Fix**: Split into `_create_new_vault()` and `_unlock_existing_vault()`
  
  2. **Vault creation has triple verification**: Creates, reads back, decrypts, compares
     - **Why wrong**: Good! This is defense in depth
     - **Fix**: None—this is excellent design
  
  3. **Secure memory failure cleanup is complex**: Nested try/except with multiple paths
     - **Why wrong**: Error-prone, easy to leak keys
     - **Fix**: Use context managers: `with SecureMemoryLock(key) as handle:`
  
  4. **Adaptive lockout reset timing is wrong**: Resets BEFORE final DB update
     - **Why wrong**: If DB update fails, lockout still reset (security issue)
     - **Fix**: Move `reset_session()` to AFTER all operations succeed
  
  5. **KDF config defaults scattered**: Default params in 3 places (here, schema, crypto_engine)
     - **Why wrong**: Inconsistent defaults possible
     - **Fix**: Centralize in config.py: `DEFAULT_KDF_PARAMS = {...}`
  
  6. **Password validation insufficient**: Only checks "not empty"
     - **Why wrong**: Accepts single space as password
     - **Fix**: `if not password.strip(): raise ValueError`

#### `lock_vault() -> bool`
- **Inputs**: None
- **Outputs**: True on success
- **Purpose**: Securely erase keys and close vault
- **Issues**:
  1. **Key zeroing has nested try/except**: Complex error handling
     - **Why wrong**: If first key zeroization fails, second might not happen
     - **Fix**: Use try/finally for each key independently
  
  2. **Database close wrapped in try/except**: Hides close failures
     - **Why wrong**: Connection leaks possible
     - **Fix**: Raise exception on close failure in strict mode

#### `add_password(...) -> str`
- **Inputs**: Entry fields
- **Outputs**: Entry UUID
- **Purpose**: Create new vault entry
- **Issues**:
  1. **Favorite parameter passed but not used**: Code inconsistency
     - **Why wrong**: Parameter silently ignored
     - **Fix**: Actually pass to database: `db.add_entry(..., favorite=favorite)`
  
  2. **Password strength calculation duplicated**: Also done in update_entry
     - **Why wrong**: Logic duplication
     - **Fix**: Extract to helper: `_calculate_strength_if_password(password)`

#### `search_entries(query, ...) -> List[Dict]`
- **Inputs**: Search query, filters
- **Outputs**: Matching entries
- **Purpose**: Vault search
- **Issues**:
  1. **Limit hardcoded check**: Raises at 1000 but DatabaseManager also checks
     - **Why wrong**: Duplicate validation
     - **Fix**: Remove check here—trust database layer

#### `get_backup_keys() -> Tuple[bytes, bytes]`
- **Inputs**: None (uses vault state)
- **Outputs**: (encryption_key, HMAC_key)
- **Purpose**: Derive independent backup keys
- **Issues**:
  1. **Uses master_key_secure instead of vault_key**: Inconsistent with architecture
     - **Why wrong**: Backup keys derived from wrong layer
     - **Fix**: Use vault_key: `vault_material = bytearray(self.vault_key_secure)`
  
  2. **Temporary buffer zeroing is manual**: Error-prone
     - **Why wrong**: If exception before `finally`, buffer leaks
     - **Fix**: Use context manager
