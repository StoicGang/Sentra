-- ============================================================================
-- SENTRA Database Schema v2.0 (Secure & Extensive)
-- SQLite database for encrypted password vault
-- ============================================================================

-- Enable strict enforcement
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- ============================================================================
-- TABLE 1: vault_metadata (Single-row configuration table)
-- ============================================================================
CREATE TABLE IF NOT EXISTS vault_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- Strict Singleton: Only ID 1 allowed
    salt BLOB NOT NULL,                     -- 16-byte Argon2id salt
    auth_hash BLOB NOT NULL,                -- 32-byte PBKDF2-SHA256 verification hash
    
    -- Encrypted vault key (Master Key protects this)
    vault_key_encrypted BLOB NOT NULL,      
    vault_key_nonce BLOB NOT NULL,          
    vault_key_tag BLOB NOT NULL,     

    -- Crypto Configuration (New in v2.0)
    kdf_config TEXT NOT NULL CHECK (json_valid(kdf_config)),      -- JSON string of KDF parameters (time_cost, memory_cost, etc.)       
    
    -- Metadata
    display_name TEXT,                      -- User-friendly name
    description TEXT,                       -- Optional purpose/notes
    username TEXT DEFAULT 'admin',          -- User identity
    account_status TEXT DEFAULT 'Active',   -- Active, Suspended, Pending
    preferences TEXT DEFAULT '{}',          -- JSON for UI settings
    auto_lock_duration INTEGER DEFAULT 900, -- Seconds (Default 15m)
    created_at TEXT NOT NULL,               -- ISO 8601
    last_unlocked_at TEXT,                  
    unlock_count INTEGER DEFAULT 0 CHECK (unlock_count >= 0),
    version TEXT DEFAULT '2.3'              
);

-- ============================================================================
-- TABLE 2: entries (Core Data)
-- ============================================================================
CREATE TABLE IF NOT EXISTS entries (
    id TEXT PRIMARY KEY,                    
    title TEXT,                             -- Legacy plaintext title (null if encrypted)
    url TEXT,                               -- Legacy plaintext URL
    username TEXT,                          -- Legacy plaintext username
    
    -- Encrypted Metadata (v2.1)
    title_encrypted BLOB,
    title_nonce BLOB,
    title_tag BLOB,
    
    url_encrypted BLOB,
    url_nonce BLOB,
    url_tag BLOB,
    
    username_encrypted BLOB,
    username_nonce BLOB,
    username_tag BLOB,

    -- Encryption Data (Secrets)
    password_encrypted BLOB NOT NULL,       
    password_nonce BLOB NOT NULL,           
    password_tag BLOB NOT NULL,             
    
    notes_encrypted BLOB,                   
    notes_nonce BLOB,                       
    notes_tag BLOB,                         
    
    -- NEW: Per-Entry Salt for HKDF (Fixes QA Issue #8)
    -- This ensures every entry has a unique key derivation path
    kdf_salt BLOB NOT NULL,                         
    
    -- Organization & Metadata
    tags TEXT,                              
    category TEXT DEFAULT 'General',        
    favorite INTEGER DEFAULT 0 CHECK (favorite IN (0, 1)), 
    
    -- Timestamps
    created_at TEXT NOT NULL,               
    modified_at TEXT NOT NULL,              
    last_accessed_at TEXT,                  
    
    -- Security Health
    password_strength INTEGER CHECK (password_strength BETWEEN 0 AND 100),
    
    -- Soft Delete
    is_deleted INTEGER DEFAULT 0 CHECK (is_deleted IN (0, 1)),
    deleted_at TEXT,

    -- TOTP Support
    totp_secret_encrypted BLOB,
    totp_secret_nonce BLOB,
    totp_secret_tag BLOB
);

CREATE INDEX IF NOT EXISTS idx_entries_category_active 
ON entries(category, is_deleted);


-- ============================================================================
-- TABLE 3: failed_attempts_log (Brute-force protection)
-- ============================================================================
CREATE TABLE IF NOT EXISTS failed_attempts_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_timestamp INTEGER NOT NULL,     -- Unix epoch seconds
    session_id TEXT,
    reason TEXT DEFAULT 'wrong_password',
    ip_address TEXT                         -- For future remote sync capability
);

CREATE TRIGGER IF NOT EXISTS prune_failed_attempts_log
AFTER INSERT ON failed_attempts_log
BEGIN
    DELETE FROM failed_attempts_log
    WHERE attempt_timestamp < CAST(strftime('%s','now','-30 days') AS INTEGER);
END;


-- ============================================================================
-- TABLE 4: config_metadata (Key-Value Store for Adaptive Lockout/App Config)
-- ============================================================================
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL CHECK (json_valid(value)),                   -- Stores JSON strings or scalars
    updated_at TEXT DEFAULT (datetime('now'))
);

-- ============================================================================
-- TABLE 5: audit_log (New: Security Event Tracking)
-- ============================================================================
-- Tracks creation, updates, and deletion of entries for forensic auditing
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id TEXT,                          -- Can be NULL for global events (login, etc)
    action_type TEXT NOT NULL,              -- e.g., 'CREATE', 'UNLOCK', 'VIEW_SECRET'
    actor TEXT DEFAULT 'system',            -- e.g., 'admin', 'user.name', 'system'
    source TEXT DEFAULT 'Internal',         -- e.g., 'Web UI', 'CLI', 'API'
    severity TEXT DEFAULT 'Info',           -- 'Info', 'Warning', 'Error'
    ip_address TEXT DEFAULT '127.0.0.1',    
    details TEXT,                           -- Optional extra info
    timestamp TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp 
ON audit_log(timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_entry_id
ON audit_log(entry_id);

-- Prune audit logs to last 1000 events to prevent bloat
CREATE TRIGGER IF NOT EXISTS prune_audit_log
AFTER INSERT ON audit_log
BEGIN
    DELETE FROM audit_log
    WHERE id NOT IN (
        SELECT id FROM audit_log
        ORDER BY timestamp DESC
        LIMIT 1000
    );
END;



-- ============================================================================
-- TABLE 6: lockout_attempts (New: Adaptive Lockout Concurrency Safety)
-- ============================================================================
-- Tracks timestamps of recent failed attempts for the sliding window lockout.
-- Uses INTEGER timestamps (Unix Epoch) for efficient math.
CREATE TABLE IF NOT EXISTS lockout_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_ts INTEGER NOT NULL
);

CREATE TRIGGER IF NOT EXISTS prune_lockout_attempts
AFTER INSERT ON lockout_attempts
BEGIN
    DELETE FROM lockout_attempts
    WHERE attempt_ts < CAST(strftime('%s','now','-1 hour') AS INTEGER);
END;


-- ============================================================================
-- TABLE 7: vault_recovery (Account Recovery)
-- ============================================================================
-- Stores encrypted copies of the vault key, one row per recovery credential.
-- The vault key is encrypted under a key derived from the user's credential:
--   passphrase: Argon2id(passphrase, kdf_salt) → ChaCha20-Poly1305(vault_key)
--   code:       HKDF(code, kdf_salt, info) → ChaCha20-Poly1305(vault_key)
-- Verifier = HMAC-SHA256(derived_key, b"sentra-recovery-verify") for fast
-- wrong-code rejection without exposing the decrypted vault_key.
-- Plaintext credentials are NEVER stored here.
CREATE TABLE IF NOT EXISTS vault_recovery (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT NOT NULL CHECK (type IN ('passphrase', 'code')),
    code_index  INTEGER,                -- NULL for passphrase; 0..N for codes
    kdf_salt    BLOB NOT NULL,          -- Random 16-byte salt per row
    nonce       BLOB NOT NULL,          -- ChaCha20-Poly1305 12-byte nonce
    ciphertext  BLOB NOT NULL,          -- Encrypted vault_key bytes
    tag         BLOB NOT NULL,          -- Poly1305 16-byte authentication tag
    verifier    BLOB,                   -- HMAC-SHA256 for fast reject
    used        INTEGER DEFAULT 0 CHECK (used IN (0, 1)),
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_vault_recovery_type
ON vault_recovery(type, used);


-- ============================================================================
-- INDEXES (Performance)
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_entries_title ON entries(title);
CREATE INDEX IF NOT EXISTS idx_entries_tags ON entries(tags);
CREATE INDEX IF NOT EXISTS idx_entries_modified ON entries(modified_at);
CREATE INDEX IF NOT EXISTS idx_entries_deleted ON entries(is_deleted);
CREATE INDEX IF NOT EXISTS idx_failed_attempts ON failed_attempts_log(attempt_timestamp);
CREATE INDEX IF NOT EXISTS idx_lockout_attempts_ts ON lockout_attempts(attempt_ts);

-- ============================================================================
-- FULL-TEXT SEARCH (FTS5) - Synchronized with Soft Deletes
-- ============================================================================
CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5(
    id UNINDEXED, 
    title,
    url,
    username,
    tags,
    content='entries',
    content_rowid='rowid'
);

-- ============================================================================
-- TRIGGERS: FTS Sync & Audit Logging
-- ============================================================================

-- 1. INSERT: Add to FTS only if not deleted. Add Audit Log.
CREATE TRIGGER IF NOT EXISTS entries_ai AFTER INSERT ON entries 
BEGIN
    INSERT INTO entries_fts(rowid, id, tags)
    SELECT new.rowid, new.id, new.tags
    WHERE new.is_deleted = 0;

    INSERT INTO audit_log (entry_id, action_type) VALUES (new.id, 'CREATE');
END;

-- 2. UPDATE: Handle FTS sync for Soft Deletes and Content Updates
CREATE TRIGGER IF NOT EXISTS entries_au AFTER UPDATE ON entries 
BEGIN
    -- If content changed and Entry is ACTIVE: Update FTS
    INSERT INTO entries_fts(entries_fts, rowid, id, tags)
    SELECT 'delete', old.rowid, old.id, old.tags
    WHERE old.is_deleted = 0;

    INSERT INTO entries_fts(rowid, id, tags)
    SELECT new.rowid, new.id, new.tags
    WHERE new.is_deleted = 0;

    -- Audit Logging Logic
    INSERT INTO audit_log (entry_id, action_type) 
    SELECT new.id, CASE 
        WHEN new.is_deleted = 1 AND old.is_deleted = 0 THEN 'SOFT_DELETE'
        WHEN new.is_deleted = 0 AND old.is_deleted = 1 THEN 'RESTORE'
        ELSE 'UPDATE'
    END;
END;

-- 3. DELETE (Hard Delete): Remove from FTS and Log
CREATE TRIGGER IF NOT EXISTS entries_ad AFTER DELETE ON entries 
BEGIN
    -- Only remove from FTS if it wasn't already in the trash (is_deleted=0)
    -- This prevents "double delete" corruption in the index.
    INSERT INTO entries_fts(entries_fts, rowid, id, tags)
    SELECT 'delete', old.rowid, old.id, old.tags
    WHERE old.is_deleted = 0;

    INSERT INTO audit_log (entry_id, action_type) VALUES (old.id, 'HARD_DELETE');
END;

CREATE TABLE IF NOT EXISTS totp_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id TEXT NOT NULL,
    attempt_ts INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_totp_attempts_secret_time
ON totp_attempts(secret_id, attempt_ts);

CREATE TRIGGER IF NOT EXISTS prune_totp_attempts
AFTER INSERT ON totp_attempts
BEGIN
    DELETE FROM totp_attempts
    WHERE attempt_ts < CAST(strftime('%s','now','-1 day') AS INTEGER);
END;

-- ============================================================================
-- TABLE 8: vault_registry (For Multi-Vault Manager)
-- ============================================================================
CREATE TABLE IF NOT EXISTS vault_registry (
    nickname TEXT PRIMARY KEY,
    path TEXT NOT NULL UNIQUE,
    created_at TEXT DEFAULT (datetime('now')),
    last_accessed_at TEXT
);
-- ============================================================================
-- TABLE 9: backup_history (Maintenance Tracking)
-- ============================================================================
CREATE TABLE IF NOT EXISTS backup_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT DEFAULT (datetime('now')),
    operation_type TEXT NOT NULL, -- 'CREATED_BACKUP', 'IMPORTED_BACKUP', 'IMPORTED_CSV', 'EXPORTED_CSV'
    filename TEXT,
    file_size INTEGER,            -- in bytes
    status TEXT DEFAULT 'Success', -- 'Success', 'Failed', 'In Progress'
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_backup_history_timestamp ON backup_history(timestamp DESC);
