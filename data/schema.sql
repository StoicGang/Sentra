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
    kdf_config TEXT,                        -- JSON string of KDF parameters (time_cost, memory_cost, etc.)       
    
    -- Metadata
    created_at TEXT NOT NULL,               -- ISO 8601
    last_unlocked_at TEXT,                  
    unlock_count INTEGER DEFAULT 0 CHECK (unlock_count >= 0),
    version TEXT DEFAULT '2.0'              
);

-- ============================================================================
-- TABLE 2: entries (Core Data)
-- ============================================================================
CREATE TABLE IF NOT EXISTS entries (
    id TEXT PRIMARY KEY,                    -- UUID
    title TEXT NOT NULL,                    
    url TEXT,                               
    username TEXT,                          
    
    -- Encrypted Data (ChaCha20-Poly1305)
    -- NOTE: Password and Notes are encrypted separately with different nonces
    password_encrypted BLOB NOT NULL,       
    password_nonce BLOB NOT NULL,           
    password_tag BLOB NOT NULL,             
    
    notes_encrypted BLOB,                   
    notes_nonce BLOB,                       
    notes_tag BLOB,                         
    
    -- Organization & Metadata
    tags TEXT,                              
    category TEXT DEFAULT 'General',        
    favorite INTEGER DEFAULT 0 CHECK (favorite IN (0, 1)), -- Boolean enforcement
    
    -- Timestamps
    created_at TEXT NOT NULL,               
    modified_at TEXT NOT NULL,              
    last_accessed_at TEXT,                  
    
    -- Security Health
    password_strength INTEGER CHECK (password_strength BETWEEN 0 AND 100),
    password_age_days INTEGER DEFAULT 0,
    
    -- Soft Delete (Trash System)
    is_deleted INTEGER DEFAULT 0 CHECK (is_deleted IN (0, 1)), -- Boolean enforcement
    deleted_at TEXT                         
);

-- ============================================================================
-- TABLE 3: failed_attempts_log (Brute-force protection)
-- ============================================================================
CREATE TABLE IF NOT EXISTS failed_attempts_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_timestamp TEXT NOT NULL,        
    session_id TEXT,                        
    reason TEXT DEFAULT 'wrong_password',
    ip_address TEXT                         -- Added for future remote sync capability
);

-- ============================================================================
-- TABLE 4: config_metadata (Key-Value Store for Adaptive Lockout/App Config)
-- ============================================================================
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,                    -- Stores JSON strings or scalars
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Trigger to auto-update 'updated_at' on metadata change
CREATE TRIGGER IF NOT EXISTS update_metadata_timestamp 
AFTER UPDATE ON metadata 
BEGIN
    UPDATE metadata SET updated_at = datetime('now') WHERE key = new.key;
END;

-- ============================================================================
-- TABLE 5: audit_log (New: Security Event Tracking)
-- ============================================================================
-- Tracks creation, updates, and deletion of entries for forensic auditing
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id TEXT NOT NULL,
    action_type TEXT NOT NULL CHECK (action_type IN ('CREATE', 'UPDATE', 'SOFT_DELETE', 'RESTORE', 'HARD_DELETE')),
    timestamp TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(entry_id) REFERENCES entries(id) ON DELETE CASCADE
);

-- ============================================================================
-- INDEXES (Performance)
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_entries_title ON entries(title);
CREATE INDEX IF NOT EXISTS idx_entries_category ON entries(category);
CREATE INDEX IF NOT EXISTS idx_entries_tags ON entries(tags);
CREATE INDEX IF NOT EXISTS idx_entries_deleted ON entries(is_deleted);
CREATE INDEX IF NOT EXISTS idx_failed_attempts ON failed_attempts_log(attempt_timestamp);

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
    INSERT INTO entries_fts(rowid, id, title, url, username, tags)
    SELECT new.rowid, new.id, new.title, new.url, new.username, new.tags
    WHERE new.is_deleted = 0;

    INSERT INTO audit_log (entry_id, action_type) VALUES (new.id, 'CREATE');
END;

-- 2. UPDATE: Handle FTS sync for Soft Deletes and Content Updates
CREATE TRIGGER IF NOT EXISTS entries_au AFTER UPDATE ON entries 
BEGIN
    -- If content changed and Entry is ACTIVE: Update FTS
    INSERT INTO entries_fts(entries_fts, rowid, id, title, url, username, tags)
    SELECT 'delete', old.rowid, old.id, old.title, old.url, old.username, old.tags
    WHERE old.is_deleted = 0;

    INSERT INTO entries_fts(rowid, id, title, url, username, tags)
    SELECT new.rowid, new.id, new.title, new.url, new.username, new.tags
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
    INSERT INTO entries_fts(entries_fts, rowid, id, title, url, username, tags)
    SELECT 'delete', old.rowid, old.id, old.title, old.url, old.username, old.tags;

    -- Note: Audit log for hard delete relies on the ID before it vanishes
    INSERT INTO audit_log (entry_id, action_type) VALUES (old.id, 'HARD_DELETE');
END;