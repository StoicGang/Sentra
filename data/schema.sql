-- ============================================================================
-- SENTRA Database Schema v1.0
-- SQLite database for encrypted password vault
-- ============================================================================

-- ============================================================================
-- TABLE 1: vault_metadata (Single-row configuration table)
-- ============================================================================
CREATE TABLE IF NOT EXISTS vault_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- Only one row allowed
    salt BLOB NOT NULL,                     -- 16-byte Argon2id salt
    auth_hash BLOB NOT NULL,                -- 32-byte PBKDF2-SHA256 password verification hash
    
    -- Encrypted vault key (used for bulk entry encryption)
    vault_key_encrypted BLOB NOT NULL,      -- Encrypted with master key
    vault_key_nonce BLOB NOT NULL,          -- 12-byte ChaCha20 nonce
    vault_key_tag BLOB NOT NULL,            -- 16-byte Poly1305 auth tag
    
    -- Metadata
    created_at TEXT NOT NULL,               -- ISO 8601 timestamp
    last_unlocked_at TEXT,                  -- Last successful unlock
    unlock_count INTEGER DEFAULT 0,         -- Total successful unlocks
    version TEXT DEFAULT '1.0'              -- Schema version
);

-- ============================================================================
-- TABLE 2: entries (Password entries with per-entry encryption)
-- ============================================================================
CREATE TABLE IF NOT EXISTS entries (
    id TEXT PRIMARY KEY,                    -- UUID for each entry
    title TEXT NOT NULL,                    -- Entry title (e.g., "GitHub Account")
    url TEXT,                               -- Associated URL
    username TEXT,                          -- Username/email
    
    -- Encrypted password field (ChaCha20-Poly1305 AEAD)
    password_encrypted BLOB NOT NULL,       -- Encrypted password
    password_nonce BLOB NOT NULL,           -- 12-byte nonce
    password_tag BLOB NOT NULL,             -- 16-byte auth tag
    
    -- Encrypted notes field (optional)
    notes_encrypted BLOB,                   -- Encrypted notes
    notes_nonce BLOB,                       -- 12-byte nonce
    notes_tag BLOB,                         -- 16-byte auth tag
    
    -- Metadata
    tags TEXT,                              -- Comma-separated tags
    category TEXT DEFAULT 'General',        -- Entry category
    favorite INTEGER DEFAULT 0,             -- Boolean flag (0 or 1)
    
    -- Timestamps
    created_at TEXT NOT NULL,               -- ISO 8601 timestamp
    modified_at TEXT NOT NULL,              -- Last modification time
    last_accessed_at TEXT,                  -- Last time entry was viewed
    
    -- Security metadata
    password_strength INTEGER,              -- Score 0-100
    password_age_days INTEGER,              -- Days since password created
    
    -- Soft delete (trash system)
    is_deleted INTEGER DEFAULT 0,           -- Boolean flag (0 = active, 1 = trashed)
    deleted_at TEXT                         -- When moved to trash
);

-- ============================================================================
-- TABLE 3: failed_attempts_log (For adaptive lockout system)
-- ============================================================================
CREATE TABLE IF NOT EXISTS failed_attempts_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_timestamp TEXT NOT NULL,        -- ISO 8601 timestamp
    session_id TEXT,                        -- Optional session identifier
    reason TEXT DEFAULT 'wrong_password'    -- Failure reason
);

-- ============================================================================
-- INDEXES for performance optimization
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_entries_title ON entries(title);
CREATE INDEX IF NOT EXISTS idx_entries_category ON entries(category);
CREATE INDEX IF NOT EXISTS idx_entries_tags ON entries(tags);
CREATE INDEX IF NOT EXISTS idx_entries_deleted ON entries(is_deleted);
CREATE INDEX IF NOT EXISTS idx_failed_attempts_timestamp ON failed_attempts_log(attempt_timestamp);

-- ============================================================================
-- FULL-TEXT SEARCH (FTS5) - For fast search functionality
-- ============================================================================
CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5(
    entry_id UNINDEXED,
    title,
    url,
    username,
    tags,
    content='entries',
    content_rowid='rowid'
);

-- ============================================================================
-- TRIGGERS to keep FTS in sync with entries table
-- ============================================================================
CREATE TRIGGER IF NOT EXISTS entries_fts_insert AFTER INSERT ON entries BEGIN
    INSERT INTO entries_fts(rowid, entry_id, title, url, username, tags)
    VALUES (new.rowid, new.id, new.title, new.url, new.username, new.tags);
END;

CREATE TRIGGER IF NOT EXISTS entries_fts_update AFTER UPDATE ON entries BEGIN
    UPDATE entries_fts 
    SET title = new.title, url = new.url, username = new.username, tags = new.tags
    WHERE rowid = new.rowid;
END;

CREATE TRIGGER IF NOT EXISTS entries_fts_delete AFTER DELETE ON entries BEGIN
    DELETE FROM entries_fts WHERE rowid = old.rowid;
END;
