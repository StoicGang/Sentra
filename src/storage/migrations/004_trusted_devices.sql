-- ============================================================================
-- Migration 004: Trusted Devices & Sync Support
-- Adds Device Tracking, Sync State, and HLC versioning to entries.
-- ============================================================================

PRAGMA foreign_keys = ON;

-- 1. Trusted Devices Registry
-- Tracks authorized devices owned by the same user.
CREATE TABLE IF NOT EXISTS trusted_devices (
    device_id TEXT PRIMARY KEY,             -- SHA256 Hash of Public Key (Identity)
    public_key BLOB NOT NULL,               -- Ed25519 Public Key
    nickname TEXT,                          -- User-assigned name (e.g., 'Work Laptop')
    trust_level INTEGER DEFAULT 1,          -- 1: Trusted, 0: Revoked
    last_synced_hlc TEXT,                   -- The HLC of the last message received from this peer
    added_at TEXT DEFAULT (datetime('now')),
    last_seen_at TEXT                       -- Last successful sync/heartbeat
);

-- 2. Sync Journal (Atomic Recovery)
-- Tracks in-progress sync batches to handle crashes/interrupts.
CREATE TABLE IF NOT EXISTS sync_journal (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id TEXT,
    entry_id TEXT,
    prev_hlc TEXT,                          -- For rollback
    status TEXT DEFAULT 'PENDING',          -- PENDING, COMMITTED
    started_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(peer_id) REFERENCES trusted_devices(device_id)
);

-- 3. Tombstones (Soft-Delete Propagation)
-- Ensures deletions are propagated across peers.
CREATE TABLE IF NOT EXISTS tombstones (
    entry_id TEXT PRIMARY KEY,
    deleted_hlc TEXT NOT NULL,
    origin_device_id TEXT NOT NULL
);

-- 4. Identity Storage (Local Only)
-- Stores this device's unique Ed25519 identity keypair.
CREATE TABLE IF NOT EXISTS local_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    device_id TEXT NOT NULL,
    public_key BLOB NOT NULL,
    private_key_encrypted BLOB NOT NULL,    -- Protected by Master Key
    nonce BLOB NOT NULL,
    tag BLOB NOT NULL
);

-- 5. Migration: Add Sync Columns to Entries
-- We use a transaction to ensure integrity.
BEGIN TRANSACTION;

-- Add HLC and Origin Device
-- Default origin_device_id is set to 'local' for existing entries.
ALTER TABLE entries ADD COLUMN hlc TEXT;
ALTER TABLE entries ADD COLUMN origin_device_id TEXT DEFAULT 'local';

-- Seed HLC for existing entries using their modified_at timestamp
-- Format: <timestamp>:<counter>:<node_id>
UPDATE entries 
SET hlc = strftime('%s', modified_at) || ':0000:local'
WHERE hlc IS NULL;

COMMIT;

-- Indexes for Sync Performance
CREATE INDEX IF NOT EXISTS idx_entries_hlc ON entries(hlc);
CREATE INDEX IF NOT EXISTS idx_entries_origin ON entries(origin_device_id);
CREATE INDEX IF NOT EXISTS idx_trusted_devices_trust ON trusted_devices(trust_level);
