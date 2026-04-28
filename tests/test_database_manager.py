import os
import sqlite3
import json
import tempfile
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from src.database_manager import (
    DatabaseManager,
    DatabaseError,
    MAX_TITLE_LEN,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_db_path(tmp_path):
    return str(tmp_path / "sentra_test.db")

@pytest.fixture
def db(temp_db_path):
    return DatabaseManager(db_path=temp_db_path)

@pytest.fixture
def vault_key():
    return b"\x11" * 32

# ---------------------------------------------------------------------------
# Initialization & Connection
# ---------------------------------------------------------------------------

def test_db_init_creates_directory(tmp_path):
    path = tmp_path / "nested" / "vault.db"
    DatabaseManager(db_path=str(path))
    assert path.parent.exists()

def test_connect_returns_singleton_connection(db):
    c1 = db.connect()
    c2 = db.connect()
    assert c1 is c2

def test_close_resets_connection(db):
    db.connect()
    db.close()
    assert db.connection is None

def test_context_manager(db):
    with db as d:
        assert d.connection is not None
    assert db.connection is None

# ---------------------------------------------------------------------------
# Schema Initialization
# ---------------------------------------------------------------------------

def test_initialize_database_success(db, tmp_path):
    # 1. Create a REAL temporary schema file
    schema_file = tmp_path / "schema.sql"
    schema_file.write_text("""
        CREATE TABLE entries(id TEXT PRIMARY KEY);
        CREATE TABLE lockout_attempts(attempt_ts INTEGER);
    """, encoding="utf-8")
    
    # 2. Patch the PATH variable to point to our real temp file
    with patch("src.database_manager.SCHEMA_PATH", str(schema_file)):
         assert db.initialize_database() is True

def test_initialize_database_missing_schema(db):
    # Patch open to raise FileNotFoundError
    with patch("builtins.open", side_effect=FileNotFoundError):
        with pytest.raises(DatabaseError, match="initialization failed"):
            db.initialize_database()

# ---------------------------------------------------------------------------
# Vault Metadata
# ---------------------------------------------------------------------------

def test_load_vault_metadata_empty(db):
    db.connect()
    # Ensure table exists so query doesn't fail
    db.connection.execute("CREATE TABLE vault_metadata (id INTEGER)")
    assert db.load_vault_metadata() is None

def test_save_and_load_vault_metadata(db):
    db.connect()
    # Create full schema for metadata
    db.connection.execute("""
        CREATE TABLE vault_metadata (
            id INTEGER PRIMARY KEY,
            salt BLOB,
            auth_hash BLOB,
            vault_key_encrypted BLOB,
            vault_key_nonce BLOB,
            vault_key_tag BLOB,
            kdf_config TEXT,
            created_at TEXT,
            version TEXT,
            unlock_count INTEGER,
            last_unlocked_at TEXT
        )
    """)

    ok = db.save_vault_metadata(
        salt=b"a"*16,
        auth_hash=b"b"*32,
        vault_key_encrypted=b"c",
        vault_key_nonce=b"d",
        vault_key_tag=b"e",
        kdf_config={"x": 1}
    )
    assert ok is True

    meta = db.load_vault_metadata()
    assert meta["unlock_count"] == 0
    assert meta["version"] == "2.0"
    
    # Verify JSON serialization of config
    assert json.loads(meta["kdf_config"]) == {"x": 1}

def test_update_unlock_timestamp(db):
    db.connect()
    db.connection.execute("""
        CREATE TABLE vault_metadata (
            id INTEGER PRIMARY KEY,
            last_unlocked_at TEXT,
            unlock_count INTEGER
        )
    """)
    db.connection.execute(
        "INSERT INTO vault_metadata VALUES (1, NULL, 0)"
    )
    db.connection.commit()

    assert db.update_unlock_timestamp() is True
    
    # Verify update happened
    row = db.connection.execute("SELECT unlock_count FROM vault_metadata").fetchone()
    assert row["unlock_count"] == 1

# ---------------------------------------------------------------------------
# Entry CRUD
# ---------------------------------------------------------------------------

@patch("src.database_manager.encrypt_entry", return_value=(b"c", b"n", b"t"))
@patch("src.database_manager.generate_salt", return_value=b"s"*16)
@patch("src.database_manager.derive_hkdf_key", return_value=b"k"*32)
def test_add_and_get_entry(
    _hkdf, _salt, _enc, db, vault_key
):
    db.connect()
    # Minimal schema for entry operations
    db.connection.executescript("""
        CREATE TABLE entries (
            id TEXT PRIMARY KEY,
            title TEXT,
            url TEXT,
            username TEXT,
            title_encrypted BLOB,
            title_nonce BLOB,
            title_tag BLOB,
            url_encrypted BLOB,
            url_nonce BLOB,
            url_tag BLOB,
            username_encrypted BLOB,
            username_nonce BLOB,
            username_tag BLOB,
            password_encrypted BLOB,
            password_nonce BLOB,
            password_tag BLOB,
            notes_encrypted BLOB,
            notes_nonce BLOB,
            notes_tag BLOB,
            kdf_salt BLOB,
            tags TEXT,
            category TEXT,
            created_at TEXT,
            modified_at TEXT,
            favorite INTEGER,
            password_strength INTEGER,
            is_deleted INTEGER DEFAULT 0,
            deleted_at TEXT,
            last_accessed_at TEXT
        )
    """)

    eid = db.add_entry(
        vault_key=vault_key,
        title="Email",
        username="user",
        password="pw",
        notes="note",
    )

    assert isinstance(eid, str)
    
    # Verify insertion: Plaintext columns should be NULL (because we encrypt them)
    row = db.connection.execute("SELECT title, title_encrypted FROM entries WHERE id=?", (eid,)).fetchone()
    assert row["title"] is None
    assert row["title_encrypted"] is not None

def test_add_entry_rejects_invalid_title(db, vault_key):
    with pytest.raises(DatabaseError, match="Invalid entry data"):
        db.add_entry(vault_key, title="")

def test_add_entry_rejects_long_title(db, vault_key):
    with pytest.raises(DatabaseError, match="Invalid entry data"):
        db.add_entry(vault_key, title="x" * (MAX_TITLE_LEN + 1))

# ---------------------------------------------------------------------------
# get_entry behavior
# ---------------------------------------------------------------------------

def test_get_entry_not_found_returns_none(db, vault_key):
    db.connect()
    db.connection.execute("""
        CREATE TABLE entries (
            id TEXT PRIMARY KEY,
            is_deleted INTEGER DEFAULT 0
        )
    """)
    assert db.get_entry("missing", vault_key) is None

# ---------------------------------------------------------------------------
# update_entry
# ---------------------------------------------------------------------------

def test_update_entry_no_fields_returns_false(db, vault_key):
    db.connect()
    db.connection.execute("""
        CREATE TABLE entries (
            id TEXT PRIMARY KEY,
            kdf_salt BLOB,
            is_deleted INTEGER DEFAULT 0
        )
    """)
    db.connection.execute(
        "INSERT INTO entries VALUES (?, ?, 0)", ("id1", b"s"*16)
    )
    db.connection.commit()

    # Should return (False, 0) because no fields were provided to update
    ok, count = db.update_entry("id1", vault_key)
    assert ok is False
    assert count == 0

# ---------------------------------------------------------------------------
# delete & restore
# ---------------------------------------------------------------------------

def test_delete_and_restore_entry(db):
    db.connect()
    db.connection.execute("""
        CREATE TABLE entries (
            id TEXT PRIMARY KEY,
            is_deleted INTEGER DEFAULT 0,
            deleted_at TEXT,
            modified_at TEXT
        )
    """)
    db.connection.execute(
        "INSERT INTO entries VALUES ('id1', 0, NULL, datetime('now'))"
    )
    db.connection.commit()

    assert db.delete_entry("id1") is True
    
    # Check it is marked deleted
    row = db.connection.execute("SELECT is_deleted FROM entries WHERE id='id1'").fetchone()
    assert row["is_deleted"] == 1
    
    assert db.restore_entry("id1") is True
    
    # Check it is restored
    row = db.connection.execute("SELECT is_deleted FROM entries WHERE id='id1'").fetchone()
    assert row["is_deleted"] == 0

# ---------------------------------------------------------------------------
# list_entries
# ---------------------------------------------------------------------------

def test_list_entries_no_crash(db):
    db.connect()
    db.connection.execute("""
        CREATE TABLE entries (
            id TEXT PRIMARY KEY, 
            title TEXT, 
            url TEXT, 
            username TEXT, 
            tags TEXT, 
            category TEXT, 
            password_strength INTEGER,
            created_at TEXT, 
            modified_at TEXT, 
            is_deleted INTEGER DEFAULT 0
        )
    """)
    # Should not crash even with large limit
    db.list_entries(limit=5000) 

# ---------------------------------------------------------------------------
# Metadata KV
# ---------------------------------------------------------------------------

def test_metadata_roundtrip(db):
    db.connect()
    db.connection.execute("""
        CREATE TABLE metadata (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    db.connection.commit()

    # Value is JSON encoded internally
    assert db.update_metadata("x", {"a": 1}) is True
    assert db.get_metadata("x") == {"a": 1}

# ---------------------------------------------------------------------------
# Lockout
# ---------------------------------------------------------------------------

def test_clear_lockout_history(db):
    db.connect()
    db.connection.execute("""
        CREATE TABLE lockout_attempts (
            attempt_ts INTEGER
        )
    """)
    db.connection.execute("INSERT INTO lockout_attempts VALUES (123)")
    db.connection.commit()

    db.clear_lockout_history()
    rows = db.connection.execute(
        "SELECT * FROM lockout_attempts"
    ).fetchall()
    assert len(rows) == 0

# ---------------------------------------------------------------------------
# Metadata Encryption & Migration
# ---------------------------------------------------------------------------

def test_migrate_entries_metadata(db, vault_key):
    db.connect()
    db.connection.executescript("""
        CREATE TABLE entries (
            id TEXT PRIMARY KEY,
            title TEXT,
            url TEXT,
            username TEXT,
            title_encrypted BLOB,
            title_nonce BLOB,
            title_tag BLOB,
            url_encrypted BLOB,
            url_nonce BLOB,
            url_tag BLOB,
            username_encrypted BLOB,
            username_nonce BLOB,
            username_tag BLOB,
            password_encrypted BLOB,
            password_nonce BLOB,
            password_tag BLOB,
            notes_encrypted BLOB,
            notes_nonce BLOB,
            notes_tag BLOB,
            kdf_salt BLOB,
            is_deleted INTEGER DEFAULT 0,
            modified_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_id TEXT,
            action_type TEXT NOT NULL,
            details TEXT,
            timestamp TEXT DEFAULT (datetime('now'))
        );
        INSERT INTO entries (id, title, url, username, password_encrypted, password_nonce, password_tag, kdf_salt, is_deleted, modified_at)
        VALUES ('v1_entry', 'Plain Title', 'http://plain.url', 'plain_user', x'00', x'00', x'00', x'00000000000000000000000000000000', 0, '2024-01-01 10:00:00');
    """)
    db.connection.commit()

    with patch("src.database_manager.encrypt_entry", return_value=(b"c", b"n", b"t")), \
         patch("src.database_manager.derive_hkdf_key", return_value=b"k"*32):
        count = db.migrate_entries_metadata(vault_key)
        assert count == 1
    
    row = db.connection.execute("SELECT title, title_encrypted, url, url_encrypted, username, username_encrypted FROM entries WHERE id='v1_entry'").fetchone()
    assert row["title"] is None
    assert row["title_encrypted"] is not None
    assert row["url"] is None
    assert row["url_encrypted"] is not None
    assert row["username"] is None
    assert row["username_encrypted"] is not None

def test_search_entries_encrypted(db, vault_key):
    # Setup entries with encrypted metadata
    db.connect()
    # We use the real add_entry (with hashing/crypto patched) to populate
    with patch("src.database_manager.encrypt_entry", side_effect=lambda p, k, associated_data=None: (p.encode() if p else None, b"nonce", b"tag")), \
         patch("src.database_manager.generate_salt", return_value=b"s"*16), \
         patch("src.database_manager.derive_hkdf_key", return_value=b"k"*32), \
         patch("src.database_manager.decrypt_entry", side_effect=lambda c, n, t, k, associated_data=None: c.decode()):
        
        # We need a proper schema first
        db.connection.executescript("""
            CREATE TABLE entries (
                id TEXT PRIMARY KEY, title TEXT, url TEXT, username TEXT,
                title_encrypted BLOB, title_nonce BLOB, title_tag BLOB,
                url_encrypted BLOB, url_nonce BLOB, url_tag BLOB,
                username_encrypted BLOB, username_nonce BLOB, username_tag BLOB,
                password_encrypted BLOB, password_nonce BLOB, password_tag BLOB,
                notes_encrypted BLOB, notes_nonce BLOB, notes_tag BLOB,
                kdf_salt BLOB, tags TEXT, category TEXT, created_at TEXT, modified_at TEXT,
                favorite INTEGER, password_strength INTEGER, is_deleted INTEGER DEFAULT 0
            );
            CREATE VIRTUAL TABLE entries_fts USING fts5(title, url, username, tags, content='entries', content_rowid='rowid');
        """)
        
        db.add_entry(vault_key, title="Secret Bank", url="bank.com", username="admin")
        db.add_entry(vault_key, title="Personal Email", url="mail.com", username="user")
        
        # Search for "Bank"
        results = db.search_entries(vault_key, "Bank")
        assert len(results) == 1
        assert results[0]["title"] == "Secret Bank"
        
        # Search for "mail"
        results = db.search_entries(vault_key, "mail")
        assert len(results) == 1
        assert results[0]["title"] == "Personal Email"
        
        # Search for something non-existent
        results = db.search_entries(vault_key, "missing")
        assert len(results) == 0