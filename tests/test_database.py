"""
Unit tests for DatabaseManager
"""

import pytest
import os
import time
from src.database_manager import DatabaseManager, DatabaseError

def test_database_connection():
    """Test basic database connection"""
    test_db = "data/test_vault.db"

    # clean up if exists
    if os.path.exists(test_db):
        os.remove(test_db)
    
    # TEst connection
    db = DatabaseManager(test_db)
    conn = db.connect()

    assert conn is not None
    assert db.connection is not None

    # Test closing 
    db.close()

    # Clean up 
    os.remove(test_db)

    print("Database connection test passed!")

def test_context_manager():
    """Test context manager usage"""
    test_db = "data/test_vault.db"

    if(os.path.exists(test_db)):
        os.remove(test_db)

    # Test context manager
    with DatabaseManager(test_db) as db:
        assert db.connection is not None

    # clean up 
    os.remove(test_db)

    print("context manager test passed!")

def test_database_initialization():
    """Test database schema initialization"""
    test_db = "data/test_vault.db"

    if os.path.exists(test_db):
        os.remove(test_db)

    db = DatabaseManager(test_db)

    # Initialize database
    result = db.initialize_database()
    assert result == True, "First initialization should return True"

    # Try again 
    result = db.initialize_database()
    assert result == False, "Second initialization should return False"

    # Verify tables exist
    conn = db.connect()
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    tables = [row[0] for row in cursor.fetchall()]

    assert 'vault_metadata' in tables
    assert 'entries' in tables
    assert 'failed_attempts_log' in tables
    assert 'entries_fts' in tables

    db.close()
    time.sleep(0.1)  # give windows time to release lock
    os.remove(test_db)  # clean

    print("Database initialization test passed!")

def test_vault_metadata_operations():
    """Test save and load vault metadata"""
    test_db = "data/test_vault.db"

    if os.path.exists(test_db):
        os.remove(test_db)

    db = DatabaseManager(test_db)
    db.initialize_database()

    # Create test vault metadata
    salt = os.urandom(16)
    auth_hash = os.urandom(32)
    vault_key_encrypted = os.urandom(32)
    vault_key_nonce = os.urandom(12)
    vault_key_tag = os.urandom(16)

    # Save metadata
    result = db.save_vault_metadata(
        salt, auth_hash, vault_key_encrypted, 
        vault_key_nonce, vault_key_tag
    )
    assert result == True, "First save should succeed"  # First save

    # Try saving again (SECOND TIME - should fail)
    result = db.save_vault_metadata(
        salt, auth_hash, vault_key_encrypted,
        vault_key_nonce, vault_key_tag
    )

    assert result == False, "Second save should fail"

    # Load metadata
    metadata = db.load_vault_metadata()
    assert metadata is not None
    assert metadata['salt'] == salt
    assert metadata['auth_hash'] == auth_hash
    assert metadata['vault_key_encrypted'] == vault_key_encrypted
    assert metadata['unlock_count'] == 0

    db.close()
    time.sleep(0.1)
    os.remove(test_db)

def test_unlock_timestamp_update():
    """Test unlock timestamp tracking"""
    test_db = "data/test_vault.db"

    if os.path.exists(test_db):
        os.remove(test_db)

    db = DatabaseManager(test_db)
    db.initialize_database()

    # save initial metadata
    db.save_vault_metadata(
        os.urandom(16), os.urandom(32), os.urandom(32),
        os.urandom(12), os.urandom(16)
    )

    # update the unlock timestamp
    result = db.update_unlock_timestamp()
    assert result == True

    # verify unlock count incremented 
    metadata = db.load_vault_metadata()
    assert metadata['unlock_count'] == 1
    assert metadata['last_unlocked_at'] is not None

    # Update again
    db.update_unlock_timestamp()
    metadata = db.load_vault_metadata()
    assert metadata['unlock_count'] == 2

    db.close()
    time.sleep(0.1)
    os.remove(test_db)

    print("Unlock timestamp update test passed!")

def test_add_entry_invalid_vault_key():
    """Test add_entry with invalid vault key"""
    test_db = "data/test_vault.db"
    
    if os.path.exists(test_db):
        os.remove(test_db)
    
    db = DatabaseManager(test_db)
    db.initialize_database()
    
    # Try with wrong size vault key
    try:
        db.add_entry(
            vault_key=b"too_short",  # Should be 32 bytes
            title="Test Entry"
        )
        assert False, "Should raise DatabaseError"
    except DatabaseError as e:
        assert "Vault key must be 32 bytes" in str(e)
        print("Invalid vault key error handled correctly")
    
    db.close()
    os.remove(test_db)


def test_get_nonexistent_entry():
    """Test retrieving non-existent entry"""
    test_db = "data/test_vault.db"
    
    if os.path.exists(test_db):
        os.remove(test_db)
    
    db = DatabaseManager(test_db)
    db.initialize_database()
    
    vault_key = os.urandom(32)
    
    # Try to get entry that doesn't exist
    result = db.get_entry("nonexistent-id", vault_key)
    
    assert result is None, "Should return None for non-existent entry"
    print("Non-existent entry returns None")
    
    db.close()
    os.remove(test_db)


def test_add_entry_success():
    """Test successful entry creation"""
    test_db = "data/test_vault_entry.db"
    
    if os.path.exists(test_db):
        os.remove(test_db)
    
    db = DatabaseManager(test_db)
    db.initialize_database()
    
    # Save vault metadata first
    db.save_vault_metadata(
        os.urandom(16), os.urandom(32), os.urandom(32),
        os.urandom(12), os.urandom(16)
    )
    
    vault_key = os.urandom(32)
    
    # Add entry
    entry_id = db.add_entry(
        vault_key=vault_key,
        title="GitHub Account",
        url="https://github.com",
        username="testuser",
        password="supersecret123",
        notes="My GitHub credentials",
        tags="dev,github",
        category="Development"
    )
    
    assert entry_id is not None
    assert len(entry_id) == 36  # UUID length
    
    db.close()
    time.sleep(0.1)
    os.remove(test_db)
    
    print("add_entry success test passed!")


def test_add_entry_invalid_vault_key():
    """Test add_entry with invalid vault key"""
    test_db = "data/test_vault_entry.db"
    
    if os.path.exists(test_db):
        os.remove(test_db)
    
    db = DatabaseManager(test_db)
    db.initialize_database()
    
    try:
        # Try with wrong size vault key (should be 32 bytes)
        db.add_entry(
            vault_key=b"too_short",
            title="Test Entry"
        )
        assert False, "Should raise DatabaseError"
    except DatabaseError as e:
        assert "Vault key must be 32 bytes" in str(e)
    
    db.close()
    time.sleep(0.1)
    os.remove(test_db)
    
    print("add_entry invalid vault key test passed!")


def test_get_entry_success():
    """Test successful entry retrieval and decryption"""
    test_db = "data/test_vault_entry.db"
    
    if os.path.exists(test_db):
        os.remove(test_db)
    
    db = DatabaseManager(test_db)
    db.initialize_database()
    
    vault_key = os.urandom(32)
    
    # Add entry
    entry_id = db.add_entry(
        vault_key=vault_key,
        title="Test Entry",
        url="https://example.com",
        username="user@example.com",
        password="mypassword123",
        notes="Some notes here",
        tags="test",
        category="Personal"
    )
    
    # Retrieve entry
    entry = db.get_entry(entry_id, vault_key)
    
    assert entry is not None
    assert entry["id"] == entry_id
    assert entry["title"] == "Test Entry"
    assert entry["url"] == "https://example.com"
    assert entry["username"] == "user@example.com"
    assert entry["password"] == "mypassword123"
    assert entry["notes"] == "Some notes here"
    assert entry["category"] == "Personal"
    
    db.close()
    time.sleep(0.1)
    os.remove(test_db)
    
    print("get_entry success test passed!")


def test_get_nonexistent_entry():
    """Test retrieving non-existent entry"""
    test_db = "data/test_vault_entry.db"
    
    if os.path.exists(test_db):
        os.remove(test_db)
    
    db = DatabaseManager(test_db)
    db.initialize_database()
    
    vault_key = os.urandom(32)
    
    # Try to get entry that doesn't exist
    result = db.get_entry("nonexistent-uuid-here", vault_key)
    
    assert result is None, "Should return None for non-existent entry"
    
    db.close()
    time.sleep(0.1)
    os.remove(test_db)
    
    print("get_nonexistent_entry test passed!")


def test_list_entries():
    """Test listing all entries"""
    test_db = "data/test_vault_entry.db"
    
    if os.path.exists(test_db):
        os.remove(test_db)
    
    db = DatabaseManager(test_db)
    db.initialize_database()
    
    vault_key = os.urandom(32)
    
    # Add multiple entries
    id1 = db.add_entry(vault_key=vault_key, title="Entry 1")
    id2 = db.add_entry(vault_key=vault_key, title="Entry 2")
    id3 = db.add_entry(vault_key=vault_key, title="Entry 3")
    
    # List all active entries
    entries = db.list_entries(include_deleted=False)
    
    assert len(entries) == 3
    titles = [e["title"] for e in entries]
    assert "Entry 1" in titles
    assert "Entry 2" in titles
    assert "Entry 3" in titles
    
    db.close()
    time.sleep(0.1)
    os.remove(test_db)
    
    print("list_entries test passed!")


def test_update_entry():
    """Test updating entry fields"""
    test_db = "data/test_vault_entry.db"
    
    if os.path.exists(test_db):
        os.remove(test_db)
    
    db = DatabaseManager(test_db)
    db.initialize_database()
    
    vault_key = os.urandom(32)
    
    # Add entry
    entry_id = db.add_entry(
        vault_key=vault_key,
        title="Original Title",
        url="https://old.example.com",
        password="oldpassword"
    )
    
    # Update entry
    result = db.update_entry(
        entry_id=entry_id,
        vault_key=vault_key,
        title="Updated Title",
        url="https://new.example.com",
        password="newpassword123"
    )
    
    assert result == True
    
    # Verify updates
    entry = db.get_entry(entry_id, vault_key)
    assert entry["title"] == "Updated Title"
    assert entry["url"] == "https://new.example.com"
    assert entry["password"] == "newpassword123"
    
    db.close()
    time.sleep(0.1)
    os.remove(test_db)
    
    print("update_entry test passed!")


def test_delete_entry_soft_delete():
    """Test soft delete (move to trash)"""
    test_db = "data/test_vault_entry.db"
    
    if os.path.exists(test_db):
        os.remove(test_db)
    
    db = DatabaseManager(test_db)
    db.initialize_database()
    
    vault_key = os.urandom(32)
    
    # Add entry
    entry_id = db.add_entry(vault_key=vault_key, title="To Delete")
    
    # Verify entry exists
    entry = db.get_entry(entry_id, vault_key)
    assert entry is not None
    
    # Soft delete
    result = db.delete_entry(entry_id)
    assert result == True
    
    # Verify entry not in active list
    entries = db.list_entries(include_deleted=False)
    assert len(entries) == 0
    
    # Verify entry in trash
    entries_in_trash = db.list_entries(include_deleted=True)
    assert len(entries_in_trash) == 1
    assert entries_in_trash[0]["is_deleted"] == 1
    
    db.close()
    time.sleep(0.1)
    os.remove(test_db)
    
    print("delete_entry soft delete test passed!")


def test_restore_entry():
    """Test restoring entry from trash"""
    test_db = "data/test_vault_entry.db"
    
    if os.path.exists(test_db):
        os.remove(test_db)
    
    db = DatabaseManager(test_db)
    db.initialize_database()
    
    vault_key = os.urandom(32)
    
    # Add and delete entry
    entry_id = db.add_entry(vault_key=vault_key, title="Restore Me")
    db.delete_entry(entry_id)
    
    # Verify in trash
    entries_in_trash = db.list_entries(include_deleted=True)
    assert len(entries_in_trash) == 1
    
    # Restore
    result = db.restore_entry(entry_id)
    assert result == True
    
    # Verify back in active list
    entries = db.list_entries(include_deleted=False)
    assert len(entries) == 1
    assert entries[0]["title"] == "Restore Me"
    
    db.close()
    time.sleep(0.1)
    os.remove(test_db)
    
    print("restore_entry test passed!")


def test_entry_crud_roundtrip():
    """Test complete CRUD cycle: Create, Read, Update, Delete, Restore"""
    test_db = "data/test_vault_entry.db"
    
    if os.path.exists(test_db):
        os.remove(test_db)
    
    db = DatabaseManager(test_db)
    db.initialize_database()
    
    vault_key = os.urandom(32)
    
    # CREATE
    entry_id = db.add_entry(
        vault_key=vault_key,
        title="Gmail",
        url="https://gmail.com",
        username="user@gmail.com",
        password="initial_password",
        notes="Personal email account",
        tags="email,important",
        category="Email"
    )
    assert entry_id is not None
    
    # READ
    entry = db.get_entry(entry_id, vault_key)
    assert entry["password"] == "initial_password"
    
    # UPDATE
    result = db.update_entry(
        entry_id=entry_id,
        vault_key=vault_key,
        password="new_password_2024",
        notes="Updated notes"
    )
    assert result == True
    
    entry = db.get_entry(entry_id, vault_key)
    assert entry["password"] == "new_password_2024"
    assert entry["notes"] == "Updated notes"
    
    # DELETE
    result = db.delete_entry(entry_id)
    assert result == True
    
    entry = db.get_entry(entry_id, vault_key)
    assert entry is None
    
    # RESTORE
    result = db.restore_entry(entry_id)
    assert result == True
    
    entry = db.get_entry(entry_id, vault_key)
    assert entry is not None
    assert entry["password"] == "new_password_2024"
    
    db.close()
    time.sleep(0.1)
    os.remove(test_db)
    
    print("CRUD roundtrip test passed!")

def test_advanced_schema_fields():
    """Test storage of favorite status and password strength"""
    test_db = "data/test_vault_advanced.db"
    
    if os.path.exists(test_db):
        os.remove(test_db)
    
    db = DatabaseManager(test_db)
    db.initialize_database()
    
    # Setup keys
    salt = os.urandom(16)
    db.save_vault_metadata(salt, os.urandom(32), os.urandom(32), os.urandom(12), os.urandom(16))
    vault_key = os.urandom(32)

    # 1. Add entry with Favorite=True and Strength=85
    entry_id = db.add_entry(
        vault_key=vault_key,
        title="Important Login",
        password="StrongPassword123!",
        favorite=True,             # <--- New Field
        password_strength=85       # <--- New Field
    )

    # 2. Retrieve and Verify
    entry = db.get_entry(entry_id, vault_key)
    assert entry['favorite'] is True, "Favorite should be boolean True"
    assert entry['password_strength'] == 85, "Strength should be 85"

    # 3. Update fields
    db.update_entry(
        entry_id, 
        vault_key, 
        favorite=False, 
        password_strength=90
    )

    # 4. Verify Update
    updated = db.get_entry(entry_id, vault_key)
    assert updated['favorite'] is False
    assert updated['password_strength'] == 90

    db.close()
    time.sleep(0.1)
    os.remove(test_db)
    print("Advanced schema fields test passed!")

def test_audit_logging_triggers():
    """Test that DB triggers automatically create audit logs"""
    test_db = "data/test_vault_audit.db"
    
    if os.path.exists(test_db):
        os.remove(test_db)
    
    db = DatabaseManager(test_db)
    db.initialize_database()
    
    # Setup keys
    db.save_vault_metadata(os.urandom(16), os.urandom(32), os.urandom(32), os.urandom(12), os.urandom(16))
    vault_key = os.urandom(32)

    # 1. CREATE Action
    entry_id = db.add_entry(vault_key=vault_key, title="Audit Test")
    
    # Check logs
    logs = db.get_audit_logs()
    assert len(logs) > 0
    assert logs[0]['action_type'] == 'CREATE'
    assert logs[0]['entry_id'] == entry_id
    assert logs[0]['title'] == "Audit Test"

    # 2. UPDATE Action
    db.update_entry(entry_id, vault_key, title="Audit Updated")
    logs = db.get_audit_logs()
    # Most recent log should be first
    assert logs[0]['action_type'] == 'UPDATE'
    assert logs[0]['title'] == "Audit Updated"

    # 3. SOFT DELETE Action
    db.delete_entry(entry_id)
    logs = db.get_audit_logs()
    assert logs[0]['action_type'] == 'SOFT_DELETE'

    # 4. RESTORE Action
    db.restore_entry(entry_id)
    logs = db.get_audit_logs()
    assert logs[0]['action_type'] == 'RESTORE'

    db.close()
    time.sleep(0.1)
    os.remove(test_db)
    print("Audit logging triggers test passed!")

if __name__ == "__main__":
    test_database_connection()
    test_context_manager()
    test_database_initialization()
    test_vault_metadata_operations()
    test_unlock_timestamp_update()
    test_add_entry_invalid_vault_key()
    test_get_nonexistent_entry()
    test_list_entries()
    test_update_entry()
    test_delete_entry_soft_delete()
    test_restore_entry()
    test_entry_crud_roundtrip()
    test_advanced_schema_fields() 
    test_audit_logging_triggers()  
    print("\n ALL DATABASE TESTS PASSED!")