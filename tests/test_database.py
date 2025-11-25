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

if __name__ == "__main__":
    test_database_connection()
    test_context_manager()
    test_database_initialization()
    test_vault_metadata_operations()
    test_unlock_timestamp_update()
    print("\n ALL DATABASE TESTS PASSED!")