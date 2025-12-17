import os
import json
import base64
import hmac
import hashlib
import uuid
import pytest
from unittest.mock import MagicMock, patch, mock_open, call

from src.backup_manager import BackupManager

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def vault_keys():
    # (encryption_key, hmac_key)
    return (b"\x01" * 32, b"\x02" * 32)

@pytest.fixture
def hierarchy_keys():
    return {"vault_key": b"\x03" * 32}

@pytest.fixture
def mock_db():
    db = MagicMock()
    # Default mock entry
    mock_entry = {
        "id": "id1",
        "title": "Email",
        "username": "user",
        "password": "secret",
        "notes": "note",
        "category": "General",
        "favorite": False,
        "password_strength": 42,
    }
    
    db.get_all_entries.return_value = [mock_entry]
    db.get_entry.return_value = mock_entry

    # Mock connection for transaction handling
    conn = MagicMock()
    db.connect.return_value = conn
    conn.cursor.return_value = conn # cursor() returns self for chaining if needed
    
    return db

# ---------------------------------------------------------------------------
# Helper: Generate Valid Backup File
# ---------------------------------------------------------------------------

def create_signed_backup(filepath, header_dict, payload_dict, hmac_key):
    """Helper to create a structurally valid, HMAC-signed backup file."""
    header_bytes = json.dumps(header_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_bytes = json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    
    header_len = len(header_bytes).to_bytes(4, "big")
    
    signature = hmac.new(
        key=hmac_key,
        msg=header_bytes + payload_bytes,
        digestmod=hashlib.sha256
    ).digest()
    
    with open(filepath, "wb") as f:
        f.write(header_len)
        f.write(header_bytes)
        f.write(payload_bytes)
        f.write(signature)

# ---------------------------------------------------------------------------
# Constructor Validation
# ---------------------------------------------------------------------------

def test_init_rejects_non_dict_hierarchy(mock_db, vault_keys):
    with pytest.raises(ValueError):
        BackupManager(mock_db, vault_keys, hierarchy_keys=None)

def test_init_rejects_missing_vault_key(mock_db, vault_keys):
    with pytest.raises(ValueError):
        BackupManager(mock_db, vault_keys, {})

def test_init_rejects_bad_vault_key_length(mock_db, vault_keys):
    with pytest.raises(ValueError):
        BackupManager(mock_db, vault_keys, {"vault_key": b"x"})

def test_init_rejects_equal_enc_and_hmac_keys(mock_db):
    key = b"\x00" * 32
    with pytest.raises(ValueError):
        BackupManager(mock_db, (key, key), {"vault_key": b"\x01" * 32})

# ---------------------------------------------------------------------------
# create_backup
# ---------------------------------------------------------------------------

@patch("src.backup_manager.encrypt_entry", return_value=(b"c", b"n", b"t"))
@patch("builtins.open", new_callable=mock_open)
@patch("os.fsync") # <--- FIX: Mock fsync so we don't hit the real OS
def test_create_backup_success_all_entries(mock_fsync, mock_file, mock_encrypt, mock_db, vault_keys, hierarchy_keys):
    """Test full backup of all entries."""
    # We fake the file descriptor ID, which is passed to the mocked fsync
    mock_file.return_value.fileno.return_value = 10
    
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)

    assert mgr.create_backup("dummy.enc") is True

    # Verify we fetched all entries using the INTERNAL key
    mock_db.get_all_entries.assert_called_once_with(vault_key=hierarchy_keys["vault_key"])
    
    # Verify file writing happened
    handle = mock_file()
    handle.write.assert_called()
    
    # Verify durability calls
    handle.fileno.assert_called() 
    mock_fsync.assert_called_once()

@patch("src.backup_manager.encrypt_entry", return_value=(b"c", b"n", b"t"))
@patch("builtins.open", new_callable=mock_open)
@patch("os.fsync") # <--- FIX: Mock fsync here too
def test_create_backup_with_selection(mock_fsync, mock_file, mock_encrypt, mock_db, vault_keys, hierarchy_keys):
    """Test backup of specific entry IDs."""
    mock_file.return_value.fileno.return_value = 10

    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)

    target_ids = ["id1", "id2"]
    assert mgr.create_backup("dummy.enc", entries=target_ids) is True

    # Verify we fetched specific entries
    assert mock_db.get_entry.call_count == 2
    mock_db.get_entry.assert_has_calls([
        call("id1", hierarchy_keys["vault_key"]),
        call("id2", hierarchy_keys["vault_key"])
    ])
    mock_db.get_all_entries.assert_not_called()
    
    mock_fsync.assert_called_once()

def test_create_backup_rejects_bad_vault_keys_tuple(mock_db, hierarchy_keys):
    # This now fails at __init__ due to strict type checking
    with pytest.raises(ValueError):
        BackupManager(mock_db, vault_keys=("x",), hierarchy_keys=hierarchy_keys)

def test_create_backup_requires_internal_vault_key(mock_db, vault_keys):
    # This now fails at __init__ due to strict type checking
    with pytest.raises(ValueError):
        BackupManager(mock_db, vault_keys, hierarchy_keys={"vault_key": None})

def test_create_backup_wraps_internal_errors(mock_db, vault_keys, hierarchy_keys):
    mock_db.get_all_entries.side_effect = Exception("db explode")
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)

    with pytest.raises(RuntimeError) as e:
        mgr.create_backup("x")
    assert "Backup failed" in str(e.value)

# ---------------------------------------------------------------------------
# restore_backup — malformed file handling
# ---------------------------------------------------------------------------

def test_restore_rejects_too_short_file(mock_db, vault_keys, hierarchy_keys, tmp_path):
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
    p = tmp_path / "short.enc"
    p.write_bytes(b"\x00\x01") # < 4+32 bytes

    with pytest.raises(RuntimeError, match="too short"):
        mgr.restore_backup(str(p))

def test_restore_rejects_invalid_header_len(mock_db, vault_keys, hierarchy_keys, tmp_path):
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
    # Header length 99999 is too big
    raw = (99999).to_bytes(4, "big") + b"x" * 50
    p = tmp_path / "bad_len.enc"
    p.write_bytes(raw)

    with pytest.raises(RuntimeError, match="Invalid header"):
        mgr.restore_backup(str(p))

# ---------------------------------------------------------------------------
# restore_backup — Logical Validation (HMAC, Version, Counts)
# ---------------------------------------------------------------------------

def test_restore_rejects_hmac_mismatch(mock_db, vault_keys, hierarchy_keys, tmp_path):
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
    p = tmp_path / "tampered.enc"
    
    # Generate valid components
    create_signed_backup(
        p, 
        {"version": 1, "entry_count": 0}, 
        {"entries": []}, 
        hmac_key=vault_keys[1] # Correct key
    )
    
    # Tamper with the file (append a byte)
    with open(p, "ab") as f:
        f.write(b"\x00")

    with pytest.raises(RuntimeError, match="HMAC mismatch"):
        mgr.restore_backup(str(p))

def test_restore_rejects_unsupported_version(mock_db, vault_keys, hierarchy_keys, tmp_path):
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
    p = tmp_path / "v2.enc"
    
    create_signed_backup(
        p,
        {"version": 2, "entry_count": 0}, # Unsupported version
        {"entries": []},
        hmac_key=vault_keys[1]
    )

    with pytest.raises(RuntimeError, match="Unsupported backup version"):
        mgr.restore_backup(str(p))

def test_restore_rejects_entry_count_mismatch(mock_db, vault_keys, hierarchy_keys, tmp_path):
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
    p = tmp_path / "count_fail.enc"
    
    create_signed_backup(
        p,
        {"version": 1, "entry_count": 5}, # Claim 5
        {"entries": []},                  # Provide 0
        hmac_key=vault_keys[1]
    )

    with pytest.raises(RuntimeError, match="entry_count mismatch"):
        mgr.restore_backup(str(p))

# ---------------------------------------------------------------------------
# restore_backup — Happy Path
# ---------------------------------------------------------------------------

@patch("src.backup_manager.decrypt_entry")
@patch("src.backup_manager.encrypt_entry", return_value=(b"c", b"n", b"t"))
@patch("src.backup_manager.derive_hkdf_key", return_value=b"\x04" * 32)
@patch("src.backup_manager.generate_salt", return_value=b"\x05" * 16)
def test_restore_backup_success(
    _salt, _hkdf, _encrypt, mock_decrypt,
    mock_db, vault_keys, hierarchy_keys, tmp_path
):
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
    p = tmp_path / "ok.enc"

    # 1. Prepare valid payload
    entry_payload = {
        "ciphertext": base64.b64encode(b"x").decode(),
        "nonce": base64.b64encode(b"y").decode(),
        "tag": base64.b64encode(b"z").decode(),
    }
    
    create_signed_backup(
        p,
        {"version": 1, "entry_count": 1},
        {"entries": [entry_payload]},
        hmac_key=vault_keys[1]
    )

    # 2. Mock decryption to return valid entry JSON
    mock_decrypt.return_value = json.dumps({
        "id": "id1",
        "title": "Restored Entry",
        "username": "user",
        "password": "secret", 
        "notes": "notes",
        "category": "Work",
        "favorite": True,
        "password_strength": 100
    })

    # 3. Execute
    assert mgr.restore_backup(str(p)) is True

    # 4. Verify DB Interactions
    conn = mock_db.connect.return_value
    conn.cursor.return_value.execute.assert_called()
    
    # Ensure BEGIN IMMEDIATE was called
    calls = conn.cursor.return_value.execute.call_args_list
    assert "BEGIN IMMEDIATE" in str(calls[0])
    
    # Ensure Insert was called
    insert_call = [c for c in calls if "INSERT OR REPLACE" in str(c)]
    assert len(insert_call) == 1
    
    # Ensure Commit
    conn.commit.assert_called_once()

# ---------------------------------------------------------------------------
# restore_backup — DB Rollback
# ---------------------------------------------------------------------------

@patch("src.backup_manager.decrypt_entry", side_effect=Exception("Decryption Corrupted"))
def test_restore_backup_rolls_back_on_entry_failure(
    _decrypt, mock_db, vault_keys, hierarchy_keys, tmp_path
):
    """
    Test that if one entry fails to process (e.g. decrypt error), 
    the entire transaction is rolled back.
    """
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
    p = tmp_path / "rollback.enc"

    # Create a VALID signed file so we pass the HMAC check and reach the processing loop
    entry_payload = {
        "ciphertext": base64.b64encode(b"x").decode(),
        "nonce": base64.b64encode(b"y").decode(),
        "tag": base64.b64encode(b"z").decode(),
    }
    create_signed_backup(
        p,
        {"version": 1, "entry_count": 1},
        {"entries": [entry_payload]},
        hmac_key=vault_keys[1]
    )

    # Execute
    with pytest.raises(RuntimeError, match="Restore failed"):
        mgr.restore_backup(str(p))

    # Verify Rollback
    conn = mock_db.connect.return_value
    conn.rollback.assert_called_once()
    # Ensure commit was NEVER called
    conn.commit.assert_not_called()