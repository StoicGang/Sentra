import json
import pytest
from unittest.mock import MagicMock, patch, ANY

from src.vault_controller import (
    VaultController,
    VaultError,
    VaultLockedError,
    VaultAlreadyUnlockedError,
    CriticalVaultError,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_db():
    db = MagicMock()
    db.initialize_database.return_value = True
    db.load_vault_metadata.return_value = None
    db.save_vault_metadata.return_value = True
    db.update_unlock_timestamp.return_value = True
    db.add_entry.return_value = "new-uuid"
    db.update_entry.return_value = True
    return db

@pytest.fixture
def mock_secure_mem():
    sm = MagicMock()
    # Simulate successful locking returning a handle object
    sm.lock_memory.side_effect = lambda buf: MagicMock(addr=1, length=len(buf), locked=True)
    sm.zeroize.return_value = True
    sm.unlock_memory.return_value = True
    sm.protect_from_fork.return_value = True
    return sm

@pytest.fixture
def mock_lockout():
    al = MagicMock()
    al.check_and_delay.return_value = (True, 0)
    al.record_failure.return_value = None
    al.reset_session.return_value = None
    return al

@pytest.fixture
def mock_pw_gen():
    pg = MagicMock()
    # Default strength return: score, label, diag
    pg.calculate_strength.return_value = (75, "Good", {})
    return pg

@pytest.fixture
def controller(mock_db, mock_secure_mem, mock_lockout, mock_pw_gen):
    # Patch dependencies to isolate Controller logic
    with patch("src.vault_controller.DatabaseManager", return_value=mock_db), \
         patch("src.vault_controller.SecureMemory", return_value=mock_secure_mem), \
         patch("src.vault_controller.AdaptiveLockout", return_value=mock_lockout), \
         patch("src.vault_controller.PasswordGenerator", return_value=mock_pw_gen):
        
        return VaultController(db_path=":memory:")

# ---------------------------------------------------------------------------
# vault_exists
# ---------------------------------------------------------------------------

def test_vault_exists_false_when_no_metadata(controller, mock_db):
    mock_db.load_vault_metadata.return_value = None
    assert controller.vault_exists() is False
    # Should attempt to init schema just in case
    mock_db.initialize_database.assert_called()

def test_vault_exists_true_when_metadata_present(controller, mock_db):
    mock_db.load_vault_metadata.return_value = {"salt": b"x"}
    assert controller.vault_exists() is True

def test_vault_exists_handles_db_error(controller, mock_db):
    mock_db.load_vault_metadata.side_effect = Exception("boom")
    
    # FIX: Catch the expected warning so it doesn't clutter output
    with pytest.warns(RuntimeWarning, match="vault_exists"):
        assert controller.vault_exists() is False

# ---------------------------------------------------------------------------
# unlock_vault — new vault path
# ---------------------------------------------------------------------------

@patch("src.vault_controller.generate_salt", return_value=b"s"*16)
@patch("src.vault_controller.derive_master_key", return_value=b"m"*32)
@patch("src.vault_controller.generate_key", return_value=b"v"*32)
@patch("src.vault_controller.compute_auth_hash", return_value=b"h"*32)
@patch("src.vault_controller.encrypt_entry", return_value=(b"c", b"n", b"t"))
@patch("src.vault_controller.decrypt_entry")
def test_unlock_new_vault_success(
    mock_decrypt, _e, _c, _g, _m, _s,
    controller, mock_db
):
    # 1. First call returns None (starts new vault flow)
    # 2. Second call returns valid metadata (verification step)
    valid_meta = {
        "salt": b"s"*16, "auth_hash": b"h"*32, 
        "vault_key_encrypted": b"c", "vault_key_nonce": b"n", "vault_key_tag": b"t",
        "kdf_config": json.dumps({})
    }
    mock_db.load_vault_metadata.side_effect = [None, valid_meta]

    # Setup decrypt to succeed round-trip verification
    # "76" hex is 'v' (118), matching our mocked generate_key b"v"*32
    mock_decrypt.return_value = json.dumps({"vault_key": ("76"*32)}) 

    assert controller.unlock_vault("password") is True
    assert controller.is_unlocked is True
    assert controller.master_key_secure is not None
    assert controller.vault_key_secure is not None

def test_unlock_rejects_empty_password(controller):
    with pytest.raises(VaultError):
        controller.unlock_vault("")

def test_unlock_fails_if_already_unlocked(controller):
    controller.is_unlocked = True
    with pytest.raises(VaultAlreadyUnlockedError):
        controller.unlock_vault("pw")

@patch("src.vault_controller.derive_master_key", return_value=b"m"*32)
@patch("src.vault_controller.generate_key", return_value=b"v"*32)
@patch("src.vault_controller.encrypt_entry", return_value=(b"c", b"n", b"t"))
@patch("src.vault_controller.decrypt_entry", return_value=json.dumps({"vault_key": "BAD_KEY"}))
def test_unlock_fails_on_key_mismatch(_d, _e, _g, _m, controller, mock_db):
    """Test the round-trip integrity check for new vaults."""
    # 1. First call returns None (starts new vault flow)
    # 2. Second call returns metadata (to proceed to verification step)
    valid_meta = {
        "salt": b"s"*16, "auth_hash": b"h"*32, 
        "vault_key_encrypted": b"c", "vault_key_nonce": b"n", "vault_key_tag": b"t",
        "kdf_config": json.dumps({})
    }
    mock_db.load_vault_metadata.side_effect = [None, valid_meta]

    # FIX: Expect CriticalVaultError because controller wraps the ValueError
    with pytest.raises(CriticalVaultError, match="Vault key mismatch"):
        controller.unlock_vault("password")

# ---------------------------------------------------------------------------
# unlock_vault — existing vault path
# ---------------------------------------------------------------------------

def _existing_metadata():
    return {
        "salt": b"s"*16,
        "auth_hash": b"h"*32,
        "vault_key_encrypted": b"c",
        "vault_key_nonce": b"n",
        "vault_key_tag": b"t",
        "kdf_config": json.dumps({
            "time_cost": 3,
            "memory_cost": 65536,
            "parallelism": 1,
            "salt_len": 16,
            "hash_len": 32,
        })
    }

@patch("src.vault_controller.verify_auth_hash", return_value=True)
@patch("src.vault_controller.derive_master_key", return_value=b"m"*32)
@patch("src.vault_controller.decrypt_entry", return_value=json.dumps({"vault_key": "76"*32}))
def test_unlock_existing_vault_success(
    _d, _m, _v,
    controller, mock_db
):
    mock_db.load_vault_metadata.return_value = _existing_metadata()
    assert controller.unlock_vault("password") is True
    assert controller.is_unlocked is True

@patch("src.vault_controller.verify_auth_hash", return_value=False)
def test_unlock_existing_invalid_password(
    _verify, controller, mock_db, mock_lockout
):
    mock_db.load_vault_metadata.return_value = _existing_metadata()
    with pytest.raises(VaultError, match="Invalid password"):
        controller.unlock_vault("wrong")
    
    # Ensure failure was recorded in adaptive lockout
    mock_lockout.record_failure.assert_called_once()

# ---------------------------------------------------------------------------
# lock_vault
# ---------------------------------------------------------------------------

def test_lock_vault_zeroizes_and_resets(controller, mock_secure_mem):
    controller.is_unlocked = True
    controller.master_key_secure = bytearray(b"a"*32)
    controller.vault_key_secure = bytearray(b"b"*32)
    controller.master_key_handle = MagicMock()
    controller.vault_key_handle = MagicMock()

    assert controller.lock_vault() is True
    assert controller.is_unlocked is False
    assert controller.master_key_secure is None
    assert controller.vault_key_secure is None
    
    # Verify secure memory interactions
    assert mock_secure_mem.zeroize.call_count >= 2
    assert mock_secure_mem.unlock_memory.call_count >= 2

# ---------------------------------------------------------------------------
# CRUD Operations (Logic Delegation)
# ---------------------------------------------------------------------------

def test_add_password_calculates_strength(controller, mock_db, mock_pw_gen):
    """Ensure add_password calls strength calculator and passes result to DB."""
    controller.is_unlocked = True
    controller.vault_key_secure = bytearray(b"v"*32)
    mock_pw_gen.calculate_strength.return_value = (85, "Strong", {})

    controller.add_password("MyTitle", password="secure_pass")

    # Verify calculator called
    mock_pw_gen.calculate_strength.assert_called_with("secure_pass")
    
    # Verify score passed to DB
    mock_db.add_entry.assert_called_once()
    args, kwargs = mock_db.add_entry.call_args
    assert kwargs["password_strength"] == 85

def test_update_entry_recalculates_strength(controller, mock_db, mock_pw_gen):
    """Ensure update_entry recalculates strength if password changes."""
    controller.is_unlocked = True
    controller.vault_key_secure = bytearray(b"v"*32)
    mock_pw_gen.calculate_strength.return_value = (40, "Weak", {})

    controller.update_entry("id1", password="new_weak_pass")

    mock_pw_gen.calculate_strength.assert_called_with("new_weak_pass")
    
    mock_db.update_entry.assert_called_once()
    _, kwargs = mock_db.update_entry.call_args
    assert kwargs["password_strength"] == 40

def test_search_entries_delegates_to_db(controller, mock_db):
    controller.is_unlocked = True
    controller.search_entries("query")
    mock_db.search_entries.assert_called_with("query", False, 50, 0)

# ---------------------------------------------------------------------------
# Locked-state enforcement
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("method,args", [
    ("add_password", ("t",)),
    ("get_password", ("id",)),
    ("list_entries", ()),
    ("search_entries", ("q",)),
    ("update_entry", ("id",)),
    ("delete_entry", ("id",)),
    ("restore_entry", ("id",)),
    ("view_audit_log", ()),
    ("get_backup_keys", ()),
    ("create_backup_manager", ()),
])
def test_methods_fail_when_locked(controller, method, args):
    controller.is_unlocked = False
    with pytest.raises(VaultLockedError):
        getattr(controller, method)(*args)

# ---------------------------------------------------------------------------
# Backup keys & manager
# ---------------------------------------------------------------------------

@patch("src.vault_controller.derive_hkdf_key", side_effect=[b"enc", b"hmac"])
def test_get_backup_keys_success(_hkdf, controller):
    controller.is_unlocked = True
    controller.master_key_secure = bytearray(b"m"*32)
    controller.vault_key_secure = bytearray(b"v"*32)

    enc, mac = controller.get_backup_keys()
    assert enc == b"enc"
    assert mac == b"hmac"

@patch("src.vault_controller.BackupManager")
def test_create_backup_manager_success(mock_bm_cls, controller):
    """Verify BackupManager is instantiated with correct keys."""
    controller.is_unlocked = True
    controller.master_key_secure = bytearray(b"m"*32)
    controller.vault_key_secure = bytearray(b"v"*32)

    with patch.object(controller, 'get_backup_keys', return_value=(b"e", b"h")):
        mgr = controller.create_backup_manager()
        
        mock_bm_cls.assert_called_once()
        _, kwargs = mock_bm_cls.call_args
        
        # Verify db passed
        assert kwargs["db"] == controller.db
        
        # Verify tuple passed for vault_keys
        assert kwargs["vault_keys"] == (b"e", b"h")
        
        # Verify hierarchy dict passed with INTERNAL key (from secure mem)
        assert kwargs["hierarchy_keys"]["vault_key"] == b"v"*32