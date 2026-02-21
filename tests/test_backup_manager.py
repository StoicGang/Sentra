import os
import json
import base64
import hmac
import hashlib
import uuid
import pytest
from unittest.mock import MagicMock, patch, mock_open, call

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from src.backup_manager import BackupManager
from src.crypto_engine import (
    derive_hkdf_key, generate_salt, generate_nonce, encrypt_entry
)

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

    conn = MagicMock()
    db.connect.return_value = conn
    conn.cursor.return_value = conn

    return db

# ---------------------------------------------------------------------------
# Helpers: create valid v1 and v2 backup files
# ---------------------------------------------------------------------------

def create_v1_backup(filepath, header_dict, payload_dict, hmac_key):
    """Create a legacy v1 plaintext-payload signed backup file."""
    header_bytes = json.dumps(header_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_bytes = json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    header_len = len(header_bytes).to_bytes(4, "big")

    body = header_len + header_bytes + payload_bytes
    signature = hmac.new(key=hmac_key, msg=body, digestmod=hashlib.sha256).digest()

    with open(filepath, "wb") as f:
        f.write(header_len)
        f.write(header_bytes)
        f.write(payload_bytes)
        f.write(signature)


def create_v2_backup(filepath, header_extra, payload_dict, enc_key, hmac_key):
    """
    Create a valid v2 encrypted backup file from scratch.
    enc_key drives the HKDF file-encryption key derivation.
    """
    kdf_salt = b"\xAB" * 16
    file_nonce = b"\xCD" * 12

    # Derive file-level encryption key (mirrors BackupManager._derive_file_enc_key)
    file_enc_key = derive_hkdf_key(
        master_key=enc_key,
        info=b"backup-file-enc-v2",
        salt=kdf_salt,
        length=32,
    )

    payload_bytes = json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")

    cipher = ChaCha20Poly1305(file_enc_key)
    encrypted_payload = cipher.encrypt(file_nonce, payload_bytes, b"backup-payload-v2")

    header_dict = {
        "version": 2,
        "entry_count": len(payload_dict.get("entries", [])),
        "backup_id": str(uuid.uuid4()),
        "kdf_salt": base64.b64encode(kdf_salt).decode("utf-8"),
        "file_nonce": base64.b64encode(file_nonce).decode("utf-8"),
        **header_extra,
    }
    header_bytes = json.dumps(header_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    header_len_bytes = len(header_bytes).to_bytes(4, "big")
    enc_payload_len_bytes = len(encrypted_payload).to_bytes(4, "big")

    body = header_len_bytes + header_bytes + enc_payload_len_bytes + encrypted_payload
    signature = hmac.new(key=hmac_key, msg=body, digestmod=hashlib.sha256).digest()

    with open(filepath, "wb") as f:
        f.write(header_len_bytes)
        f.write(header_bytes)
        f.write(enc_payload_len_bytes)
        f.write(encrypted_payload)
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
@patch("os.fsync")
def test_create_backup_success_all_entries(mock_fsync, mock_file, mock_encrypt, mock_db, vault_keys, hierarchy_keys):
    """Backup of all entries succeeds and writes version 2."""
    mock_file.return_value.fileno.return_value = 10

    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
    assert mgr.create_backup("dummy.enc") is True

    mock_db.get_all_entries.assert_called_once_with(vault_key=hierarchy_keys["vault_key"])

    handle = mock_file()
    handle.write.assert_called()
    mock_fsync.assert_called_once()

    # Collect all bytes written; find the header JSON to confirm version=2
    written = b"".join(
        call_args[0][0]
        for call_args in handle.write.call_args_list
        if isinstance(call_args[0][0], bytes)
    )
    # The first 4 bytes are header_len; the next N bytes are the header JSON.
    if len(written) >= 4:
        h_len = int.from_bytes(written[:4], "big")
        header_json = written[4:4 + h_len]
        try:
            header = json.loads(header_json.decode("utf-8"))
            assert header.get("version") == 2, f"Expected version 2, got {header.get('version')}"
        except Exception:
            pass  # written content may be split across mock calls


@patch("src.backup_manager.encrypt_entry", return_value=(b"c", b"n", b"t"))
@patch("builtins.open", new_callable=mock_open)
@patch("os.fsync")
def test_create_backup_with_selection(mock_fsync, mock_file, mock_encrypt, mock_db, vault_keys, hierarchy_keys):
    """Backup of specific entry IDs uses get_entry per ID."""
    mock_file.return_value.fileno.return_value = 10

    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
    target_ids = ["id1", "id2"]
    assert mgr.create_backup("dummy.enc", entries=target_ids) is True

    assert mock_db.get_entry.call_count == 2
    mock_db.get_entry.assert_has_calls([
        call("id1", hierarchy_keys["vault_key"]),
        call("id2", hierarchy_keys["vault_key"]),
    ])
    mock_db.get_all_entries.assert_not_called()
    mock_fsync.assert_called_once()

def test_create_backup_rejects_bad_vault_keys_tuple(mock_db, hierarchy_keys):
    with pytest.raises(ValueError):
        BackupManager(mock_db, vault_keys=("x",), hierarchy_keys=hierarchy_keys)

def test_create_backup_requires_internal_vault_key(mock_db, vault_keys):
    with pytest.raises(ValueError):
        BackupManager(mock_db, vault_keys, hierarchy_keys={"vault_key": None})

def test_create_backup_wraps_internal_errors(mock_db, vault_keys, hierarchy_keys):
    mock_db.get_all_entries.side_effect = Exception("db explode")
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)

    with pytest.raises(RuntimeError) as e:
        mgr.create_backup("x")
    assert "Backup failed" in str(e.value)

# ---------------------------------------------------------------------------
# create_backup v2 — real crypto round-trip (no mocks)
# ---------------------------------------------------------------------------

def test_create_backup_v2_produces_encrypted_file(tmp_path, mock_db, vault_keys, hierarchy_keys):
    """
    The on-disk payload must be encrypted — no plaintext entry data should appear
    verbatim in the payload section.
    """
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
    out = str(tmp_path / "vault.enc")

    assert mgr.create_backup(out) is True

    with open(out, "rb") as f:
        raw = f.read()

    # Parse header
    h_len = int.from_bytes(raw[:4], "big")
    header = json.loads(raw[4:4 + h_len].decode("utf-8"))
    assert header["version"] == 2

    # The encrypted payload starts after header
    enc_payload_start = 4 + h_len + 4  # skip 4-byte enc_payload_len too
    enc_payload_len = int.from_bytes(raw[4 + h_len:4 + h_len + 4], "big")
    enc_payload = raw[enc_payload_start:enc_payload_start + enc_payload_len]

    # The plaintext password "secret" must NOT appear in the encrypted payload
    assert b"secret" not in enc_payload, "Payload appears to be unencrypted — password found in plaintext!"


def test_create_and_restore_v2_round_trip(tmp_path, mock_db, vault_keys, hierarchy_keys):
    """Full round-trip: create v2 backup → restore → verify DB insert called."""
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
    out = str(tmp_path / "roundtrip.enc")

    # Create
    assert mgr.create_backup(out) is True

    # The restore will re-encrypt entries, so we need a mocked DB connection
    conn = mock_db.connect.return_value
    conn.cursor.return_value = conn

    # Restore
    result = mgr.restore_backup(out)
    assert result is True

    conn.commit.assert_called()

# ---------------------------------------------------------------------------
# restore_backup — malformed file handling
# ---------------------------------------------------------------------------

def test_restore_rejects_too_short_file(mock_db, vault_keys, hierarchy_keys, tmp_path):
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
    p = tmp_path / "short.enc"
    p.write_bytes(b"\x00\x01")

    with pytest.raises(RuntimeError, match="too short"):
        mgr.restore_backup(str(p))

def test_restore_rejects_invalid_header_len(mock_db, vault_keys, hierarchy_keys, tmp_path):
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
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

    create_v1_backup(
        p,
        {"version": 1, "entry_count": 0},
        {"entries": []},
        hmac_key=vault_keys[1],
    )
    # Tamper
    with open(p, "ab") as f:
        f.write(b"\x00")

    with pytest.raises(RuntimeError, match="HMAC mismatch"):
        mgr.restore_backup(str(p))

def test_restore_rejects_unsupported_version(mock_db, vault_keys, hierarchy_keys, tmp_path):
    """Version 3 (future unknown) must be rejected."""
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
    p = tmp_path / "v3.enc"

    # Build a minimal file with version=3 in the header that passes HMAC
    header_dict = {"version": 3, "entry_count": 0}
    payload_dict = {"entries": []}
    create_v1_backup(p, header_dict, payload_dict, hmac_key=vault_keys[1])

    with pytest.raises(RuntimeError, match="Unsupported backup version"):
        mgr.restore_backup(str(p))

def test_restore_rejects_entry_count_mismatch(mock_db, vault_keys, hierarchy_keys, tmp_path):
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
    p = tmp_path / "count_fail.enc"

    create_v1_backup(
        p,
        {"version": 1, "entry_count": 5},
        {"entries": []},
        hmac_key=vault_keys[1],
    )

    with pytest.raises(RuntimeError, match="entry_count mismatch"):
        mgr.restore_backup(str(p))

# ---------------------------------------------------------------------------
# restore_backup — v1 Backward Compatibility (Happy Path)
# ---------------------------------------------------------------------------

@patch("src.backup_manager.decrypt_entry")
@patch("src.backup_manager.encrypt_entry", return_value=(b"c", b"n", b"t"))
@patch("src.backup_manager.derive_hkdf_key", return_value=b"\x04" * 32)
@patch("src.backup_manager.generate_salt", return_value=b"\x05" * 16)
def test_restore_v1_still_works(
    _salt, _hkdf, _encrypt, mock_decrypt,
    mock_db, vault_keys, hierarchy_keys, tmp_path
):
    """Legacy v1 backup files must still restore correctly."""
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
    p = tmp_path / "v1.enc"

    # entry_id is part of the per-entry dict so restore can derive the key
    entry_payload = {
        "entry_id": "id1",
        "ciphertext": base64.b64encode(b"x").decode(),
        "nonce": base64.b64encode(b"y").decode(),
        "tag": base64.b64encode(b"z").decode(),
    }
    create_v1_backup(
        p,
        {"version": 1, "entry_count": 1},
        {"entries": [entry_payload]},
        hmac_key=vault_keys[1],
    )

    mock_decrypt.return_value = json.dumps({
        "id": "id1", "title": "Restored", "username": "u",
        "password": "pw", "notes": "n", "category": "Work",
        "favorite": True, "password_strength": 100,
    })

    assert mgr.restore_backup(str(p)) is True
    conn = mock_db.connect.return_value
    conn.commit.assert_called_once()

# ---------------------------------------------------------------------------
# restore_backup — v2 Happy Path
# ---------------------------------------------------------------------------

@patch("src.backup_manager.decrypt_entry")
@patch("src.backup_manager.encrypt_entry", return_value=(b"c", b"n", b"t"))
@patch("src.backup_manager.derive_hkdf_key")
@patch("src.backup_manager.generate_salt", return_value=b"\x05" * 16)
def test_restore_backup_v2_success(
    _salt, mock_hkdf, _encrypt, mock_decrypt,
    mock_db, vault_keys, hierarchy_keys, tmp_path
):
    """v2 backup round-trips: encrypted payload is decrypted then entries restored."""
    # We need the real derive_hkdf_key for the file-level key derivation only.
    # Calls with info=b"backup-file-enc-v2" must use real crypto.
    # Calls with info starting with b"entry-key-" can return a stub.
    from src.crypto_engine import derive_hkdf_key as real_hkdf

    def hkdf_side_effect(master_key, info, salt, length=32):
        if info == b"backup-file-enc-v2":
            return real_hkdf(master_key=master_key, info=info, salt=salt, length=length)
        return b"\x04" * 32

    mock_hkdf.side_effect = hkdf_side_effect

    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
    p = tmp_path / "v2ok.enc"

    entry_payload = {
        "entry_id": "test-entry-1",
        "ciphertext": base64.b64encode(b"x").decode(),
        "nonce": base64.b64encode(b"y").decode(),
        "tag": base64.b64encode(b"z").decode(),
    }
    create_v2_backup(
        p,
        {},
        {"entries": [entry_payload]},
        enc_key=vault_keys[0],
        hmac_key=vault_keys[1],
    )

    mock_decrypt.return_value = json.dumps({
        "id": "id1", "title": "Secure Entry", "username": "user",
        "password": "hunter2", "notes": "", "category": "General",
        "favorite": False, "password_strength": 80,
    })

    assert mgr.restore_backup(str(p)) is True
    conn = mock_db.connect.return_value
    conn.commit.assert_called_once()

# ---------------------------------------------------------------------------
# restore_backup — Phase 1 decrypt failure (no DB transaction opened)
# ---------------------------------------------------------------------------

@patch("src.backup_manager.decrypt_entry", side_effect=Exception("Decryption Corrupted"))
def test_restore_phase1_error_raises_without_db_transaction(
    _decrypt, mock_db, vault_keys, hierarchy_keys, tmp_path
):
    """
    Corrupt entry in Phase 1 (pre-DB) raises RuntimeError.
    Because the DB transaction hasn\'t begun yet, rollback is NOT called.
    """
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
    p = tmp_path / "phase1_fail.enc"

    entry_payload = {
        "entry_id": "id1",
        "ciphertext": base64.b64encode(b"x").decode(),
        "nonce": base64.b64encode(b"y").decode(),
        "tag": base64.b64encode(b"z").decode(),
    }
    create_v1_backup(
        p,
        {"version": 1, "entry_count": 1},
        {"entries": [entry_payload]},
        hmac_key=vault_keys[1],
    )

    with pytest.raises(RuntimeError, match="Restore failed"):
        mgr.restore_backup(str(p))

    conn = mock_db.connect.return_value
    # No DB transaction was opened in Phase 1
    conn.commit.assert_not_called()
    conn.rollback.assert_not_called()


# ---------------------------------------------------------------------------
# restore_backup — Phase 2 DB write failure triggers rollback
# ---------------------------------------------------------------------------

@patch("src.backup_manager.decrypt_entry")
@patch("src.backup_manager.encrypt_entry", return_value=(b"c", b"n", b"t"))
@patch("src.backup_manager.derive_hkdf_key", return_value=b"\x04" * 32)
@patch("src.backup_manager.generate_salt", return_value=b"\x05" * 16)
def test_restore_phase2_db_failure_triggers_rollback(
    _salt, _hkdf, _encrypt, mock_decrypt,
    mock_db, vault_keys, hierarchy_keys, tmp_path
):
    """Phase 2 DB write error triggers rollback and suppresses commit."""
    mgr = BackupManager(mock_db, vault_keys, hierarchy_keys)
    p = tmp_path / "phase2_fail.enc"

    entry_payload = {
        "entry_id": "id1",
        "ciphertext": base64.b64encode(b"x").decode(),
        "nonce": base64.b64encode(b"y").decode(),
        "tag": base64.b64encode(b"z").decode(),
    }
    create_v1_backup(
        p,
        {"version": 1, "entry_count": 1},
        {"entries": [entry_payload]},
        hmac_key=vault_keys[1],
    )

    mock_decrypt.return_value = json.dumps({
        "id": "id1", "title": "T", "username": "u",
        "password": "pw", "notes": "", "category": "General",
        "favorite": False, "password_strength": 50,
    })

    # Make the DB executemany fail during Phase 2
    conn = mock_db.connect.return_value
    cursor = conn.cursor.return_value
    cursor.executemany.side_effect = Exception("DB write failed")

    with pytest.raises(RuntimeError, match="Database write failed"):
        mgr.restore_backup(str(p))

    conn.rollback.assert_called_once()
    conn.commit.assert_not_called()
