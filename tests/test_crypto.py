import pytest
import json
import time
from unittest.mock import patch, MagicMock
from cryptography.exceptions import InvalidTag
from argon2.exceptions import HashingError

from src.crypto_engine import (
    generate_salt,
    generate_nonce,
    generate_key,
    derive_master_key,
    compute_auth_hash,
    verify_auth_hash,
    benchmark_argon2_params,
    encrypt_entry,
    decrypt_entry,
    compute_hmac,
    derive_hkdf_key,
    MIN_MEMORY_KB,
    MAX_MEMORY_KB,
)

# ---------------------------------------------------------------------------
# Random Generation
# ---------------------------------------------------------------------------

def test_generate_salt_length_and_uniqueness():
    s1 = generate_salt()
    s2 = generate_salt()
    assert isinstance(s1, bytes)
    assert len(s1) == 16
    assert s1 != s2

def test_generate_nonce_length_and_uniqueness():
    n1 = generate_nonce()
    n2 = generate_nonce()
    assert isinstance(n1, bytes)
    assert len(n1) == 12
    assert n1 != n2

def test_generate_key_length_and_uniqueness():
    k1 = generate_key()
    k2 = generate_key()
    assert isinstance(k1, bytes)
    assert len(k1) == 32
    assert k1 != k2

# ---------------------------------------------------------------------------
# Argon2 Master Key Derivation
# ---------------------------------------------------------------------------

def test_derive_master_key_success():
    salt = generate_salt()
    key = derive_master_key("password", salt)
    assert isinstance(key, bytes)
    assert len(key) == 32

def test_derive_master_key_deterministic():
    salt = generate_salt()
    k1 = derive_master_key("password", salt)
    k2 = derive_master_key("password", salt)
    assert k1 == k2

def test_derive_master_key_rejects_non_int_memory():
    salt = generate_salt()
    with pytest.raises(ValueError):
        derive_master_key("pw", salt, memory_cost="64MB")

def test_derive_master_key_rejects_low_memory():
    salt = generate_salt()
    with pytest.raises(ValueError):
        derive_master_key("pw", salt, memory_cost=MIN_MEMORY_KB - 1)

def test_derive_master_key_rejects_excessive_memory():
    salt = generate_salt()
    with pytest.raises(ValueError):
        derive_master_key("pw", salt, memory_cost=MAX_MEMORY_KB + 1)

@patch("src.crypto_engine.low_level.hash_secret_raw")
def test_derive_master_key_wraps_hashing_error(mock_argon2):
    """Test that internal Argon2 errors are caught and re-raised as RuntimeError."""
    mock_argon2.side_effect = HashingError("Simulated Failure")
    salt = generate_salt()
    
    with pytest.raises(RuntimeError, match="Argon2id key derivation failed"):
        derive_master_key("password", salt)

# ---------------------------------------------------------------------------
# Authentication Hash (PBKDF2)
# ---------------------------------------------------------------------------

def test_compute_auth_hash_deterministic():
    salt = generate_salt()
    h1 = compute_auth_hash("password", salt)
    h2 = compute_auth_hash("password", salt)
    assert h1 == h2
    assert len(h1) == 32

def test_compute_auth_hash_accepts_bytes_password():
    """Test that bytes password input is handled correctly."""
    salt = generate_salt()
    h1 = compute_auth_hash("password", salt)
    h2 = compute_auth_hash(b"password", salt)
    assert h1 == h2

def test_verify_auth_hash_success_and_failure():
    salt = generate_salt()
    stored = compute_auth_hash("password", salt)

    assert verify_auth_hash(stored, "password", salt) is True
    assert verify_auth_hash(stored, "wrong", salt) is False

# ---------------------------------------------------------------------------
# Encryption / Decryption (ChaCha20-Poly1305)
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_roundtrip():
    key = generate_key()
    plaintext = json.dumps({"secret": "data"})
    aad = b"context"

    c, n, t = encrypt_entry(plaintext, key, aad)
    out = decrypt_entry(c, n, t, key, aad)

    assert out == plaintext

def test_encrypt_decrypt_none_aad():
    """Test implicit default AAD (b'') when None is passed."""
    key = generate_key()
    plaintext = "secret"
    
    # Encrypt with None
    c, n, t = encrypt_entry(plaintext, key, associated_data=None)
    
    # Decrypt with None
    out = decrypt_entry(c, n, t, key, associated_data=None)
    assert out == plaintext

def test_decrypt_fails_with_wrong_key():
    key = generate_key()
    wrong_key = generate_key()
    plaintext = "secret"

    c, n, t = encrypt_entry(plaintext, key)
    with pytest.raises(InvalidTag):
        decrypt_entry(c, n, t, wrong_key)

def test_decrypt_fails_with_modified_ciphertext():
    key = generate_key()
    plaintext = "secret"

    c, n, t = encrypt_entry(plaintext, key)
    tampered = c[:-1] + bytes([c[-1] ^ 0xFF])

    with pytest.raises(InvalidTag):
        decrypt_entry(tampered, n, t, key)

def test_decrypt_fails_with_wrong_aad():
    key = generate_key()
    plaintext = "secret"

    c, n, t = encrypt_entry(plaintext, key, b"aad1")
    with pytest.raises(InvalidTag):
        decrypt_entry(c, n, t, key, b"aad2")

@patch("src.crypto_engine.ChaCha20Poly1305")
def test_encrypt_wraps_generic_error(mock_cipher_cls):
    """Test that generic encryption errors are wrapped."""
    mock_instance = mock_cipher_cls.return_value
    mock_instance.encrypt.side_effect = Exception("Crypto failure")
    
    key = generate_key()
    with pytest.raises(RuntimeError, match="Encryption failed"):
        encrypt_entry("data", key)

@patch("src.crypto_engine.ChaCha20Poly1305")
def test_decrypt_wraps_generic_error(mock_cipher_cls):
    """Test that generic decryption errors (not InvalidTag) are wrapped."""
    mock_instance = mock_cipher_cls.return_value
    mock_instance.decrypt.side_effect = Exception("Crypto failure")
    
    key = generate_key()
    with pytest.raises(RuntimeError, match="Decryption failed"):
        decrypt_entry(b"c", b"n", b"t", key)

# ---------------------------------------------------------------------------
# HMAC
# ---------------------------------------------------------------------------

def test_compute_hmac_deterministic_and_sensitive():
    key = generate_key()
    data = b"important"

    h1 = compute_hmac(data, key)
    h2 = compute_hmac(data, key)

    assert h1 == h2
    assert len(h1) == 32

    assert compute_hmac(b"important!", key) != h1

def test_compute_hmac_accepts_bytearray():
    key = bytearray(generate_key())
    data = bytearray(b"data")

    h = compute_hmac(data, key)
    assert isinstance(h, bytes)
    assert len(h) == 32

# ---------------------------------------------------------------------------
# HKDF
# ---------------------------------------------------------------------------

def test_derive_hkdf_key_success():
    master = generate_key()
    salt = generate_salt()
    info = b"context"

    k1 = derive_hkdf_key(master, info, salt)
    k2 = derive_hkdf_key(master, info, salt)

    assert k1 == k2
    assert len(k1) == 32

def test_derive_hkdf_key_diff_info_diff_key():
    master = generate_key()
    salt = generate_salt()

    k1 = derive_hkdf_key(master, b"a", salt)
    k2 = derive_hkdf_key(master, b"b", salt)

    assert k1 != k2

def test_derive_hkdf_key_rejects_missing_salt():
    master = generate_key()
    with pytest.raises(ValueError, match="HKDF requires an explicit, non-empty salt"):
        derive_hkdf_key(master, b"context", None)

def test_derive_hkdf_key_rejects_empty_byte_salt():
    """Test that empty bytes b'' are also rejected as salt."""
    master = generate_key()
    with pytest.raises(ValueError, match="HKDF requires an explicit, non-empty salt"):
        derive_hkdf_key(master, b"context", b"")

def test_derive_hkdf_key_rejects_non_bytes_master():
    salt = generate_salt()
    with pytest.raises(TypeError):
        derive_hkdf_key("not-bytes", b"context", salt)

# ---------------------------------------------------------------------------
# Argon2 Benchmark (Smoke Test)
# ---------------------------------------------------------------------------

def test_benchmark_argon2_params_smoke():
    # This is intentionally light. We only assert structure, not speed.
    params = benchmark_argon2_params(target_time=0.5)

    assert isinstance(params, dict)
    assert "time_cost" in params
    assert "memory_cost" in params
    assert "parallelism" in params
    assert "measured_time" in params