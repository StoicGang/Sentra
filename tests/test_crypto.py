# tests/test_crypto.py
import pytest
import json
from cryptography.exceptions import InvalidTag
from src.crypto_engine import (
    generate_salt, generate_nonce, generate_key,
    derive_master_key, compute_auth_hash, benchmark_argon2_params,
    encrypt_entry, decrypt_entry, compute_hmac
)


class TestRandomGeneration:
    """Test CSPRNG functions"""
    
    def test_generate_salt(self):
        """Test salt generation and uniqueness"""
        salt1 = generate_salt()
        salt2 = generate_salt()
        
        assert len(salt1) == 16, "Salt should be 16 bytes"
        assert len(salt2) == 16, "Salt should be 16 bytes"
        assert salt1 != salt2, "Each salt should be unique"
    
    def test_generate_nonce(self):
        """Test nonce generation and uniqueness"""
        nonce1 = generate_nonce()
        nonce2 = generate_nonce()
        
        assert len(nonce1) == 12, "Nonce should be 12 bytes"
        assert len(nonce2) == 12, "Nonce should be 12 bytes"
        assert nonce1 != nonce2, "Each nonce should be unique"
        
        # Test uniqueness over 1000 generations
        nonces = {generate_nonce() for _ in range(1000)}
        assert len(nonces) == 1000, "All nonces should be unique"
    
    def test_generate_key(self):
        """Test key generation"""
        key = generate_key()
        assert len(key) == 32, "Key should be 32 bytes"


class TestKeyDerivation:
    """Test Argon2id and PBKDF2 functions"""
    
    def test_derive_master_key(self):
        """Test Argon2id key derivation"""
        password = "TestPassword123!"
        salt = generate_salt()
        
        master_key = derive_master_key(password, salt, time_cost=2, memory_cost=32768)
        
        assert len(master_key) == 32, "Master key should be 32 bytes"
        assert isinstance(master_key, bytes), "Master key should be bytes"
        
        # Verify deterministic
        master_key2 = derive_master_key(password, salt, time_cost=2, memory_cost=32768)
        assert master_key == master_key2, "Same inputs should produce same key"
    
    def test_compute_auth_hash(self):
        """Test PBKDF2 authentication hash"""
        password = "MySecurePassword123!"
        salt = generate_salt()
        
        auth_hash = compute_auth_hash(password, salt)
        
        assert len(auth_hash) == 32, "Auth hash should be 32 bytes"
        assert isinstance(auth_hash, bytes), "Auth hash should be bytes"
        
        # Verify deterministic
        auth_hash2 = compute_auth_hash(password, salt)
        assert auth_hash == auth_hash2, "Same password+salt should produce same hash"
        
        # Verify different password = different hash
        wrong_hash = compute_auth_hash("WrongPassword", salt)
        assert auth_hash != wrong_hash, "Different passwords should produce different hashes"


class TestEncryption:
    """Test ChaCha20-Poly1305 AEAD encryption"""
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption round-trip"""
        test_entry = {
            "url": "https://github.com",
            "username": "test@example.com",
            "password": "SecurePass123!",
            "notes": "Test account"
        }
        plaintext = json.dumps(test_entry)
        
        password = "MasterPassword123!"
        salt = generate_salt()
        key = derive_master_key(password, salt, time_cost=2, memory_cost=32768)
        
        # Encrypt
        ciphertext, nonce, auth_tag = encrypt_entry(plaintext, key)
        
        assert len(nonce) == 12, "Nonce should be 12 bytes"
        assert len(auth_tag) == 16, "Auth tag should be 16 bytes"
        assert len(ciphertext) > 0, "Ciphertext should not be empty"
        
        # Decrypt
        decrypted = decrypt_entry(ciphertext, nonce, auth_tag, key)
        
        assert decrypted == plaintext, "Decrypted text should match original"
        assert json.loads(decrypted) == test_entry, "Decrypted JSON should match original"
    
    def test_tampering_detection(self):
        """Test that tampering is detected"""
        plaintext = json.dumps({"password": "secret123"})
        
        password = "MasterPassword123!"
        salt = generate_salt()
        key = derive_master_key(password, salt, time_cost=2, memory_cost=32768)
        
        ciphertext, nonce, auth_tag = encrypt_entry(plaintext, key)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)
        
        # Should raise InvalidTag
        with pytest.raises(InvalidTag):
            decrypt_entry(tampered, nonce, auth_tag, key)


class TestHMAC:
    """Test HMAC integrity functions"""
    
    def test_compute_hmac(self):
        """Test HMAC computation"""
        data = b"Test backup data"
        key = generate_key()
        
        hmac1 = compute_hmac(data, key)
        hmac2 = compute_hmac(data, key)
        
        assert len(hmac1) == 32, "HMAC should be 32 bytes"
        assert hmac1 == hmac2, "Same data+key should produce same HMAC"
    
    def test_hmac_tampering_detection(self):
        """Test HMAC detects tampering"""
        data = b"Original data"
        key = generate_key()
        
        original_hmac = compute_hmac(data, key)
        
        # Tamper with data
        tampered_data = b"Tampered data"
        tampered_hmac = compute_hmac(tampered_data, key)
        
        assert original_hmac != tampered_hmac, "HMAC should differ for different data"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
