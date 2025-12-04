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

    def setup_method(self):
        self.password = "MasterPassword123!"
        self.salt = generate_salt()
        self.key = derive_master_key(self.password, self.salt, time_cost=1, memory_cost=8192)
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption round-trip (no AAD)"""
        test_entry = {"url": "https://github.com", "password": "SecurePass123!"}
        plaintext = json.dumps(test_entry)
        
        # Encrypt
        ciphertext, nonce, auth_tag = encrypt_entry(plaintext, self.key)
        
        assert len(nonce) == 12
        assert len(auth_tag) == 16
        
        # Decrypt
        decrypted = decrypt_entry(ciphertext, nonce, auth_tag, self.key)
        assert decrypted == plaintext

    def test_encrypt_decrypt_with_aad(self):
        """Test encryption with Associated Data (Context Binding)"""
        plaintext = "Sensitive Data"
        context = b"entry-uuid-1234"

        # Encrypt with Context
        ciphertext, nonce, tag = encrypt_entry(plaintext, self.key, associated_data=context)

        # Decrypt with SAME Context -> Success
        decrypted = decrypt_entry(ciphertext, nonce, tag, self.key, associated_data=context)
        assert decrypted == plaintext

    def test_aad_mismatch_detection(self):
        """Test that decryption fails if AAD context does not match"""
        plaintext = "Sensitive Data"
        context = b"correct-context"
        wrong_context = b"wrong-context"

        # Encrypt
        ciphertext, nonce, tag = encrypt_entry(plaintext, self.key, associated_data=context)

        # Decrypt with WRONG Context -> Fail
        with pytest.raises(InvalidTag):
            decrypt_entry(ciphertext, nonce, tag, self.key, associated_data=wrong_context)

        # Decrypt with NO Context -> Fail
        with pytest.raises(InvalidTag):
            decrypt_entry(ciphertext, nonce, tag, self.key, associated_data=None)
    
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
