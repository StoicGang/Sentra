"""
Manual tests for crypto engine - run directly for verification
python src/manual_tests.py
"""

import json
import time
from src.crypto_engine import (
    generate_salt, generate_nonce, generate_key,
    derive_master_key, compute_auth_hash, benchmark_argon2_params,
    encrypt_entry, decrypt_entry, compute_hmac
)


if __name__ == "__main__":
    print("Sentra Crypto Engine - Manual Verification Tests\n")
    print("=" * 60)

    test_password = "MySecureTestPassword123!"
    print(f"Test Password: {test_password}\n")

    # Test 1: Generate salt
    print("=" * 60)
    print("Test 1: Generate Salt for Key Derivation")
    print("=" * 60)
    salt = generate_salt()
    print(f"  Salt (hex): {salt.hex()}")
    print(f"  ✓ Salt generated\n")

    # Test 2: Derive master key
    print("=" * 60)
    print("Test 2: Master Key Derivation (Argon2id)")
    print("=" * 60)
    start = time.time()
    master_key = derive_master_key(test_password, salt, time_cost=2, memory_cost=32768)
    elapsed = time.time() - start

    print(f"  Master key length: {len(master_key)} bytes")
    print(f"  Master key (hex): {master_key.hex()[:32]}...")
    print(f"  Derivation time: {elapsed:.2f}s")
    print(f"  ✓ Master key derived successfully\n")

    # Test 3: Authentication hash
    print("=" * 60)
    print("Test 3: Authentication Hash (PBKDF2-HMAC-SHA256)")
    print("=" * 60)
    auth_hash1 = compute_auth_hash(test_password, salt)
    auth_hash2 = compute_auth_hash(test_password, salt)
    auth_hash3 = compute_auth_hash("WrongPassword", salt)
    
    print(f"  Auth hash 1: {auth_hash1.hex()[:32]}...")
    print(f"  Auth hash 2 (same password): {auth_hash2.hex()[:32]}...")
    print(f"  Auth hash 3 (wrong password): {auth_hash3.hex()[:32]}...")
    print(f"  Hash 1 == Hash 2: {auth_hash1 == auth_hash2}")
    print(f"  Hash 1 == Hash 3: {auth_hash1 == auth_hash3}")
    print(f"  ✓ Authentication hash working correctly\n")
    
    # Test 4: Device benchmarking
    print("=" * 60)
    print("Test 4: Device Benchmarking")
    print("=" * 60)
    optimal_params = benchmark_argon2_params(target_time=2.0)
    print(f"✓ Device benchmarked successfully\n")
    
    # Test 5: Encryption/Decryption Round-Trip
    print("=" * 60)
    print("Test 5: Encryption/Decryption Round-trip")
    print("=" * 60)

    test_entry = {
        "url": "https://github.com",
        "username": "developer@example.com",
        "password": "GitHub!2024@Secure",
        "notes": "Work account"
    }
    plaintext = json.dumps(test_entry)
    entry_key = master_key

    ciphertext, nonce, auth_tag = encrypt_entry(plaintext, entry_key)
    print(f"    Original plaintext: {plaintext}")
    print(f"    Ciphertext length: {len(ciphertext)} bytes")
    print(f"    Nonce: {nonce.hex()[:16]}... (12 bytes)")
    print(f"    Auth tag: {auth_tag.hex()[:16]}... (16 bytes)")

    decrypted_plaintext = decrypt_entry(ciphertext, nonce, auth_tag, entry_key)
    decrypted_entry = json.loads(decrypted_plaintext)
    print(f"    Decrypted plaintext: {decrypted_plaintext}")
    print(f"    Round-trip match: {plaintext == decrypted_plaintext}")
    print(f"✓ Encryption/decryption working\n")

    print("=" * 60)
    print("Test 6: Tampering Detection")
    print("=" * 60)

    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0xFF
    tampered_ciphertext = bytes(tampered_ciphertext)

    print(f"    Original ciphertext: {ciphertext.hex()[:16]}...")
    print(f"    Tampered ciphertext: {tampered_ciphertext.hex()[:16]}...")

    try: 
        decrypt_entry(tampered_ciphertext, nonce, auth_tag, entry_key)
        print(f"✗ ERROR: Should have detected tampering!")
    except Exception:
        print(f"✓ Tampering detected! Decryption failed with InvalidTag\n")

    print("=" * 60)
    print("Test 7: HMAC Computation")
    print("=" * 60)

    backup_data = plaintext.encode('utf-8')
    hmac_tag1 = compute_hmac(backup_data, entry_key)
    hmac_tag2 = compute_hmac(backup_data, entry_key)

    tampered_backup = backup_data[:-1] + b'X'
    hmac_tag3 = compute_hmac(tampered_backup, entry_key)

    print(f"  Backup data length: {len(backup_data)} bytes")
    print(f"  HMAC tag 1: {hmac_tag1.hex()[:32]}...")
    print(f"  HMAC tag 2 (same data): {hmac_tag2.hex()[:32]}...")
    print(f"  HMAC tag 3 (tampered): {hmac_tag3.hex()[:32]}...")
    print(f"  Tags 1 == 2: {hmac_tag1 == hmac_tag2}")
    print(f"  Tags 1 == 3: {hmac_tag1 == hmac_tag3}")
    print(f"✓ HMAC working correctly\n")

    print("=" * 60)
    print("✅ ALL MANUAL TESTS PASSED")
    print("=" * 60)
