"""
Sentra Crypto Engine - Core Cryptographic Operations
Handles : Key derivations, encryption/decryption, HMAC, random generation
"""
import os
import secrets
from typing import Tuple

"""
==========================================================================
PART A : Random Generations (CSPRNG)
==========================================================================
"""

#Function to generate salt 
def generate_salt(length: int = 16) -> bytes:
    """
    Generate the secure random salt for Argon2id.
    
    Args: 
        length: salt length in bytes (default: 16 bytes = 128 bits)
        
    Returns:
        Random salt as bytes
        
    Security: 
        - Uses os.random() which fulls from OS entropy pool
        - Salt must be unique per vault (prevents rainbow table attacks)
        - 16 bytes  = 2^128 possible values (collision probability is negligible)

    Example: 
        >>> salt = generate_salt()
        >>> len(salt)
        16
        >>> salt == generate_salt() # different every time 
        false    
    """
    # TODO: Implement using os.urandom() --> it returns n random bytes 
    result = os.urandom(length)
    return result

#Function to generate nonce
def generate_nonce(length: int = 12) -> bytes:
    """
    Generate the secure random nonce for Chacha20-Poly1305.

    Args: 
        length: Nonce length in bytes (default: 12 bytes = 96 bits)

    Returns: 
        Random nonce as bytes

    Security: 
        - Chacha20-Poly1305 requires 96-bit (12-byte) nonce
        - MUST be unique for every encryption with the same key 
        - Nonce reuse = catastrophic security failure (plaintext recovery)
        - Using CSPRNG ensures uniqueness (2^96 space)

    Example:
        >>> nonce = generate_nonce()
        >>> len(nonce)
        12 
    """
    # TODO: Implement using os.urandom()
    result = os.urandom(length)
    return result

#Function to generate the key 
def generate_key(length: int = 32) -> bytes:
    """
    Generate secure random key. 
    
    Args: 
        length: Key length in bytes (default: 32 bytes = 256 bits)
        
    Returns:
        Random key as bytes
        
    Security: 
        - Used for generating recovery keys, vaults keys (testing), etc.
        - 256 bits  = Industry standard for symmetic encryption
        - Never use this for master key (master key comes from password via Argon2id)
        
    Example: 
        >>> key = generate_key()
        >>> len(key)
        32
    """
    #TODO: Implement using secrets.token_bytes()
    result = secrets.token_bytes(length)
    return result
    #WHY secrets instead of os.urandom? secrets is explicitly designed for crypto more randomness allowed by the OS

"""
=============================================================================================
TESTING HELPERS
=============================================================================================
"""

if __name__ == "__main__":
    print("Sentra Crypto Engine - Random Geneartion Test\n")

    # Test 1 : generate the salt
    print("test 1: Generate the salt")
    salt = generate_salt()
    print(f"  Salt length: {len(salt)} bytes")
    print(f"  Salt (hex): {salt.hex()}")

    # Test 2 : Generate Nonce
    print("Test 2: Generate Nonce")
    nonce = generate_nonce()
    print(f"  Nonce length: {len(nonce)} bytes")
    print(f"  Nonce (hex): {nonce.hex()}")
    
    # Test 3: Generate key
    print("Test 3: Generate Key")
    key = generate_key()
    print(f"  Key length: {len(key)} bytes")
    print(f"  Key (hex): {key.hex()[:32]}... (truncated)")
    
    # Test 4: Uniqueness check
    print("Test 4: Uniqueness Check (generate 1000 salts)")
    salts = [generate_salt() for _ in range(1000)]
    unique_salts = len(set(salts))
    print(f"  Generated: 1000 salts")
    print(f"  Unique: {unique_salts} salts")

"""
🎓 Question 1: Why do we need unique nonces for ChaCha20-Poly1305? What happens if we reuse a nonce with the same key?
    ChaCha20 is a keystream generator. It takes key + nonce + counter and produced key stream of random looking bytes. 
    If we xor a key stream with plaintext, we get ciphertext. But if you use the same key to the same nonce, we get the same key stream. 
    Poly1305, uses a one time key derived by Chacha20 with nonce. If we reuse nonce, we reuse the same one time key.

🎓 Question 2: What's the difference between os.urandom() and secrets.token_bytes()? When would you use each?
    os.random(): It is a low level API directly calls OS cryptographic random number generation function.
    secrets.token_bytes(): Internally uses system random. Which itself relies on Os.urandom
    Both are based on the same principle to provide the randomness. Into the number. But it depends upon whether we want to have security related purpose.

🎓 Question 3: In the uniqueness test, we generated 1000 salts. Given that salts are 16 bytes (128 bits), what's the probability of a collision? (Don't calculate, just conceptually - is it high, low, or negligible?)
    negligible (1000 out of 2^128)
"""