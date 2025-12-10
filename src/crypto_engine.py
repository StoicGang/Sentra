"""
Sentra Crypto Engine - Core Cryptographic Operations
Handles : Key derivations, encryption/decryption, HMAC, random generation
"""
import os
import secrets
from typing import Tuple
from argon2 import low_level
from argon2.exceptions import HashingError
import time
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hmac



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
    result = secrets.token_bytes(length)
    return result
    #WHY secrets instead of os.urandom? secrets is explicitly designed for crypto more randomness allowed by the OS

# function to derive the master key
def derive_master_key(
    password: str,
    salt: bytes,
    time_cost: int = 3,
    memory_cost: int = 65536,  # 64 MB in KB
    parallelism: int = 4,
    hash_len: int = 32
) -> bytes:
    """
    Derive master encryption key from password using Argon2id. 
    
    Args: 
        password: master password (UTF-8 string)
        salt: 16-byte random salt
        time_cost: Number of iterations (default: 3)
        memory_cost: Memory usage in KB (default: 65536 or 64 MB)
        parallelism: Number of parallel threads (default: 4)
        hash_len: Output key length in bytes (default: 32) 
    
    Returns:
        32-byte master key (vault key encryption)
    
    Security:
        - Argon2id = hybrid mode (data-independent + data-dependent)
        - Memory-hard: Forces attacker to use 64+ MB RAM per guess
        - GPU-resistant: Memory bandwidth bottleneck
        - Time-cost: 3 iterations balance security vs usability
        - Parameters should be device-benchmarked on init

    Performance:
        - Target: <= 2 sec unlock time on modern hardware
        - Adjust parameters based on device capability 

    Example: 
        >>> password = "#ThisIsPassword123!"
        >>> salt = generate_salt()
        >>> master_key = derive_master_key(password, salt)
        >>> len(master_key)
        32
    """
    # TODO: Implement Argon2id key derivation
    # HINTS:
    # 1. Use argon2.low_level.hash_secret_raw()
    # 2. Encode password to UTF-8 bytes
    # 3. Specify Type.ID for Argon2id variant
    # 4. Handle potential HashingError exceptions
    
    try:
        password_bytes = password.encode("utf-8")
        raw_hash = low_level.hash_secret_raw(
            secret=password_bytes, 
            salt=salt, 
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len= hash_len,
            type=low_level.Type.ID
        )
        return raw_hash
    except HashingError as e:
        raise RuntimeError(f"Argon2id key derivation failed: {e}")

#function to compute the authentication hash
def compute_auth_hash(
        password: str, 
        salt: bytes, 
        iterations: int = 100000
) -> bytes:
    """
    Compute authentication hash for password verification. 

    Args: 
        password: Master password (UTF-8 string)
        salt: 16-byte random salt (SAME salt as master key derivation)
        iterations: PBKDF2 iteration count (default: 100000)

    Returns:
        32-byte authentication hash (stored in vault_metadata)

    Security: 
        - Separate from master key derivation (different purpose)
        - Uses PBKDF2-HMAC-SHA256 (fast, sufficient for stored hash)
        - 100k iterations adequate since this is just verification
        - Attacker must still break Argon2id to access vault

    Note: 
        - This hash is STORED in vault_metadata
        - Used only for quick password verification
        - Master key is NEVER stored (derived fresh on unlock)

    Example: 
        >>> password = "MySecurePass123!" 
        >>> salt = generate_salt()
        >>> auth_hash = compute_auth_hash(password, salt)
        >>> len(auth_hash)
        32
        >>> # Later verification:
        >>> auth_hash == compute_auth_hash("MySecurePass123!", salt)
        true
    """
    # TODO: Implement PBKDF2-HMAC-SHA256 authentication hash
    # HINTS:
    # 1. Use hashlib.pbkdf2_hmac('sha256', ...)
    # 2. password.encode('utf-8') for bytes
    # 3. Return 32-byte hash (dklen=32)

    if isinstance(password, str):
        password_bytes = password.encode('utf-8')
    else:
        password_bytes = password
    auth_hash = hashlib.pbkdf2_hmac(
        'sha256',   # Hash algorithm
        password_bytes,   # Password as bytes
        salt,       # Salt
        iterations, # Iteration count
        dklen = 32  # Derived key length
    )
    return auth_hash

#function to implement the device benchmarking
def benchmark_argon2_params(
        target_time: float = 2.0,
        min_memory_kb: int = 32768,  # 32 MB minimum
        max_memory_kb: int = 262144, # 256 MB maximum
        parallelism: int =4
) -> dict:
    """
    Benchmark device to find optimal Argon2id parameters for <=2s unlock.

    Args:
        target_time: Target unlock time in seconds (default: 2.0s)
        min_memory_kb: Minimum memory cost in KB (default: 32 MB)
        max_memory_kb: Maximum memory cost in KB (default: 256 MB)
        parallelism: Number of threads (default: 4 = typical CPU cores)
    
    Returns: 
        dict with optimal parameters:
        {
            'time_cost': int, 
            'memory_cost': int, 
            'parallelism': int, 
            'measured_time': float
        }
    
    Algorithm:
        1. Start with min_memory, time_cost = 2
        2. Test dervation time
        3. It too fast -> increase memory_cost
        4. If too slow -> decrease memory_cost or increase time_cost
        5. find sweet spot where time ~ target_time

    Example:
        >>> params = benchmark_argon2_params(target_time=2.0)
        >>> print(params)
        {'time_cost': 3, 'memory_cost':65536, 'parallelism':4, 'measured_time': 1.87}
    """
    print(" Benchmarking Argon2id parameters for your device...")
    print(f"   Target unlock time: {target_time}s\n")

    test_password = "benchmark_test_password_123"
    test_salt = generate_salt()

    # TODO: Implement benchmarking algorithm
    # HINTS:
    # 1. Start with memory_cost = min_memory_KB, time_cost = 2
    # 2. Use time.time() to measure derivation time
    # 3. Adjust memory_cost to approach target_time
    # 4. Try a few iterations to find optimal parameters

    # Default template:
    best_params = {
        'time_cost': 2, 
        'memory_cost': min_memory_kb,
        'parallelism': parallelism, 
        'measured_time': 0.0
    }

    # benchmarking logic
    memory_levels = [32768, 65536, 131072] # 32, 64, 128 MB

    for memory in memory_levels:
        start_time = time.time()
        derive_master_key(test_password, test_salt,
                          time_cost=3, 
                          memory_cost=memory,
                          parallelism=parallelism)
        elapsed = time.time() - start_time

        print(f"    Memory: {memory // 1024} MB -> Time: {elapsed:.2f}s")

        if elapsed <= target_time and elapsed > best_params['measured_time']:
            best_params = {
                'time_cost': 3, 
                'memory_cost': memory,
                'parallelism': parallelism, 
                'measured_time': elapsed
            }

    print(f"\n✓ Optimal parameters found:")
    print(f"   Time cost: {best_params['time_cost']}")
    print(f"   Memory cost: {best_params['memory_cost']} KB ({best_params['memory_cost'] // 1024} MB)")
    print(f"   Parallelism: {best_params['parallelism']}")
    print(f"   Measured time: {best_params['measured_time']:.2f}s\n")
    
    return best_params

"""
=============================================================================
 PART C: ENCRYPTION/DECRYPTION (ChaCha20-Poly1305)
=============================================================================
"""

# function to encrypt the entry
def encrypt_entry(
        plaintext: str,
        key: bytes,
        associated_data: bytes = None
) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt entry data using ChaCha20-Poly1305 AEAD cipher.
    
    Args:
        palintext: JSON-serialized entry data (UTF-8 string)
        key: 32-byte encryption key (from dervie_master_key or derive_entry_key)
        associated_data: Optinal AAD to bind ciphertext to context (e.g., entry_id + timestamp for integrity binding)

    Returns: 
        Tuple of (ciphertext, nonce, auth_tag)
        - Ciphertext: Encrypted data (same length as plaintext)
        - nonce: 12-byte unique nonce used for encryption
        - auth_tag: 16-byte Poly1305 authentication tag

    Security: 
        - Nonce MUST be unique for every encryption with same key
        - Poly1305 provides authenticated encryption (AEAD)
        - Never reuse (key, nonce) pair
        - AAD binds ciphertext to specific context 

    Example:
        >>> entry_json = '{\"url\": \"https://example.com\", \"password\": \"secret\"}'
        >>> key = derive_master_key(password, salt)
        >>> ciphertext, nonce, auth_tag = encrypt_entry(entry_json, key)
        >>> len(ciphertext)
        60
        >>> len(nonce)
        12
        >>> len(auth_tag)
        16  
    """
    try:
        if associated_data is None: associated_data = b""
        nonce = generate_nonce(12)
        cipher = ChaCha20Poly1305(key)
        plaintext_bytes = plaintext.encode('utf-8')
        cipher_with_tag = cipher.encrypt(nonce, plaintext_bytes, associated_data)
        # ChaCha20-Poly1305 returns ciphertext + 16-byte tag appended at the end
        # so we split the last 16 bytes as the tag
        ciphertext = cipher_with_tag[:-16]
        auth_tag = cipher_with_tag[-16:]
        return ciphertext, nonce, auth_tag
    except Exception as e:
        raise RuntimeError(f"Encryption failed: {e}")

# function to decrypt the entry
def decrypt_entry(
        ciphertext: bytes,
        nonce: bytes, 
        auth_tag: bytes, 
        key: bytes, 
        associated_data: bytes = None
) -> str:
    """
    Decrypt and verify entry data using ChaCha20-Poly1305 AEAD cipher.
    
    Args:
        ciphertext: Encrypted entry data
        nonce: 12-byte nonce used during encryption
        auth_tag: 16-byte Poly1305 authentication tag
        key: 32-byte encryption key (same key used for encryption)
        associated_data: Optional AAD (MUST match encryption AAD)
        
    Returns: 
        Decrypted plaintext (JSON string)
    
    Raises: 
        InvalidTag: If authentication tag verification fails (integrity voilation)
        
    Security:
        - MUST verify auth_tag before returning plaintext
        - Tampering detection via Poly1305 tag validation 
        - Returns plaintext ONLY if tag is valid
        
    Example: 
        >>> plaintext = decrypt_entry(ciphertext, nonce, auth_tag, key)
        >>> json.loads(plaintext)
        {'url': 'https://example.com', 'password': 'secret'}
    """
    
    try:
        if associated_data is None: associated_data = b""
        cipher = ChaCha20Poly1305(key)
        ciphertext_with_tag = ciphertext + auth_tag
        plaintext_bytes = cipher.decrypt(nonce, ciphertext_with_tag, associated_data)
        plaintext = plaintext_bytes.decode('utf-8')
        return plaintext
    
    except InvalidTag:
        raise InvalidTag("Entry data corrupted or tampered. Restore from backup.")
    except Exception as e:
        raise RuntimeError(f"Decryption failed: {e}")

# function to check the integrity using HMAC
def compute_hmac(data: bytes, key: bytes, algorithm: str = 'sha256') -> bytes:
    """
    Compute HMAC for data integrity verification 
    
    Args: 
        data: Data to authenticate (e.g., backup file content)
        key: Secret key ( derived from master password)
        algorithm: HMAC ALGORITHM (default: sha256)
        
    Returns: 
        32-bytes HMAC digest (for SHA256)
        
    Security:
        - HMAC provides integrity + authenticity
        - Used for backup file verification 
        - Attacker connot forge valid HMAC without knowing key
    Example: 
        >>> backup_data = b'{\"entries\": [...]}'
        >>> key = derive_master_key(password, salt)
        >>> hmac_tag = compute_hmac(backup_data, key)
        >>> len(hmac_tag)
        32
        >>> # Verification:
        >>> compute_hmac(backup_data, key) == hmac_tag
        True
        >>> # Tampering detection:
        >>> tampered_data = backup_data[:-1] + b'x'
        >>> compute_hmac(tampered_data, key) == hmac_tag
        False
    """
    if isinstance(key, bytearray):
        key = bytes(key)
    
    if isinstance(data, bytearray):
        data = bytes(data)

    h = hmac.new(key, data, hashlib.sha256)

    return h.digest()

def verify_auth_hash(stored_hash: bytes, password: str, salt: bytes) -> bool:
    """
    Verify password against stored hash using constant-time comparison.
    """
    computed = compute_auth_hash(password, salt)
    return hmac.compare_digest(computed, stored_hash)

# ... existing code ...

def derive_hkdf_key(
    master_key: bytes,
    info: bytes,
    salt: bytes = None,
    length: int = 32
) -> bytes:
    """
    Derive a sub-key from a master key using HKDF-SHA256.
    
    Args:
        master_key: The source key material (e.g., vault_key).
        info: Context-specific byte string (e.g., b"backup-enc").
              Different 'info' produces completely different keys.
        salt: Optional salt. If None, defaults to a string of zero bytes.
        length: Desired output length in bytes (default 32).
        
    Returns:
        Derived key bytes.
    """
    if not isinstance(master_key, bytes):
        raise TypeError("Master key must be bytes")
        
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info
    )
    return hkdf.derive(master_key)