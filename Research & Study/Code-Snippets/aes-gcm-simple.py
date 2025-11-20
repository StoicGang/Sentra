# aes_gcm_demo.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Step 1: generate a 256-bit key (32 bytes) 
key = AESGCM.generate_key(bit_length=256) #instead of 256 we can use 128 or 192
print("key:", key)

# Step 2: create AES-GCM cipher object
aesgcm = AESGCM(key)
print("aesgcm:" , aesgcm)

# Step 3: define plaintext and nonce
plaintext = input("Enter plaintext: ").encode()  # Encode to bytes as ciphertext can't  handle the strings
nonce = os.urandom(12)  # must be unique every encryption! it creates 96 bit nonce. 
print("nonce:", nonce)

# Step 4: encrypt
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
print("Ciphertext:", ciphertext)

# Step 5: decrypt
decrypted = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
print("Decrypted:", decrypted.decode())  # Convert bytes back to string
