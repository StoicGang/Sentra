from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64

# Generate a 256-bit key (in a real app, store securely!)
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)

# plaintext
plaintext = input("Enter the Secret Message: ").encode()

# Generate a unique 12-byte nonce
nonce = os.urandom(12)

# Encrypt
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
print ("Encrypted data: ", ciphertext)

# Store nonce + ciphertext together (can be saved to a file)
data_to_store = base64.b64encode(nonce + ciphertext)
with open("storage.dat", "wb") as f:
    f.write(data_to_store)

# Later: read and decrypt
with open("storage.dat", "rb") as f:
    stored_data = base64.b64decode(f.read())

stored_nonce = stored_data[:12]
stored_ciphertext = stored_data[12:]

decrypted = aesgcm.decrypt(stored_nonce, stored_ciphertext, associated_data=None)
print("Decrypted:", decrypted.decode())
