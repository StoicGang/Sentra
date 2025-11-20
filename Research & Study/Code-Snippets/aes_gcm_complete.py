from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64
from typing import Tuple

def generate_key(bit_length: int = 256) -> bytes:
    return AESGCM.generate_key(bit_length=bit_length) # generate the key of length 256


def create_aesgcm(key: bytes) -> AESGCM:
    return AESGCM(key) # create the AESGSM object to access the methods


def make_nonce(length: int = 12) -> bytes:
    return os.urandom(length)  # create the "Number used only Once" 


def encrypt(aesgcm: AESGCM, nonce: bytes, plaintext: bytes, associated_data: bytes = None) -> bytes:
    return aesgcm.encrypt(nonce, plaintext, associated_data) # create the ciphertext


def decrypt(aesgcm: AESGCM, nonce: bytes, ciphertext: bytes, associated_data: bytes = None) -> bytes:
    return aesgcm.decrypt(nonce, ciphertext, associated_data) # revert the ciphertext to plaintext


def store(nonce: bytes, ciphertext: bytes, filename: str = "storage.dat") -> None:
    data_to_store = base64.b64encode(nonce + ciphertext)
    with open(filename, "wb") as f:
        f.write(data_to_store) # insert the string (composed of nonce and ciphertext) to the file


def load(filename: str = "storage.dat") -> Tuple[bytes, bytes]:
    with open(filename, "rb") as f:
        stored_data = base64.b64decode(f.read())
    stored_nonce = stored_data[:12]
    stored_ciphertext = stored_data[12:]
    return stored_nonce, stored_ciphertext


def main() -> None:
    plaintext = input("Enter the Message: ").encode()

    key = generate_key()
    aesgcm = create_aesgcm(key)

    nonce = make_nonce()
    print("Nonce: ", nonce)

    ciphertext = encrypt(aesgcm, nonce, plaintext)
    print("ciphertext: ", ciphertext)

    decrypted = decrypt(aesgcm, nonce, ciphertext)
    print("Decrypted: ", decrypted.decode())

    store(nonce, ciphertext)

    stored_nonce, stored_ciphertext = load()
    print("Stored nonce: ", stored_nonce)
    print("Stored Cipher: ", stored_ciphertext)

    decrypted_stored = decrypt(aesgcm, stored_nonce, stored_ciphertext)
    print("Decrypt Stored Data: ", decrypted_stored.decode())


if __name__ == "__main__":
    main()