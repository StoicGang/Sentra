# aes_gcm.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64
import sys
from cryptography.exceptions import InvalidTag

def encrypt_text(plaintext: str, aad: bytes | None = None):
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # recommended 12-byte nonce for GCM
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
    return {
        "key_hex": key.hex(),
        "nonce_hex": nonce.hex(),
        "ciphertext_b64": base64.b64encode(ct).decode("ascii")
    }

def decrypt_data(key_hex: str, nonce_hex: str, ciphertext_b64: str, aad: bytes | None = None):
    key = bytes.fromhex(key_hex)
    nonce = bytes.fromhex(nonce_hex)
    ct = base64.b64decode(ciphertext_b64)
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce, ct, aad)
        return pt.decode("utf-8")
    except InvalidTag:
        raise ValueError("Authentication failed (Invalid tag / corrupted data)")

def main():
    while True:
        print("\nChoose an action:")
        print("  1) Encrypt plaintext (AES-GCM)")
        print("  2) Decrypt ciphertext (AES-GCM)")
        print("  3) Exit")
        choice = input("Enter choice (1/2/3): ").strip()

        if choice == "1":
            text = input("Plaintext: ")
            aad_input = input("Associated data (leave empty for none): ")
            aad = aad_input.encode("utf-8") if aad_input else None

            out = encrypt_text(text, aad)
            print("\nKey (hex):", out["key_hex"])
            print("Nonce (hex):", out["nonce_hex"])
            print("Ciphertext (base64):", out["ciphertext_b64"])

        elif choice == "2":
            key = input("Key (hex): ").strip()
            nonce = input("Nonce (hex): ").strip()
            cipher = input("Ciphertext (base64): ").strip()
            aad_input = input("Associated data (leave empty for none): ")
            aad = aad_input.encode("utf-8") if aad_input else None

            try:
                plaintext = decrypt_data(key, nonce, cipher, aad)
                print("\nDecrypted plaintext:", plaintext)
            except ValueError as e:
                print("Error:", e, file=sys.stderr)

        elif choice == "3" or choice.lower() in ("q", "quit", "exit"):
            print("Exiting.")
            break

        else:
            print("Invalid choice, try again.")

if __name__ == "__main__":
    main()
