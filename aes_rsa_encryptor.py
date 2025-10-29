import sys
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

# --- Symmetric Encryption Functions (AES) ---

def aes_encrypt_decrypt():
    print("\n--- AES Symmetric Encryption ---")
    message = input("Enter message to encrypt: ").encode()
    key = get_random_bytes(16)  # 128-bit key
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message)

    print("\n🔐 Encrypted Message (Base64):", base64.b64encode(ciphertext).decode())
    print("🔑 AES Key (Base64):", base64.b64encode(key).decode())
    print("Nonce (Base64):", base64.b64encode(cipher.nonce).decode())

    # Decryption
    nonce = cipher.nonce
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted = cipher.decrypt(ciphertext)
    print("\n💡 Decrypted Message:", decrypted.decode(), "\n")


# --- Asymmetric Encryption Functions (RSA) ---

def rsa_encrypt_decrypt():
    print("\n--- RSA Asymmetric Encryption ---")
    message = input("Enter message to encrypt: ").encode()

    # Generate RSA Key Pair
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    print("\n✅ RSA Key Pair Generated Successfully!")
    print("Public Key:\n", public_key.decode())
    print("Private Key:\n", private_key.decode())

    # Encryption
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_message = cipher_rsa.encrypt(message)
    print("\n🔐 Encrypted Message (Base64):", base64.b64encode(encrypted_message).decode())

    # Decryption
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    decrypted_message = cipher_rsa.decrypt(encrypted_message)
    print("💡 Decrypted Message:", decrypted_message.decode(), "\n")


# --- Main Menu ---

def main_menu():
    print("==========================================")
    print("   PRACTICAL 8 – Symmetric & Asymmetric Encryption")
    print("==========================================")
    print("Choose an option:")
    print("1. AES Symmetric Encryption & Decryption")
    print("2. RSA Asymmetric Encryption & Decryption")
    print("3. Exit")

    choice = input("\nEnter your choice (1-3): ")

    if choice == '1':
        aes_encrypt_decrypt()
    elif choice == '2':
        rsa_encrypt_decrypt()
    elif choice == '3':
        print("\nExiting... Goodbye!\n")
        sys.exit(0)
    else:
        print("Invalid choice, please try again.\n")


if __name__ == "__main__":
    while True:
        main_menu()
