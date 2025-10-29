import sys
import base64
import hashlib
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def symmetric_encrypt_decrypt():
    print("\n--- Symmetric Encryption (Fernet) ---")
    key = Fernet.generate_key()
    f = Fernet(key)
    print(f"Generated Key (keep this safe!): {key.decode()}")
    
    message = input("Enter message to encrypt: ").encode()
    encrypted = f.encrypt(message)
    print(f"\nEncrypted Text: {encrypted.decode()}")
    
    choice = input("\nDo you want to decrypt it? (y/n): ").lower()
    if choice == 'y':
        decrypted = f.decrypt(encrypted)
        print(f"Decrypted Text: {decrypted.decode()}")
    print("----------------------------------------\n")


def asymmetric_encrypt_decrypt():
    print("\n--- Asymmetric Encryption (RSA) ---")
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    print("RSA keys generated.")
    message = input("Enter message to encrypt: ").encode()

    # Encrypt with public key
    public_key_obj = RSA.import_key(public_key)
    cipher_rsa_enc = PKCS1_OAEP.new(public_key_obj)
    encrypted = cipher_rsa_enc.encrypt(message)
    encoded_encrypted = base64.b64encode(encrypted).decode()
    print(f"\nEncrypted Text (Base64): {encoded_encrypted}")

    choice = input("\nDo you want to decrypt it? (y/n): ").lower()
    if choice == 'y':
        private_key_obj = RSA.import_key(private_key)
        cipher_rsa_dec = PKCS1_OAEP.new(private_key_obj)
        decrypted = cipher_rsa_dec.decrypt(base64.b64decode(encoded_encrypted))
        print(f"Decrypted Text: {decrypted.decode()}")
    print("----------------------------------------\n")


def hashing():
    print("\n--- Hashing (SHA-256) ---")
    message = input("Enter message to hash: ").encode()
    hashed = hashlib.sha256(message).hexdigest()
    print(f"SHA-256 Hash: {hashed}")
    print("----------------------------------------\n")


def main():
    print("Simple Python CLI Encryption Tool")
    print("----------------------------------------")
    print("Choose an option:")
    print("1. Symmetric Encryption (Fernet)")
    print("2. Asymmetric Encryption (RSA)")
    print("3. Hashing (SHA-256)")
    print("4. Exit")

    choice = input("\nEnter your choice (1-4): ")

    if choice == '1':
        symmetric_encrypt_decrypt()
    elif choice == '2':
        asymmetric_encrypt_decrypt()
    elif choice == '3':
        hashing()
    elif choice == '4':
        print("Exiting... Goodbye!")
        sys.exit(0)
    else:
        print("Invalid choice, please try again.\n")


if __name__ == "__main__":
    while True:
        main()
