# practical7_digital_signature.py
# Digital Signatures & Message Authentication in Python
# Developed for Computer and Network Security - Practical 7
# Updated version (PowerShell-friendly with file-based key handling)

import sys
import base64
import hmac
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


# --- Digital Signature Functions ---

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Save keys into files (PowerShell-safe)
    with open("private_key.pem", "wb") as priv_file:
        priv_file.write(private_key)
    with open("public_key.pem", "wb") as pub_file:
        pub_file.write(public_key)

    print("\n✅ RSA Key Pair Generated Successfully!")
    print("🔒 Private key saved as 'private_key.pem'")
    print("🔑 Public key saved as 'public_key.pem'")
    return private_key, public_key


def digital_signature():
    print("\n--- Digital Signature Creation ---")
    message = input("Enter message to sign: ").encode()

    private_key, public_key = generate_keys()
    key = RSA.import_key(private_key)

    hash_value = SHA256.new(message)
    signature = pkcs1_15.new(key).sign(hash_value)

    encoded_signature = base64.b64encode(signature).decode()
    with open("signature.txt", "w") as sig_file:
        sig_file.write(encoded_signature)

    print("\n🔏 Signature (Base64 Encoded) saved in 'signature.txt'")
    print("💡 Public key stored in 'public_key.pem' for verification.\n")


def verify_signature():
    print("\n--- Digital Signature Verification ---")

    # Load key & signature from files (automatic)
    try:
        with open("public_key.pem", "r") as f:
            public_key_input = f.read()
        with open("signature.txt", "r") as f:
            signature_input = f.read()
    except FileNotFoundError:
        print("\n❌ Required files not found! Make sure 'public_key.pem' and 'signature.txt' exist.\n")
        return

    message = input("Enter the original message: ").encode()

    try:
        public_key = RSA.import_key(public_key_input)
        signature = base64.b64decode(signature_input)
        hash_value = SHA256.new(message)

        pkcs1_15.new(public_key).verify(hash_value, signature)
        print("\n✅ Signature Verification Successful! Message is authentic and unchanged.\n")

    except (ValueError, TypeError):
        print("\n❌ Signature Verification Failed! Message or signature is invalid.\n")


# --- HMAC (Message Authentication) Functions ---

def generate_hmac():
    print("\n--- Message Authentication Code (HMAC) ---")
    key = input("Enter shared secret key: ").encode()
    message = input("Enter message: ").encode()

    mac = hmac.new(key, message, hashlib.sha256).hexdigest()
    print("\n🔐 Generated HMAC (SHA-256):", mac)

    check = input("\nDo you want to verify the HMAC? (y/n): ").lower()
    if check == 'y':
        mac_check = hmac.new(key, message, hashlib.sha256).hexdigest()
        if mac == mac_check:
            print("✅ Message Integrity Verified.")
        else:
            print("❌ Message has been altered!")


# --- Main Menu ---

def main_menu():
    print("==========================================")
    print("   PRACTICAL 7 – Digital Signatures & HMAC")
    print("==========================================")
    print("Choose an option:")
    print("1. Generate and Sign a Message (Digital Signature)")
    print("2. Verify a Digital Signature")
    print("3. Generate and Verify HMAC")
    print("4. Exit")

    choice = input("\nEnter your choice (1-4): ")

    if choice == '1':
        digital_signature()
    elif choice == '2':
        verify_signature()
    elif choice == '3':
        generate_hmac()
    elif choice == '4':
        print("\nExiting... Goodbye!\n")
        sys.exit(0)
    else:
        print("Invalid choice, please try again.\n")


if __name__ == "__main__":
    while True:
        main_menu()
