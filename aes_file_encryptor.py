import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def pad(data):
    # Padding to make data length multiple of 16 bytes
    return data + b' ' * (16 - len(data) % 16)

def aes_encrypt_file():
    filename = input("Enter file name to encrypt (e.g., message.txt): ")
    with open(filename, "rb") as f:
        data = f.read()

    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(pad(data))

    with open("encrypted.bin", "wb") as f:
        [f.write(x) for x in (cipher.nonce, tag, ciphertext)]

    print("\n✅ File Encrypted Successfully!")
    print("🔑 AES Key (Base64):", base64.b64encode(key).decode())

def aes_decrypt_file():
    filename = input("Enter encrypted file name (e.g., encrypted.bin): ")
    key_b64 = input("Enter AES key (Base64): ")
    key = base64.b64decode(key_b64)

    with open(filename, "rb") as f:
        nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]

    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt(ciphertext)

    with open("decrypted.txt", "wb") as f:
        f.write(data.strip())

    print("\n✅ File Decrypted Successfully! Saved as decrypted.txt")

def main_menu():
    print("\n==============================")
    print(" PRACTICAL 9 – File Encryption (AES)")
    print("==============================")
    print("1. Encrypt a File")
    print("2. Decrypt a File")
    print("3. Exit")

    choice = input("\nEnter your choice (1-3): ")
    if choice == '1':
        aes_encrypt_file()
    elif choice == '2':
        aes_decrypt_file()
    elif choice == '3':
        exit()
    else:
        print("Invalid choice!")

if __name__ == "__main__":
    while True:
        main_menu()
