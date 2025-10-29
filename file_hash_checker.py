import hashlib

def generate_file_hash():
    filename = input("Enter file name to hash: ")
    with open(filename, "rb") as f:
        file_data = f.read()

    hash_value = hashlib.sha256(file_data).hexdigest()
    print("\n✅ SHA-256 Hash Generated Successfully!")
    print("🔹 Hash:", hash_value)

    with open("hash.txt", "w") as h:
        h.write(hash_value)
    print("Hash saved in 'hash.txt'.")

def verify_file_hash():
    filename = input("Enter file name to verify: ")
    with open(filename, "rb") as f:
        file_data = f.read()
    new_hash = hashlib.sha256(file_data).hexdigest()

    saved_hash = input("Enter the original hash (or paste from hash.txt): ")

    if new_hash == saved_hash:
        print("\n✅ File Integrity Verified. No changes detected.")
    else:
        print("\n❌ Integrity Check Failed! File may have been modified.")

def main_menu():
    print("\n==============================")
    print(" PRACTICAL 10 – File Hashing & Integrity Check")
    print("==============================")
    print("1. Generate File Hash (SHA-256)")
    print("2. Verify File Integrity")
    print("3. Exit")

    choice = input("\nEnter your choice (1-3): ")
    if choice == '1':
        generate_file_hash()
    elif choice == '2':
        verify_file_hash()
    elif choice == '3':
        exit()
    else:
        print("Invalid choice!")

if __name__ == "__main__":
    while True:
        main_menu()
