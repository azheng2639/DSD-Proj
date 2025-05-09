from functions import DiffieHellman, encrypt_message, decrypt_message

def main():
    # The p and g values are from our coursework, without these values, one will be generated, which may take a long time.
    dh = DiffieHellman(key_bits=1024, p=2**255 - 19, g=2)
    print(f"my public key: {dh.public_key}")
    shared_secret = None

    while True:
        print("\nChoose an option:")
        print("1. Retrieve public key")
        print("2. Generate shared secret")
        print("3. Encrypt a message")
        print("4. Decrypt a message")
        print("5. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            # Retrieve public key
            print(f"Public key: {dh.public_key}")
            print("Please share this public key with the other party.")

        elif choice == "2":
            # Generate shared secret
            if dh is None:
                print("Please generate keys first.")
                continue

            other_public = int(input("Enter the other party's public key: "))
            try:
                shared_secret = dh.generate_shared_secret(other_public)
                print("Secure shared secret generated.")
            except ValueError as e:
                print(f"Error: {e}")

        elif choice == "3":
            # Encrypt a message
            if shared_secret is None:
                print("Please generate the shared secret first.")
                continue

            message = input("Enter the message to encrypt: ")
            ciphertext = encrypt_message(message, shared_secret)
            print(f"Encrypted message: {ciphertext}")

        elif choice == "4":
            # Decrypt a message
            if shared_secret is None:
                print("Please generate the shared secret first.")
                continue

            ciphertext = input("Enter the ciphertext to decrypt: ")
            try:
                plaintext = decrypt_message(ciphertext, shared_secret)
                print(f"Decrypted message: {plaintext}")
            except Exception as e:
                print(f"Error during decryption: {e}")

        elif choice == "5":
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
