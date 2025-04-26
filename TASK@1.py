def Caesar_Cipher():
    def Encrypt(text, key):
        result = ""
        for char in text:
            if char.isalpha():
                shift = key % 26
                if char.islower():
                    result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                else:
                    result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                result += char
        return result

    def Decrypt(text, key):
        return Encrypt(text, -key)  # Decryption is reverse shifting

    choice = input("Do you want to Encrypt or Decrypt? (E/D): ").strip().upper()

    if choice == 'E':
        text = input("Enter the word to Encrypt: ")
        key = int(input("Enter the key (shift number): "))
        encrypted = Encrypt(text, key)
        print(f"Encrypted word: {encrypted}")

    elif choice == 'D':
        text = input("Enter the word to Decrypt: ")
        key = int(input("Enter the key (shift number): "))
        decrypted = Decrypt(text, key)
        print(f"Decrypted word: {decrypted}")

    else:
        print("Invalid choice. Please enter 'E' for Encrypt or 'D' for Decrypt.")

# Run the function
Caesar_Cipher()
