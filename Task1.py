from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# Caesar Cipher Function
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
        return Encrypt(text, -key) 

    choice = input("Do you want to Encrypt or Decrypt using Caesar Cipher? (E/D): ").strip().upper()

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

# RSA Encryption/Decryption Function
def RSA_Cipher():
    key = RSA.generate(1024)  # Generate RSA keys
    public_key = key.publickey().export_key()  
    private_key = key.export_key()  

    def rsa_encrypt(plaintext, public_key): 
        recipient_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        encrypted_text = cipher_rsa.encrypt(plaintext.encode())
        return base64.b64encode(encrypted_text).decode()

    def rsa_decrypt(ciphertext, private_key): 
        private_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_text = cipher_rsa.decrypt(base64.b64decode(ciphertext))
        return decrypted_text.decode()

    choice = input("Do you want to Encrypt or Decrypt using RSA? (E/D): ").strip().upper()

    if choice == 'E':
        plaintext = input("Enter the plaintext to Encrypt: ")
        encrypted = rsa_encrypt(plaintext, public_key) 
        print("Encrypted Text:", encrypted)

    elif choice == 'D':
        ciphertext = input("Enter the ciphertext to Decrypt: ")
        decrypted = rsa_decrypt(ciphertext, private_key) 
        print("Decrypted Text:", decrypted)

    else:
        print("Invalid choice. Please enter 'E' for Encrypt or 'D' for Decrypt.")


def Main_Menu():
    print("Welcome to the Encryption/Decryption Program!")
    method_choice = input("Do you want to use Caesar Cipher or RSA? (C/R): ").strip().upper()

    if method_choice == 'C':
        Caesar_Cipher()
    elif method_choice == 'R':
        RSA_Cipher()
    else:
        print("Invalid choice. Please enter 'C' for Caesar Cipher or 'R' for RSA.")


Main_Menu()
