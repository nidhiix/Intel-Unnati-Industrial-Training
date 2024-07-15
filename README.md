# Intel-Unnati-Industrial-Training
# Protecting User Password Keys at Rest
pip install cryptography passlib
from cryptography.fernet import Fernet
from passlib.hash import bcrypt

# Step 1: Hashing the Password
def hash_password(password):
    hashed = bcrypt.hash(password)
    return hashed

# Step 2: Encrypting the Hashed Password
def encrypt_data(data, key):
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(data.encode())
    return cipher_text

# Step 3: Decrypting the Encrypted Data
def decrypt_data(cipher_text, key):
    cipher_suite = Fernet(key)
    decrypted_text = cipher_suite.decrypt(cipher_text).decode()
    return decrypted_text

# Step 4: Key Management (Generating and Loading the Key)
def generate_key():
    return Fernet.generate_key()

# Step 5: Demonstration of the Whole Process
def main():
# Original password
    password = "my_secure_password"

# Generate encryption key
    key = generate_key()
    print(f"Encryption Key: {key.decode()}")

# Hash the password
    hashed_password = hash_password(password)
    print(f"Hashed Password: {hashed_password}")

# Encrypt the hashed password
    encrypted_hashed_password = encrypt_data(hashed_password, key)
    print(f"Encrypted Hashed Password: {encrypted_hashed_password}")

# Decrypt the hashed password
    decrypted_hashed_password = decrypt_data(encrypted_hashed_password, key)
    print(f"Decrypted Hashed Password: {decrypted_hashed_password}")

# Verify the original password against the decrypted hashed password
    is_correct = bcrypt.verify(password, decrypted_hashed_password)
    print(f"Password verification result: {is_correct}")

if name == "main":
    main()
