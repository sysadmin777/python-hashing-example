# secure_storage.py
# This script demonstrates the modern, secure way to handle passwords.
# You will need to install the bcrypt library:
# pip install bcrypt

import hashlib
import bcrypt

# The user's password, as entered during signup or login.
password_from_user = "P@ssword123!"
password_bytes = password_from_user.encode('utf-8')

# --- For Demonstration: Salting an MD5 Hash (Still considered INSECURE) ---
# This is an old technique. While better than an unsalted MD5, it's still
# not recommended because MD5 is too fast.
print("--- Method 3: Salted MD5 (Still INSECURE) ---")
# A salt should be a random value, but here we'll use a static one for simplicity.
# In a real (but still flawed) system, this salt would be stored with the user's record.
static_salt = b'$2a$12$Y3s0.ASd2w493l3s7e9v5u' # Example salt
salted_password_bytes = static_salt + password_bytes
md5_hash_obj = hashlib.md5(salted_password_bytes)
salted_md5_hex = md5_hash_obj.hexdigest()
print(f"User's Password: {password_from_user}")
print(f"Stored Salted MD5 Hash: {salted_md5_hex}")
print("Problem: MD5 is too fast. An attacker who gets the hash and salt can still crack it quickly.\n")


# --- The CORRECT Way: Using a Modern, Slow Hashing Algorithm like bcrypt ---
# bcrypt automatically generates a salt and combines it with the hash.
print("--- Method 4: bcrypt (The CORRECT, MODERN Method) ---")

# 1. Generate a salt and hash the password (this is done once, during signup)
# The `gensalt()` function creates a new random salt every time.
# The `hashpw()` function hashes the password with this salt.
salt = bcrypt.gensalt()
hashed_password = bcrypt.hashpw(password_bytes, salt)

print(f"User's Password: {password_from_user}")
print(f"Stored bcrypt Hash (Salt is included): {hashed_password.decode()}")
print("\nThis single value is what you store in your database. It contains:")
print("  - The algorithm used ($2b$)")
print("  - The 'cost factor' (how slow it is)")
print("  - The 128-bit salt")
print("  - The resulting hash\n")


# 2. Verify a password (this is done every time a user tries to log in)
# The user enters their password again.
login_attempt_password = "P@ssword123!"

# The `checkpw` function re-hashes the login attempt with the *same salt*
# that is stored inside the `hashed_password` value from the database.
if bcrypt.checkpw(login_attempt_password.encode('utf-8'), hashed_password):
    print("Verification Result: SUCCESS! The passwords match.")
else:
    print("Verification Result: FAILED! The passwords do not match.")

# Demonstrate failure
login_attempt_wrong_password = "wrongpassword"
if bcrypt.checkpw(login_attempt_wrong_password.encode('utf-8'), hashed_password):
    print("\nVerification with wrong password: SUCCESS! (This should not happen)")
else:
    print("\nVerification with wrong password: FAILED! (Correctly rejected)")

