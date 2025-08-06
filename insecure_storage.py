# insecure_storage.py
# WARNING: This code is for demonstration purposes only and is highly insecure.
# Do not use this in a real application.

import hashlib

# The user's password, as entered during signup.
password_from_user = "P@ssword123!"

# --- The WRONG Way: Storing in Plaintext ---
# This is the worst-case scenario from our story. If this leaks, it's game over.
print("--- Method 1: Plaintext (NEVER DO THIS) ---")
print(f"Stored Value: {password_from_user}\n")


# --- A Slightly Better, but still BROKEN Way: Unsalted MD5 ---
# The developer thinks they are being clever by hashing it.
# However, MD5 is a broken algorithm for passwords.
print("--- Method 2: Unsalted MD5 (BROKEN) ---")
# We need to encode the password into bytes before hashing.
password_bytes = password_from_user.encode('utf-8')
md5_hash_obj = hashlib.md5(password_bytes)
unsalted_md5_hex = md5_hash_obj.hexdigest()

print(f"User's Password: {password_from_user}")
print(f"Stored MD5 Hash: {unsalted_md5_hex}")
print("Problem: If two users have the same password, they have the same hash.")
print("Attackers can use 'rainbow tables' to look up this hash and find the password in seconds.\n")