import json
from pathlib import Path
from getpass import getpass
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

import db  # <-- uses nexus_terminal.db to store the hashed pairing code
ph = PasswordHasher()

db.init_db()
USERS_FILE = Path("users.json")

def load_users():
    if not USERS_FILE.exists():
        return {}
    return json.loads(USERS_FILE.read_text(encoding="utf-8"))

def save_users(users):
    USERS_FILE.write_text(json.dumps(users, indent=2), encoding="utf-8")

def create_user(username: str, password: str, role: str = "survivor"):
    users = load_users()
    if username in users:
        raise SystemExit(f"User '{username}' already exists.")

    # Hash the login password with Argon2 and store in users.json
    users[username] = {
        "scheme": "argon2",
        "hash": ph.hash(password),
        "role": role,
    }
    save_users(users)

    # Generate a unique pairing code and store ONLY its Argon2 hash in SQLite
    plain_code = db.generate_user_code()       # e.g., JF8L-ONSF-B54A
    db.set_user_code_hash(username, plain_code)

    # Show the pairing code ONCE to the admin/creator
    print("\n=== ACCOUNT CREATED ===")
    print(f"Username : {username}")
    print(f"Role     : {role}")
    print("Pairing code (give this to the user now and store it safely):")
    print(f"  {plain_code}")
    print("\nThis code is NOT stored in plaintext and cannot be recovered later.\n")

if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 2:
        username = sys.argv[1]
    else:
        username = input("Username: ").strip()
    if not username:
        raise SystemExit("Username required.")

    pw = getpass("Password: ")
    pw2 = getpass("Confirm Password: ")
    if pw != pw2:
        print("Passwords don't match. Aborting.")
        raise SystemExit(1)
    if len(pw) < 8:
        print("Warning: password shorter than 8 chars.")

    role = input("Role (default: survivor): ").strip() or "survivor"
    create_user(username, pw, role)
