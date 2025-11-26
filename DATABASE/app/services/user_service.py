import bcrypt
from pathlib import Path
import sqlite3
from DATABASE.app.data.users import get_user_by_username, insert_user
from DATABASE.app.data.schema import create_users_table
from DATABASE.app.data.db import connect_database


# Path to the DATA folder within this folder
DATA_DIR = Path(__file__).parent / "DATA"
DB_PATH = DATA_DIR / "intelligence_platform.db"

def migrate_users_from_file(filepath=DATA_DIR / "users.txt"):
    """Migrate users from a text file into the users table."""
    conn = connect_database()

    # Ensure users table exists
    create_users_table(conn)

    if not filepath.exists():
        print(f"⚠️ File not found: {filepath}")
        conn.close()
        return

    cursor = conn.cursor()
    migrated_count = 0

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Parse line: username,password_hash
            parts = line.split(',')
            if len(parts) >= 2:
                username = parts[0].strip()
                password_hash = parts[1].strip()

                try:
                    cursor.execute(
                        "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                        (username, password_hash, 'user')
                    )
                    if cursor.rowcount > 0:
                        migrated_count += 1
                except sqlite3.Error as e:
                    print(f"Error migrating user {username}: {e}")

    conn.commit()
    conn.close()
    print(f"✅ Migrated {migrated_count} users from {filepath.name}")


def register_user(username, password, role='user'):
    """Register new user with password hashing."""
    # Hash password
    password_hash = bcrypt.hashpw(password.encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')

    # Insert into database
    insert_user(username, password_hash, role)
    return True, f"User '{username}' registered successfully."


def login_user(username, password):
    """Authenticate user."""
    user = get_user_by_username(username)
    if not user:
        return False, "User not found."

    # Verify password
    stored_hash = user[2]  # password_hash column
    if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
        return True, f"Login successful!"
    return False, "Incorrect password."


def validate_username(user_name):
    # check the length of the user name
    if len(user_name) < 4:
        return False, "Username must be at least 4 characters long\n"
    # check if there is a space
    if " " in user_name:
        return False, "Username cannot contain spaces"
    return True, ""


def validate_password(password):
    # check for password length
    if len(password) < 8:
        return False, "Password must be atleast 8 characters long"

    if ' ' in password:
        return False, "Password should not have spaces"

    has_upper = any(p.isupper() for p in password)
    has_lower = any(p.islower() for p in password)
    has_number = any(p.isdigit() for p in password)
    has_special = any(p in "@$*#%^_!*&" for p in password)

    if not (has_upper and has_lower and has_number and has_special):
        return False, "Password must contain:\nAt least one uppercase letter\nAt least one number\nAt least one lowercase letter\nAt least one special character (@$*#%^_!*&)"

    return True, ""