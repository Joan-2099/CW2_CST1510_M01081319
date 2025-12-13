import bcrypt
from pathlib import Path
import sqlite3
import streamlit as st

from DATABASE.app.data.users import Users
from DATABASE.app.data.schema import TableCreator
from DATABASE.app.data.db import connect_database

conn = connect_database()
table_creator=TableCreator(conn)
# Path to the DATA folder within this folder
DATA_DIR = Path(__file__).parent / "DATA"
DB_PATH = DATA_DIR / "intelligence_platform.db"

users = Users() 

class UserService:
    def __init__(self, dbs_path):
        self.dbs_path = dbs_path

    def migrate_users_from_file(self,filepath=DATA_DIR / "users.txt"):
        """Migrate users from a text file into the users table."""
        conn = connect_database()

        # Ensure users table exists
        table_creator.create_users_table()

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

    def insert_user(self,username, password_hash, role):
        conn = connect_database()
        cursor = conn.cursor()
        #using error handling to display error message for taken username
        try:
            # Check if username already exists
            cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                return False, f"The username '{username}' is already taken."

            # Insert new user
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, role)
            )
            conn.commit()
            return True, f"User '{username}' inserted successfully."
        except sqlite3.Error as e:
            # This happens if username already exists
            return False, f"Database error: {e}"
        finally:
            conn.close()

    def register_user(self,username, password, role):
        #Register new user with password hashing.
        valid_username, msg = Users.validate_username(username)
        if not valid_username:
            return False, msg
        valid_pass, msg = Users.validate_password(password)
        if not valid_pass:
            return False, msg
        #check if username exists
        valid_pass, msg = users.existing_username(username)
        if not valid_pass:
            return False,msg
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')
        
        # Insert into database
        valid_insert, msg = self.insert_user(username, password_hash, role)
        if not valid_insert:
            return False, msg
        return True, msg

    #Authenticate user
    @staticmethod
    def login_user(username, password):
        
        user_data = users.get_user_by_username(username)
        
        #check if fields are empty
        if not username.strip():
            return False, "Please enter username",None
        
        if not password.strip() :
            return False, "Please enter password",None
        
        #check if username doesnt exist
        if not user_data:
            return False, "User not found.",None
        # Verify password
        stored_hash = user_data[2]  # password_hash column
        role = user_data[3]#this gets role from Database
        
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            return True, f"Login successful!",role

        else:
            return False, "Incorrect password.", None

    @staticmethod
    def init_session ():
        if "username" not in st.session_state:
            st.session_state["username"] = None
        if "role" not in st.session_state:
            st.session_state["role"] = None
        if "is_logged_in" not in st.session_state:
            st.session_state["is_logged_in"] = False

    @staticmethod
    def logout():
        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.role = None
        st.rerun()
  
    #function to ensure users remain logged in or locked out if not logged in
    @staticmethod
    def require_login(role=None):
        # Check if user is logged in at all
        if not st.session_state.get("logged_in", False):
            st.warning("You must be logged in to access this page.")
            st.stop()

    @staticmethod
    def require_role(role):
        # First ensure user is logged in
        if not st.session_state.get("logged_in", False):
            st.warning("You must be logged in to access this page.")
            st.stop()

        # Now check role
        if st.session_state.get("role") != role:
            st.warning(f"This page is restricted to {role}.")
            st.stop()
