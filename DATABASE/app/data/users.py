import bcrypt
from .db import connect_database

class Users:
    def __init__(self, username=None, stored_hash=None, role=None):
        self.username = username
        self.stored_hash = stored_hash
        self.role = role

    #function to get username from dbs
    def get_user_by_username(self,username):
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        return user

    
    #function to get users role from dbs
    def get_user_by_role(self,username):
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE role = ?", (username,))
        user_role = cursor.fetchall()#it is used to ensures that the first role isnt returnes if multiple user have the same role
        conn.close()
        return user_role
    
    @staticmethod#used for funcs that dont update or modify instance(self) or class args
    def validate_username(user_name):
        # check the length of the user name
        if len(user_name) < 4:
            return False, "Username must be at least 4 characters long\n"
        # check if there is a space
        if " " in user_name:
            return False, "Username cannot contain spaces"
        return True, ""

    @staticmethod
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
    
   
    # function to check if username exists
    def verify_user_name(self,username):
        if self.get_user_by_username(username) is None:
            return False, "Username not found"
        return True, " "
    
    def existing_username(self,username):
        if self.get_user_by_username(username) is None:
            return True, " "
        return False, "Username already exists"
    
    #function to check if inputed password matches stored hash
    def verify_password(self,password):
        if bcrypt.checkpw(password.encode('utf-8'), self.stored_hash.encode('utf-8')):
            return True, ""
        return False, "Incorrect password"

    
