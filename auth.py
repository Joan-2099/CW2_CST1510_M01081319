import bcrypt
import os

USER_DATA_FILE = "users.txt"


def register_user(username, password):

    # checks if txt file already exists and creates it
    if not os.path.exists(USER_DATA_FILE):
        open(USER_DATA_FILE, "w").close()

    # check if username already exists
    with open(USER_DATA_FILE, "r") as file:
        for line in file:
            # _ for hash whoich is irreleveant and ,1 only split once
            stored_username, _ = line.strip().split(",", 1)
            if stored_username == username:
                return False, "User name already exists!"

    # hashing the password
    hash_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    # appenD the new user info
    with open(USER_DATA_FILE, "a") as file:
        file.write(f"{username},{hash_password.decode()}\n")

    print()
    return True, "Registration successful"


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


def hash_password(password):
    # Encode the password to bytes, required by bcrypt

    password_bytes = password.encode()

    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)

    # Decode the hash back to a string to store in a text file
    return hashed_password


def verify_user_name(user_name):
    if not os.path.exists(USER_DATA_FILE):
        return False, "No users registered yet"

    with open(USER_DATA_FILE, "r") as file:
        for line in file:
            # _ for hash whoich is irreleveant and ,1 only split once
            stored_username, _ = line.strip().split(",", 1)
            if stored_username == user_name:
                return True, ""

    return False, "User name does not exist"


def get_stored_hash(user_name):
    with open(USER_DATA_FILE, "r") as file:
        for line in file:
            stored_username, stored_hash = line.strip().split(",", 1)
            if stored_username == user_name:
                return stored_hash
    return None


def verify_password(password, stored_hash):
    pass_2_verify = password.encode()
    stored_hash_bytes = stored_hash.encode()

    # check is encoded passworded matches with the hash
    if bcrypt.checkpw(pass_2_verify, stored_hash_bytes):
        return True, ""
    else:
        return False, "Password must contain:\nAtleast one upper case letter\nAtleast one number\nAtleast one lowercase letter\nAtleast one special character(@$*#%^_!*&)"


def login(user_name, password):
    with open(USER_DATA_FILE, "r") as file:
        for line in file:
            stored_username, stored_password = line.strip().split(",", 1)

            if stored_username == user_name:

                stored_password_bytes = stored_password.encode()
                password_bytes = password.encode()

                if bcrypt.checkpw(password_bytes, stored_password_bytes):
                    print("You are logged in")
                    return True
                else:
                    print("Incorrect password")
                    return False

            print("User name not found")
            return False


def display_menu():
    print("MULTI-DOMAIN INTELLIGENCE PLATFORM\n")
    print("---Secure Authentication Sytems---")
    print("\n----------------------------\n")
    print("[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")


def main():

    # Main program
    print("Welcome to the Week 7 Authentication System!")

    while True:
        display_menu()
        choice = int(input("Please select an option(1-3)").strip())

        if choice == 1:
            # Pegistration flow
            print("\n-----------USER REGISTRATION--------")
            user_name = input("Please enter a username:\t")

            # validate username
            is_valid, error_msg = validate_username(user_name)
            if not is_valid:
                print(f"Error: {error_msg}\n")
                print("\n------------------------------\n")
                continue
            password = input("Please enter a password: \t")

            # validate password
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                print(f"Error:{error_msg}\n")
                print("\n--------------------------\n")
                continue

            # confirm password
            password_confirm = input("Confirm password:\t").strip()
            if password != password_confirm:
                print(f"Error: Passwords do not match")
                continue

            # Register the User
            success, msg = register_user(user_name, password)
            print(msg)

        # login user
        elif choice == 2:
            print("\n---------USER LOGIN-------------\n")
            user_name = input("Enter user name:\t")

            # check if user nam matches
            is_valid, error_msg = verify_user_name(user_name)
            if not is_valid:
                print(f"Error:{error_msg}\n")
                print("\n----------------------\n")
                continue

            # get stored hash for the username
            stored_hash = get_stored_hash(user_name)
            if not stored_hash:
                print("Error: User not found or data corrupted.\n")
                continue

            password = input("Enter password:\t").strip()
            is_valid, error_msg = verify_password(password, stored_hash)
            if not is_valid:
                print(f"Error: {error_msg}\n")
                print("\n-----------------------------\n")
                continue

            # success message if it all checks out
            print(f"\n Login successful")

        elif choice == 3:
            print("\nThank you for using the authentication system.")
            print("Exiting...")
            break

        else:
            print("\nError: Invalid option. Please select 1, 2, or 3.")


if __name__ == "__main__":
    main()
