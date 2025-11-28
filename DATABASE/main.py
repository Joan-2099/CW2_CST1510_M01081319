import bcrypt
from app.data.db import connect_database
from app.data.schema import create_all_tables
from app.services.user_service import register_user, login_user, migrate_users_from_file
from app.data.incidents import insert_incident, get_all_incidents
from app.data.db import init_database


def display_menu():
    print("[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")


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



# function created to retrieve password
# function created to get username
def verify_user_name(user_name):
    from app.data.users import get_user_by_username
    if get_user_by_username(user_name):
        return True, ""
    return False, "Username not found"

def get_stored_hash(user_name):
    from app.data.users import get_user_by_username
    user = get_user_by_username(user_name)
    return user[2] if user else None

# function created to ensure password is correct


def verify_password(password, stored_hash):
    if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
        return True, ""
    return False, "Incorrect password"


def main():
    print("=" * 60)
    print("Week 8: Database Demo")
    print("=" * 60)

    # Initialize database (tables created here)
    init_database()

    # 2. Migrate users
    migrate_users_from_file()

    print("\n________________WELCOME TO THE AUTHENTICATION SYSTEM_______________")

    while True:
        display_menu()
        try:
            choice = int(input("Select an option(1-3)").strip())
        except ValueError:
            # catch non-numeric input
            print("Error: Please enter a number between 1-3.")
            continue

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
            password = input("Please enter a password:\t")

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

            # register user role
            role = input("Please enter your role:\t")
            # Register the User
            success, msg = register_user(user_name, password, role)
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

            # Ask user for password and verify it
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

    # 5. Query data
    df = get_all_incidents()
    print(f"Total incidents: {len(df)}")


if __name__ == "__main__":
    main()
