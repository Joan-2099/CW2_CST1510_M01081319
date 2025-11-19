
Student Name: Joan Martha Acom
Student ID: M01081319
Course: CST1510 -Programming and Communication with Python

# Week 7: Secure Authentication System

## Project Description
A command-line authentication system implementing secure password hashing
This system allows users to register accounts and log in with proper pass.

## Features
- Secure password hashing using bcrypt with automatic salt generation
- User registration with duplicate username prevention
- User login with password verification
- Input validation for usernames and passwords
- File-based user data persistence

## Technical Implementation
- Hashing Algorithm: bcrypt with automatic salting
- Data Storage: Plain text file (`users.txt`) with comma-separated values
- Password Security: One-way hashing, no plaintext storage
- Validation: Username (Atleast 5 alphanumeric characters), Password (atleast 8 characters|)


# Week 8: SQLite Database Integration & Incident Management System

## Project description
This week extends the secure authentication system from Week 7 by migrating from file-based storage to a structured SQLite relational database. The project now supports persistent, query-friendly data storage, user authentication backed by hashed passwords, and the ability to log and manage cyber incidents through a menu-driven command-line interface.

# Features

## Database Initialization
- When the program starts, the init_database() function in db.py is called.
init_database():
- Checks if the DATA folder exists; if not, it creates it.
- Connects to the SQLite database file intelligence_platform.db.
- Calls create_all_tables(conn) from schema.py to create the necessary tables.
- Closes the database connection after tables are created.

## Tables Creation
    The database consists of four core tables, each designed to store specific data:

    users Table – Stores registered users:

    id (INTEGER PRIMARY KEY AUTOINCREMENT)- Unique identifier for each user.
    username (TEXT, UNIQUE)- Login name.
    password_hash (TEXT)- Hashed password using bcrypt.
    role (TEXT, default 'user')- User role (e.g., analyst, admin).
This ensures secure storage of users with hashed passwords and unique usernames.

    cyber_incidents Table – Stores all cyber incident reports:

    id (INTEGER PRIMARY KEY AUTOINCREMENT): Unique incident identifier.
    date (TEXT): Date of the incident.
    incident_type (TEXT): Type/category of the incident.
    severity (TEXT): Incident severity (High, Medium, Low).
    status (TEXT): Status of the incident (Open, Closed).
    description (TEXT): Details about the incident.
    reported_by (TEXT): Username of the reporter.
    created_at (TIMESTAMP, default CURRENT_TIMESTAMP): Automatic record creation timestamp.
This provides a structured way to log, track, and manage cyber incidents.

    datasets_metadata Table – Stores metadata about datasets:

    id (INTEGER PRIMARY KEY AUTOINCREMENT)
    name (TEXT)
    description (TEXT)
    source (TEXT)
    date_created (TEXT)
    last_updated (TEXT)
    record_count (INTEGER)
    file_size_mb (REAL)
    created_at (TIMESTAMP, default CURRENT_TIMESTAMP)
This tracks datasets relevant to the platform, including size, records, and update history.

    it_tickets Table – Stores IT support ticket data:

    id (INTEGER PRIMARY KEY AUTOINCREMENT)
    title (TEXT)
    description (TEXT)
    status (TEXT, default 'open')
    assigned_to (TEXT)
    date_created (TEXT)
    resolved_date (TEXT)
    created_at (TIMESTAMP, default CURRENT_TIMESTAMP)
This organizes IT support tasks and their progress/status.

## User Data Flow
During registration:
- Input is validated (username length, password complexity, matching passwords) as mentioned in week 7
- User data is inserted into the users table.
- Duplicate usernames are prevented by SQLite’s UNIQUE constraint.

During login:
- Username is checked for existence within database
- Stored hashed password is retrieved.
- Input password is verified (refer to week 7)
- Successful login grants access to interact with incidents.

## Cyber Incidents Data Flow
- Users can add incidents via the CLI.
- Data is inserted into the cyber_incidents table.
- Each incident is automatically timestamped.
- Incidents can later be queried or updated as part of CRUD operations.

## Interactive CLI
Menu-based interface with three options:
Register a new user
Login
Exit
Prompts guide the user through registration, login, and error handling.
