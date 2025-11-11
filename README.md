
# Week 7: Secure Authentication System
Student Name: Joan Martha Acom
Student ID: M01081319
Course: CST1510 -Programming and Communication

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
