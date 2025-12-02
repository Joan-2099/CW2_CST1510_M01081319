import csv
from datetime import datetime
import streamlit as st
import bcrypt
import os
from .db import connect_database


def get_user_by_username(username):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_by_role(username):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE role = ?", (username,))
    role = cursor.fetchone()
    conn.close()
    return role

# function created to get username
def verify_user_name(user_name):
    from app.data.users import get_user_by_username
    if get_user_by_username(user_name):
        return True, ""
    return False, "Username not found"

def verify_password(password, stored_hash):
    if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
        return True, ""
    return False, "Incorrect password"


def insert_user(username, password_hash, role='user'):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, password_hash, role)
    )
    conn.commit()
    conn.close()
