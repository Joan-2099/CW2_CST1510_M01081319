import sys
import streamlit as st
from pathlib import Path

# Absolute path to project root
project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

from DATABASE.app.services.user_service import UserService
from DATABASE.app.data.db import connect_database

DB_FILE_PATH = project_root / "DATA" / "intelligence_platform.db"
user_service = UserService(str(DB_FILE_PATH))

# connencting to database
conn = connect_database("DATA/intelligence_platform.db")

st.set_page_config(
    page_title="Register",
    page_icon="📝",
    layout="centered"
)
#Register tab
st.subheader("Register 📝")
register_form = st.form("Register Form")
    
with st.form("Registration"):
    #register user input
    st.subheader("User Registration")
    username=st.text_input("Enter username")
    password=st.text_input("Enter password")
    confirm_pass=st.text_input("Confirm password")
    role=st.selectbox("Role",["user","staff"])

    register =st.form_submit_button("Register")

    #validate user
    if register:
        # confirm password
        if password != confirm_pass:
            st.error(f"Error: Passwords do not match")
        else:
            #register user   
            is_valid, msg =user_service.register_user(username, password, role)
            if not is_valid:
                st.error(msg)
            else:
                st.success(f"{username} registered succesfully")
                st.markdown("Would you like to login")
                
                login=st.form_submit_button("Login")
                if login:
                    st.switch_page("Home.py")
        