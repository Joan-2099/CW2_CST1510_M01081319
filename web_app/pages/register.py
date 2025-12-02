import sys
import streamlit as st
from pathlib import Path

# Absolute path to project root
project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

from DATABASE.app.data.users import verify_user_name
from DATABASE.app.services.user_service import register_user,validate_password,validate_username
from DATABASE.app.data.db import connect_database

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
    user_name=st.text_input("Enter username")
    password=st.text_input("Enter password")
    confirm_pass=st.text_input("Confirm password")
    role=st.selectbox("Role",["user","staff"])

    register =st.form_submit_button("Register")

    #validate user
    if register:
        #check if username already exists
        #is_valid, error_msg= verify_user_name(user_name)
        #if not is_valid:
         #   st.error(f"Error: {error_msg}")

        #check that username meets the specifications
        is_valid, error_msg = validate_username(user_name)
        if not is_valid:
            st.error(f"Error: {error_msg}")

        #check if password is strong     
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            st.error(f"Error: {error_msg}")

        # confirm password
        if password != confirm_pass:
            st.error(f"Error: Passwords do not match")
        else:
            #register user   
            register_user(user_name, password, role)
            st.success(f"{user_name} registered succesfully")
            
            st.markdown("Would you like to login")
            login=st.form_submit_button("Login")
            if login:
                st.switch_page("pages/login.py")
        