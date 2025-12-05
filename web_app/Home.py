import sys
import streamlit as st
from pathlib import Path

# Absolute path to project root
project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

from DATABASE.app.services.user_service import UserService
from DATABASE.app.data.db import connect_database


# Define the absolute path to the database
DB_FILE_PATH = project_root / "DATA" / "intelligence_platform.db"

user_service = UserService(str(DB_FILE_PATH))

# connencting to database
conn = connect_database("DATA/intelligence_platform.db")


st.title("Welcome to my Dashboard")

st.set_page_config(
    page_title="Home",
    page_icon="🔑",
    layout="centered"
)

#with tab_login:
st.subheader("Login 🔑")
login_form = st.form("Login Form")

with st.sidebar:
    st.markdown("Navigation")

# initialize session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "role" not in st.session_state:
    st.session_state.role=""

if not st.session_state.logged_in:
    with st.form("Login"):
        #login user input
        st.subheader("Login form")
        username=st.text_input("Enter username")
        password=st.text_input("Enter password")

        col1, col2 = st.columns(2)
        with col1:
            login = st.form_submit_button("Login")
            #logging user in
            if login:
                is_valid, error_msg, role = UserService.login_user(username, password)
                if not is_valid:
                    st.error(f"Error: {error_msg}")
                else:
                    st.success(f"{username} logged insuccessfully!")
                    st.session_state.logged_in = True
                    st.session_state.username=username
                    st.session_state.role=role
                    #st.switch_page("pages/main_dash.py")
        with col2:
            new_acc=st.form_submit_button("Create new acount")
            st.markdown("If you don't have account")
            if new_acc:
                st.info("Redirect to registration page or open registration form")
                st.switch_page("pages/register.py")  
else:
    st.success(f"User '{st.session_state.username}' is logged in as {st.session_state.role}")
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.role = None
        st.experimental_rerun()
            
