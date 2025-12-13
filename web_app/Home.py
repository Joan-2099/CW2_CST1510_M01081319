import sys
import streamlit as st
from pathlib import Path
from streamlit_lottie import st_lottie

# Absolute path to project root
project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

from DATABASE.app.services.user_service import UserService
from DATABASE.app.data.db import connect_database
from Animations.json_anm import load_lottiefile


# Define the absolute path to the database
DB_FILE_PATH = project_root / "DATA" / "intelligence_platform.db"

user_service = UserService(str(DB_FILE_PATH))

# connencting to database
conn = connect_database("DATA/intelligence_platform.db")


st.title("Welcome to my Dashboard")

st.set_page_config(
    page_title="Home",
    page_icon="🔑",
    layout="wide"
)

#with tab_login:
st.subheader("Login 🔑")
login_form = st.form("Login Form")


# initialize session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "role" not in st.session_state:
    st.session_state.role=""
        
tab1,tab2 =st.tabs(["Login","Register"])

with tab1:
    if not st.session_state.logged_in:
        col1,col2 = st.columns(2)
        with col1:
            with st.form("Login"):
                #login user input
                st.subheader("Login form")
                username=st.text_input("Enter username")
                password=st.text_input("Enter password")

                
                login = st.form_submit_button("Login")
                #logging user in
                if login:
                    is_valid, error_msg,role = UserService.login_user(username, password)
                    if not is_valid:
                        st.error(f"Error: {error_msg}")
                    else:
                        st.success(f"{username} logged insuccessfully!")
                        st.session_state.logged_in = True
                        st.session_state.username=username
                        st.session_state.role=role
                        st.switch_page("pages/main.py")

        with col2:
            lottie_file=load_lottiefile("Animations/Unlock.json")
            st_lottie(lottie_file,
                    speed =1,
                    height=450,
                    key=None
            )
                
            
    else:
        st.success(f"User '{st.session_state.username}' is logged in as {st.session_state.role}")
        if st.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.username = None
            st.session_state.role = None
            st.rerun()

    
            
with tab2:
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
                    
