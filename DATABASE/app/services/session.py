import streamlit as st

def init_session ():
    if "username" not in st.session_state:
        st.session_state["username"] = None
    if "role" not in st.session_state:
        st.session_state["role"] = None
    if "is_logged_in" not in st.session_state:
        st.session_state["is_logged_in"] = False