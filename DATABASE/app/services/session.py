import streamlit as st

def init_session ():
    if "username" not in st.session_state:
        st.session_state["username"] = None
    if "role" not in st.session_state:
        st.session_state["role"] = None
    if "is_logged_in" not in st.session_state:
        st.session_state["is_logged_in"] = False

def logout():
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None
    st.rerun()