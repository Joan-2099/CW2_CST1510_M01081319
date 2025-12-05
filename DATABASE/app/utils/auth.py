import streamlit as st

def require_login(role=None):
    if not st.session_state.get("logged_in", False):
        st.warning("You must be logged in to access this page.")
        st.stop()

    if role is not None and st.session_state.get("role") != role:
        st.warning(f"This page is restricted to {role}")
        st.stop()

