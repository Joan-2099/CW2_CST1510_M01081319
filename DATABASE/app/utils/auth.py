import streamlit as st
from streamlit.runtime.scriptrunner import RerunException
from streamlit.runtime.scriptrunner import get_script_run_ctx


#function to ensure users remain logged in or locked out if not logged in
def require_login(role=None):
    if "username" not in st.session_state or st.session_state["username"] is None:
        st.warning("You must be logged in to access this page.")
        st.stop()

    if role is not None and st.session_state.get("role") != role:
        st.warning(f"This page is restricted to {role} users.")
        st.stop()

def logout():
    """Clear session state and refresh page to enforce login."""
    ctx = get_script_run_ctx()
    if ctx is not None:
        raise RerunException(ctx)
