import streamlit as st

def staff_restrict(role=None):
    if role is not None and st.session_state.get("role") != role:
        st.warning(f"This page is restricted to {role}")
        st.stop()

