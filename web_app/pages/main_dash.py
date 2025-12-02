import sys
from pathlib import Path
import streamlit as st

project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

from DATABASE.app.utils.auth import require_login

st.title("Main dash")
if "username" not in st.session_state:
    st.session_state["username"] = None
if "role" not in st.session_state:
    st.session_state["role"] = None
    
require_login(role="user")

st.write("Well logged in")