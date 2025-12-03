import sys
from pathlib import Path
import streamlit as st

project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))
from DATABASE.app.services.session import init_session
from DATABASE.app.services.user_service import UserService
DB_FILE_PATH = project_root / "DATA" / "intelligence_platform.db"


st.title("Main dash")
init_session()
UserService.require_login(role="user")

st.write("Well logged in")