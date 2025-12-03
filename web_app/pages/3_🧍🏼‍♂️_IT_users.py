import sys
from pathlib import Path
import streamlit as st

project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

from DATABASE.app.data.tickets import Tickets
from DATABASE.app.data.db import connect_database
from DATABASE.app.services.user_service import UserService
from DATABASE.app.services.session import init_session

DB_FILE_PATH = project_root / "DATA" / "intelligence_platform.db"

user_serve = UserService(str(DB_FILE_PATH))

tickets_manager = Tickets()

#CONNECT TO DB
conn = connect_database("DATA/intelligence_platform.db")

st.set_page_config(
    page_title="IT customer service",
    page_icon="🛠️",
    layout="centered"
)

st.title("🛠️IT customer service")


# Initialize session state for user
init_session()
# Ensure user is logged in
user_serve.require_login(role="user")

# Get tickets as DataFrame
df = tickets_manager.get_all_tickets()
st.dataframe(df)



#enter new ticket
st.header("🎫 IT Ticket Manager")


with st.form("🎫 IT Ticket Manager"):
    title = st.text_input("Issue Title")
    description = st.text_area("Describe the issue in detail")
    
    submit_new = st.form_submit_button("Submit Ticket")

if submit_new:
    new_ticket_id = tickets_manager.insert_ticket(
        title=title,
        description=description,
        status="Open",
        assigned_to="Unassigned"
    )
    st.success(f"Ticket #{new_ticket_id} created successfully!")
    st.rerun()#ensures the table is updated after entry

