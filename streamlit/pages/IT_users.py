import sys
from pathlib import Path
import streamlit as st
import pandas as pd

project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

from DATABASE.app.data.new_ticks import get_all_tickets, get_ticket_by_id, insert_ticket
from DATABASE.app.data.db import connect_database

st.set_page_config(
    page_title="IT customer service",
    page_icon="🛠️",
    layout="centered"
)

st.title("🛠️IT customer service")
# Ensure username exists
if "username" not in st.session_state:
    st.warning("You must be logged in to assign tickets.")
    st.stop()  # stops execution if no user is logged in

# Get tickets as DataFrame
df = get_all_tickets(as_df=True)
st.dataframe(df, use_container_width=True)

#CONNECT TO DB
conn = connect_database("DATA/intelligence_platform.db")


#enter new ticket
st.header("🎫 IT Ticket Manager")


with st.form("🎫 IT Ticket Manager"):
    title = st.text_input("Issue Title")
    description = st.text_area("Describe the issue in detail")
    
    submit_new = st.form_submit_button("Submit Ticket")

if submit_new:
    new_ticket_id = insert_ticket(
        title=title,
        description=description,
        status="Open",
        assigned_to="Unassigned"
    )
    st.success(f"Ticket #{new_ticket_id} created successfully!")
