import streamlit as st
import sys
from pathlib import Path
import streamlit as st
import pandas as pd

project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

from DATABASE.app.data.new_ticks import get_all_tickets, get_ticket_by_id, assign_ticket
from DATABASE.app.data.db import connect_database

st.set_page_config(
    page_title="IT Staff",
    page_icon="🛠️",
    layout="centered"
)

st.title("🛠️IT Staff")
# Ensure username exists
if "username" not in st.session_state:
    st.warning("You must be logged in as a staff member to assign tickets.")
    st.stop()  # stops execution if no user is logged in

# Get tickets as DataFrame
df = get_all_tickets(as_df=True)
st.dataframe(df, use_container_width=True)

#CONNECT TO DB
conn = connect_database("DATA/intelligence_platform.db")



tickets = get_all_tickets()
unassigned = df[df["assigned_to"] == "Unassigned"]


st.subheader("Unassigned Tickets")

if unassigned.empty:
    st.info("Everything's assigned. Enjoy the silence.")
else:
    for _, row in unassigned.iterrows():
        with st.expander(f"#{row.id} — {row.title}"):
            st.write(f"**Description:** {row.description}")
            st.write(f"**Status:** {row.status}")

            # Assign button
            if st.button(f"Assign ticket #{row.id} to me"):
                assign_ticket(row.id, st.session_state["username"])
                st.success(f"Ticket #{row.id} assigned to you.")
                st.rerun()
