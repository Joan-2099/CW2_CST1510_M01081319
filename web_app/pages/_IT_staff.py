import streamlit as st
import sys
from pathlib import Path
from google import genai
import pandas as pd

api_key = st.secrets["GEMINAI_API_KEY"]
client = genai.Client(api_key=api_key)

project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

from DATABASE.app.data.tickets import Tickets
from DATABASE.app.data.db import connect_database
from DATABASE.app.services.user_service import UserService
from DATABASE.app.services.session import init_session
from DATABASE.app.data.api import API_analyzer
from DATABASE.app.data.incidents import Incidents

api_analyze= API_analyzer()
# Define the absolute path to the database
DB_FILE_PATH = project_root / "DATA" / "intelligence_platform.db"

tickets_manager = Tickets()

st.set_page_config(
    page_title="IT Staff",
    page_icon="🛠️",
    layout="wide"
)

st.title("🛠️IT Staff")

init_session()
#ensure staff is logged in
UserService.require_login(role="staff")

#CONNECT TO DB
conn = connect_database("DATA/intelligence_platform.db")
incidents_manager=Incidents(conn)


st.subheader("Unassigned Tickets")
# Get tickets as DataFrame
df = tickets_manager.get_all_tickets(as_df=True)
st.dataframe(df)
col1,col2 = st.columns(2)
with col1:
    st.subheader("Unassigned tickets")
    unassigned = df[df["assigned_to"] == "Unassigned"]

    if unassigned.empty:
        st.info("Everything's assigned.")
    else:
        for _, row in unassigned.iterrows():
            with st.expander(f"#{row.id} — {row.title}"):
                st.write(f"**Description:** {row.description}")
                
                #update ticket status
                new_status =st.selectbox("Update ticket status",["Open","In progress","Resolved"], key=f"unassigned_status_{row.id}")   
                
                # Assign button + update status
                assigned = st.button(f"Assign ticket #{row.id} to me", key=f"assign_{row.id}")
                if assigned:
                    # Assign to current user
                    tickets_manager.update_ticket_status(row.id, new_status)
                    tickets_manager.assign_ticket(row.id, st.session_state["username"])
                    st.success(f"Ticket #{row.id} assigned to you and status updated to In Progress.")
                    st.rerun()
with col2:
    #tickets assigned to me
    st.subheader("Tickets Assigned to Me")

    # Filter tickets for the logged-in staff member
    my_tickets = df[df["assigned_to"] == st.session_state["username"]]

    if my_tickets.empty:
        st.info("No tickets assigned to you at the moment.")
    else:
        for _, row in my_tickets.iterrows():
            with st.expander(f"#{row.id} — {row.title}"):
                st.write(f"**Description:** {row.description}")
                st.write(f"**Current Status:** {row.status}")
                st.write(f"**Assigned To:** {row.assigned_to}")

                # status selector
                status_key = f"my_ticket_status_{row.id}"
                new_status = st.selectbox(
                    "Update status",
                    ["Open", "In Progress", "Resolved"],
                    index=["Open", "In progress", "Resolved"].index(row.status),
                    key=status_key
                )

                if st.button("Update Status", key=f"update_my_ticket_{row.id}"):
                    tickets_manager.update_ticket_status(row.id, new_status)
                    st.success(f"Ticket #{row.id} status updated to {new_status}.")
                    st.rerun() 

#AI Analysis
st.subheader("AI Ticket Analysis")
ticket_options = [f"{row.id} — {row.title}" for _, row in df.iterrows()]
selected = st.selectbox("Select or search a ticket", ticket_options, key ="AI analyzer ticket")

if selected:
    ticket_id = int(selected.split(" — ")[0])
    ticket_row = df[df["id"] == ticket_id].iloc[0]

    if st.button(f"Analyze Ticket #{ticket_id}", key=f"analyze_{ticket_id}"):
        ai_text=api_analyze.analyze_it_tickets(ticket_row)
        st.info(ai_text)

#Changing incidents status
st.subheader("Unresoleved incident")
incidents_df=incidents_manager.get_all_incidents()
# Only unresolved incidents
unresolved = incidents_df[incidents_df["status"] != "Resolved"]

if unresolved.empty:
    st.info("All incidents are resolved.")
else:
    for _, row in unresolved.iterrows():
        with st.expander(f"#{row.id} — {row.incident_type} on {row.date}"):
            st.write(f"**Severity:** {row.severity}")
            st.write(f"**Description:** {row.description}")
            st.write(f"**Reported by:** {row.reported_by}")
            st.write(f"**Current Status:** {row.status}")

            # Dynamic status selector
            status_key = f"status_{row.id}"
            new_status = st.selectbox(
                "Update status",
                ["Open", "In Progress", "Resolved"],
                index=["Open", "In Progress", "Resolved"].index(row.status),
                key=status_key
            )

            if st.button("Update Status", key=f"update_{row.id}"):
                incidents_manager.update_incident(row.id, status=new_status)
                st.success(f"Incident #{row.id} status updated to {new_status}.")
                st.rerun()  # refresh table immediately



