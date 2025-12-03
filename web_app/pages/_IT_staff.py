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

# Define the absolute path to the database
DB_FILE_PATH = project_root / "DATA" / "intelligence_platform.db"

tickets_manager = Tickets()

st.set_page_config(
    page_title="IT Staff",
    page_icon="🛠️",
    layout="centered"
)

st.title("🛠️IT Staff")

init_session()
#ensure staff is logged in
UserService.require_login(role="staff")

# Get tickets as DataFrame
df = tickets_manager.get_all_tickets()
st.dataframe(df)

#CONNECT TO DB
conn = connect_database("DATA/intelligence_platform.db")

unassigned = df[df["assigned_to"] == "Unassigned"]


st.subheader("Unassigned Tickets")

if unassigned.empty:
    st.info("Everything's assigned.")
else:
    for _, row in unassigned.iterrows():
        with st.expander(f"#{row.id} — {row.title}"):
            st.write(f"**Description:** {row.description}")
            st.write(f"**Status:** {row.status}")

            # Assign button + update status
            if st.button(f"Assign ticket #{row.id} to me", key=f"assign_{row.id}"):
                # Assign to current user
                tickets_manager.assign_ticket(row.id, st.session_state["username"])
                
                # Optional: update status to "In Progress"
                conn = connect_database("DATA/intelligence_platform.db")
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE tickets SET status = ? WHERE id = ?",
                    ("In Progress", row.id)
                )
                conn.commit()
                conn.close()
                
                st.success(f"Ticket #{row.id} assigned to you and status updated to In Progress.")
                st.rerun()

#AI Analysis
st.subheader("AI Ticket Analysis")
ticket_options = [f"{row.id} — {row.title}" for _, row in df.iterrows()]
selected = st.selectbox("Select or search a ticket", ticket_options)

if selected:
    ticket_id = int(selected.split(" — ")[0])
    ticket_row = df[df["id"] == ticket_id].iloc[0]

    if st.button(f"Analyze Ticket #{ticket_id}", key=f"analyze_{ticket_id}"):
        system_prompt = f"""
        You are an IT operations expert.
        Analyze this ticket and provide troubleshooting suggestions, potential causes, and priority recommendations.
        """
        with st.spinner("Analyzing ticket with AI..."):
            response = client.models.generate_content(
                model="gemini-2.0-flash-thinking-exp",
                contents=f"{system_prompt}\nTicket Title: {ticket_row.title}\nDescription: {ticket_row.description}"
            )
        st.info(response.text)