import sys
from pathlib import Path

# Absolute path to project root
project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

import streamlit as st
from DATABASE.app.data.db import connect_database
from DATABASE.app.data.incidents import Incidents
from DATABASE.app.services.user_service import UserService
from DATABASE.app.services.session import init_session

DB_FILE_PATH = project_root / "DATA" / "intelligence_platform.db"

# connencting to database
conn = connect_database("DATA/intelligence_platform.db")

#initialize session state
init_session()
UserService.require_login(role="user")

#call class name
incidents_manager= Incidents()
  
# fetch
df = incidents_manager.get_all_incidents()
st.dataframe(df)

# Build options: "ID — Incident Type (Severity)"
options = [
    f"{row['id']} — {row['incident_type']} ({row['severity']})"
    for _, row in df.iterrows()
]

# Selectbox with searchable input
selected = st.selectbox(
    "Select or search for an incident to analyze", 
    options, 
    help="Type to search or scroll through incidents"
)

if selected:
    incident_id = int(selected.split(" — ")[0])
    incident = df[df['id'] == incident_id].iloc[0]

    if st.button("AI Analyze Incident", key=f"analyze_{incident_id}"):
        analysis = incidents_manager.analyze_incident(incident['description'], incident['severity'])
        st.info(analysis)

from datetime import date

with st.form("New Incident"):
    reported_by=st.text_input("Name")
    title = st.text_input("Incident Title")
    severity = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"])
    status = st.selectbox("Status", ["Open", "In Progress", "Resolved"])
    description = st.text_area("Description")
    

    submitted = st.form_submit_button("Add Incident")

    if submitted and title:
        today = date.today().isoformat()
        incidents_manager.insert_incident(today, title, severity, status, description,reported_by)
        st.success("Incident added successfully!")
        st.rerun()


st.divider()

if st.button("Log out"):
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None
    st.experimental_rerun()

    