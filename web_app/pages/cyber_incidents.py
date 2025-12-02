import sys
from pathlib import Path

# Absolute path to project root
project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

import streamlit as st
from DATABASE.app.data.db import connect_database
from DATABASE.app.data.incidents import get_all_incidents, insert_incident, analyze_incident
from DATABASE.app.utils.auth import require_login, logout


# connencting to database
conn = connect_database("DATA/intelligence_platform.db")

st.title("Cyber Incidents Dashboard")
if "username" not in st.session_state:
    st.session_state["username"] = None
if "role" not in st.session_state:
    st.session_state["role"] = None

require_login(role="user")
  
incidents = get_all_incidents()
st.dataframe(incidents, use_container_width=True)

# Build options: "ID — Incident Type (Severity)"
options = [
    f"{row['id']} — {row['incident_type']} ({row['severity']})"
    for _, row in incidents.iterrows()
]

# Selectbox with searchable input
selected = st.selectbox(
    "Select or search for an incident to analyze", 
    options, 
    help="Type to search or scroll through incidents"
)

if selected:
    incident_id = int(selected.split(" — ")[0])
    incident = incidents[incidents['id'] == incident_id].iloc[0]

    if st.button("AI Analyze Incident", key=f"analyze_{incident_id}"):
        analysis = analyze_incident(incident['description'], incident['severity'])
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
        insert_incident(today, title, severity, status, description,reported_by)
        st.success("Incident added successfully!")

st.divider()

if st.button("Log out"):
    st.session_state.clear()
    logout()

    