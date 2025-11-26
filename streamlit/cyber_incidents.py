import sys
from pathlib import Path

# Absolute path to your project root
project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

import streamlit as st
from DATABASE.app.data.db import connect_database
from DATABASE.app.data.incidents import get_all_incidents, insert_incident

# connencting to database
conn = connect_database("DATA/intelligence_platform.db")

st.title("Cyber Incidents Dashboard")

incidents = get_all_incidents()
st.dataframe(incidents, use_container_width=True)

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
    st.session_state.logged_in=False
    st.session_state.user_name=""
    st.info("You have been logged out")
    st.switch_page("Home.py")