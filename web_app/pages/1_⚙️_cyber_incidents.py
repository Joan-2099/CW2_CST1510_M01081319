import sys
from pathlib import Path
import pandas as pd
import plotly.express as px
import matplotlib.pyplot as plt
from datetime import date

# Absolute path to project root
project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

import streamlit as st
from DATABASE.app.data.db import connect_database
from DATABASE.app.data.incidents import Incidents
from DATABASE.app.services.user_service import UserService
from DATABASE.app.services.session import init_session
from DATABASE.app.data.api import API_analyzer

api_analyze= API_analyzer()

st.set_page_config(
    page_title="Cyber_Incidents",
    page_icon="🛠️",
    layout="wide"
)
st.title("Cyber Incidents page")

#initialize session state
init_session()
UserService.require_login(role="user")

df = None

#allow user to upload csv file
uploaded_file = st.file_uploader(
    "Upload CSV file",
    type=["csv"],  # to onlty allow CSV files
    help="Select a CSV file to preview and check."
)

if uploaded_file is not None:
    try:
        if uploaded_file is not None:
            # Read CSV into pandas DataFrame
            df = pd.read_csv(uploaded_file)
            st.success("CSV uploaded successgully")
    except Exception as e:
        # Show error if the CSV cannot be read
        st.error(f"Error reading CSV file: {e}")

if "incidents_manager" not in st.session_state:
    conn = connect_database()
    st.session_state.incidents_manager = Incidents(conn)

incidents_manager = st.session_state.incidents_manager

# fetch data
df = incidents_manager.get_all_incidents()

#Correct mispelt and duplicate incident
df['incident_type'] = df['incident_type'].str.strip().str.title()

df['incident_type'] = df['incident_type'].replace({
    'Phising': 'Phishing',  # merge misspelling
})
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
        try:
            ai_text = api_analyze.analyze_incident(incident['description'], incident['severity'])
            st.info(ai_text)
        except Exception as e:
            st.error(f"AI analysis failed: {e}")



#create input form
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

#convert created_at column into a datetime
df['created_at'] = pd.to_datetime(df['created_at'])

#treands grouped by months
trend = df.groupby([
    'incident_type',
    df['created_at'].dt.to_period('M')   # group by Month/Year automatically
]).size().reset_index(name='count')

# If created_at is a period
trend['created_at'] = trend['created_at'].dt.to_timestamp()

# Make sure it's datetime
trend['created_at'] = pd.to_datetime(trend['created_at'])

# Now subtract one month safely
latest_month = trend['created_at'].max()
prev_month = latest_month - pd.DateOffset(months=1)

#extract counts for those two motnhs
latest = trend[trend['created_at'] == latest_month]
previous = trend[trend['created_at'] == prev_month]

#one line per incident
merge = latest.merge(
    previous, 
    on='incident_type', 
    how='left',
    suffixes=('_latest', '_prev')
)

#calculate the percentage change
merge['change'] = (
    (merge['count_latest'] - merge['count_prev']) 
    / merge['count_prev'].replace(0, 1)#this is done to avaid division by zero
) * 100

#identify the top spiking threat
top_spike = merge.sort_values('change', ascending=False).iloc[0]

#display the spiking metric as a percentage
st.metric(
    "Fastest Growing Threat", 
    top_spike['incident_type'], 
    f"{top_spike['change']:.1f}%"
)


#Charts and visualizations
st.subheader("Bar Chart showin the Severity per Incident")
st.write(df['incident_type'].value_counts())
fig = px.bar(
    df, 
    x='incident_type',  # column name in df
    y='severity', 
    color='incident_type'  # if you want each incident_type to have different colors
)
#display bar chart
st.plotly_chart(fig, use_container_width=True)


# Make sure 'date_created' is a datetime column
df['created_at'] = pd.to_datetime(df['created_at'])

# Select incident type
incident_choice = st.selectbox("Select Incident Type:", df['incident_type'].unique(),key="incident_choice_linechart")

# Filter dataframe
df_filtered = df[df['incident_type'] == incident_choice]

# Map severity to numeric values
severity_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
df_filtered['severity_numeric'] = df_filtered['severity'].map(severity_map)

# Sort by date
df_filtered = df_filtered.sort_values('created_at')

st.subheader(f"Line Chart of Severity Over Time for {incident_choice}")

# Plot
fig, ax = plt.subplots()
ax.plot(df_filtered['created_at'], df_filtered['severity_numeric'], marker='o', linestyle='-')
ax.set_xlabel("Date Created")
ax.set_ylabel("Severity (1=Low, 4=Critical)")
ax.set_title(f"Severity Over Time for {incident_choice}")
ax.grid(True)
#display line chart
st.pyplot(fig)

st.divider()

if st.button("Log out"):
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None
    st.experimental_rerun()

    