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
conn = connect_database()

df = None
tab1, tab2 = st.tabs(["Incidents","Incidents manager"])
with tab1:
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
    col1, col2 = st.columns(2)
    with col1:
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

    with col2:
        # Filter for Phishing specifically
        phishing_df = df[df['incident_type'] == 'Phishing']

        # Count unresolved Phishing incidents
        phishing_unresolved = phishing_df[phishing_df['status'] != 'Resolved'].shape[0]

        st.metric(
            "Unresolved Phishing Cases", 
            phishing_unresolved,
            f"{len(phishing_df)} total Phishing incidents"
            )
    
    st.subheader("Phishing Incident Status Breakdown")
    cols = st.columns(3)
    status_counts = phishing_df['status'].value_counts()
    for i, status in enumerate(["Open", "In Progress", "Resolved"]):
        cols[i].metric(f"{status}", status_counts.get(status, 0))

    #numbers of incidents by incident type with donut chart
    col1,col2 = st.columns(2)
    with col1:
        # Count of each incident type
        incident_counts = df['incident_type'].value_counts().reset_index()
        incident_counts.columns = ['Incident Type', 'Count']

        # Create donut chart
        fig = px.pie(
            incident_counts,
            names='Incident Type',
            values='Count',
            hole=0.4,  # This creates the hole in the middle
            color_discrete_sequence=px.colors.qualitative.Set3  # For custom colours
        )

        fig.update_traces(
            textposition='inside',
            textinfo='percent+label'  # Shows both percentage and label inside slices
        )

        fig.update_layout(
            title_text='Incident Type Breakdown',
            annotations=[dict(text='Incidents', x=0.5, y=0.5, font_size=20, showarrow=False)]
        )

    
        # Display in Streamlit
        st.plotly_chart(fig, use_container_width=True)
    with col2:
        #bottleneck
        # Convert created_at to datetime if not already
        df['resolved_at'] = pd.to_datetime(df['resolved_at'], errors='coerce')
        df['created_at'] = pd.to_datetime(df['created_at'])

        # Compute resolution time in days
        df['resolution_days'] = (df['resolved_at'] - df['created_at']).dt.days

        avg_resolution = df.groupby('incident_type')['resolution_days'].mean().sort_values(ascending=False)
        #st.subheader("Average Resolution Time by Incident Type (days)")
        #st.dataframe(avg_resolution)

        #display bottleneck with chart
        fig = px.bar(
            avg_resolution, 
            x=avg_resolution.index, 
            y='resolution_days',
            labels={'x': 'Incident Type', 'resolution_days': 'Avg Resolution (days)'}
        )
        fig.update_layout(
            title_text='Resolution Time by Incident Type',
            annotations=[dict(text='Incidents', x=0.5, y=0.5, font_size=20, showarrow=False)]
        )
        st.plotly_chart(fig, use_container_width=True)

    # Make sure 'date_created' is a datetime column
    df['created_at'] = pd.to_datetime(df['created_at'])

    # Select incident type
    incident_choice = st.selectbox("Select Incident Type:", df['incident_type'].unique(),key="incident_choice_linechart")

    # Filter dataframe
    df_filtered = df[df['incident_type'] == incident_choice]

    # Map severity to numeric values if not already done
    severity_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    df_filtered['severity_numeric'] = df_filtered['severity'].map(severity_map)

    # Sort by date
    df_filtered = df_filtered.sort_values('created_at')

    # Create interactive line chart
    fig = px.line(
        df_filtered, 
        x='created_at', 
        y='severity_numeric',
        markers=True,
        title=f"Severity Over Time for {incident_choice}",
        labels={
            'created_at': 'Date Created',
            'severity_numeric': 'Severity (1=Low, 4=Critical)'
        },
        template='plotly_dark'  # or 'plotly_white', 'ggplot2', etc.
    )

    # Add hover info for better readability
    fig.update_traces(
        hovertemplate='<b>Date:</b> %{x}<br><b>Severity:</b> %{y}<br><b>Level:</b> %{customdata}',
        customdata=df_filtered['severity']
    )

    # Optional: make line smoother
    fig.update_traces(line=dict(shape='spline', width=3), marker=dict(size=8))

    # Display in Streamlit
    st.plotly_chart(fig, use_container_width=True)

with tab2:
    UserService.require_login(role="staff")
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

st.divider()

if st.button("Log out"):
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None
    st.rerun()

    