import sys
from pathlib import Path
import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit_lottie import st_lottie

# Absolute path to project root
project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

from DATABASE.app.data.db import connect_database
from DATABASE.app.data.incidents import Incidents
from DATABASE.app.services.user_service import UserService
from DATABASE.app.data.api import API_analyzer
from DATABASE.app.data.schema import TableCreator
from DATABASE.app.utils.csv_utils import load_to_table
from datetime import date, timedelta
from DATABASE.app.utils.csv_schema import TABLE_SCHEMAS

from Animations.json_anm import load_lottiefile

api_analyze= API_analyzer()

st.set_page_config(
    page_title="Cyber_Incidents",
    page_icon="🛠️",
    layout="wide"
)
st.title("Cyber Incidents page")

#initialize session state
UserService.init_session()
# Ensure user is logged in
UserService.require_login()
conn = connect_database()
st.session_state.incidents_manager = Incidents(conn)
incidents_manager = st.session_state.incidents_manager

df = None
tab1, tab2 = st.tabs(["Incidents","Incidents manager"])

with tab1:
    # fetch data
    df = incidents_manager.get_all_incidents(conn)

    uploaded_file = st.file_uploader(
    "Upload CSV file",
    type=["csv"],  # to onlty allow CSV files
    help="Select a CSV file to preview and check."
    )
    
    if uploaded_file is not None:

        # Load CSV to DB and get number of new rows inserted
        success, rows_added, message = load_to_table(conn,csv_source=uploaded_file,table_name="cyber_incidents",
            table_schemas=TABLE_SCHEMAS)

        # Show feedback to user
        if success:
            st.success(f"CSV processed successfully! {rows_added} new rows added.")
        else:
            st.warning(message)

    # Refresh table after CSV load
    df = incidents_manager.get_all_incidents(conn)
    st.dataframe(df)


    #Correct mispelt and duplicate incident
    df['incident_type'] = df['incident_type'].str.strip().str.title()

    df['incident_type'] = df['incident_type'].replace({
        'Phising': 'Phishing',  # merge misspelling
    })

    # Build options: "ID — Incident Type (Severity)"
    options = [
        f"{row['id']} — {row['incident_type']} ({row['severity']})"
        for _, row in df.iterrows()
    ]
    col1,col2 = st.columns(2)
    with col1:
        st.subheader("AI analyze incidents")
        # Selectbox with searchable input
        selected = st.selectbox(
            "Select or search for an incident to analyze", 
            options, 
            help="Type to search or scroll through incidents"
        )
        analyze = st.button("AI Analyze Incident", key=f"analyze_this incident")

    with col2:
        tools =load_lottiefile("Animations/Tools.json")
        st_lottie(tools,
            speed =1,
            height=250,
            key=None
        )
        

    if selected:
        incident_id = int(selected.split(" — ")[0])
        incident = df[df['id'] == incident_id].iloc[0]

        if analyze:
            try:
                ai_text = api_analyze.analyze_incident(incident['description'], incident['severity'])
                st.info(ai_text)
            except Exception as e:
                st.error(f"AI analysis failed: {e}")



    #create input form
    with st.expander("Input incident"):
        st.subheader("Insert incident")
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

        #KPI ref:https://medium.com/@cameronjosephjones/building-a-kpi-dashboard-in-streamlit-using-python-c88ac63903f5
       
        # Make sure created_at is datetime
        df['created_at'] = pd.to_datetime(df['created_at'])

        # Identify top growing in recent 14 days
        recent_period = df['created_at'].max() - timedelta(days=14)
        recent_incidents = df[df['created_at'] >= recent_period]

        # Count incidents per type in the recent period
        recent_counts = recent_incidents['incident_type'].value_counts()

        # Top growing = most reported in recent period
        top_type = recent_counts.idxmax()
        top_count = recent_counts.max()

        # Display KPI in Streamlit
        st.metric(
            "Fastest Growing Threat (Recent)", 
            top_type, 
            f"{top_count} incidents in last 14 days"
        )

    with col2:
        # Select incident type for KPI
        incident_kpi_choice = st.selectbox(
            "Select Incident Type for KPI",
            df['incident_type'].unique(),
            index=0  # default to the first incident type
        )

        # Filter incidents by chosen type
        kpi_df = df[df['incident_type'] == incident_kpi_choice]

        # Count new incidents in last 7 days
        recent_count = kpi_df[kpi_df['created_at'] >= pd.Timestamp.today() - pd.Timedelta(days=7)].shape[0]

        # Display KPI
        st.metric(
            f"New {incident_kpi_choice} Incidents (7d)",
            recent_count,
            f"{len(kpi_df)} total {incident_kpi_choice} incidents"
        )

            
    # Select which incident type to view status breakdown for
    st.subheader("Incident Status Breakdown")
    incident_type_choice = st.selectbox(
        "Select Incident Type for Status Breakdown:",
        df['incident_type'].unique()
    )

    # Filter dataframe based on user selection
    selected_df = df[df['incident_type'] == incident_type_choice]

    # Count status metrics
    status_counts = selected_df['status'].value_counts()
    unresolved_count = selected_df[selected_df['status'] != 'Resolved'].shape[0]

    # Create 4 columns for the statuses
    cols = st.columns(4)
    cols[0].metric("Open", status_counts.get("Open", 0))
    cols[1].metric("In Progress", status_counts.get("In Progress", 0))
    cols[2].metric("Resolved", status_counts.get("Resolved", 0))
    cols[3].metric("Unresolved", unresolved_count)



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
        # Convert dates
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

    # For severity line chart
    
    incident_choice = st.selectbox("Select Incident Type:", df['incident_type'].unique(), key="incident_choice_linechart")
    df_filtered = df[df['incident_type'] == incident_choice].copy()  # important .copy()
    severity_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    df_filtered['severity_numeric'] = df_filtered['severity'].map(severity_map)
    df_filtered = df_filtered.sort_values('created_at')

    fig_line = px.line(df_filtered, x='created_at', y='severity_numeric', markers=True,
                    title=f"Severity Over Time for {incident_choice}",
                    labels={'created_at':'Date Created', 'severity_numeric':'Severity (1=Low,4=Critical)'},
                    template='plotly_dark')
    st.plotly_chart(fig_line, use_container_width=True)


    

with tab2:
    UserService.require_role("staff")
    #Changing incidents status
    st.subheader("Unresoleved incident")
    incidents_df=incidents_manager.get_all_incidents(conn)
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

    