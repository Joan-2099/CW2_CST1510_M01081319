import sys
from pathlib import Path
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
import altair as alt

project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

from DATABASE.app.data.tickets import Tickets
from DATABASE.app.data.db import connect_database
from DATABASE.app.services.user_service import UserService
from DATABASE.app.services.session import init_session
from DATABASE.app.data.api import API_analyzer

DB_FILE_PATH = project_root / "DATA" / "intelligence_platform.db"

user_serve = UserService(str(DB_FILE_PATH))

tickets_manager = Tickets()

api_analyze= API_analyzer()
#CONNECT TO DB
conn = connect_database("DATA/intelligence_platform.db")

st.set_page_config(
    page_title="IT customer service",
    page_icon="🛠️",
    layout="centered"
)

st.title("🛠️IT customer service")


# Initialize session state for user
init_session()
# Ensure user is logged in
UserService.require_login()
tab1, tab2 = st.tabs(["IT users","IT staff"])

with tab1:
    # Get tickets as DataFrame
    df = tickets_manager.get_all_tickets(as_df=True)
    st.dataframe(df)

    #enter new ticket
    st.header("🎫 IT Ticket Manager")


    with st.form("🎫 IT Ticket Manager"):
        title = st.text_input("Issue Title")
        description = st.text_area("Describe the issue in detail")
        
        submit_new = st.form_submit_button("Submit Ticket")

    if submit_new:
        new_ticket_id = tickets_manager.insert_ticket(
            title=title,
            description=description,
            status="Open",
            assigned_to="Unassigned"
        )
        st.success(f"Ticket #{new_ticket_id} created successfully!")
        st.rerun()#ensures the table is updated after entry

    #display how many tickets are handled by each staff member
    st.subheader("📊 Tickets per Staff Member")

    # Count tickets per staff
    tickets_per_staff = df.groupby("assigned_to").size().reset_index(name="count")

    # Horizontal bar chart
    chart = alt.Chart(tickets_per_staff).mark_bar().encode(
        x='count:Q',
        y=alt.Y('assigned_to:N', sort='-x'),  # horizontal bars, sorted by count
        color=alt.Color('assigned_to:N', legend=None)  # different color per staff
    ).properties(
        width=600,
        height=300
    )

    st.altair_chart(chart, use_container_width=True)

    #display the most common status among the tickets
    st.subheader("🟢 Ticket Status Distribution")
    status_counts = df["status"].value_counts()

    fig, ax = plt.subplots()
    ax.pie(status_counts, labels=status_counts.index, autopct='%1.1f%%', startangle=90, colors=["#f6c23e", "#36b9cc", "#1cc88a"])
    ax.axis("equal")  # Equal aspect ratio ensures pie is circular
    st.pyplot(fig)

    #display what statuses do each staff member have usually
    st.subheader("👥 Staff vs Ticket Status")
    status_staff = df.groupby(["assigned_to", "status"]).size().unstack(fill_value=0)
    st.bar_chart(status_staff)

   #display the average ticket resolution by staff
    st.subheader("⏱️ Average Ticket Resolution Time by Staff")
    df_resolved = df[df["status"] == "Resolved"].copy()
    df_resolved["created_at"] = pd.to_datetime(df_resolved["created_at"])
    df_resolved["resolved_date"] = pd.to_datetime(df_resolved["resolved_date"])
    df_resolved["resolution_time_hours"] = (df_resolved["resolved_date"] - df_resolved["created_at"]).dt.total_seconds() / 3600

    avg_resolution = df_resolved.groupby("assigned_to")["resolution_time_hours"].mean().sort_values(ascending=False)
    st.bar_chart(avg_resolution)




with tab2:
    st.subheader("Tickets table")
    UserService.require_role("staff")
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
