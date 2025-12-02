import pandas as pd
import csv
import sys
import streamlit as st
from pathlib import Path
from google import genai
from DATABASE.app.data.db import connect_database
#When importing to streamlit its important not to use relative imports

project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2") 
sys.path.append(str(project_root)) 

api_key = st.secrets["GEMINAI_API_KEY"]
client = genai.Client(api_key=api_key)


#import csv path
CSV_FILE = Path(__file__).resolve().parents[3] / "DATA"/ "cyber_incidents.csv"
print("Writing it at", CSV_FILE)

def insert_incident(date, incident_type, severity, status, description, reported_by):
    """Insert new incident."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO cyber_incidents 
        (date, incident_type, severity, status, description, reported_by)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (date, incident_type, severity, status, description, reported_by))
    conn.commit()
    incident_id = cursor.lastrowid
    conn.close()

    # If the file doesn't exist or it's empty, write the header once
    write_header = not CSV_FILE.exists() or CSV_FILE.stat().st_size == 0

    with open(CSV_FILE, mode="a", newline='', encoding="utf-8") as file:
        writer = csv.writer(file)

        # Add header only once
        if write_header:
            writer.writerow([
                "incident_id", "date", "incident_type", 
                "severity", "status", "description", "reported_by"
            ])

        # Add the incident row
        writer.writerow([
            incident_id, date, incident_type,
            severity, status, description, reported_by
        ])

    return incident_id


def get_all_incidents():
    """Get all incidents as DataFrame."""
    conn = connect_database()
    df = pd.read_sql_query(
        "SELECT * FROM cyber_incidents ORDER BY id DESC",
        conn
    )
    conn.close()
    return df


def delete_incident(incident_id):
    """Delete an incident by its ID."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute("""
        DELETE FROM cyber_incidents WHERE id = ?
    """, (incident_id,))
    conn.commit()
    conn.close()
    return cursor.rowcount  # returns number of rows deleted


def update_incident(incident_id, date=None, incident_type=None, severity=None, status=None, description=None, reported_by=None):
    """Update an incident by its ID. Only provided fields will be updated."""
    conn = connect_database()
    cursor = conn.cursor()

    # Build dynamic SQL based on which fields are provided
    fields = []
    values = []

    if date is not None:
        fields.append("date = ?")
        values.append(date)
    if incident_type is not None:
        fields.append("incident_type = ?")
        values.append(incident_type)
    if severity is not None:
        fields.append("severity = ?")
        values.append(severity)
    if status is not None:
        fields.append("status = ?")
        values.append(status)
    if description is not None:
        fields.append("description = ?")
        values.append(description)
    if reported_by is not None:
        fields.append("reported_by = ?")
        values.append(reported_by)

    # Only proceed if there’s something to update
    if fields:
        sql = f"UPDATE cyber_incidents SET {', '.join(fields)} WHERE id = ?"
        values.append(incident_id)
        cursor.execute(sql, values)
        conn.commit()

    conn.close()
    return cursor.rowcount  # returns number of rows updated

def analyze_incident(description, severity):

    response = client.models.generate_content(
        model="gemini-2.0-flash-thinking-exp",
        contents=f"""You are a cybersecurity expert.
        Analyze this cyber incident and give insights.

        Severity: {severity}
        Description: {description}
        """
    )
    return response.text