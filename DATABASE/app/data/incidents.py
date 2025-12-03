import pandas as pd
import csv
import sys
import streamlit as st
from pathlib import Path
from google import genai
from DATABASE.app.data.db import connect_database

project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
sys.path.append(str(project_root))

api_key = st.secrets["GEMINAI_API_KEY"]
client = genai.Client(api_key=api_key)

CSV_FILE = Path(__file__).resolve().parents[3] / "DATA" / "cyber_incidents.csv"


class Incidents:
    def __init__(self):
        self.csv_path = CSV_FILE

    # Create Incident
    def insert_incident(self, date, incident_type, severity, status, description, reported_by):
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

        # Write to CSV
        write_header = not self.csv_path.exists() or self.csv_path.stat().st_size == 0

        with open(self.csv_path, "a", newline='', encoding="utf-8") as f:
            writer = csv.writer(f)

            if write_header:
                writer.writerow([
                    "incident_id", "date", "incident_type",
                    "severity", "status", "description", "reported_by"
                ])

            writer.writerow([
                incident_id, date, incident_type,
                severity, status, description, reported_by
            ])

        return incident_id

    # Read all incidents
    def get_all_incidents(self):
        conn = connect_database()
        df = pd.read_sql_query("SELECT * FROM cyber_incidents ORDER BY id DESC", conn)
        conn.close()
        return df

    # Delete Incident
    @staticmethod
    def delete_incident(self, incident_id):
        conn = connect_database()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM cyber_incidents WHERE id = ?", (incident_id,))
        conn.commit()
        rows = cursor.rowcount
        conn.close()

        return rows

    # Update Incident
    def update_incident(self, incident_id, date=None, incident_type=None,
                        severity=None, status=None, description=None, reported_by=None):

        conn = connect_database()
        cursor = conn.cursor()

        # dictionary of field → value
        field_map = {
        "date": date,
        "incident_type": incident_type,
        "severity": severity,
        "status": status,
        "description": description,
        "reported_by": reported_by,
        }

        #create list to store changes
        fields = []
        values = []

        for field, value in field_map.items():
            if value is not None:
                fields.append(f"{field} = ?")
                values.append(value)

        # Only run the update if at least one field is being changed
        if fields:
            sql = f"UPDATE cyber_incidents SET {', '.join(fields)} WHERE id = ?"
            values.append(incident_id)
            cursor.execute(sql, values)
            conn.commit()

        rows = cursor.rowcount
        conn.close()

        # Write to CSV if something changed
        if fields:
            write_header = not self.csv_path.exists() or self.csv_path.stat().st_size == 0

            with open(self.csv_path, "a", newline='', encoding="utf-8") as f:
                writer = csv.writer(f)

                if write_header:
                    writer.writerow([
                        "incident_id", "date", "incident_type",
                        "severity", "status", "description", "reported_by"
                    ])

                writer.writerow([
                    incident_id, date, incident_type,
                    severity, status, description, reported_by
                ])

            return incident_id


    # AI Analysis
    def analyze_incident(self, description, severity):
        response = client.models.generate_content(
            model="gemini-2.0-flash-thinking-exp",
            contents=f"""
                You are a cybersecurity expert.
                Analyze this cyber incident and give insights.

                Severity: {severity}
                Description: {description}
            """
        )
        return response.text
