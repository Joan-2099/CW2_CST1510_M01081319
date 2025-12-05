import pandas as pd
import csv
from pathlib import Path
from google import genai
from DATABASE.app.data.db import connect_database
import streamlit as st

project_root = Path("/Users/joanmartha/Desktop/CST1510_CS2")
CSV_FILE = project_root / "DATA" / "cyber_incidents.csv"


class Incidents:
    def __init__(self,conn,CSV_FILE = project_root / "DATA" / "cyber_incidents.csv"):
        self.csv_path = CSV_FILE
        self.conn = conn

    def _write_to_csv(self, row_data):
        write_header = not self.csv_path.exists() or self.csv_path.stat().st_size == 0
        with open(self.csv_path, "a", newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            if write_header:
                writer.writerow([
                    "incident_id", "date", "incident_type",
                    "severity", "status", "description", "reported_by"
                ])
            writer.writerow(row_data)

    def insert_incident(self, date, incident_type, severity, status, description, reported_by):
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO cyber_incidents 
            (date, incident_type, severity, status, description, reported_by)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (date, incident_type, severity, status, description, reported_by))
        self.conn.commit()
        incident_id = cursor.lastrowid

        self._write_to_csv([
            incident_id, date, incident_type, severity, status, description, reported_by
        ])
        return incident_id

    def get_all_incidents(self):
        df = pd.read_sql_query("SELECT * FROM cyber_incidents ORDER BY id DESC", self.conn)
        return df

    def delete_incident(self, incident_id):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM cyber_incidents WHERE id = ?", (incident_id,))
        self.conn.commit()
        rows = cursor.rowcount
        return rows

    def update_incident(self, incident_id, date=None, incident_type=None,
                        severity=None, status=None, description=None, reported_by=None):
        cursor = self.conn.cursor()
        field_map = {
            "date": date,
            "incident_type": incident_type,
            "severity": severity,
            "status": status,
            "description": description,
            "reported_by": reported_by,
        }
        fields = []
        values = []
        for field, value in field_map.items():
            if value is not None:
                fields.append(f"{field} = ?")
                values.append(value)

        if fields:
            sql = f"UPDATE cyber_incidents SET {', '.join(fields)} WHERE id = ?"
            values.append(incident_id)
            cursor.execute(sql, values)
            self.conn.commit()

            self._write_to_csv([
                incident_id, date, incident_type, severity, status, description, reported_by
            ])
            return incident_id
        return None

    
# Pass connect function into the class instance
conn = connect_database()
incidents_manager = Incidents(conn)
